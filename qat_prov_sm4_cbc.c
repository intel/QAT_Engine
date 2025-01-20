/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2023-2025 Intel Corporation.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * ====================================================================
 */

/*****************************************************************************
 * @qat_prov_sm4_cbc.c
 *
 * This file contains the qatprovider implementation for SM4-CBC operations
 *
 *****************************************************************************/
#include <assert.h>

#include "qat_provider.h"
#include "qat_prov_sm4_cbc.h"
#include "qat_utils.h"
#include "e_qat.h"

#ifdef ENABLE_QAT_SW_SM4_CBC
# include "qat_sw_sm4_cbc.h"
#endif
#ifdef ENABLE_QAT_HW_SM4_CBC
# include "qat_hw_sm4_cbc.h"
#endif

#include "qat_constant_time.h"

#define ossl_assert(x) ((x) != 0)
#define UNINITIALISED_SIZET ((int)-1)
/* Max padding including padding length byte */
# define MAX_PADDING 256
# define SSL3_VERSION 0x0300

#if defined(ENABLE_QAT_HW_SM4_CBC) || defined(ENABLE_QAT_SW_SM4_CBC)
static OSSL_FUNC_cipher_freectx_fn qat_sm4_cbc_freectx;
OSSL_FUNC_cipher_get_ctx_params_fn qat_sm4_cbc_get_ctx_params;
OSSL_FUNC_cipher_gettable_ctx_params_fn qat_sm4_cbc_generic_gettable_ctx_params;
OSSL_FUNC_cipher_set_ctx_params_fn qat_sm4_cbc_set_ctx_params;
OSSL_FUNC_cipher_settable_ctx_params_fn qat_sm4_cbc_generic_settable_ctx_params;

static int qat_sm4_cbc_generic_initiv(QAT_PROV_CBC_CTX *ctx, const unsigned char *iv,
                               size_t ivlen)
{
    if (ivlen != ctx->ivlen
        || ivlen > sizeof(ctx->iv)) {
        QATerr(ERR_LIB_PROV, QAT_R_INVALID_IV_LENGTH);
        return 0;
    }
    ctx->iv_set = 1;
    memcpy(ctx->iv, iv, ivlen);
    memcpy(ctx->oiv, iv, ivlen);
    return 1;
}

static int qat_ssl3_cbc_copy_mac(size_t *reclen,
                             size_t origreclen,
                             unsigned char *recdata,
                             unsigned char **mac,
                             int *alloced,
                             size_t block_size,
                             size_t mac_size,
                             size_t good,
                             OSSL_LIB_CTX *libctx)
{
    unsigned char rotated_mac_buf[64 + EVP_MAX_MD_SIZE];
    unsigned char *rotated_mac;
    unsigned char randmac[EVP_MAX_MD_SIZE];
    unsigned char *out;

    /*
     * mac_end is the index of |recdata| just after the end of the MAC.
     */
    size_t mac_end = *reclen;
    size_t mac_start = mac_end - mac_size;
    size_t in_mac;
    /*
     * scan_start contains the number of bytes that we can ignore because the
     * MAC's position can only vary by 255 bytes.
     */
    size_t scan_start = 0;
    size_t i, j;
    size_t rotate_offset;

    if (!ossl_assert(origreclen >= mac_size
                     && mac_size <= EVP_MAX_MD_SIZE))
        return 0;

    /* If no MAC then nothing to be done */
    if (mac_size == 0) {
        /* No MAC so we can do this in non-constant time */
        if (good == 0)
            return 0;
        return 1;
    }

    *reclen -= mac_size;

    if (block_size == 1) {
        /* There's no padding so the position of the MAC is fixed */
        if (mac != NULL)
            *mac = &recdata[*reclen];
        if (alloced != NULL)
            *alloced = 0;
        return 1;
    }

    /* Create the random MAC we will emit if padding is bad */
    if (RAND_bytes_ex(libctx, randmac, mac_size, 0) <= 0)
        return 0;

    if (!ossl_assert(mac != NULL && alloced != NULL))
        return 0;
    *mac = out = OPENSSL_zalloc(mac_size);
    if (*mac == NULL)
        return 0;
    *alloced = 1;

    rotated_mac = rotated_mac_buf + ((0 - (size_t)rotated_mac_buf) & 63);

    /* This information is public so it's safe to branch based on it. */
    if (origreclen > mac_size + 255 + 1)
        scan_start = origreclen - (mac_size + 255 + 1);

    in_mac = 0;
    rotate_offset = 0;
    memset(rotated_mac, 0, mac_size);
    for (i = scan_start, j = 0; i < origreclen; i++) {
        size_t mac_started = qat_constant_time_eq(i, mac_start);
        size_t mac_ended = qat_constant_time_lt(i, mac_end);
        unsigned char b = recdata[i];

        in_mac |= mac_started;
        in_mac &= mac_ended;
        rotate_offset |= j & mac_started;
        rotated_mac[j++] |= b & in_mac;
        j &= qat_constant_time_lt(j, mac_size);
    }

    /* Now rotate the MAC */
    j = 0;
    for (i = 0; i < mac_size; i++) {
        /* in case cache-line is 32 bytes, touch second line */
        ((volatile unsigned char *)rotated_mac)[rotate_offset ^ 32];

        /* If the padding wasn't good we emit a random MAC */
        out[j++] = qat_constant_time_select_8((unsigned char)(good & 0xff),
                                          rotated_mac[rotate_offset++],
                                          randmac[i]);
        rotate_offset &= qat_constant_time_lt(rotate_offset, mac_size);
    }

    return 1;
}

int qat_tls1_cbc_remove_padding_and_mac(size_t *reclen,
                                    size_t origreclen,
                                    unsigned char *recdata,
                                    unsigned char **mac,
                                    int *alloced,
                                    size_t block_size, size_t mac_size,
                                    int aead,
                                    OSSL_LIB_CTX *libctx)
{
    size_t good = -1;
    size_t padding_length, to_check, i;
    size_t overhead = ((block_size == 1) ? 0 : 1) /* padding length byte */
                      + mac_size;

    /*
     * These lengths are all public so we can test them in non-constant
     * time.
     */
    if (overhead > *reclen)
        return 0;

    if (block_size != 1) {

        padding_length = recdata[*reclen - 1];

        if (aead) {
            /* padding is already verified and we don't need to check the MAC */
            *reclen -= padding_length + 1 + mac_size;
            return 1;
        }

        good = qat_constant_time_ge(*reclen, overhead + padding_length);
        /*
         * The padding consists of a length byte at the end of the record and
         * then that many bytes of padding, all with the same value as the
         * length byte. Thus, with the length byte included, there are i+1 bytes
         * of padding. We can't check just |padding_length+1| bytes because that
         * leaks decrypted information. Therefore we always have to check the
         * maximum amount of padding possible. (Again, the length of the record
         * is public information so we can use it.)
         */
        to_check = 256;        /* maximum amount of padding, inc length byte. */
        if (to_check > *reclen)
            to_check = *reclen;

        for (i = 0; i < to_check; i++) {
            unsigned char mask = qat_constant_time_ge_8(padding_length, i);
            unsigned char b = recdata[*reclen - 1 - i];
            /*
             * The final |padding_length+1| bytes should all have the value
             * |padding_length|. Therefore the XOR should be zero.
             */
            good &= ~(mask & (padding_length ^ b));
        }

        /*
         * If any of the final |padding_length+1| bytes had the wrong value, one
         * or more of the lower eight bits of |good| will be cleared.
         */
        good = qat_constant_time_eq(0xff, good & 0xff);
        *reclen -= good & (padding_length + 1);
    }

    return qat_ssl3_cbc_copy_mac(reclen, origreclen, recdata, mac, alloced,
                             block_size, mac_size, good, libctx);
}

int qat_cipher_tlsunpadblock(OSSL_LIB_CTX *libctx, unsigned int tlsversion,
                              unsigned char *buf, size_t *buflen,
                              size_t blocksize,
                              unsigned char **mac, int *alloced, size_t macsize,
                              int aead)
{
    int ret;

    if (tlsversion <= 0)
        return 0;

    /* Remove the explicit IV */
    buf += blocksize;
    *buflen -= blocksize;
    /* Fall through */

    ret = qat_tls1_cbc_remove_padding_and_mac(buflen, *buflen, buf, mac,
                                          alloced, blocksize, macsize,
                                          aead, libctx);
    return ret;
}

size_t qat_cipher_fillblock(unsigned char *buf, size_t *buflen,
                             size_t blocksize,
                             const unsigned char **in, size_t *inlen)
{
    size_t blockmask = ~(blocksize - 1);
    size_t bufremain = blocksize - *buflen;

    assert(*buflen <= blocksize);
    assert(blocksize > 0 && (blocksize & (blocksize - 1)) == 0);

    if (*inlen < bufremain)
        bufremain = *inlen;
    memcpy(buf + *buflen, *in, bufremain);
    *in += bufremain;
    *inlen -= bufremain;
    *buflen += bufremain;

    return *inlen & blockmask;
}

int qat_cipher_trailingdata(unsigned char *buf, size_t *buflen, size_t blocksize,
                             const unsigned char **in, size_t *inlen)
{
    if (*inlen == 0)
        return 1;

    if (*buflen + *inlen > blocksize) {
        QATerr(ERR_LIB_PROV, QAT_R_INTERNAL_ERROR);
        return 0;
    }

    memcpy(buf + *buflen, *in, *inlen);
    *buflen += *inlen;
    *inlen = 0;

    return 1;
}

void qat_sm4_cbc_initctx(void *provctx, QAT_PROV_CBC_CTX *ctx, size_t keybits,
                         size_t blkbits, size_t ivbits, uint64_t flags)
{
    if ((flags & PROV_CIPHER_FLAG_INVERSE_CIPHER) != 0)
        ctx->inverse_cipher = 1;
    if ((flags & PROV_CIPHER_FLAG_VARIABLE_LENGTH) != 0)
        ctx->variable_keylength = 1;

    ctx->nid = NID_sm4_cbc;
    ctx->pad = 1;
    ctx->keylen = ((keybits) / 8);
    ctx->ivlen = ((ivbits) / 8);
    ctx->mode = EVP_CIPH_CBC_MODE;
    ctx->blocksize = blkbits / 8;
    if (provctx != NULL)
        ctx->libctx = prov_libctx_of(provctx); /* used for rand */
#ifdef ENABLE_QAT_HW_SM4_CBC
    ctx->qat_cipher_ctx = OPENSSL_zalloc(sizeof(qat_sm4_ctx));
#endif
}

static void *qat_sm4_cbc_newctx(void *provctx, size_t keybits, size_t blkbits,
		                size_t ivbits, uint64_t flags)
{
    QAT_EVP_CIPHER_SM4_CBC *cipher = NULL;
    QAT_SM4CBC_CTX *ctx;

    if (!qat_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx)
        return NULL;
    cipher = OPENSSL_zalloc(sizeof(QAT_EVP_CIPHER_SM4_CBC));
    if (!cipher)
        return NULL;

    cipher->nid = NID_sm4_cbc;
    ctx->cipher = cipher;
    qat_sm4_cbc_initctx(provctx, &ctx->base, keybits, blkbits, ivbits, flags);

    return ctx;
}

int qat_sm4_cbc_einit(void *vctx, const unsigned char *inkey,
                      int keylen, const unsigned char *iv, int ivlen,
                      const OSSL_PARAM params[])
{
    int sts = 0;
    QAT_PROV_CBC_CTX *ctx = (QAT_PROV_CBC_CTX *) vctx;
    ctx->num = 0;
    ctx->bufsz = 0;
    ctx->updated = 0;
    ctx->enc = 1;

#ifdef ENABLE_QAT_SW_SM4_CBC
    if (qat_sw_sm4_cbc_offload) {
        sts = qat_sw_sm4_cbc_key_init(ctx, inkey, keylen, iv, ivlen, 1);
        if (sts != 1) {
            QATerr(ERR_LIB_PROV, QAT_R_EINIT_OPERATION_FAILED);
            return sts;
	}
    }
#endif
#ifdef ENABLE_QAT_HW_SM4_CBC
    if (qat_hw_sm4_cbc_offload) {
        sts = qat_sm4_cbc_init(ctx, inkey, keylen, iv, ivlen, 1);
        if (sts != 1) {
            QATerr(ERR_LIB_PROV, QAT_R_EINIT_OPERATION_FAILED);
            return sts;
        }
    }
#endif
    if (iv != NULL && ctx->mode != EVP_CIPH_ECB_MODE) {
        if (!qat_sm4_cbc_generic_initiv(ctx, iv, ivlen))
            return 0;
    }
    if (iv == NULL && ctx->iv_set
        && (ctx->mode == EVP_CIPH_CBC_MODE\
            || ctx->mode == EVP_CIPH_CFB_MODE
            || ctx->mode == EVP_CIPH_OFB_MODE))
        /* reset IV for these modes to keep compatibility with 1.1.1 */
        memcpy(ctx->iv, ctx->oiv, ctx->ivlen);

    if (inkey != NULL) {
        if (ctx->variable_keylength == 0) {
            if (keylen != ctx->keylen) {
                QATerr(ERR_LIB_PROV, QAT_R_INVALID_KEY_LENGTH);
                return 0;
            }
        } else {
            ctx->keylen = keylen;
        }
    }

    return qat_sm4_cbc_set_ctx_params(ctx, params);
}

int qat_sm4_cbc_dinit(void *vctx, const unsigned char *inkey,
                      int keylen, const unsigned char *iv, int ivlen,
                      const OSSL_PARAM params[])
{
    int sts = 0;
    QAT_PROV_CBC_CTX *ctx = (QAT_PROV_CBC_CTX *) vctx;
    ctx->num = 0;
    ctx->bufsz = 0;
    ctx->updated = 0;
    ctx->enc = 0;

#ifdef ENABLE_QAT_SW_SM4_CBC
    if (qat_sw_sm4_cbc_offload) {
        sts = qat_sw_sm4_cbc_key_init(ctx, inkey, keylen, iv, ivlen, 0);
        if (sts != 1) {
            QATerr(ERR_LIB_PROV, QAT_R_DINIT_OPERATION_FAILED);
            return sts;
        }
    }
#endif
#ifdef ENABLE_QAT_HW_SM4_CBC
    if (qat_hw_sm4_cbc_offload) {
        sts = qat_sm4_cbc_init(ctx, inkey, keylen, iv, ivlen, 0);
        if (sts != 1) {
            QATerr(ERR_LIB_PROV, QAT_R_DINIT_OPERATION_FAILED);
            return sts;
        }
    }
#endif
    if (iv != NULL && ctx->mode != EVP_CIPH_ECB_MODE) {
        if (!qat_sm4_cbc_generic_initiv(ctx, iv, ivlen))
            return 0;
    }
    if (iv == NULL && ctx->iv_set
        && (ctx->mode == EVP_CIPH_CBC_MODE
            || ctx->mode == EVP_CIPH_CFB_MODE
            || ctx->mode == EVP_CIPH_OFB_MODE))
        /* reset IV for these modes to keep compatibility with 1.1.1 */
        memcpy(ctx->iv, ctx->oiv, ctx->ivlen);

    if (inkey != NULL) {
        if (ctx->variable_keylength == 0) {
            if (keylen != ctx->keylen) {
                QATerr(ERR_LIB_PROV, QAT_R_INVALID_KEY_LENGTH);
                return 0;
            }
        } else {
            ctx->keylen = keylen;
        }
    }

    return qat_sm4_cbc_set_ctx_params(ctx, params);

}

int qat_sm4_cbc_block_update(void *vctx, unsigned char *out,
                              size_t *outl, size_t outsize,
                              const unsigned char *in, size_t inl)
{
    size_t outlint = 0;
    QAT_PROV_CBC_CTX *ctx = (QAT_PROV_CBC_CTX *) vctx;
    size_t blksz = ctx->blocksize;
    size_t nextblocks;

    if (ctx->tlsversion > 0) {
        /*
         * Each update call corresponds to a TLS record and is individually
         * padded
         */

        /* Sanity check inputs */
        if (in == NULL
                || in != out
                || outsize < inl
                || !ctx->pad) {
            QATerr(ERR_LIB_PROV, QAT_R_CIPHER_OPERATION_FAILED);
            return 0;
        }

        if (ctx->enc) {
            unsigned char padval;
            size_t padnum, loop;

            /* Add padding */

            padnum = blksz - (inl % blksz);

            if (outsize < inl + padnum) {
                QATerr(ERR_LIB_PROV, QAT_R_CIPHER_OPERATION_FAILED);
                return 0;
            }

            if (padnum > MAX_PADDING) {
                QATerr(ERR_LIB_PROV, QAT_R_CIPHER_OPERATION_FAILED);
                return 0;
            }
            padval = (unsigned char)(padnum - 1);
            if (ctx->tlsversion == SSL3_VERSION) {
                if (padnum > 1)
                    memset(out + inl, 0, padnum - 1);
                *(out + inl + padnum - 1) = padval;
            } else {
                /* we need to add 'padnum' padding bytes of value padval */
                for (loop = inl; loop < inl + padnum; loop++)
                    out[loop] = padval;
            }
            inl += padnum;
        }

        if ((inl % blksz) != 0) {
            QATerr(ERR_LIB_PROV, QAT_R_CIPHER_OPERATION_FAILED);
            return 0;
        }

#ifdef ENABLE_QAT_SW_SM4_CBC
        if (qat_sw_sm4_cbc_offload) {
            if (qat_sw_sm4_cbc_cipher(ctx, out, outl, outsize, in, inl) <= 0) {
                QATerr(ERR_LIB_PROV, QAT_R_CBC_OPERATION_FAILED);
                return 0;
            }
        }
#endif
#ifdef ENABLE_QAT_HW_SM4_CBC
        if (qat_hw_sm4_cbc_offload) {
            if (qat_sm4_cbc_do_cipher(ctx, out, outl, outsize, in, inl) <= 0) {
                QATerr(ERR_LIB_PROV, QAT_R_CBC_OPERATION_FAILED);
                return 0;
            }
        }
#endif
        if (ctx->alloced) {
            OPENSSL_free(ctx->tlsmac);
            ctx->alloced = 0;
            ctx->tlsmac = NULL;
        }

        if (!ctx->enc
            && !qat_cipher_tlsunpadblock(ctx->libctx, ctx->tlsversion,
                                          out, outl,
                                          blksz, &ctx->tlsmac, &ctx->alloced,
                                          ctx->tlsmacsize, 0)) {
            QATerr(ERR_LIB_PROV, QAT_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
        return 1;
    }

    if (ctx->bufsz != 0)
        nextblocks = qat_cipher_fillblock(ctx->buf, &ctx->bufsz, blksz,
                                           &in, &inl);
    else
        nextblocks = inl & ~(blksz-1);

    /*
     * If we're decrypting and we end an update on a block boundary we hold
     * the last block back in case this is the last update call and the last
     * block is padded.
     */
    if (ctx->bufsz == blksz && (ctx->enc || inl > 0 || !ctx->pad)) {
        if (outsize < blksz) {
            QATerr(ERR_LIB_PROV, QAT_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
#ifdef ENABLE_QAT_SW_SM4_CBC
        if (qat_sw_sm4_cbc_offload) {
            if (qat_sw_sm4_cbc_cipher(ctx, out, outl, outsize, in, inl) <= 0) {
                QATerr(ERR_LIB_PROV, QAT_R_CBC_OPERATION_FAILED);
                return 0;
            }
        }
#endif
#ifdef ENABLE_QAT_HW_SM4_CBC
        if (qat_hw_sm4_cbc_offload) {
            if (qat_sm4_cbc_do_cipher(ctx, out, outl, outsize, in, inl) <= 0) {
                QATerr(ERR_LIB_PROV, QAT_R_CBC_OPERATION_FAILED);
                return 0;
            }
        }
#endif
        ctx->bufsz = 0;
        outlint = blksz;
        out += blksz;
    }
    if (nextblocks > 0) {
        if (!ctx->enc && ctx->pad && nextblocks == inl) {
            if (!ossl_assert(inl >= blksz)) {
                QATerr(ERR_LIB_PROV, QAT_R_OUTPUT_BUFFER_TOO_SMALL);
                return 0;
            }
            nextblocks -= blksz;
        }
        outlint += nextblocks;
        if (outsize < outlint) {
            QATerr(ERR_LIB_PROV, QAT_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
    }
    if (nextblocks > 0) {
#ifdef ENABLE_QAT_SW_SM4_CBC
        if (qat_sw_sm4_cbc_offload) {
            if (qat_sw_sm4_cbc_cipher(ctx, out, outl, outsize, in, inl) <= 0) {
                QATerr(ERR_LIB_PROV, QAT_R_CBC_OPERATION_FAILED);
                return 0;
            }
        }
#endif
#ifdef ENABLE_QAT_HW_SM4_CBC
        if (qat_hw_sm4_cbc_offload) {
            if (qat_sm4_cbc_do_cipher(ctx, out, outl, outsize, in, inl) <= 0) {
                QATerr(ERR_LIB_PROV, QAT_R_CBC_OPERATION_FAILED);
                return 0;
            }
        }
#endif
        in += nextblocks;
        inl -= nextblocks;
    }
    if (inl != 0
        && !qat_cipher_trailingdata(ctx->buf, &ctx->bufsz, blksz, &in, &inl)) {
        /* QATerr already called */
        return 0;
    }

    *outl = outlint;
    return inl == 0;
}

int qat_sm4_cbc_block_final(void *vctx, unsigned char *out,
                             size_t *outl, size_t outsize)
{
    int ret = 0;

    if (!qat_prov_is_running())
        goto end;

    *outl = 0;
    ret = 1;

 end:
    return ret;
}

int qat_sm4_cbc_cipher(void *vctx, unsigned char *out,
                       size_t *outl, size_t outsize,
                       const unsigned char *in, size_t inl)
{
    int ret = 0;
    QAT_PROV_CBC_CTX *ctx = (QAT_PROV_CBC_CTX *) vctx;

    if (!qat_prov_is_running())
        goto end;

    if (outsize < inl) {
        QATerr(ERR_LIB_PROV, QAT_R_OUTPUT_BUFFER_TOO_SMALL);
        goto end;
    }
#ifdef ENABLE_QAT_SW_SM4_CBC
    if (qat_sw_sm4_cbc_offload) {
        if (qat_sw_sm4_cbc_cipher(ctx, out, outl, outsize, in, inl) <= 0) {
            QATerr(ERR_LIB_PROV, QAT_R_CBC_OPERATION_FAILED);
            return 0;
        }
    }
#endif
#ifdef ENABLE_QAT_HW_SM4_CBC
    if (qat_hw_sm4_cbc_offload) {
        if (qat_sm4_cbc_do_cipher(ctx, out, outl, outsize, in, inl) <= 0)  {
            QATerr(ERR_LIB_PROV, QAT_R_CBC_OPERATION_FAILED);
            return 0;
        }
    }
#endif
    *outl = inl;
    ret = 1;

 end:
    return ret;
}

static void qat_sm4_cbc_freectx(void *vctx)
{
    QAT_SM4CBC_CTX *ctx = (QAT_SM4CBC_CTX *) vctx;
    if (ctx->cipher) {
        OPENSSL_free(ctx->cipher);
        ctx->cipher = NULL;
    }
#ifdef ENABLE_QAT_SW_SM4_CBC
    if (qat_sw_sm4_cbc_offload)
        qat_sw_sm4_cbc_cleanup((QAT_PROV_CBC_CTX *) ctx);
#endif
#ifdef ENABLE_QAT_HW_SM4_CBC
    if (qat_hw_sm4_cbc_offload)
        qat_sm4_cbc_cleanup((QAT_PROV_CBC_CTX *) ctx);
#endif
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void qat_sm4_cbc_copyctx(QAT_PROV_CBC_CTX *dst,
                                const QAT_PROV_CBC_CTX *src)
{
    QAT_PROV_CBC_CTX *sctx = (QAT_PROV_CBC_CTX *)src;
    QAT_PROV_CBC_CTX *dctx = (QAT_PROV_CBC_CTX *)dst;

    *dctx = *sctx;
}

static void *qat_sm4_cbc_dupctx(void *ctx)
{
    QAT_SM4CBC_CTX *in = (QAT_SM4CBC_CTX *)ctx;
    QAT_SM4CBC_CTX *ret;

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL) {
        QATerr(ERR_LIB_PROV, QAT_R_ZALLOC_FAILURE);
        return NULL;
    }
    qat_sm4_cbc_copyctx(&ret->base, &in->base);

    return ret;
}

static const OSSL_PARAM qat_sm4_cbc_known_gettable_params[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CTS, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
    OSSL_PARAM_END
};
const OSSL_PARAM *qat_sm4_cbc_generic_gettable_params(ossl_unused void *provctx)
{
    return qat_sm4_cbc_known_gettable_params;
}

int qat_sm4_cbc_generic_get_params(OSSL_PARAM params[], unsigned int md,
                                   uint64_t flags, size_t kbits,
                                   size_t blkbits, size_t ivbits)
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, md)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_AEAD) != 0)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CUSTOM_IV) != 0)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CTS) != 0)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_TLS1_MULTIBLOCK) != 0)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_HAS_RAND_KEY);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_RAND_KEY) != 0)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, kbits / 8)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blkbits / 8)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ivbits / 8)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}

static const OSSL_PARAM qat_sm4_cbc_aead_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN, NULL, 0),
    OSSL_PARAM_END
};
const OSSL_PARAM *qat_sm4_cbc_generic_gettable_ctx_params(
        ossl_unused void *cctx, ossl_unused void *provctx
    )
{
    return qat_sm4_cbc_aead_known_gettable_ctx_params;
}

static const OSSL_PARAM qat_sm4_cbc_aead_known_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV, NULL, 0),
    OSSL_PARAM_END
};
const OSSL_PARAM *qat_sm4_cbc_generic_settable_ctx_params(
        ossl_unused void *cctx, ossl_unused void *provctx
    )
{
    return qat_sm4_cbc_aead_known_settable_ctx_params;
}

int qat_sm4_cbc_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    QAT_PROV_CBC_CTX *ctx = (QAT_PROV_CBC_CTX *)vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->ivlen)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->pad)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(p, &ctx->oiv, ctx->ivlen)
        && !OSSL_PARAM_set_octet_string(p, &ctx->oiv, ctx->ivlen)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivlen)
        && !OSSL_PARAM_set_octet_string(p, &ctx->iv, ctx->ivlen)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->num)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS_MAC);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(p, ctx->tlsmac, ctx->tlsmacsize)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    return 1;
}

int qat_sm4_cbc_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    QAT_PROV_CBC_CTX *ctx = (QAT_PROV_CBC_CTX *)vctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL) {
        unsigned int pad;

        if (!OSSL_PARAM_get_uint(p, &pad)) {
            QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ctx->pad = pad ? 1 : 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_USE_BITS);
    if (p != NULL) {
        unsigned int bits;

        if (!OSSL_PARAM_get_uint(p, &bits)) {
            QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ctx->use_bits = bits ? 1 : 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_VERSION);
    if (p != NULL) {
        if (!OSSL_PARAM_get_uint(p, &ctx->tlsversion)) {
            QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_MAC_SIZE);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &ctx->tlsmacsize)) {
            QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL) {
        unsigned int num;

        if (!OSSL_PARAM_get_uint(p, &num)) {
            QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ctx->num = num;
    }
    return 1;
}

/* qat_sm4_cbc_functions */
QAT_sm4_cbc_func(qat_sm4, cbc, CBC, 0, 128, 128, 128, block);
#endif
