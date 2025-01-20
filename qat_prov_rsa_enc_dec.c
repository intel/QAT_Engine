/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2024-2025 Intel Corporation.
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
 * @file qat_prov_rsa_enc_dec.c
 *
 * This file provides an implementation to qatprovider RSA Encryption and Decryption operations
 *
 *****************************************************************************/
# include <openssl/core_dispatch.h>
# include <openssl/params.h>
# include <openssl/err.h>
# include <openssl/rsa.h>
# include <openssl/core_names.h>
# include <openssl/evp.h>
# include <openssl/proverr.h>
# include <openssl/rand.h>
# include <openssl/sha.h>
# include <openssl/prov_ssl.h>
# include "e_qat.h"
# include "qat_provider.h"
# include "qat_prov_rsa.h"
# include "qat_utils.h"
# include "qat_constant_time.h"

# ifdef QAT_HW
#  include "qat_hw_rsa.h"
# endif

#ifdef QAT_SW
#include "qat_sw_rsa.h"
#endif

# define QAT_MAX_NAME_SIZE           50/* Algorithm name */
# define QAT_MAX_PROPQUERY_SIZE     256/* Property query strings */

#if defined(ENABLE_QAT_HW_RSA) || defined(ENABLE_QAT_SW_RSA)

static OSSL_ITEM qat_padding_item[] = {
    {RSA_PKCS1_PADDING, OSSL_PKEY_RSA_PAD_MODE_PKCSV15},
    {RSA_NO_PADDING, OSSL_PKEY_RSA_PAD_MODE_NONE},
    {RSA_PKCS1_OAEP_PADDING, OSSL_PKEY_RSA_PAD_MODE_OAEP},
    {RSA_PKCS1_OAEP_PADDING, "oeap"},
    {RSA_X931_PADDING, OSSL_PKEY_RSA_PAD_MODE_X931},
    {0, NULL}
};

static void *qat_prov_rsa_newctx(void *provctx);
static int qat_prov_rsa_encrypt_init(void *ctx, void *rsa,
                                     const OSSL_PARAM params[]);
static int qat_prov_rsa_encrypt(void *vprsactx, unsigned char *out,
                                size_t *outlen, size_t outsize,
                                const unsigned char *in, size_t inlen);
static int qat_prov_rsa_decrypt_init(void *ctx, void *rsa,
                                     const OSSL_PARAM params[]);
static int qat_prov_rsa_decrypt(void *vprsactx, unsigned char *out,
                                size_t *outlen, size_t outsize,
                                const unsigned char *in, size_t inlen);
static void qat_prov_rsa_freectx(void *vprsactx);
static void *qat_prov_rsa_dupctx(void *vprsactx);
static int qat_prov_rsa_get_ctx_params(void *vprsactx, OSSL_PARAM * params);
static const OSSL_PARAM *qat_prov_rsa_gettable_ctx_params(ossl_unused void
                                                          *vprsactx,
                                                          ossl_unused void
                                                          *provctx);
static int qat_prov_rsa_set_ctx_params(void *vprsactx,
                                       const OSSL_PARAM params[]);
static const OSSL_PARAM *qat_prov_rsa_settable_ctx_params(ossl_unused void
                                                          *vprsactx,
                                                          ossl_unused void
                                                          *provctx);


typedef struct qat_evp_asym_cipher_st {
    int name_id;
    char *type_name;
    const char *description;
    OSSL_PROVIDER *prov;
    CRYPTO_REF_COUNT refcnt;
#if OPENSSL_VERSION_NUMBER < 0x30200000
    CRYPTO_RWLOCK *lock;
#endif
    OSSL_FUNC_asym_cipher_newctx_fn *newctx;
    OSSL_FUNC_asym_cipher_encrypt_init_fn *encrypt_init;
    OSSL_FUNC_asym_cipher_encrypt_fn *encrypt;
    OSSL_FUNC_asym_cipher_decrypt_init_fn *decrypt_init;
    OSSL_FUNC_asym_cipher_decrypt_fn *decrypt;
    OSSL_FUNC_asym_cipher_freectx_fn *freectx;
    OSSL_FUNC_asym_cipher_dupctx_fn *dupctx;
    OSSL_FUNC_asym_cipher_get_ctx_params_fn *get_ctx_params;
    OSSL_FUNC_asym_cipher_gettable_ctx_params_fn *gettable_ctx_params;
    OSSL_FUNC_asym_cipher_set_ctx_params_fn *set_ctx_params;
    OSSL_FUNC_asym_cipher_settable_ctx_params_fn *settable_ctx_params;
} QAT_EVP_ASYM_CIPHER;

static QAT_EVP_ASYM_CIPHER get_default_rsa_asym_cipher()
{
    static QAT_EVP_ASYM_CIPHER s_asym_cipher;
    static int initilazed = 0;
    if (!initilazed) {
        QAT_EVP_ASYM_CIPHER *asym_cipher = (QAT_EVP_ASYM_CIPHER *)EVP_ASYM_CIPHER_fetch(NULL, "RSA", "provider=default");
        if (asym_cipher) {
            s_asym_cipher = *asym_cipher;
            EVP_ASYM_CIPHER_free((EVP_ASYM_CIPHER *)asym_cipher);
            initilazed = 1;
        } else {
            WARN("EVP_ASYM_CIPHER_fetch from default provider failed");
        }
    }
    return s_asym_cipher;
}

static void *qat_prov_rsa_newctx(void *provctx)
{
    QAT_PROV_RSA_ENC_DEC_CTX *ctx;

    if (!qat_prov_is_running())
        return NULL;
    ctx = OPENSSL_zalloc(sizeof(QAT_PROV_RSA_ENC_DEC_CTX));
    if (ctx == NULL)
        return NULL;
    ctx->libctx = prov_libctx_of(provctx);

    return ctx;
}

int qat_rsa_check_key(OSSL_LIB_CTX * ctx, const RSA *rsa, int operation)
{
    int protect = 0;

    switch (operation) {
    case EVP_PKEY_OP_SIGN:
        protect = 1;
    case EVP_PKEY_OP_VERIFY:
        break;
    case EVP_PKEY_OP_ENCAPSULATE:
    case EVP_PKEY_OP_ENCRYPT:
        protect = 1;
    case EVP_PKEY_OP_VERIFYRECOVER:
    case EVP_PKEY_OP_DECAPSULATE:
    case EVP_PKEY_OP_DECRYPT:
        if (QAT_RSA_test_flags(rsa,
                               RSA_FLAG_TYPE_MASK) == RSA_FLAG_TYPE_RSASSAPSS) {
            QATerr(ERR_LIB_PROV,
                   QAT_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
            return 0;
        }
        break;
    default:
        QATerr(ERR_LIB_PROV, QAT_R_INTERNAL_ERROR);
        return 0;
    }

# if !defined(OPENSSL_NO_FIPS_SECURITYCHECKS)
    if (qat_securitycheck_enabled(ctx)) {
        int sz = QAT_RSA_bits(rsa);

        if (protect ? (sz < 2048) : (sz < 1024)) {
            QATerr(ERR_LIB_PROV, QAT_R_INVALID_KEY_LENGTH);
            return 0;
        }
    }
# else
    (void)protect;
# endif                         /* OPENSSL_NO_FIPS_SECURITYCHECKS */
    return 1;
}

int qat_rsa_padding_add_PKCS1_OAEP_mgf1_ex(OSSL_LIB_CTX * libctx,
                                           unsigned char *to, int tlen,
                                           const unsigned char *from, int flen,
                                           const unsigned char *param,
                                           int plen, const EVP_MD *md,
                                           const EVP_MD *mgf1md)
{
    int rv = 0;
    int i, emlen = tlen - 1;
    unsigned char *db, *seed;
    unsigned char *dbmask = NULL;
    unsigned char seedmask[EVP_MAX_MD_SIZE];
    int mdlen, dbmask_len = 0;

    if (md == NULL) {
        md = EVP_sha1();
    }
    if (mgf1md == NULL)
        mgf1md = md;

    mdlen = EVP_MD_get_size(md);
    if (mdlen <= 0) {
        QATerr(ERR_LIB_RSA, QAT_R_INVALID_LENGTH);
        return 0;
    }

    if (flen > emlen - 2 * mdlen - 1) {
        QATerr(ERR_LIB_RSA, QAT_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        return 0;
    }

    if (emlen < 2 * mdlen + 1) {
        QATerr(ERR_LIB_RSA, QAT_R_KEY_SIZE_TOO_SMALL);
        return 0;
    }

    to[0] = 0;
    seed = to + 1;
    db = to + mdlen + 1;

    if (!EVP_Digest((void *)param, plen, db, NULL, md, NULL))
        goto err;
    memset(db + mdlen, 0, emlen - flen - 2 * mdlen - 1);
    db[emlen - flen - mdlen - 1] = 0x01;
    memcpy(db + emlen - flen - mdlen, from, (unsigned int)flen);
    if (RAND_bytes_ex(libctx, seed, mdlen, 0) <= 0)
        goto err;

    dbmask_len = emlen - mdlen;
    dbmask = OPENSSL_malloc(dbmask_len);
    if (dbmask == NULL) {
        QATerr(ERR_LIB_RSA, QAT_R_MALLOC_FAILURE);
        goto err;
    }

    if (QAT_PKCS1_MGF1(dbmask, dbmask_len, seed, mdlen, mgf1md) < 0)
        goto err;
    for (i = 0; i < dbmask_len; i++)
        db[i] ^= dbmask[i];

    if (QAT_PKCS1_MGF1(seedmask, mdlen, db, dbmask_len, mgf1md) < 0)
        goto err;
    for (i = 0; i < mdlen; i++)
        seed[i] ^= seedmask[i];
    rv = 1;

 err:
    OPENSSL_cleanse(seedmask, sizeof(seedmask));
    OPENSSL_clear_free(dbmask, dbmask_len);
    return rv;
}

/******************************************************************************
 *    * function:
 *          qat_rsa_public_encrypt(int flen, const unsigned char *from,
 *                                   unsigned char *to, RSA *rsa, int padding)
 *
 * qat_rsa_public_encrypt - RSA public key encryption using QAT engine.
 *
 * @param flen [IN] - Length of the input data (in bytes) to be encrypted.
 * @param from [IN] -  Pointer to the input data to be encrypted.
 * @param to [IN] - Pointer to the output buffer.
 * @param rsa [IN] -  RSA key structure containing the public key.
 * @param padding [IN] - Padding mode to be used for encryption.
 *
 * description:
 *    This function performs RSA public key encryption. Depending on the
 *    configuration, it may offload the encryption operation to hardware (QAT)
 *    or software (QAT_SW) if offloading is enabled. The result is stored in
 *    the output buffer provided.
 *
 * returns:
 * - The size of the decrypted data on success.
 * - 0 or a negative value on error.
 ******************************************************************************/
static int qat_rsa_public_encrypt(int flen, const unsigned char *from,
                                   unsigned char *to, RSA *rsa, int padding)
{
    int ret = 0;
#ifdef ENABLE_QAT_HW_RSA
    if (qat_hw_rsa_offload)
        ret = qat_rsa_pub_enc(flen, from, to, rsa, padding);
#endif

#ifdef ENABLE_QAT_SW_RSA
    if (qat_sw_rsa_offload)
        ret = multibuff_rsa_pub_enc(flen, from, to, rsa, padding);
#endif
    return ret;
}

/******************************************************************************
 *    * function:
 *          qat_rsa_private_decrypt(int flen, const unsigned char *from,
 *                                   unsigned char *to, RSA *rsa, int padding)
 *
 * qat_rsa_private_decrypt - RSA private key decryption using QAT engine.
 *
 * @param flen [IN] - Length of the encrypted input data to be decrypted.
 * @param from [IN] -  Pointer to the encrypted input data.
 * @param to [IN] - Pointer to the output buffer.
 * @param rsa [IN] -  RSA key structure containing the private key.
 * @param padding [IN] - Padding mode to be used for decryption.
 *
 * description:
 *    This function performs RSA private key decryption. Depending on the
 *    configuration, it may offload the decryption operation to hardware (QAT)
 *    or software (QAT_SW) if offloading is enabled. The result is
 *    stored in the output buffer provided.
 *
 * returns:
 * - The size of the decrypted data on success.
 * - 0 or a negative value on error.
 ******************************************************************************/
static int qat_rsa_private_decrypt(int flen, const unsigned char *from,
                                    unsigned char *to, RSA *rsa, int padding)
{
    int ret = 0;
#ifdef ENABLE_QAT_HW_RSA
    if (qat_hw_rsa_offload)
        ret = qat_rsa_priv_dec(flen, from, to, rsa, padding);
#endif

#ifdef ENABLE_QAT_SW_RSA
    if (qat_sw_rsa_offload)
        ret = multibuff_rsa_priv_dec(flen, from, to, rsa, padding);
#endif
    return ret;
}

static int qat_prov_rsa_encrypt(void *vprsactx, unsigned char *out,
                                size_t *outlen, size_t outsize,
                                const unsigned char *in, size_t inlen)
{
    QAT_PROV_RSA_ENC_DEC_CTX *ctx = (QAT_PROV_RSA_ENC_DEC_CTX *) vprsactx;
    int ret;

    if (!qat_prov_is_running())
        return 0;

    if (out == NULL) {
        size_t len = QAT_RSA_size(ctx->rsa);

        if (len == 0) {
            QATerr(ERR_LIB_PROV, QAT_R_INVALID_KEY);
            return 0;
        }
        *outlen = len;
        return 1;
    }
    if (ctx->pad_mode == RSA_PKCS1_OAEP_PADDING) {
        int rsasize = QAT_RSA_size(ctx->rsa);
        unsigned char *tbuf;

        if ((tbuf = OPENSSL_malloc(rsasize)) == NULL) {
            QATerr(ERR_LIB_PROV, QAT_R_MALLOC_FAILURE);
            return 0;
        }
        if (ctx->oaep_md == NULL) {
            ctx->oaep_md = EVP_MD_fetch(ctx->libctx, "SHA-1", NULL);
            if (ctx->oaep_md == NULL) {
                OPENSSL_free(tbuf);
                QATerr(ERR_LIB_PROV, QAT_R_INTERNAL_ERROR);
                return 0;
            }
        }
        ret =
            qat_rsa_padding_add_PKCS1_OAEP_mgf1_ex(ctx->libctx, tbuf,
                                                   rsasize, in, inlen,
                                                   ctx->oaep_label,
                                                   ctx->oaep_labellen,
                                                   ctx->oaep_md, ctx->mgf1_md);

        if (!ret) {
            OPENSSL_free(tbuf);
            return 0;
        }
	if (qat_hw_rsa_offload || qat_sw_rsa_offload) {
            ret = qat_rsa_public_encrypt(rsasize, tbuf, out, ctx->rsa, RSA_NO_PADDING);
        } else {
            typedef int (*fun_ptr)(void *vprsactx, unsigned char *out,
                                   size_t *outlen, size_t outsize,
                                   const unsigned char *in, size_t inlen);
            fun_ptr fun = get_default_rsa_asym_cipher().encrypt;
            if (!fun)
                return 0;
            return fun(vprsactx, out, outlen, outsize, in, inlen);
        }
        OPENSSL_free(tbuf);
    } else {
        if (qat_hw_rsa_offload || qat_sw_rsa_offload) {
            ret = qat_rsa_public_encrypt(inlen, in, out, ctx->rsa, ctx->pad_mode);
        } else {
            typedef int (*fun_ptr)(void *vprsactx, unsigned char *out,
                                   size_t *outlen, size_t outsize,
                                   const unsigned char *in, size_t inlen);
            fun_ptr fun = get_default_rsa_asym_cipher().encrypt;
            if (!fun)
                return 0;
            return fun(vprsactx, out, outlen, outsize, in, inlen);
        }
    }
    if (ret < 0)
        return ret;
    *outlen = ret;
    return 1;
}

int qat_rsa_padding_check_PKCS1_type_2_TLS(OSSL_LIB_CTX * libctx,
                                           unsigned char *to, size_t tlen,
                                           const unsigned char *from,
                                           size_t flen, int client_version,
                                           int alt_version)
{
    unsigned int i, good, version_good;
    unsigned char rand_premaster_secret[SSL_MAX_MASTER_KEY_LENGTH];

    /*
     * If these checks fail then either the message in publicly invalid, or
     * we've been called incorrectly. We can fail immediately.
     */
    if (flen < RSA_PKCS1_PADDING_SIZE + SSL_MAX_MASTER_KEY_LENGTH
        || tlen < SSL_MAX_MASTER_KEY_LENGTH) {
        QATerr(ERR_LIB_RSA, QAT_R_PKCS_DECODING_ERROR);
        return -1;
    }

    /*
     * Generate a random premaster secret to use in the event that we fail
     * to decrypt.
     */
    if (RAND_priv_bytes_ex(libctx, rand_premaster_secret,
                           sizeof(rand_premaster_secret), 0) <= 0) {
        QATerr(ERR_LIB_RSA, QAT_R_INTERNAL_ERROR);
        return -1;
    }

    good = qat_constant_time_is_zero(from[0]);
    good &= qat_constant_time_eq(from[1], 2);

    for (i = 2; i < flen - SSL_MAX_MASTER_KEY_LENGTH - 1; i++)
        good &= ~qat_constant_time_is_zero_8(from[i]);
    good &=
        qat_constant_time_is_zero_8(from[flen - SSL_MAX_MASTER_KEY_LENGTH - 1]);

    version_good =
        qat_constant_time_eq(from[flen - SSL_MAX_MASTER_KEY_LENGTH],
                             (client_version >> 8) & 0xff);
    version_good &=
        qat_constant_time_eq(from[flen - SSL_MAX_MASTER_KEY_LENGTH + 1],
                             client_version & 0xff);

    if (alt_version > 0) {
        unsigned int workaround_good;

        workaround_good =
            qat_constant_time_eq(from[flen - SSL_MAX_MASTER_KEY_LENGTH],
                                 (alt_version >> 8) & 0xff);
        workaround_good &=
            qat_constant_time_eq(from[flen - SSL_MAX_MASTER_KEY_LENGTH + 1],
                                 alt_version & 0xff);
        version_good |= workaround_good;
    }

    good &= version_good;

    for (i = 0; i < SSL_MAX_MASTER_KEY_LENGTH; i++) {
        to[i] =
            qat_constant_time_select_8(good,
                                       from[flen - SSL_MAX_MASTER_KEY_LENGTH +
                                            i], rand_premaster_secret[i]);
    }

    return SSL_MAX_MASTER_KEY_LENGTH;
}

static int qat_prov_rsa_decrypt(void *vprsactx, unsigned char *out,
                                size_t *outlen, size_t outsize,
                                const unsigned char *in, size_t inlen)
{
    QAT_PROV_RSA_ENC_DEC_CTX *ctx = (QAT_PROV_RSA_ENC_DEC_CTX *) vprsactx;
    int ret;
    size_t len = QAT_RSA_size(ctx->rsa);

    if (!qat_prov_is_running())
        return 0;

    if (ctx->pad_mode == RSA_PKCS1_WITH_TLS_PADDING) {
        if (out == NULL) {
            *outlen = SSL_MAX_MASTER_KEY_LENGTH;
            return 1;
        }
        if (outsize < SSL_MAX_MASTER_KEY_LENGTH) {
            QATerr(ERR_LIB_PROV, QAT_R_BAD_LENGTH);
            return 0;
        }
    } else {
        if (out == NULL) {
            if (len == 0) {
                QATerr(ERR_LIB_PROV, QAT_R_INVALID_KEY);
                return 0;
            }
            *outlen = len;
            return 1;
        }

        if (outsize < len) {
            QATerr(ERR_LIB_PROV, QAT_R_BAD_LENGTH);
            return 0;
        }
    }
    if (ctx->pad_mode == RSA_PKCS1_OAEP_PADDING
        || ctx->pad_mode == RSA_PKCS1_WITH_TLS_PADDING) {
        unsigned char *tbuf;

        if ((tbuf = OPENSSL_malloc(len)) == NULL) {
            QATerr(ERR_LIB_PROV, QAT_R_MALLOC_FAILURE);
            return 0;
        }
        if (qat_hw_rsa_offload || qat_sw_rsa_offload) {
            ret = qat_rsa_private_decrypt(inlen, in, tbuf, ctx->rsa, RSA_NO_PADDING);
        } else {
            typedef int (*fun_ptr)(void *vprsactx, unsigned char *out,
                                size_t *outlen, size_t outsize,
                                const unsigned char *in, size_t inlen);
            fun_ptr fun = get_default_rsa_asym_cipher().decrypt;
            if (!fun)
                return 0;
            return fun(vprsactx, out, outlen, outsize, in, inlen);
        }
        /*
         * With no padding then, on success ret should be len, otherwise an
         * error occurred (non-constant time)
         */
        if (ret != (int)len) {
            OPENSSL_free(tbuf);
            QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_DECRYPT);
            return 0;
        }
        if (ctx->pad_mode == RSA_PKCS1_OAEP_PADDING) {
            if (ctx->oaep_md == NULL) {
                ctx->oaep_md = EVP_MD_fetch(ctx->libctx, "SHA-1", NULL);
                if (ctx->oaep_md == NULL) {
                    OPENSSL_free(tbuf);
                    QATerr(ERR_LIB_PROV, QAT_R_INTERNAL_ERROR);
                    return 0;
                }
            }
            ret = RSA_padding_check_PKCS1_OAEP_mgf1(out, outsize, tbuf,
                                                    len, len,
                                                    ctx->oaep_label,
                                                    ctx->oaep_labellen,
                                                    ctx->oaep_md, ctx->mgf1_md);
        } else {
            if (ctx->client_version <= 0) {
                QATerr(ERR_LIB_PROV, QAT_R_BAD_TLS_CLIENT_VERSION);
                OPENSSL_free(tbuf);
                return 0;
            }
            ret =
                qat_rsa_padding_check_PKCS1_type_2_TLS(ctx->libctx, out,
                                                       outsize, tbuf, len,
                                                       ctx->client_version,
                                                       ctx->alt_version);
        }
        OPENSSL_free(tbuf);
    } else {
        if (qat_hw_rsa_offload || qat_sw_rsa_offload) {
            ret = qat_rsa_private_decrypt(inlen, in, out, ctx->rsa, ctx->pad_mode);
        } else {
            typedef int (*fun_ptr)(void *vprsactx, unsigned char *out,
                                size_t *outlen, size_t outsize,
                                const unsigned char *in, size_t inlen);
            fun_ptr fun = get_default_rsa_asym_cipher().decrypt;
            if (!fun)
                return 0;
            return fun(vprsactx, out, outlen, outsize, in, inlen);
        }
    }
    *outlen =
        qat_constant_time_select_s(qat_constant_time_msb_s(ret), *outlen, ret);
    ret = qat_constant_time_select_int(qat_constant_time_msb(ret), 0, 1);
    return ret;
}

static void qat_prov_rsa_freectx(void *vprsactx)
{
    QAT_PROV_RSA_ENC_DEC_CTX *ctx = (QAT_PROV_RSA_ENC_DEC_CTX *) vprsactx;
    QAT_RSA_free(ctx->rsa);
    EVP_MD_free(ctx->oaep_md);
    EVP_MD_free(ctx->mgf1_md);
    OPENSSL_free(ctx->oaep_label);
    OPENSSL_free(ctx);
}

static void *qat_prov_rsa_dupctx(void *vprsactx)
{
    QAT_PROV_RSA_ENC_DEC_CTX *srcctx = (QAT_PROV_RSA_ENC_DEC_CTX *) vprsactx;
    QAT_PROV_RSA_ENC_DEC_CTX *dstctx;

    if (!qat_prov_is_running())
        return NULL;

    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    *dstctx = *srcctx;
    if (dstctx->rsa != NULL && !QAT_RSA_up_ref(dstctx->rsa)) {
        OPENSSL_free(dstctx);
        return NULL;
    }

    if (dstctx->oaep_md != NULL && !EVP_MD_up_ref(dstctx->oaep_md)) {
        QAT_RSA_free(dstctx->rsa);
        OPENSSL_free(dstctx);
        return NULL;
    }

    if (dstctx->mgf1_md != NULL && !EVP_MD_up_ref(dstctx->mgf1_md)) {
        QAT_RSA_free(dstctx->rsa);
        EVP_MD_free(dstctx->oaep_md);
        OPENSSL_free(dstctx);
        return NULL;
    }

    return dstctx;
}

static int qat_prov_rsa_get_ctx_params(void *vprsactx, OSSL_PARAM * params)
{
    QAT_PROV_RSA_ENC_DEC_CTX *ctx = (QAT_PROV_RSA_ENC_DEC_CTX *) vprsactx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p != NULL)
        switch (p->data_type) {
        case OSSL_PARAM_INTEGER:
            if (!OSSL_PARAM_set_int(p, ctx->pad_mode))
                return 0;
            break;
        case OSSL_PARAM_UTF8_STRING:
            {
                int i;
                char *word = NULL;

                for (i = 0; qat_padding_item[i].id != 0; i++) {
                    if (ctx->pad_mode == (int)qat_padding_item[i].id) {
                        word = qat_padding_item[i].ptr;
                        break;
                    }
                }
                if (word != NULL) {
                    if (!OSSL_PARAM_set_utf8_string(p, word))
                        return 0;
                } else {
                    QATerr(ERR_LIB_PROV, QAT_R_INTERNAL_ERROR);
                }
            }
            break;
        default:
            return 0;
        }

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->oaep_md == NULL
                                                 ? ""
                                                 : EVP_MD_get0_name(ctx->
                                                                    oaep_md)))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
    if (p != NULL) {
        EVP_MD *mgf1_md = ctx->mgf1_md == NULL ? ctx->oaep_md : ctx->mgf1_md;

        if (!OSSL_PARAM_set_utf8_string(p, mgf1_md == NULL
                                        ? "" : EVP_MD_get0_name(mgf1_md)))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL);
    if (p != NULL &&
        !OSSL_PARAM_set_octet_ptr(p, ctx->oaep_label, ctx->oaep_labellen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->client_version))
        return 0;

    p = OSSL_PARAM_locate(params,
                          OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->alt_version))
        return 0;

    return 1;
}

static const OSSL_PARAM qat_rsa_known_gettable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, OSSL_PARAM_OCTET_PTR,
                    NULL, 0),
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, NULL),
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *qat_prov_rsa_gettable_ctx_params(ossl_unused void
                                                          *vprsactx,
                                                          ossl_unused void
                                                          *provctx)
{
    return qat_rsa_known_gettable_ctx_params;
}

static int qat_prov_rsa_set_ctx_params(void *vprsactx,
                                       const OSSL_PARAM params[])
{
    QAT_PROV_RSA_ENC_DEC_CTX *ctx = (QAT_PROV_RSA_ENC_DEC_CTX *) vprsactx;
    const OSSL_PARAM *p;
    char mdname[QAT_MAX_NAME_SIZE];
    char mdprops[QAT_MAX_PROPQUERY_SIZE] = { '\0' };
    char *str = NULL;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
    if (p != NULL) {
        str = mdname;
        if (!OSSL_PARAM_get_utf8_string(p, &str, sizeof(mdname)))
            return 0;

        p = OSSL_PARAM_locate_const(params,
                                    OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS);
        if (p != NULL) {
            str = mdprops;
            if (!OSSL_PARAM_get_utf8_string(p, &str, sizeof(mdprops)))
                return 0;
        }

        EVP_MD_free(ctx->oaep_md);
        ctx->oaep_md = EVP_MD_fetch(ctx->libctx, mdname, mdprops);
        if (ctx->oaep_md == NULL)
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p != NULL) {
        int pad_mode = 0;

        switch (p->data_type) {
        case OSSL_PARAM_INTEGER:
            if (!OSSL_PARAM_get_int(p, &pad_mode))
                return 0;
            break;
        case OSSL_PARAM_UTF8_STRING:
            {
                int i;

                if (p->data == NULL)
                    return 0;

                for (i = 0; qat_padding_item[i].id != 0; i++) {
                    if (strcmp(p->data, qat_padding_item[i].ptr) == 0) {
                        pad_mode = qat_padding_item[i].id;
                        break;
                    }
                }
            }
            break;
        default:
            return 0;
        }

        if (pad_mode == RSA_PKCS1_PSS_PADDING)
            return 0;
        if (pad_mode == RSA_PKCS1_OAEP_PADDING && ctx->oaep_md == NULL) {
            ctx->oaep_md = EVP_MD_fetch(ctx->libctx, "SHA1", mdprops);
            if (ctx->oaep_md == NULL)
                return 0;
        }
        ctx->pad_mode = pad_mode;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
    if (p != NULL) {
        str = mdname;
        if (!OSSL_PARAM_get_utf8_string(p, &str, sizeof(mdname)))
            return 0;

        p = OSSL_PARAM_locate_const(params,
                                    OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS);
        if (p != NULL) {
            str = mdprops;
            if (!OSSL_PARAM_get_utf8_string(p, &str, sizeof(mdprops)))
                return 0;
        } else {
            str = NULL;
        }

        EVP_MD_free(ctx->mgf1_md);
        ctx->mgf1_md = EVP_MD_fetch(ctx->libctx, mdname, str);

        if (ctx->mgf1_md == NULL)
            return 0;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL);
    if (p != NULL) {
        void *tmp_label = NULL;
        size_t tmp_labellen;

        if (!OSSL_PARAM_get_octet_string(p, &tmp_label, 0, &tmp_labellen))
            return 0;
        OPENSSL_free(ctx->oaep_label);
        ctx->oaep_label = (unsigned char *)tmp_label;
        ctx->oaep_labellen = tmp_labellen;
    }

    p = OSSL_PARAM_locate_const(params,
                                OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION);
    if (p != NULL) {
        unsigned int client_version;

        if (!OSSL_PARAM_get_uint(p, &client_version))
            return 0;
        ctx->client_version = client_version;
    }

    p = OSSL_PARAM_locate_const(params,
                                OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION);
    if (p != NULL) {
        unsigned int alt_version;

        if (!OSSL_PARAM_get_uint(p, &alt_version))
            return 0;
        ctx->alt_version = alt_version;
    }

    return 1;
}

static const OSSL_PARAM qat_rsa_known_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, NULL),
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *qat_prov_rsa_settable_ctx_params(ossl_unused void
                                                          *vprsactx,
                                                          ossl_unused void
                                                          *provctx)
{
    return qat_rsa_known_settable_ctx_params;
}

static int qat_prov_rsa_init(void *vprsactx, void *vrsa,
                             const OSSL_PARAM params[], int operation)
{
    QAT_PROV_RSA_ENC_DEC_CTX *ctx = (QAT_PROV_RSA_ENC_DEC_CTX *) vprsactx;

    if (!qat_prov_is_running() || ctx == NULL || vrsa == NULL)
        return 0;

    if (!qat_rsa_check_key(ctx->libctx, vrsa, operation))
        return 0;

    if (!QAT_RSA_up_ref(vrsa))
        return 0;
    QAT_RSA_free(ctx->rsa);
    ctx->rsa = vrsa;
    ctx->operation = operation;

    switch (QAT_RSA_test_flags(ctx->rsa, RSA_FLAG_TYPE_MASK)) {
    case RSA_FLAG_TYPE_RSA:
        ctx->pad_mode = RSA_PKCS1_PADDING;
        break;
    default:
        QATerr(ERR_LIB_PROV, QAT_R_INTERNAL_ERROR);
        return 0;
    }
    return qat_prov_rsa_set_ctx_params(ctx, params);
}

static int qat_prov_rsa_encrypt_init(void *ctx, void *rsa,
                                     const OSSL_PARAM params[])
{
    return qat_prov_rsa_init(ctx, rsa, params, EVP_PKEY_OP_ENCRYPT);
}

static int qat_prov_rsa_decrypt_init(void *ctx, void *rsa,
                                     const OSSL_PARAM params[])
{
    return qat_prov_rsa_init(ctx, rsa, params, EVP_PKEY_OP_DECRYPT);
}

const OSSL_DISPATCH qat_rsa_asym_cipher_functions[] = {
    {OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))qat_prov_rsa_newctx},
    {OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT,
     (void (*)(void))qat_prov_rsa_encrypt_init},
    {OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))qat_prov_rsa_encrypt},
    {OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,
     (void (*)(void))qat_prov_rsa_decrypt_init},
    {OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))qat_prov_rsa_decrypt},
    {OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))qat_prov_rsa_freectx},
    {OSSL_FUNC_ASYM_CIPHER_DUPCTX, (void (*)(void))qat_prov_rsa_dupctx},
    {OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,
     (void (*)(void))qat_prov_rsa_get_ctx_params},
    {OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS,
     (void (*)(void))qat_prov_rsa_gettable_ctx_params},
    {OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,
     (void (*)(void))qat_prov_rsa_set_ctx_params},
    {OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
     (void (*)(void))qat_prov_rsa_settable_ctx_params},
    {0, NULL}
};
#endif                          /* ENABLE_QAT_HW_RSA */
