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
 * @file qat_sw_sha2.c
 *
 * This file provides an implementation of SHA2 operations
 *
 *****************************************************************************/
#if defined(ENABLE_QAT_FIPS) && defined(ENABLE_QAT_SW_SHA2)
/* Local Includes */
# include "e_qat.h"
# include "qat_evp.h"
# include "qat_utils.h"
# include "qat_sw_gcm.h"
# ifdef QAT_OPENSSL_PROVIDER
#  include "qat_prov_ciphers.h"
# endif
# ifdef ENABLE_QAT_FIPS
#  include "qat_prov_cmvp.h"
# endif

# include "qat_sw_sha2.h"

# ifdef ENABLE_QAT_FIPS
extern int qat_fips_key_zeroize;
# endif

IMB_MGR *sha_ipsec_mgr = NULL;
int qat_imb_sha2(int nid, IMB_MGR * ipsec_mgr, unsigned char hash_type,
                 const void *data, size_t len, unsigned char *out);

/******************************************************************************
 * function:
 *    sha_init_ipsec_mb_mgr(void)
 *
 * @retval 0      function failed
 * @retval 1      function succeeded
 *
 * description:
 *    Allocate and Initialize the Intel IPsec Multi-Buffer Library Manager
 *    to help dispatch AVX512 APIS
 *
 ******************************************************************************/
int sha_init_ipsec_mb_mgr()
{
    if (sha_ipsec_mgr == NULL) {
        sha_ipsec_mgr = alloc_mb_mgr(0);

        if (sha_ipsec_mgr == NULL) {
            WARN("Error allocating Intel IPsec MB_MGR!\n");
            return 0;
        } else {
            /* Initialize the manager to dispatch AVX512 IPsec APIs */
            init_mb_mgr_avx512(sha_ipsec_mgr);
            return 1;
        }
    }

    if (qat_reload_algo)
        return 1;

    return 0;
}

/******************************************************************************
 * function:
 *    sha_free_ipsec_mb_mgr(void)
 *
 * description:
 *    Free Intel IPsec Multi-Buffer Library Manager resources
 *
 ******************************************************************************/
void sha_free_ipsec_mb_mgr()
{
    if (sha_ipsec_mgr) {
        free_mb_mgr(sha_ipsec_mgr);
        sha_ipsec_mgr = NULL;
    }
}

/******************************************************************************
 * function:
 *    qat_sha2_ctx_get_nid(QAT_SHA2_CTX *ctx)
 *
 * description:
 *    Function takes QAT_SHA2_CTX as input argument and return NID
 *
 ******************************************************************************/
int qat_sha2_ctx_get_nid(QAT_SHA2_CTX *ctx)
{
    return ctx->md_type;
}

/******************************************************************************
* function:
*         mb_qat_SHA2_init(QAT_SHA2_CTX *ctx)
*
* @param ctx     [IN]  - pointer to existing context
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function initialises the hash algorithm parameters for EVP context.
*
******************************************************************************/
int mb_qat_SHA2_init(QAT_SHA2_CTX *ctx)
{
    if (NULL == ctx) {
        WARN("ctx is NULL\n");
        return 0;
    }
    if (ctx->md_type == NID_sha224) {
        ctx->h[0] = 0xc1059ed8UL;
        ctx->h[1] = 0x367cd507UL;
        ctx->h[2] = 0x3070dd17UL;
        ctx->h[3] = 0xf70e5939UL;
        ctx->h[4] = 0xffc00b31UL;
        ctx->h[5] = 0x68581511UL;
        ctx->h[6] = 0x64f98fa7UL;
        ctx->h[7] = 0xbefa4fa4UL;
        ctx->md_len = SHA224_DIGEST_LENGTH;
        return 1;
    }

    if (ctx->md_type == NID_sha256) {
        ctx->h[0] = 0x6a09e667UL;
        ctx->h[1] = 0xbb67ae85UL;
        ctx->h[2] = 0x3c6ef372UL;
        ctx->h[3] = 0xa54ff53aUL;
        ctx->h[4] = 0x510e527fUL;
        ctx->h[5] = 0x9b05688cUL;
        ctx->h[6] = 0x1f83d9abUL;
        ctx->h[7] = 0x5be0cd19UL;
        ctx->md_len = SHA256_DIGEST_LENGTH;
        return 1;
    }

    if (ctx->md_type == NID_sha384) {
        ctx->h[0] = U64(0xcbbb9d5dc1059ed8);
        ctx->h[1] = U64(0x629a292a367cd507);
        ctx->h[2] = U64(0x9159015a3070dd17);
        ctx->h[3] = U64(0x152fecd8f70e5939);
        ctx->h[4] = U64(0x67332667ffc00b31);
        ctx->h[5] = U64(0x8eb44a8768581511);
        ctx->h[6] = U64(0xdb0c2e0d64f98fa7);
        ctx->h[7] = U64(0x47b5481dbefa4fa4);

        ctx->Nl = 0;
        ctx->Nh = 0;
        ctx->num = 0;
        ctx->md_len = SHA384_DIGEST_LENGTH;
        return 1;

    }

    if (ctx->md_type == NID_sha512) {
        ctx->h[0] = U64(0x6a09e667f3bcc908);
        ctx->h[1] = U64(0xbb67ae8584caa73b);
        ctx->h[2] = U64(0x3c6ef372fe94f82b);
        ctx->h[3] = U64(0xa54ff53a5f1d36f1);
        ctx->h[4] = U64(0x510e527fade682d1);
        ctx->h[5] = U64(0x9b05688c2b3e6c1f);
        ctx->h[6] = U64(0x1f83d9abfb41bd6b);
        ctx->h[7] = U64(0x5be0cd19137e2179);

        ctx->Nl = 0;
        ctx->Nh = 0;
        ctx->num = 0;
        ctx->md_len = SHA512_DIGEST_LENGTH;
        return 1;
    }
    return 0;
}

/******************************************************************************
* function:
*    mb_qat_SHA2_update(QAT_SHA2_CTX *ctx, const void *data, size_t len)
*
* @param ctx          [IN]  - pointer to existing context
* @param data         [IN]  - input buffer
* @param len          [IN]  - length of input buffer
*
* @retval -1      function failed
* @retval len     function succeeded
*
* description:
*    This function performs the cryptographic transform according to the
*  parameters setup during initialisation.
*
*
******************************************************************************/
int mb_qat_SHA2_update(QAT_SHA2_CTX *ctx, const void *actual_data, size_t len)
{
    unsigned char *data = (unsigned char *)actual_data;
    unsigned char *p = NULL;
    size_t n;
    int nid = 0;
    unsigned long long data_size = 0;
# ifdef ENABLE_QAT_FIPS
    qat_fips_get_approved_status();
# endif
    if (ctx->md_type == NID_sha256 || ctx->md_type == NID_sha224) {
        p = ctx->u.small_data;
    }

    if (ctx->md_type == NID_sha384 || ctx->md_type == NID_sha512) {
        p = ctx->u.large_data;
    }
    data_size = QAT_SHA_MAX_SIZE;
    nid = qat_sha2_ctx_get_nid(ctx);
    n = ctx->num;
    DEBUG("ctx = %p, NID = %d, in = %p, len = %zu\n",
          ctx, nid, actual_data, len);

    if (n != 0) {
        /* Offload threshold met */
        if (len >= data_size || len + n >= data_size) {
            /* Use part of new packet filling the packet buffer */
            data_size += data_size;
            memcpy(p + n, data, len);
            ctx->num += (unsigned int)len;

            return 1;
        } else {
            /* Append the new packets to buffer */
            memcpy(p + n, data, len);
            ctx->num += (unsigned int)len;

            return 1;
        }
    }
    n = len / data_size;
    if (n > 0) {
        n *= data_size;

        qat_imb_sha2(nid, sha_ipsec_mgr, ctx->md_type, data, n,
                     ctx->digest_data1);
        data += n;
        len -= n;
    }

    /* Save the bytes into buffer if there're some bytes left
     * after the previous update. */
    if (len != 0) {
        if (ctx->md_type == NID_sha256 || ctx->md_type == NID_sha224) {
            p = ctx->u.small_data;
        }

        if (ctx->md_type == NID_sha384 || ctx->md_type == NID_sha512) {
            p = ctx->u.large_data;
        }
        ctx->num = (unsigned int)len;
        memcpy(p, data, len);
    }

    return 1;
}

/******************************************************************************
* function:
*   mb_qat_SHA2_final(QAT_SHA2_CTX *ctx, unsigned char *md) 
*
* @param ctx       [IN]  - pointer to existing context
* @param md        [OUT] - output buffer for digest result
*
* @retval -1     function failed
* @retval  1     function succeeded
*
* description:
*    This function performs the copy operation of digest into md buffer.
*
******************************************************************************/
int mb_qat_SHA2_final(QAT_SHA2_CTX *ctx, unsigned char *md)
{
    int nid = 0;
    unsigned char *p = NULL;
    nid = qat_sha2_ctx_get_nid(ctx);
# ifdef ENABLE_QAT_FIPS
    qat_fips_get_approved_status();
# endif
    if (ctx->md_type == NID_sha256 || ctx->md_type == NID_sha224) {
        p = ctx->u.small_data;
    }

    if (ctx->md_type == NID_sha384 || ctx->md_type == NID_sha512) {
        p = ctx->u.large_data;
    }
    DEBUG("ctx = %p, NID = %d, in = %p, len = %d\n", ctx, nid, p, ctx->num);

    qat_imb_sha2(nid, sha_ipsec_mgr, ctx->md_type, p, ctx->num,
                 ctx->digest_data1);
    memcpy(md, ctx->digest_data1, ctx->md_size);

    return 1;
}

/******************************************************************************
* function:
*     mb_qat_sha2_cleanup(QAT_SHA2_CTX *ctx)
*
* @param ctx    [IN]  - pointer to existing context
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function will cleanup all allocated resources required to perform the
*  cryptographic transform.
*
******************************************************************************/
int mb_qat_sha2_cleanup(QAT_SHA2_CTX *ctx)
{
# ifdef ENABLE_QAT_FIPS
    qat_fips_key_zeroize = 0;
# endif

    QAT_SHA2_CTX *sha_ctx = (QAT_SHA2_CTX *) ctx;
    memset(sha_ctx, 0, sizeof(QAT_SHA2_CTX));

    OPENSSL_clear_free(ctx, sizeof(*ctx));
# ifdef ENABLE_QAT_FIPS
    qat_fips_key_zeroize = 1;
    qat_fips_get_key_zeroize_status();
# endif

    return 1;
}
#endif                          /*ENABLE_QAT_FIPS && ENABLE_QAT_SW_SHA2 */
