/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016 Intel Corporation.
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
 * @file qat_ciphers.c
 *
 * This file contains the engine implementations for cipher operations
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <pthread.h>
#ifdef USE_QAT_CONTIG_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
# include "cmn_mem_drv_inf.h"
#endif

#include "qat_utils.h"
#include "e_qat.h"
#include "e_qat_err.h"

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_sym.h"
#include "qat_ciphers.h"

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/tls1.h>
#include <openssl/async.h>
#include <openssl/lhash.h>
#include <string.h>

#ifdef OPENSSL_ENABLE_QAT_CIPHERS
# ifdef OPENSSL_DISABLE_QAT_CIPHERS
#  undef OPENSSL_DISABLE_QAT_CIPHERS
# endif
#endif

static int qat_aes_cbc_hmac_sha_init(EVP_CIPHER_CTX *ctx,
                                      const unsigned char *inkey,
                                      const unsigned char *iv,int enc);
static int qat_aes_cbc_hmac_sha_cleanup(EVP_CIPHER_CTX *ctx);
static int qat_aes_cbc_hmac_sha_cipher(EVP_CIPHER_CTX *ctx,
                                        unsigned char *out,
                                        const unsigned char *in, size_t len);
static int qat_aes_cbc_hmac_sha_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                                      void *ptr);

/* Qat cipher AES128-SHA1 function structure declaration */
static EVP_CIPHER *_hidden_aes_128_cbc_hmac_sha1 = NULL;
const EVP_CIPHER *qat_aes_128_cbc_hmac_sha1(void)
{
    if (_hidden_aes_128_cbc_hmac_sha1 == NULL
        && ((_hidden_aes_128_cbc_hmac_sha1 =
             EVP_CIPHER_meth_new(NID_aes_128_cbc_hmac_sha1,
                                 AES_BLOCK_SIZE,
                                 AES_KEY_SIZE_128)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_128_cbc_hmac_sha1,
                                              AES_IV_LEN)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_128_cbc_hmac_sha1,
                                          0 | qat_common_cbc_flags |
                                          EVP_CIPH_FLAG_AEAD_CIPHER)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_128_cbc_hmac_sha1,
                                         qat_aes_cbc_hmac_sha_init)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_cbc_hmac_sha1,
                                              qat_aes_cbc_hmac_sha_cipher)
            || !EVP_CIPHER_meth_set_cleanup(_hidden_aes_128_cbc_hmac_sha1,
                                              qat_aes_cbc_hmac_sha_cleanup)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_cbc_hmac_sha1,
                                                  sizeof(qat_chained_sha1_ctx))
            || !EVP_CIPHER_meth_set_set_asn1_params(_hidden_aes_128_cbc_hmac_sha1,
                                                    EVP_CIPH_FLAG_DEFAULT_ASN1 ?
                                                    NULL :
                                                    EVP_CIPHER_set_asn1_iv)
            || !EVP_CIPHER_meth_set_get_asn1_params(_hidden_aes_128_cbc_hmac_sha1,
                                                    EVP_CIPH_FLAG_DEFAULT_ASN1 ?
                                                    NULL :
                                                    EVP_CIPHER_get_asn1_iv)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_cbc_hmac_sha1,
                                         qat_aes_cbc_hmac_sha_ctrl))) {
        EVP_CIPHER_meth_free(_hidden_aes_128_cbc_hmac_sha1);
        _hidden_aes_128_cbc_hmac_sha1 = NULL;
    }
    return _hidden_aes_128_cbc_hmac_sha1;
}

/* Qat cipher AES256-SHA1 function structure declaration */
static EVP_CIPHER *_hidden_aes_256_cbc_hmac_sha1 = NULL;
const EVP_CIPHER *qat_aes_256_cbc_hmac_sha1(void)
{
    if (_hidden_aes_256_cbc_hmac_sha1 == NULL
        && ((_hidden_aes_256_cbc_hmac_sha1 =
             EVP_CIPHER_meth_new(NID_aes_256_cbc_hmac_sha1,
                                 AES_BLOCK_SIZE,
                                 AES_KEY_SIZE_256)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_256_cbc_hmac_sha1,
                                              AES_IV_LEN)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_256_cbc_hmac_sha1,
                                          0 | qat_common_cbc_flags |
                                          EVP_CIPH_FLAG_AEAD_CIPHER)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_256_cbc_hmac_sha1,
                                         qat_aes_cbc_hmac_sha_init)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_cbc_hmac_sha1,
                                              qat_aes_cbc_hmac_sha_cipher)
            || !EVP_CIPHER_meth_set_cleanup(_hidden_aes_256_cbc_hmac_sha1,
                                              qat_aes_cbc_hmac_sha_cleanup)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_cbc_hmac_sha1,
                                                  sizeof(qat_chained_sha1_ctx))
            || !EVP_CIPHER_meth_set_set_asn1_params(_hidden_aes_256_cbc_hmac_sha1,
                                                    EVP_CIPH_FLAG_DEFAULT_ASN1 ?
                                                    NULL :
                                                    EVP_CIPHER_set_asn1_iv)
            || !EVP_CIPHER_meth_set_get_asn1_params(_hidden_aes_256_cbc_hmac_sha1,
                                                    EVP_CIPH_FLAG_DEFAULT_ASN1 ?
                                                    NULL :
                                                    EVP_CIPHER_get_asn1_iv)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_cbc_hmac_sha1,
                                         qat_aes_cbc_hmac_sha_ctrl))) {
        EVP_CIPHER_meth_free(_hidden_aes_256_cbc_hmac_sha1);
        _hidden_aes_256_cbc_hmac_sha1 = NULL;
    }
    return _hidden_aes_256_cbc_hmac_sha1;
}

/* Qat cipher AES128-SHA256 function structure declaration */
static EVP_CIPHER *_hidden_aes_128_cbc_hmac_sha256 = NULL;
const EVP_CIPHER *qat_aes_128_cbc_hmac_sha256(void)
{
    if (_hidden_aes_128_cbc_hmac_sha256 == NULL
        && ((_hidden_aes_128_cbc_hmac_sha256 =
             EVP_CIPHER_meth_new(NID_aes_128_cbc_hmac_sha256,
                                 AES_BLOCK_SIZE,
                                 AES_KEY_SIZE_128)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_128_cbc_hmac_sha256,
                                              AES_IV_LEN)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_128_cbc_hmac_sha256,
                                          0 | qat_common_cbc_flags |
                                          EVP_CIPH_FLAG_AEAD_CIPHER)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_128_cbc_hmac_sha256,
                                         qat_aes_cbc_hmac_sha_init)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_cbc_hmac_sha256,
                                              qat_aes_cbc_hmac_sha_cipher)
            || !EVP_CIPHER_meth_set_cleanup(_hidden_aes_128_cbc_hmac_sha256,
                                              qat_aes_cbc_hmac_sha_cleanup)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_cbc_hmac_sha256,
                                                  sizeof(qat_chained_sha256_ctx))
            || !EVP_CIPHER_meth_set_set_asn1_params(_hidden_aes_128_cbc_hmac_sha256,
                                                    EVP_CIPH_FLAG_DEFAULT_ASN1 ?
                                                    NULL :
                                                    EVP_CIPHER_set_asn1_iv)
            || !EVP_CIPHER_meth_set_get_asn1_params(_hidden_aes_128_cbc_hmac_sha256,
                                                    EVP_CIPH_FLAG_DEFAULT_ASN1 ?
                                                    NULL :
                                                    EVP_CIPHER_get_asn1_iv)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_cbc_hmac_sha256,
                                         qat_aes_cbc_hmac_sha_ctrl))) {
        EVP_CIPHER_meth_free(_hidden_aes_128_cbc_hmac_sha256);
        _hidden_aes_128_cbc_hmac_sha256 = NULL;
    }
    return _hidden_aes_128_cbc_hmac_sha256;
}

/* Qat cipher AES256-SHA256 function structure declaration */
static EVP_CIPHER *_hidden_aes_256_cbc_hmac_sha256 = NULL;
const EVP_CIPHER *qat_aes_256_cbc_hmac_sha256(void)
{
    if (_hidden_aes_256_cbc_hmac_sha256 == NULL
        && ((_hidden_aes_256_cbc_hmac_sha256 =
             EVP_CIPHER_meth_new(NID_aes_256_cbc_hmac_sha256,
                                 AES_BLOCK_SIZE,
                                 AES_KEY_SIZE_256)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_256_cbc_hmac_sha256,
                                              AES_IV_LEN)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_256_cbc_hmac_sha256,
                                          0 | qat_common_cbc_flags |
                                          EVP_CIPH_FLAG_AEAD_CIPHER)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_256_cbc_hmac_sha256,
                                         qat_aes_cbc_hmac_sha_init)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_cbc_hmac_sha256,
                                              qat_aes_cbc_hmac_sha_cipher)
            || !EVP_CIPHER_meth_set_cleanup(_hidden_aes_256_cbc_hmac_sha256,
                                              qat_aes_cbc_hmac_sha_cleanup)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_cbc_hmac_sha256,
                                                  sizeof(qat_chained_sha256_ctx))
            || !EVP_CIPHER_meth_set_set_asn1_params(_hidden_aes_256_cbc_hmac_sha256,
                                                    EVP_CIPH_FLAG_DEFAULT_ASN1 ?
                                                    NULL :
                                                    EVP_CIPHER_set_asn1_iv)
            || !EVP_CIPHER_meth_set_get_asn1_params(_hidden_aes_256_cbc_hmac_sha256,
                                                    EVP_CIPH_FLAG_DEFAULT_ASN1 ?
                                                    NULL :
                                                    EVP_CIPHER_get_asn1_iv)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_cbc_hmac_sha256,
                                         qat_aes_cbc_hmac_sha_ctrl))) {
        EVP_CIPHER_meth_free(_hidden_aes_256_cbc_hmac_sha256);
        _hidden_aes_256_cbc_hmac_sha256 = NULL;
    }
    return _hidden_aes_256_cbc_hmac_sha256;
}

/* Qat Symmetric cipher function register */
int qat_cipher_nids[] = {
    NID_aes_128_cbc_hmac_sha1,
    NID_aes_256_cbc_hmac_sha1,
    NID_aes_128_cbc_hmac_sha256,
    NID_aes_256_cbc_hmac_sha256
};

#ifndef OPENSSL_DISABLE_QAT_CIPHERS

void qat_create_ciphers(void)
{
    qat_aes_128_cbc_hmac_sha1();
    qat_aes_256_cbc_hmac_sha1();
    qat_aes_128_cbc_hmac_sha256();
    qat_aes_256_cbc_hmac_sha256();
}

void qat_free_ciphers(void)
{
    if (_hidden_aes_128_cbc_hmac_sha1) {
        EVP_CIPHER_meth_free(_hidden_aes_128_cbc_hmac_sha1);
        _hidden_aes_128_cbc_hmac_sha1 = NULL;
    }

    if (_hidden_aes_256_cbc_hmac_sha1) {
        EVP_CIPHER_meth_free(_hidden_aes_256_cbc_hmac_sha1);
        _hidden_aes_256_cbc_hmac_sha1 = NULL;
    }

    if (_hidden_aes_128_cbc_hmac_sha256) {
        EVP_CIPHER_meth_free(_hidden_aes_128_cbc_hmac_sha256);
        _hidden_aes_128_cbc_hmac_sha256 = NULL;
    }

    if (_hidden_aes_256_cbc_hmac_sha256) {
        EVP_CIPHER_meth_free(_hidden_aes_256_cbc_hmac_sha256);
        _hidden_aes_256_cbc_hmac_sha256 = NULL;
    }
}

#else

void qat_create_ciphers(void) {}

void qat_free_ciphers(void) {}

#endif

#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
# define CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT 2048

CRYPTO_ONCE qat_pkt_threshold_table_once = CRYPTO_ONCE_STATIC_INIT;
CRYPTO_THREAD_LOCAL qat_pkt_threshold_table_key;

void qat_pkt_threshold_table_make_key(void)
{
    CRYPTO_THREAD_init_local(&qat_pkt_threshold_table_key, qat_free_pkt_threshold_table);
}

typedef struct cipher_threshold_table_s {
    int nid;
    int threshold;
}PKT_THRESHOLD;

DEFINE_LHASH_OF(PKT_THRESHOLD);

PKT_THRESHOLD qat_pkt_threshold_table[] = {
    {NID_aes_128_cbc_hmac_sha1,CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_256_cbc_hmac_sha1,CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_128_cbc_hmac_sha256,CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_256_cbc_hmac_sha256,CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT}
};

static int pkt_threshold_table_cmp(const PKT_THRESHOLD * a, const PKT_THRESHOLD * b)
{
    return (a->nid == b->nid)?0:1;
}

static unsigned long pkt_threshold_table_hash(const PKT_THRESHOLD * a)
{
    return (unsigned long)(a->nid);
}

LHASH_OF(PKT_THRESHOLD) *qat_create_pkt_threshold_table(void)
{
    int i;
    LHASH_OF(PKT_THRESHOLD) *ret = NULL;
    ret = lh_PKT_THRESHOLD_new(pkt_threshold_table_hash,pkt_threshold_table_cmp);
    if(ret == NULL) {
        return ret;
    }
    for(i = 0; i < sizeof(qat_pkt_threshold_table);i++) {
        lh_PKT_THRESHOLD_insert(ret,&qat_pkt_threshold_table[i]);
    }
    return ret;
}

int qat_pkt_threshold_table_set_threshold(int nid, int threshold)
{
    PKT_THRESHOLD entry,*ret;
    LHASH_OF(PKT_THRESHOLD) *tbl = NULL;
    if(NID_undef == nid) {
        WARN("Unsupported NID\n");
        return 0;
    }
    if((tbl = CRYPTO_THREAD_get_local(&qat_pkt_threshold_table_key)) == NULL) {
        tbl = qat_create_pkt_threshold_table();
        if(tbl != NULL) {
            CRYPTO_THREAD_set_local(&qat_pkt_threshold_table_key, tbl);
        }
        else {
            WARN("Create packet threshold table fail.\n");
            return 0;
        }
    }
    entry.nid = nid;
    ret = lh_PKT_THRESHOLD_retrieve(tbl,&entry);
    if(ret == NULL) {
        WARN("Threshold entry retrieve failed for the NID : %d\n",entry.nid);
        return 0;
    }
    ret->threshold = threshold;
    lh_PKT_THRESHOLD_insert(tbl, ret); 
    return 1;
}

int qat_pkt_threshold_table_get_threshold(int nid)
{
    PKT_THRESHOLD entry,*ret;
    LHASH_OF(PKT_THRESHOLD) *tbl = NULL;
    if((tbl = CRYPTO_THREAD_get_local(&qat_pkt_threshold_table_key)) == NULL) {
        tbl = qat_create_pkt_threshold_table();
        if(tbl != NULL) { 
            CRYPTO_THREAD_set_local(&qat_pkt_threshold_table_key, tbl);
        }
        else {
            WARN("Create packet threshold table fail.\n");
            return 0;
        }
    }
    entry.nid = nid;
    ret = lh_PKT_THRESHOLD_retrieve(tbl,&entry);
    if(ret == NULL) {
        WARN("Threshold entry retrieve failed for the NID : %d\n",entry.nid);
        return 0;
    }
    return ret->threshold;
}

void qat_free_pkt_threshold_table(void *thread_key)
{
    LHASH_OF(PKT_THRESHOLD) *tbl = (LHASH_OF(PKT_THRESHOLD) *) thread_key;
    if((tbl = CRYPTO_THREAD_get_local(&qat_pkt_threshold_table_key))) {
        lh_PKT_THRESHOLD_free(tbl);
    }
}

#endif
/******************************************************************************
* function:
*         qat_ciphers(ENGINE *e,
*                     const EVP_CIPHER **cipher,
*                     const int **nids,
*                     int nid)
*
* @param e      [IN] - OpenSSL engine pointer
* @param cipher [IN] - cipher structure pointer
* @param nids   [IN] - cipher function nids
* @param nid    [IN] - cipher operation id
*
* description:
*   Qat engine cipher operations registrar
******************************************************************************/
int
qat_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids,
            int nid)
{
    int ok = 1;

    /* No specific cipher => return a list of supported nids ... */
    if (cipher == NULL) {
        *nids = qat_cipher_nids;
        /* num ciphers supported (size of array/size of 1 element) */
        return (sizeof(qat_cipher_nids) / sizeof(qat_cipher_nids[0]));
    }

#ifndef OPENSSL_DISABLE_QAT_CIPHERS
    switch (nid) {
    case NID_aes_128_cbc_hmac_sha1:
         *cipher = qat_aes_128_cbc_hmac_sha1();
         break;
    case NID_aes_256_cbc_hmac_sha1:
         *cipher = qat_aes_256_cbc_hmac_sha1();
         break;
    case NID_aes_128_cbc_hmac_sha256:
         *cipher = qat_aes_128_cbc_hmac_sha256();
         break;
    case NID_aes_256_cbc_hmac_sha256:
         *cipher = qat_aes_256_cbc_hmac_sha256();
         break;
    default:
        ok = 0;
        *cipher = NULL;
    }
#else
    switch (nid) {
    case NID_aes_128_cbc_hmac_sha1:
        *cipher = EVP_aes_128_cbc_hmac_sha1();
        break;
    case NID_aes_256_cbc_hmac_sha1:
        *cipher = EVP_aes_256_cbc_hmac_sha1();
        break;
    case NID_aes_128_cbc_hmac_sha256:
        *cipher = EVP_aes_128_cbc_hmac_sha256();
        break;
    case NID_aes_256_cbc_hmac_sha256:
        *cipher = EVP_aes_256_cbc_hmac_sha256();
        break;
    default:
        ok = 0;
        *cipher = NULL;
    }
#endif

    return ok;
}

/******************************************************************************
* function:
*         qat_get_sha_digest_len(EVP_CIPHER_CTX *evp_ctx)
*
* @param evp_ctx [IN] - pointer to the evp context
*
* description:
*    This function is to find the sha digest length
*    based on NID
*    it will return Sha digest Length if successful and 0 on failure.
*
******************************************************************************/
static int qat_get_sha_digest_len(EVP_CIPHER_CTX *evp_ctx)
{

    if (evp_ctx == NULL) {
        WARN("[%s] --- ctx is NULL.\n", __func__);
        return 0;
    }

    switch (EVP_CIPHER_CTX_nid(evp_ctx)) {
    case NID_aes_128_cbc_hmac_sha1:
    case NID_aes_256_cbc_hmac_sha1:
            return SHA_DIGEST_LENGTH;

    case NID_aes_128_cbc_hmac_sha256:
    case NID_aes_256_cbc_hmac_sha256:
            return SHA256_DIGEST_LENGTH;

    default:
        {
            WARN("[%s] --- unknown NID.\n", __func__);
            return 0;
        }
    }
}

/******************************************************************************
* function:
*         cipher_int_chained(EVP_CIPHER_CTX *evp_ctx,
*                            qat_chained_ctx *qat_ctx,
*                            const unsigned char* key,
*                            const unsigned char* iv,
*                            int enc)
*
* @param evp_ctx [IN] - pointer to the evp context
* @param qat_ctx [IN] - pointer to the qat context
* @param key     [IN] - pointer to the cipher key
* @param iv      [IN] - pointer to the iv this maybe NULL.
* @param enc     [IN] - whether we are doing encryption (1) or decryption (0).
*
* description:
*    This function is to create QAT specific session data
*    It is called from the session init function.
*    it will return 1 if successful and 0 on failure.
******************************************************************************/
static int cipher_init_chained(EVP_CIPHER_CTX *evp_ctx,
                               qat_chained_ctx * qat_ctx,
                               const unsigned char *key,
                               const unsigned char *iv, int enc)
{

    int sha_digest_len = 0;
    if ((qat_ctx == NULL) || (key == NULL) || (evp_ctx == NULL)) {
        WARN("[%s] --- qat_ctx or key or ctx is NULL.\n", __func__);
        return 0;
    }

    qat_ctx->session_data = OPENSSL_malloc(sizeof(CpaCySymSessionSetupData));
    if (NULL == qat_ctx->session_data) {
        WARN("OPENSSL_malloc() failed for session setup data allocation.\n");
        return 0;
    }

    if (NULL != iv)
        memmove(EVP_CIPHER_CTX_iv_noconst(evp_ctx), iv, EVP_CIPHER_CTX_iv_length(evp_ctx));
    else
        memset(EVP_CIPHER_CTX_iv_noconst(evp_ctx), 0, EVP_CIPHER_CTX_iv_length(evp_ctx));

    DUMPL("iv", iv, EVP_CIPHER_CTX_iv_length(evp_ctx));
    DUMPL("key", key, EVP_CIPHER_CTX_key_length(evp_ctx));

    /* Priority of this session */
    qat_ctx->session_data->sessionPriority = CPA_CY_PRIORITY_HIGH;
    qat_ctx->session_data->symOperation = CPA_CY_SYM_OP_ALGORITHM_CHAINING;

    /* Cipher algorithm and mode */
    qat_ctx->session_data->cipherSetupData.cipherAlgorithm =
        CPA_CY_SYM_CIPHER_AES_CBC;
    /* Cipher key length 256 bits (32 bytes) */
    qat_ctx->session_data->cipherSetupData.cipherKeyLenInBytes =
        (Cpa32U) EVP_CIPHER_CTX_key_length(evp_ctx);
    /* Cipher key */
    if (NULL ==
        (qat_ctx->session_data->cipherSetupData.pCipherKey =
         OPENSSL_malloc(EVP_CIPHER_CTX_key_length(evp_ctx)))) {
        WARN("[%s] --- unable to allocate memory for Cipher key.\n",
             __func__);
        goto end;
    }

    memmove(qat_ctx->session_data->cipherSetupData.pCipherKey, key,
           EVP_CIPHER_CTX_key_length(evp_ctx));

    /* Operation to perform */
    if (enc) {
        qat_ctx->session_data->cipherSetupData.cipherDirection =
            CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT;
        qat_ctx->session_data->algChainOrder =
            CPA_CY_SYM_ALG_CHAIN_ORDER_HASH_THEN_CIPHER;
    } else {
        qat_ctx->session_data->cipherSetupData.cipherDirection =
            CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT;
        qat_ctx->session_data->algChainOrder =
            CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH;
    }

    /* Hash Configuration */
    qat_ctx->session_data->hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_AUTH;
    qat_ctx->session_data->hashSetupData.authModeSetupData.aadLenInBytes = 0;

    if ((sha_digest_len = qat_get_sha_digest_len(evp_ctx)) == 0) {
        WARN("[%s] Unable to get sha digest length\n", __func__);
        goto end;
    }

    qat_ctx->session_data->hashSetupData.digestResultLenInBytes =
        sha_digest_len;

    if (sha_digest_len == SHA_DIGEST_LENGTH)
        qat_ctx->session_data->hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA1;
    else
        qat_ctx->session_data->hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA256;

    qat_ctx->hmac_key = OPENSSL_malloc(HMAC_KEY_SIZE);
    if (NULL == qat_ctx->hmac_key) {
        WARN("[%s] Unable to allocate memory or HMAC Key\n", __func__);
        goto end;
    }
    memset(qat_ctx->hmac_key, 0, HMAC_KEY_SIZE);
    qat_ctx->session_data->hashSetupData.authModeSetupData.authKey =
        qat_ctx->hmac_key;
    qat_ctx->session_data->hashSetupData.authModeSetupData.authKeyLenInBytes =
        HMAC_KEY_SIZE;

    qat_ctx->initParamsSet = 1;
    qat_ctx->payload_length = NO_PAYLOAD_LENGTH_SPECIFIED;

    return 1;

 end:
    if (NULL != qat_ctx->session_data) {
        if (NULL != qat_ctx->session_data->cipherSetupData.pCipherKey) {
            OPENSSL_cleanse(qat_ctx->session_data->cipherSetupData.pCipherKey,
                            qat_ctx->session_data->cipherSetupData.
                            cipherKeyLenInBytes);
            OPENSSL_free(qat_ctx->session_data->cipherSetupData.pCipherKey);
            qat_ctx->session_data->cipherSetupData.pCipherKey = NULL;
        }
        OPENSSL_free(qat_ctx->session_data);
        qat_ctx->session_data = NULL;
    }
    return 0;
}

/******************************************************************************
* function:
*         qat_aes_cbc_hmac_sha_init(EVP_CIPHER_CTX *ctx,
*                                    const unsigned char *inkey,
*                                    const unsigned char *iv,
*                                    int enc)
*
* @param ctx    [IN]  - pointer to existing ctx
* @param inKey  [IN]  - input cipher key
* @param iv     [IN]  - initialisation vector
* @param enc    [IN]  - 1 encrypt 0 decrypt
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function initialises the cipher and hash algorithm parameters for this
*  EVP context.
*
******************************************************************************/
int qat_aes_cbc_hmac_sha_init(EVP_CIPHER_CTX *ctx,
                                      const unsigned char *inkey,
                                      const unsigned char *iv, int enc)
{
    /* Initialise a QAT session  and set the cipher keys */
    qat_chained_ctx *qat_ctx = NULL;

    if (ctx == NULL || inkey == NULL) {
        WARN("[%s] ctx or inkey is NULL.\n", __func__);
        return 0;
    }
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
    const EVP_CIPHER *ia_cipher = NULL;
#endif
    int nid = EVP_CIPHER_CTX_nid(ctx);
    switch (nid) {
    case NID_aes_128_cbc_hmac_sha1:
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
        ia_cipher = EVP_aes_128_cbc_hmac_sha1();
#endif
        qat_ctx = &(((qat_chained_sha1_ctx *)qat_chained_data(ctx))->qat_ctx);
        break;
    case NID_aes_256_cbc_hmac_sha1:
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
        ia_cipher = EVP_aes_256_cbc_hmac_sha1();
#endif
        qat_ctx = &(((qat_chained_sha1_ctx *)qat_chained_data(ctx))->qat_ctx);
        break;
    case NID_aes_128_cbc_hmac_sha256:
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
        ia_cipher = EVP_aes_128_cbc_hmac_sha256();
#endif
        qat_ctx = &(((qat_chained_sha256_ctx *)qat_chained_data(ctx))->qat_ctx);
        break;
    case NID_aes_256_cbc_hmac_sha256:
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
        ia_cipher = EVP_aes_256_cbc_hmac_sha256();
#endif
        qat_ctx = &(((qat_chained_sha256_ctx *)qat_chained_data(ctx))->qat_ctx);
        break;
    default:
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
        ia_cipher = NULL;
#endif
        return 0;
    }
    if (iv)
        memcpy((unsigned char *)EVP_CIPHER_CTX_original_iv(ctx), iv, EVP_CIPHER_CTX_iv_length(ctx));
    memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), EVP_CIPHER_CTX_original_iv(ctx), EVP_CIPHER_CTX_iv_length(ctx));
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
    if(EVP_CIPHER_meth_get_init(ia_cipher)(ctx, inkey, iv, enc) == 0)
        goto end;
#endif
    if (qat_ctx == NULL) {
        WARN("[%s] --- qat_ctx is NULL.\n", __func__);
        return 0;
    }


    /* Pre-allocate necessary memory */
    /*
     * This is a whole block the size of the memory alignment. If the
     * alignment was to become smaller than the header size
     * (TLS_VIRT_HEADER_SIZE) which is unlikely then we would need to add
     * some more logic here to work how many blocks of size
     * QAT_BYTE_ALIGNMENT we need to allocate to fit the header in.
     */
    qat_ctx->tls_virt_hdr =
        qaeCryptoMemAlloc(QAT_BYTE_ALIGNMENT, __FILE__, __LINE__);
    if (NULL == qat_ctx->tls_virt_hdr) {
        WARN("[%s] Unable to allcoate memory for MAC preamble\n",
                __func__);
        return 0;
    }
    memset(qat_ctx->tls_virt_hdr, 0, QAT_BYTE_ALIGNMENT);
    qat_ctx->srcFlatBuffer[0].pData = qat_ctx->tls_virt_hdr;
    qat_ctx->srcFlatBuffer[0].dataLenInBytes = QAT_BYTE_ALIGNMENT;
    qat_ctx->dstFlatBuffer[0].pData = qat_ctx->srcFlatBuffer[0].pData;
    qat_ctx->dstFlatBuffer[0].dataLenInBytes = QAT_BYTE_ALIGNMENT;

    qat_ctx->pIv =
        qaeCryptoMemAlloc(EVP_CIPHER_CTX_iv_length(ctx), __FILE__,
                __LINE__);
    if (qat_ctx->pIv == NULL) {
        WARN("[%s] --- pIv is NULL.\n", __func__);
        goto end;
    }

    if (!cipher_init_chained(ctx, qat_ctx, inkey, iv, enc)) {
        WARN("[%s] cipher_init_chained failed.\n", __func__);
        goto end;
    }

    return 1;

 end:
    if (NULL != qat_ctx->tls_virt_hdr) {
        qaeCryptoMemFree(qat_ctx->tls_virt_hdr);
        qat_ctx->tls_virt_hdr = NULL;
    }
    if (NULL != qat_ctx->pIv) {
        qaeCryptoMemFree(qat_ctx->pIv);
        qat_ctx->pIv = NULL;
    }

    return 0;

}

/******************************************************************************
* function:
*    qat_aes_cbc_hmac_sha_ctrl(EVP_CIPHER_CTX *ctx,
*                               int type, int arg, void *ptr)
*
* @param ctx    [IN]  - pointer to existing ctx
* @param type   [IN]  - type of request either
*                       EVP_CTRL_AEAD_SET_MAC_KEY or EVP_CTRL_AEAD_TLS1_AAD
* @param arg    [IN]  - size of the pointed to by ptr
* @param ptr    [IN]  - input buffer contain the necessary parameters
*
* @retval x      The return value is dependent on the type of request being made
*       EVP_CTRL_AEAD_SET_MAC_KEY return of 1 is success
*       EVP_CTRL_AEAD_TLS1_AAD return value indicates the amount fo padding to
*               be applied to the SSL/TLS record
* @retval -1     function failed
*
* description:
*    This function is a generic control interface provided by the EVP API. For
*  chained requests this interface is used fro setting the hmac key value for
*  authentication of the SSL/TLS record. The second type is used to specify the
*  TLS virtual header which is used in the authentication calculationa nd to
*  identify record payload size.
*
******************************************************************************/
int qat_aes_cbc_hmac_sha_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                                      void *ptr)
{
    qat_chained_ctx *evp_ctx = NULL;
    int retVal = 0;
    int sha_digest_len = 0;
    unsigned char *hmac_key = NULL;
    CpaCySymSessionSetupData *sessionSetupData = NULL;
    unsigned char *p = NULL;
    unsigned int len = 0;

    if (ctx == NULL) {
        WARN("[%s] --- ctx parameter is NULL.\n", __func__);
        return -1;
    }
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
    const EVP_CIPHER *ia_cipher = NULL;
    size_t *payload_len_ptr = NULL;
#endif
    int nid = EVP_CIPHER_CTX_nid(ctx);
    switch (nid) {
    case NID_aes_128_cbc_hmac_sha1:
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
        ia_cipher = EVP_aes_128_cbc_hmac_sha1();
        payload_len_ptr = &(((qat_chained_sha1_ctx *)qat_chained_data(ctx))->payload_length);
#endif
        evp_ctx = &(((qat_chained_sha1_ctx *)qat_chained_data(ctx))->qat_ctx);
        break;
    case NID_aes_256_cbc_hmac_sha1:
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
        ia_cipher = EVP_aes_256_cbc_hmac_sha1();
        payload_len_ptr = &(((qat_chained_sha1_ctx *)qat_chained_data(ctx))->payload_length);
#endif
        evp_ctx = &(((qat_chained_sha1_ctx *)qat_chained_data(ctx))->qat_ctx);
        break;
    case NID_aes_128_cbc_hmac_sha256:
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
        ia_cipher = EVP_aes_128_cbc_hmac_sha256();
        payload_len_ptr = &(((qat_chained_sha256_ctx *)qat_chained_data(ctx))->payload_length);
#endif
        evp_ctx = &(((qat_chained_sha256_ctx *)qat_chained_data(ctx))->qat_ctx);
        break;
    case NID_aes_256_cbc_hmac_sha256:
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
        ia_cipher = EVP_aes_256_cbc_hmac_sha256();
        payload_len_ptr = &(((qat_chained_sha256_ctx *)qat_chained_data(ctx))->payload_length);
#endif
        evp_ctx = &(((qat_chained_sha256_ctx *)qat_chained_data(ctx))->qat_ctx);
        break;
    default:
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
        ia_cipher = NULL;
#endif
        return 0;
    }

#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
    EVP_CIPHER_meth_get_ctrl(ia_cipher)(ctx, type, arg, ptr);
#endif
    
    if (evp_ctx == NULL) {
        WARN("[%s] --- evp_ctx is NULL.\n", __func__);
        return -1;
    }

    if ((sha_digest_len = qat_get_sha_digest_len(ctx)) == 0) {
        WARN("[%s] --- Unable to get sha digest length\n", __func__);
        return -1;
    }

    switch (type) {
    case EVP_CTRL_AEAD_SET_MAC_KEY:
        hmac_key = evp_ctx->hmac_key;
        sessionSetupData = evp_ctx->session_data;

        if (NULL == hmac_key || NULL == sessionSetupData) {
            WARN("[%s] --- HMAC Key or sessionSetupData are NULL",
                    __func__);
            return -1;
        }

        memset(hmac_key, 0, HMAC_KEY_SIZE);

        if (arg > HMAC_KEY_SIZE) {
            if (sha_digest_len == SHA_DIGEST_LENGTH) {
                SHA1_Init(&(evp_ctx->sha_key_wrap.sha1_key_wrap));
                SHA1_Update(&(evp_ctx->sha_key_wrap.sha1_key_wrap), ptr, arg);
                SHA1_Final(hmac_key, &(evp_ctx->sha_key_wrap.sha1_key_wrap));
                sessionSetupData->hashSetupData.
                    authModeSetupData.authKeyLenInBytes = HMAC_KEY_SIZE;
            } else {
                SHA256_Init(&(evp_ctx->sha_key_wrap.sha256_key_wrap));
                SHA256_Update(&(evp_ctx->sha_key_wrap.sha256_key_wrap), ptr, arg);
                SHA256_Final(hmac_key, &(evp_ctx->sha_key_wrap.sha256_key_wrap));
                sessionSetupData->hashSetupData.
                    authModeSetupData.authKeyLenInBytes = HMAC_KEY_SIZE;
            }
        } else {
            memmove(hmac_key, ptr, arg);
            sessionSetupData->hashSetupData.
                authModeSetupData.authKeyLenInBytes = arg;
        }

        DUMPL("hmac_key", hmac_key, arg);

        evp_ctx->initHmacKeySet = 1;
        retVal = 1;
        break;

    case EVP_CTRL_AEAD_TLS1_AAD:
        /*
         * Values to include in the record MAC calculation are included
         * in this type This returns the amount of padding required for
         * the send/encrypt direction
         */
        p = ptr;

        if (arg < TLS_VIRT_HDR_SIZE) {
            retVal = -1;
            break;
        }

#ifdef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
        len =
            (p[arg - QAT_TLS_PAYLOADLENGTH_MSB_OFFSET] << QAT_BYTE_SHIFT |
             p[arg - QAT_TLS_PAYLOADLENGTH_LSB_OFFSET]);
#else
        len = *(unsigned int *)payload_len_ptr;
#endif

        evp_ctx->tls_version =
            (p[arg - QAT_TLS_VERSION_MSB_OFFSET] << QAT_BYTE_SHIFT |
             p[arg - QAT_TLS_VERSION_LSB_OFFSET]);

        if (EVP_CIPHER_CTX_encrypting(ctx)) {
            evp_ctx->payload_length = len;
#ifdef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
            if (evp_ctx->tls_version >= TLS1_1_VERSION) {
                len -= AES_BLOCK_SIZE;
                /* TODO: Why does this code reduce the len in the
                   TLS header by the IV for the framework? */
                p[arg - QAT_TLS_PAYLOADLENGTH_MSB_OFFSET] =
                    len >> QAT_BYTE_SHIFT;
                p[arg - QAT_TLS_PAYLOADLENGTH_LSB_OFFSET] = len;
            }
#endif
            if (NULL == evp_ctx->tls_virt_hdr) {
                WARN("Unable to allocate memory for mac preamble in qat/n");
                return -1;
            }
            /*
             * Copy the header from p into the QAT_BYTE_ALIGNMENT
             * sized buffer so that the header is in the final part
             * of the buffer
             */
            memmove(evp_ctx->tls_virt_hdr +
                    (QAT_BYTE_ALIGNMENT - TLS_VIRT_HDR_SIZE), p,
                    TLS_VIRT_HDR_SIZE);
            DUMPL("tls_virt_hdr",
                    evp_ctx->tls_virt_hdr + (QAT_BYTE_ALIGNMENT -
                        TLS_VIRT_HDR_SIZE), arg);
            retVal =
                (int)(((len + sha_digest_len +
                                AES_BLOCK_SIZE) & -AES_BLOCK_SIZE) - len);
            break;
        } else {
            /*
             * Copy the header from ptr into the QAT_BYTE_ALIGNMENT
             * sized buffer so that the header is in the final part
             * of the buffer
             */
            if (arg > TLS_VIRT_HDR_SIZE)
                arg = TLS_VIRT_HDR_SIZE;
            memmove(evp_ctx->tls_virt_hdr +
                    (QAT_BYTE_ALIGNMENT - TLS_VIRT_HDR_SIZE), ptr,
                    arg);
            evp_ctx->payload_length = arg;
            retVal = sha_digest_len;
            break;
        }

    default:
        WARN("[%s] --- unknown type parameter.\n", __func__);
        return -1;
    }
    return retVal;
}

/******************************************************************************
* function:
*    qat_aes_cbc_hmac_sha_cleanup(EVP_CIPHER_CTX *ctx)
*
* @param ctx    [IN]  - pointer to existing ctx
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function will cleanup all allocated resources required to perfrom the
*  cryptographic transform.
*
******************************************************************************/
int qat_aes_cbc_hmac_sha_cleanup(EVP_CIPHER_CTX *ctx)
{
    qat_chained_ctx *evp_ctx = NULL;
    CpaStatus sts = 0;
    CpaCySymSessionSetupData *sessSetup = NULL;
    int retVal = 1;

    if (ctx == NULL) {
        WARN("[%s] ctx parameter is NULL.\n", __func__);
        return 0;
    }

    int nid = 0;
    nid = EVP_CIPHER_CTX_nid(ctx);
    switch (nid) {
    case NID_aes_128_cbc_hmac_sha1:
    case NID_aes_256_cbc_hmac_sha1:
        evp_ctx = &(((qat_chained_sha1_ctx *)qat_chained_data(ctx))->qat_ctx);
        break;
    case NID_aes_128_cbc_hmac_sha256:
    case NID_aes_256_cbc_hmac_sha256:
        evp_ctx = &(((qat_chained_sha256_ctx *)qat_chained_data(ctx))->qat_ctx);
        break;
    default:
        return 0;
    }

    if (evp_ctx == NULL) {
        WARN("[%s] evp_ctx parameter is NULL.\n", __func__);
        return 0;
    }

    sessSetup = evp_ctx->session_data;
    if (sessSetup) {
        if (evp_ctx->qat_ctx) {
            if ((sts =
                 cpaCySymRemoveSession(evp_ctx->instanceHandle,
                                       evp_ctx->qat_ctx))
                != CPA_STATUS_SUCCESS) {
                WARN("[%s] cpaCySymRemoveSession FAILED, sts = %d.!\n",
                     __func__, sts);
                retVal = 0;
                /*
                 * Lets not return yet and instead make a best effort to
                 * cleanup the rest to avoid memory leaks
                 */
            }
            qaeCryptoMemFree(evp_ctx->qat_ctx);
            evp_ctx->qat_ctx = NULL;
        }
        if (sessSetup->hashSetupData.authModeSetupData.authKey) {
            OPENSSL_cleanse(sessSetup->hashSetupData.authModeSetupData.authKey,
                            sessSetup->hashSetupData.authModeSetupData.
                             authKeyLenInBytes);
            OPENSSL_free(sessSetup->hashSetupData.authModeSetupData.authKey);
            sessSetup->hashSetupData.authModeSetupData.authKey = NULL;
        }

        if (evp_ctx->tls_virt_hdr) {
            qaeCryptoMemFree(evp_ctx->tls_virt_hdr);
            evp_ctx->tls_virt_hdr = NULL;
        }
        if (evp_ctx->srcBufferList.pPrivateMetaData) {
            qaeCryptoMemFree(evp_ctx->srcBufferList.pPrivateMetaData);
            evp_ctx->srcBufferList.pPrivateMetaData = NULL;
        }
        if (evp_ctx->dstBufferList.pPrivateMetaData) {
            qaeCryptoMemFree(evp_ctx->dstBufferList.pPrivateMetaData);
            evp_ctx->dstBufferList.pPrivateMetaData = NULL;
        }
        if (evp_ctx->pIv) {
            qaeCryptoMemFree(evp_ctx->pIv);
            evp_ctx->pIv = NULL;

        }
        if (sessSetup->cipherSetupData.pCipherKey) {
            OPENSSL_cleanse(sessSetup->cipherSetupData.pCipherKey,
                            sessSetup->cipherSetupData.cipherKeyLenInBytes);
            OPENSSL_free(sessSetup->cipherSetupData.pCipherKey);
            sessSetup->cipherSetupData.pCipherKey = NULL;
        }
        OPENSSL_free(sessSetup);
        evp_ctx->session_data=NULL;
    }
    evp_ctx->init = 0;
    evp_ctx->payload_length = NO_PAYLOAD_LENGTH_SPECIFIED;
    return retVal;
}

/******************************************************************************
* function:
*         qat_aes_sha_session_init(EVP_CIPHER_CTX *ctx)
*
* @param ctx [IN] - pointer to context
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function synchronises the initialisation of the QAT session and
*  pre-allocates the necessary buffers for the session.
******************************************************************************/
static int qat_aes_sha_session_init(EVP_CIPHER_CTX *ctx)
{
    qat_chained_ctx *evp_ctx = NULL;
    CpaCySymSessionSetupData *sessionSetupData = NULL;
    Cpa32U sessionCtxSize = 0;
    CpaCySymSessionCtx pSessionCtx = NULL;
    Cpa32U metaSize = 0;

    if (ctx == NULL) {
        WARN("[%s] --- parameters ctx is NULL.\n", __func__);
        return 0;
    }

    int nid = 0;
    nid = EVP_CIPHER_CTX_nid(ctx);
    switch (nid) {
    case NID_aes_128_cbc_hmac_sha1:
    case NID_aes_256_cbc_hmac_sha1:
        evp_ctx = &(((qat_chained_sha1_ctx *)qat_chained_data(ctx))->qat_ctx);
        break;
    case NID_aes_128_cbc_hmac_sha256:
    case NID_aes_256_cbc_hmac_sha256:
        evp_ctx = &(((qat_chained_sha256_ctx *)qat_chained_data(ctx))->qat_ctx);
        break;
    default:
        return 0;
    }

    if (evp_ctx == NULL) {
        WARN("[%s] --- evp_ctx is NULL.\n", __func__);
        return 0;
    }

    /*
     * All parameters have not been set yet or we have already been
     * initialised.
     */
    if ((1 != evp_ctx->initParamsSet) || (1 == evp_ctx->init)) {
        WARN("[%s] --- parameters not set or initialised yet.\n", __func__);
        return 0;
    }

    sessionSetupData = evp_ctx->session_data;
    evp_ctx->instanceHandle = get_next_inst();

    if (evp_ctx->instanceHandle == NULL || sessionSetupData == NULL) {
        WARN("[%s] --- evp_ctx->instanceHandle or sessionSetupData are NULL.\n", __func__);
        return 0;
    }

    if (cpaCySymSessionCtxGetSize(evp_ctx->instanceHandle, sessionSetupData,
                                  &sessionCtxSize) != CPA_STATUS_SUCCESS) {
        WARN("[%s] --- cpaCySymSessionCtxGetSize failed.\n", __func__);
        return 0;
    }

    pSessionCtx =
        (CpaCySymSessionCtx) qaeCryptoMemAlloc(sessionCtxSize, __FILE__,
                                               __LINE__);
    if (NULL == pSessionCtx) {
        WARN("[%s] --- pSessionCtx malloc failed !\n", __func__);
        return 0;
    }

    if (EVP_CIPHER_CTX_encrypting(ctx))
        sessionSetupData->verifyDigest = CPA_FALSE;
    else
        sessionSetupData->verifyDigest = CPA_TRUE;

    sessionSetupData->digestIsAppended = CPA_TRUE;

    if (cpaCySymInitSession
        (evp_ctx->instanceHandle, qat_crypto_callbackFn, sessionSetupData,
         pSessionCtx) != CPA_STATUS_SUCCESS) {
        WARN("[%s] --- cpaCySymInitSession failed.\n", __func__);
        qaeCryptoMemFree(pSessionCtx);
        return 0;
    }

    evp_ctx->srcBufferList.numBuffers = 2;
    evp_ctx->srcBufferList.pBuffers = (evp_ctx->srcFlatBuffer);
    evp_ctx->srcBufferList.pUserData = NULL;

    evp_ctx->dstBufferList.numBuffers = 2;
    evp_ctx->dstBufferList.pBuffers = (evp_ctx->dstFlatBuffer);
    evp_ctx->dstBufferList.pUserData = NULL;

    /* setup meta data for buffer lists */
    if (cpaCyBufferListGetMetaSize(evp_ctx->instanceHandle,
                                   evp_ctx->srcBufferList.numBuffers,
                                   &metaSize) != CPA_STATUS_SUCCESS) {
        WARN("[%s] --- cpaCyBufferListGetBufferSize failed.\n", __func__);
        qaeCryptoMemFree(pSessionCtx);
        return 0;
    }

    if (metaSize) {
        evp_ctx->srcBufferList.pPrivateMetaData =
            qaeCryptoMemAlloc(metaSize, __FILE__, __LINE__);
        if (!(evp_ctx->srcBufferList.pPrivateMetaData)) {
            WARN("[%s] --- srcBufferList.pPrivateMetaData is NULL.\n",
                 __func__);
            qaeCryptoMemFree(pSessionCtx);
            return 0;
        }
    } else {
        evp_ctx->srcBufferList.pPrivateMetaData = NULL;
    }
    metaSize = 0;

    if (cpaCyBufferListGetMetaSize(evp_ctx->instanceHandle,
                                   evp_ctx->dstBufferList.numBuffers,
                                   &metaSize) != CPA_STATUS_SUCCESS) {
        WARN("[%s] --- cpaCyBufferListGetBufferSize failed.\n", __func__);
        if (evp_ctx->srcBufferList.pPrivateMetaData) {
            qaeCryptoMemFree(evp_ctx->srcBufferList.pPrivateMetaData);
            evp_ctx->srcBufferList.pPrivateMetaData = NULL;
        }
        qaeCryptoMemFree(pSessionCtx);
        return 0;
    }

    if (metaSize) {
        evp_ctx->dstBufferList.pPrivateMetaData =
            qaeCryptoMemAlloc(metaSize, __FILE__, __LINE__);
        if (!(evp_ctx->dstBufferList.pPrivateMetaData)) {
            WARN("[%s] --- dstBufferList.pPrivateMetaData is NULL.\n",
                 __func__);
            if (evp_ctx->srcBufferList.pPrivateMetaData) {
                qaeCryptoMemFree(evp_ctx->srcBufferList.pPrivateMetaData);
                evp_ctx->srcBufferList.pPrivateMetaData = NULL;
            }
            qaeCryptoMemFree(pSessionCtx);
            return 0;
        }
    } else {
        evp_ctx->dstBufferList.pPrivateMetaData = NULL;
    }

    /*
     * Create the OpData structure to remove this processing from the data
     * path
     */
    evp_ctx->qat_ctx = pSessionCtx;
    evp_ctx->OpData.sessionCtx = evp_ctx->qat_ctx;
    evp_ctx->OpData.packetType = CPA_CY_SYM_PACKET_TYPE_FULL;

    evp_ctx->OpData.pIv = evp_ctx->pIv;
    evp_ctx->OpData.ivLenInBytes = (Cpa32U) EVP_CIPHER_CTX_iv_length(ctx);
    /*
     * We want to ensure the start of crypto data is on a 64 byte, aligned
     * boundary. This is for QAT internal performance reasons.
     */
    evp_ctx->OpData.cryptoStartSrcOffsetInBytes = QAT_BYTE_ALIGNMENT;
    /*
     * We start hashing from the start of the header. Due to needing the
     * crypto data aligned to a 64 byte boundary we need to start the header
     * that comes first at an offset into the 64 byte aligned block so the
     * header will end on a 64 byte alignment.
     */
    evp_ctx->OpData.hashStartSrcOffsetInBytes =
        QAT_BYTE_ALIGNMENT - TLS_VIRT_HDR_SIZE;
    evp_ctx->OpData.pAdditionalAuthData = NULL;

    evp_ctx->init = 1;

    return 1;
}
/******************************************************************************
* function:
*    qat_aes_cbc_hmac_sha_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
*                                 const unsigned char *in, size_t len)
*
* @param ctx    [IN]  - pointer to existing ctx
* @param out   [OUT]  - output buffer for transform result
* @param in     [IN]  - input buffer
* @param len    [IN]  - length of input buffer
*
* @retval 0      function failed
* @retval 1      function succeeded
*
* description:
*    This function performs the cryptographic transform according to the
*  parameters setup during initialisation.
*
******************************************************************************/
int qat_aes_cbc_hmac_sha_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                      const unsigned char *in, size_t len)
{
    CpaStatus sts = 0;
    unsigned int pad_len = 0;
    struct op_done opDone;
    qat_chained_ctx *evp_ctx = NULL;
    int retVal = 0;
    size_t plen = 0, iv = 0;    /* explicit IV in TLS 1.1 and later */
    int sha_digest_len = 0;

    CRYPTO_QAT_LOG("CIPHER - %s\n", __func__);

    if (ctx == NULL || in == NULL || out == NULL) {
        WARN("[%s] --- ctx, in or out parameters are NULL.\n", __func__);
        return 0;
    }

#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
    const EVP_CIPHER *ia_cipher = NULL;
#endif

    int nid = EVP_CIPHER_CTX_nid(ctx);
    switch (nid) {
    case NID_aes_128_cbc_hmac_sha1:
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
        ia_cipher = EVP_aes_128_cbc_hmac_sha1();
#endif
        evp_ctx = &(((qat_chained_sha1_ctx *)qat_chained_data(ctx))->qat_ctx);
        break;
    case NID_aes_256_cbc_hmac_sha1:
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
        ia_cipher = EVP_aes_256_cbc_hmac_sha1();
#endif
        evp_ctx = &(((qat_chained_sha1_ctx *)qat_chained_data(ctx))->qat_ctx);
        break;
    case NID_aes_128_cbc_hmac_sha256:
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
        ia_cipher = EVP_aes_128_cbc_hmac_sha256();
#endif
        evp_ctx = &(((qat_chained_sha256_ctx *)qat_chained_data(ctx))->qat_ctx);
        break;
    case NID_aes_256_cbc_hmac_sha256:
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
        ia_cipher = EVP_aes_256_cbc_hmac_sha256();
#endif
        evp_ctx = &(((qat_chained_sha256_ctx *)qat_chained_data(ctx))->qat_ctx);
        break;
    default:
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
        ia_cipher = NULL;
#endif
        return 0;
    }

#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
    if(len <= qat_pkt_threshold_table_get_threshold(nid)) {
        retVal = EVP_CIPHER_meth_get_do_cipher(ia_cipher)(ctx, out, in, len);
        return retVal;
    }
#endif

    if (evp_ctx == NULL) {
        WARN("[%s] --- evp_ctx is NULL.\n", __func__);
        return 0;
    }

    if (len % AES_BLOCK_SIZE) {
        WARN("[%s] --- len is not a multiple of the AES_BLOCK_SIZE.\n",
             __func__);
        return 0;
    }

    if (!(evp_ctx->init)) {
        if (0 == qat_aes_sha_session_init(ctx)) {
            WARN("[%s] --- Unable to initialise Cipher context.\n", __func__);
            return 0;
        }
    }

    if ((sha_digest_len = qat_get_sha_digest_len(ctx)) == 0) {
        WARN("[%s] --- Unable to get sha digest length\n", __func__);
        return -1;
    }

    plen = evp_ctx->payload_length;
    if (NO_PAYLOAD_LENGTH_SPECIFIED == plen) {
        plen = len - sha_digest_len;
    } else if (EVP_CIPHER_CTX_encrypting(ctx)
             && len !=
             ((plen + sha_digest_len + AES_BLOCK_SIZE) & -AES_BLOCK_SIZE)) {
        return 0;
    } else if (evp_ctx->tls_version >= TLS1_1_VERSION) {
        iv = AES_BLOCK_SIZE;
        memmove(evp_ctx->OpData.pIv, in, EVP_CIPHER_CTX_iv_length(ctx));
        /*
         * Note: The OpenSSL framework assumes that the IV field will be part
         * of the encrypted data, yet never looks at the output of the
         * encryption/decryption process for this field. In order to chain
         * HASH and CIPHER we need to present contiguous SGL to QAT, thus we
         * need to copy the IV from input to output in in order to skip this
         * field in encryption
         */
        if (in != out)
            memmove(out, in, EVP_CIPHER_CTX_iv_length(ctx));
        in += iv;
        out += iv;
        len -= iv;
        evp_ctx->payload_length -= iv;
        plen -= iv;
    } else {
        memmove(evp_ctx->OpData.pIv, EVP_CIPHER_CTX_iv(ctx), EVP_CIPHER_CTX_iv_length(ctx));
    }

    /* Build request/response buffers */
    evp_ctx->srcFlatBuffer[1].pData =
        qaeCryptoMemAlloc(len, __FILE__, __LINE__);
    if ((evp_ctx->srcFlatBuffer[1].pData) == NULL) {
        WARN("[%s] --- src/dst buffer allocation.\n", __func__);
	return 0;
    }
    evp_ctx->dstFlatBuffer[1].pData = evp_ctx->srcFlatBuffer[1].pData;
    memmove(evp_ctx->dstFlatBuffer[1].pData, in, len);

    evp_ctx->srcFlatBuffer[1].dataLenInBytes = len;
    evp_ctx->srcBufferList.pUserData = NULL;
    evp_ctx->dstFlatBuffer[1].dataLenInBytes = len;
    evp_ctx->dstBufferList.pUserData = NULL;

    evp_ctx->OpData.messageLenToCipherInBytes = len;

    if (NO_PAYLOAD_LENGTH_SPECIFIED == evp_ctx->payload_length) {
        evp_ctx->OpData.messageLenToHashInBytes =
            (TLS_VIRT_HDR_SIZE + len) - sha_digest_len;
    } else if (!EVP_CIPHER_CTX_encrypting(ctx)) {
        AES_KEY aes_key;
        unsigned char in_blk[AES_BLOCK_SIZE] = { 0x0 };
        unsigned char *key =
            evp_ctx->session_data->cipherSetupData.pCipherKey;
        unsigned int key_len = EVP_CIPHER_CTX_key_length(ctx);
        unsigned char ivec[AES_BLOCK_SIZE] = { 0x0 };
        unsigned char out_blk[AES_BLOCK_SIZE] = { 0x0 };

        key_len = key_len * 8;  /* convert to bits */
        memmove(in_blk, (in + (len - AES_BLOCK_SIZE)), AES_BLOCK_SIZE);
        memmove(ivec, (in + (len - (AES_BLOCK_SIZE + AES_BLOCK_SIZE))),
               AES_BLOCK_SIZE);

        /* Dump input parameters */
        DUMPL("Key :", key, EVP_CIPHER_CTX_key_length(ctx));
        DUMPL("IV :", ivec, AES_BLOCK_SIZE);
        DUMPL("Input Blk :", in_blk, AES_BLOCK_SIZE);

        AES_set_decrypt_key(key, key_len, &aes_key);
        AES_cbc_encrypt(in_blk, out_blk, AES_BLOCK_SIZE, &aes_key, ivec, 0);

        DUMPL("Output Blk :", out_blk, AES_BLOCK_SIZE);

        /* Extract pad length */
        pad_len = out_blk[AES_BLOCK_SIZE - 1];

        /* Calculate and update length */
        evp_ctx->payload_length = len - (pad_len + 1 + sha_digest_len);
        /*
         * Take into account that the field is part of the header that is
         * offset into a byte aligned buffer.
         */
        evp_ctx->tls_virt_hdr[QAT_BYTE_ALIGNMENT -
                              QAT_TLS_PAYLOADLENGTH_MSB_OFFSET] =
            evp_ctx->payload_length >> QAT_BYTE_SHIFT;
        /*
         * Take into account that the field is part of the header that is
         * offset into a byte aligned buffer.
         */
        evp_ctx->tls_virt_hdr[QAT_BYTE_ALIGNMENT -
                              QAT_TLS_PAYLOADLENGTH_LSB_OFFSET] =
            evp_ctx->payload_length;

        /* HMAC Length */
        evp_ctx->OpData.messageLenToHashInBytes =
            TLS_VIRT_HDR_SIZE + evp_ctx->payload_length;
        /* Only copy the offset header data itself and not the whole block */
        memmove(evp_ctx->dstFlatBuffer[0].pData +
               (QAT_BYTE_ALIGNMENT - TLS_VIRT_HDR_SIZE),
               evp_ctx->tls_virt_hdr + (QAT_BYTE_ALIGNMENT -
                                        TLS_VIRT_HDR_SIZE),
               TLS_VIRT_HDR_SIZE);
    } else {
        evp_ctx->OpData.messageLenToHashInBytes =
            TLS_VIRT_HDR_SIZE + evp_ctx->payload_length;
    }

    /* Add record padding */
    if (EVP_CIPHER_CTX_encrypting(ctx)) {
        plen += sha_digest_len;
        for (pad_len = len - plen - 1; plen < len; plen++)
            evp_ctx->dstFlatBuffer[1].pData[plen] = pad_len;
    }

    initOpDone(&opDone);
    if (opDone.job) {
        if (qat_setup_async_event_notification(0) == 0) {
            WARN("Failure to setup async event notifications\n");
            cleanupOpDone(&opDone);
            return 0;
        }
    }
    if (!EVP_CIPHER_CTX_encrypting(ctx) &&
        (NO_PAYLOAD_LENGTH_SPECIFIED != evp_ctx->payload_length) &&
        ((evp_ctx->tls_version) < TLS1_1_VERSION))
        memmove(EVP_CIPHER_CTX_iv_noconst(ctx), in + len - AES_BLOCK_SIZE,
               EVP_CIPHER_CTX_iv_length(ctx));

    CRYPTO_QAT_LOG("CIPHER - %s\n", __func__);
    DEBUG("Pre Perform Op\n");

    if ((sts = myPerformOp(evp_ctx->instanceHandle,
                            &opDone,
                            &(evp_ctx->OpData),
                            &(evp_ctx->srcBufferList),
                            &(evp_ctx->dstBufferList),
                            &(evp_ctx->session_data->verifyDigest))) !=
                            CPA_STATUS_SUCCESS) {
        qaeCryptoMemFree(evp_ctx->srcFlatBuffer[1].pData);
        evp_ctx->srcFlatBuffer[1].pData = NULL;
        evp_ctx->dstFlatBuffer[1].pData = NULL;
        cleanupOpDone(&opDone);
        WARN("[%s] --- cpaCySymPerformOp failed sts=%d.\n", __func__,
             sts);
        return 0;
    }

    do {
        if(opDone.job) {
            /* If we get a failure on qat_pause_job then we will
               not flag an error here and quit because we have
               an asynchronous request in flight.
               We don't want to start cleaning up data
               structures that are still being used. If
               qat_pause_job fails we will just yield and
               loop around and try again until the request
               completes and we can continue. */
            if (qat_pause_job(opDone.job, 0) == 0)
                pthread_yield();
        } else {
            pthread_yield();
        }
    } while(!opDone.flag);

    cleanupOpDone(&opDone);

    if (opDone.verifyResult == CPA_TRUE)
        retVal = 1;

    DEBUG("Post Perform Op\n");

    if (EVP_CIPHER_CTX_encrypting(ctx) && ((evp_ctx->tls_version) < TLS1_1_VERSION))
        memmove(EVP_CIPHER_CTX_iv_noconst(ctx),
               evp_ctx->dstBufferList.pBuffers[1].pData + len -
               AES_BLOCK_SIZE, EVP_CIPHER_CTX_iv_length(ctx));
    evp_ctx->payload_length = NO_PAYLOAD_LENGTH_SPECIFIED;

    memmove(out, evp_ctx->dstFlatBuffer[1].pData, len);
    qaeCryptoMemFree(evp_ctx->srcFlatBuffer[1].pData);
    evp_ctx->srcFlatBuffer[1].pData = NULL;
    evp_ctx->dstFlatBuffer[1].pData = NULL;

    return retVal;
}

