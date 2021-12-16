/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2019-2021 Intel Corporation.
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
 * @file qat_evp.c
 *
 * This file provides an initialisation of the various operations at the EVP
 * layer for an OpenSSL engine.
 *
 *****************************************************************************/
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <stddef.h>
#include <stdarg.h>
#include "openssl/ossl_typ.h"
#include "openssl/kdf.h"
#include "openssl/evp.h"

#include "e_qat.h"
#include "qat_evp.h"
#include "qat_utils.h"

#ifdef QAT_HW
# include "qat_hw_ciphers.h"
# include "qat_hw_ec.h"
# include "qat_hw_gcm.h"
# include "qat_hw_sha3.h"
# include "qat_hw_chachapoly.h"
#endif

#ifdef QAT_SW_IPSEC
# include "qat_sw_gcm.h"
#endif

#ifdef QAT_SW
# include "qat_sw_ecx.h"
# include "qat_sw_ec.h"
# include "qat_sw_sm3.h"
# include "crypto_mb/cpu_features.h"
#endif

#ifdef QAT_HW_INTREE
# define ENABLE_QAT_HW_SHA3
# define ENABLE_QAT_HW_CHACHAPOLY
#endif

typedef struct _chained_info {
    const int nid;
    EVP_CIPHER *cipher;
    const int keylen;
} chained_info;

static chained_info info[] = {
#ifdef ENABLE_QAT_HW_CIPHERS
    {NID_aes_128_cbc_hmac_sha1, NULL, AES_KEY_SIZE_128},
    {NID_aes_128_cbc_hmac_sha256, NULL, AES_KEY_SIZE_128},
    {NID_aes_256_cbc_hmac_sha1, NULL, AES_KEY_SIZE_256},
    {NID_aes_256_cbc_hmac_sha256, NULL, AES_KEY_SIZE_256},
#endif
#ifdef ENABLE_QAT_HW_CHACHAPOLY
    {NID_chacha20_poly1305, NULL, CHACHA_KEY_SIZE},
#endif
#if defined(ENABLE_QAT_HW_GCM) || defined(ENABLE_QAT_SW_GCM)
    {NID_aes_128_gcm, NULL, AES_KEY_SIZE_128},
    {NID_aes_192_gcm, NULL, AES_KEY_SIZE_192},
    {NID_aes_256_gcm, NULL, AES_KEY_SIZE_256},
#endif
};

static const unsigned int num_cc = sizeof(info) / sizeof(chained_info);

/* Qat Symmetric cipher function register */
int qat_cipher_nids[] = {
#ifdef ENABLE_QAT_HW_CIPHERS
    NID_aes_128_cbc_hmac_sha1,
    NID_aes_128_cbc_hmac_sha256,
    NID_aes_256_cbc_hmac_sha1,
    NID_aes_256_cbc_hmac_sha256,
#endif
#ifdef ENABLE_QAT_HW_CHACHAPOLY
    NID_chacha20_poly1305,
#endif
#if defined(ENABLE_QAT_HW_GCM) || defined(ENABLE_QAT_SW_GCM)
    NID_aes_128_gcm,
    NID_aes_192_gcm,
    NID_aes_256_gcm,
#endif
};

/* Supported EVP nids */
int qat_evp_nids[] = {
#ifdef ENABLE_QAT_HW_PRF
    EVP_PKEY_TLS1_PRF,
#endif
#ifdef ENABLE_QAT_HW_HKDF
    EVP_PKEY_HKDF,
#endif
#if defined(ENABLE_QAT_HW_ECX) || defined(ENABLE_QAT_SW_ECX)
    EVP_PKEY_X25519,
#endif
#ifdef ENABLE_QAT_HW_ECX
    EVP_PKEY_X448
#endif
};
const int num_evp_nids = sizeof(qat_evp_nids) / sizeof(qat_evp_nids[0]);

typedef struct _digest_data {
    const int m_type;
    const int pkey_type;
} digest_data;

static digest_data digest_info[] = {
#ifdef ENABLE_QAT_HW_SHA3
    { NID_sha3_224,  NID_RSA_SHA3_224},
    { NID_sha3_256,  NID_RSA_SHA3_256},
    { NID_sha3_384,  NID_RSA_SHA3_384},
    { NID_sha3_512,  NID_RSA_SHA3_512},
#endif
#ifdef ENABLE_QAT_SW_SM3
    { NID_sm3,  NID_sm3WithRSAEncryption},
#endif
};

/* QAT Hash Algorithm register */
int qat_digest_nids[] = {
#ifdef ENABLE_QAT_HW_SHA3
    NID_sha3_224,
    NID_sha3_256,
    NID_sha3_384,
    NID_sha3_512,
#endif
#ifdef ENABLE_QAT_SW_SM3
    NID_sm3,
#endif
};
const int num_digest_nids = sizeof(qat_digest_nids) / sizeof(qat_digest_nids[0]);

#ifndef ENABLE_QAT_HW_SMALL_PKT_OFFLOAD
typedef struct cipher_threshold_table_s {
    int nid;
    int threshold;
} PKT_THRESHOLD;

static PKT_THRESHOLD qat_pkt_threshold_table[] = {
# ifdef ENABLE_QAT_HW_CIPHERS
    {NID_aes_128_cbc_hmac_sha1, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_256_cbc_hmac_sha1, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_128_cbc_hmac_sha256,
     CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_256_cbc_hmac_sha256,
     CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
# endif
# ifdef ENABLE_QAT_HW_SHA3
    {NID_sha3_224, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_sha3_256, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_sha3_384, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_sha3_512, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
# endif
# ifdef ENABLE_QAT_HW_CHACHAPOLY
    {NID_chacha20_poly1305, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
# endif
};

static int pkt_threshold_table_size =
    (sizeof(qat_pkt_threshold_table) / sizeof(qat_pkt_threshold_table[0]));
#endif

static EC_KEY_METHOD *qat_ec_method = NULL;
static EVP_PKEY_METHOD *_hidden_x25519_pmeth = NULL;
static EVP_PKEY_METHOD *_hidden_x448_pmeth = NULL;

/* Have a store of the s/w EVP_PKEY_METHOD for software fallback purposes. */
const EVP_PKEY_METHOD *sw_x25519_pmeth = NULL;
const EVP_PKEY_METHOD *sw_x448_pmeth = NULL;
EVP_MD *qat_sw_sm3_meth = NULL;

const EVP_MD *qat_sw_create_sm3_meth(int nid , int key_type)
{
#ifdef ENABLE_QAT_SW_SM3
    int res = 1;

    if ((qat_sw_sm3_meth = EVP_MD_meth_new(nid, key_type)) == NULL) {
        WARN("Failed to allocate digest methods for nid %d\n", nid);
        return NULL;
    }

    /* For now check using MBX_ALGO_X25519 as algo info for sm3 is not implemented */
    if (mbx_get_algo_info(MBX_ALGO_X25519)) {
        res &= EVP_MD_meth_set_result_size(qat_sw_sm3_meth, 32);
        res &= EVP_MD_meth_set_input_blocksize(qat_sw_sm3_meth, 64);
        res &= EVP_MD_meth_set_app_datasize(qat_sw_sm3_meth, sizeof(EVP_MD*) + 580);
        res &= EVP_MD_meth_set_flags(qat_sw_sm3_meth, (EVP_MD_CTX_FLAG_ONESHOT|EVP_MD_CTX_FLAG_NO_INIT));
        res &= EVP_MD_meth_set_init(qat_sw_sm3_meth, qat_sw_sm3_init);
        res &= EVP_MD_meth_set_update(qat_sw_sm3_meth, qat_sw_sm3_update);
        res &= EVP_MD_meth_set_final(qat_sw_sm3_meth, qat_sw_sm3_final);
        qat_sw_sm3_offload = 1;
    }

    if (0 == res) {
        WARN("Failed to set MD methods for nid %d\n", nid);
        EVP_MD_meth_free(qat_sw_sm3_meth);
        qat_sw_sm3_meth = NULL;
    }

    DEBUG("QAT SW SM3 Registration succeeded\n");
#endif

    if (!qat_sw_sm3_offload)
        return EVP_sm3();

    return qat_sw_sm3_meth;
}

/******************************************************************************
 * function:
 *         qat_create_digest_meth(int nid , int pkeytype)
 *
 * @param nid    [IN] - EVP operation id
 *
 * description:
 *   Creates qat EVP MD methods for the nid
******************************************************************************/
static const EVP_MD *qat_create_digest_meth(int nid , int pkeytype)
{
    switch (nid) {
#ifdef ENABLE_QAT_HW_SHA3
        case NID_sha3_224:
        case NID_sha3_256:
        case NID_sha3_384:
        case NID_sha3_512:
            if (qat_hw_offload)
                return qat_create_sha3_meth(nid , pkeytype);
#endif
#ifdef ENABLE_QAT_SW_SM3
        case NID_sm3:
            return qat_sw_create_sm3_meth(nid , pkeytype);
#endif
        default:
            WARN("Invalid nid %d\n", nid);
            return NULL;
    }
}
/******************************************************************************
 * function:
 *         qat_digest_methods(ENGINE *e,
 *                          const EVP_MD **md,
 *                          const int **nids,
 *                          int nid)
 *
 * @param e      [IN] - OpenSSL engine pointer
 * @param pmeth  [IN] - EVP methods structure pointer
 * @param nids   [IN] - EVP function nids
 * @param nid    [IN] - EVP operation id
 *
 * description:
 *   QAT engine digest operations register.
******************************************************************************/
int qat_digest_methods(ENGINE *e, const EVP_MD **md,
                       const int **nids, int nid)
{
    int i;
    if (md == NULL) {
        if (unlikely(nids == NULL)) {
            WARN("Invalid input params.\n");
            return 0;
        }
        *nids = qat_digest_nids;
        return num_digest_nids;
    }

    for (i = 0; i < num_digest_nids; i++) {
        if (nid == qat_digest_nids[i]) {
            *md = qat_create_digest_meth(digest_info[i].m_type,
                                         digest_info[i].pkey_type);
            return 1;
        }
    }

    WARN("NID %d not supported\n", nid);
    *md = NULL;
    return 0;
}

EVP_PKEY_METHOD *qat_x25519_pmeth(void)
{
    if (_hidden_x25519_pmeth)
        return _hidden_x25519_pmeth;

    if ((_hidden_x25519_pmeth =
         EVP_PKEY_meth_new(EVP_PKEY_X25519, 0)) == NULL) {
        QATerr(QAT_F_QAT_X25519_PMETH, QAT_R_ALLOC_QAT_X25519_METH_FAILURE);
        return NULL;
    }

    /* Now save the current (non-offloaded) x25519 pmeth to sw_x25519_pmeth */
    /* for software fallback purposes */
    if ((sw_x25519_pmeth = EVP_PKEY_meth_find(EVP_PKEY_X25519)) == NULL) {
        QATerr(QAT_F_QAT_X25519_PMETH, ERR_R_INTERNAL_ERROR);
        return NULL;
    }

#ifdef ENABLE_QAT_HW_ECX
    if (qat_hw_offload) {
        EVP_PKEY_meth_set_keygen(_hidden_x25519_pmeth, NULL, qat_pkey_ecx_keygen);
        EVP_PKEY_meth_set_derive(_hidden_x25519_pmeth, NULL, qat_pkey_ecx_derive25519);
        EVP_PKEY_meth_set_ctrl(_hidden_x25519_pmeth, qat_pkey_ecx_ctrl, NULL);
        qat_hw_ecx_offload = 1;
        DEBUG("QAT HW X25519 registration succeeded\n");
    }
#endif

#ifdef ENABLE_QAT_SW_ECX
    if (!qat_hw_ecx_offload && mbx_get_algo_info(MBX_ALGO_X25519)) {
        EVP_PKEY_meth_set_keygen(_hidden_x25519_pmeth, NULL, multibuff_x25519_keygen);
        EVP_PKEY_meth_set_derive(_hidden_x25519_pmeth, NULL, multibuff_x25519_derive);
        EVP_PKEY_meth_set_ctrl(_hidden_x25519_pmeth, multibuff_x25519_ctrl, NULL);
        qat_sw_ecx_offload = 1;
        DEBUG("QAT SW X25519 registration succeeded\n");
    }
#endif

    if (qat_hw_ecx_offload == 0 && qat_sw_ecx_offload == 0)
        EVP_PKEY_meth_copy(_hidden_x25519_pmeth, sw_x25519_pmeth);

    return _hidden_x25519_pmeth;
}

EVP_PKEY_METHOD *qat_x448_pmeth(void)
{
    if (_hidden_x448_pmeth)
        return _hidden_x448_pmeth;

    if ((_hidden_x448_pmeth =
         EVP_PKEY_meth_new(EVP_PKEY_X448, 0)) == NULL) {
        QATerr(QAT_F_QAT_X448_PMETH, QAT_R_ALLOC_QAT_X448_METH_FAILURE);
        return NULL;
    }

    /* Now save the current (non-offloaded) x448 pmeth to sw_x448_pmeth */
    /* for software fallback purposes */
    if ((sw_x448_pmeth = EVP_PKEY_meth_find(EVP_PKEY_X448)) == NULL) {
        QATerr(QAT_F_QAT_X448_PMETH, ERR_R_INTERNAL_ERROR);
        return NULL;
    }

#ifdef ENABLE_QAT_HW_ECX
    if (qat_hw_offload) {
        EVP_PKEY_meth_set_keygen(_hidden_x448_pmeth, NULL, qat_pkey_ecx_keygen);
        EVP_PKEY_meth_set_derive(_hidden_x448_pmeth, NULL, qat_pkey_ecx_derive448);
        EVP_PKEY_meth_set_ctrl(_hidden_x448_pmeth, qat_pkey_ecx_ctrl, NULL);
        qat_hw_ecx_offload = 1;
        DEBUG("QAT HW ECDH X448 Registration succeeded\n");
    }
#endif

    if (!qat_hw_ecx_offload)
        EVP_PKEY_meth_copy(_hidden_x448_pmeth, sw_x448_pmeth);

    return _hidden_x448_pmeth;
}

/******************************************************************************
 * function:
 *         qat_create_pkey_meth(int nid)
 *
 * @param nid    [IN] - EVP operation id
 *
 * description:
 *   Creates qat EVP Pkey methods for the nid
******************************************************************************/
static EVP_PKEY_METHOD *qat_create_pkey_meth(int nid)
{
    switch (nid) {
#ifdef ENABLE_QAT_HW_PRF
    case EVP_PKEY_TLS1_PRF:
        return qat_prf_pmeth();
#endif

#ifdef ENABLE_QAT_HW_HKDF
    case EVP_PKEY_HKDF:
        return qat_hkdf_pmeth();
#endif

#if defined(ENABLE_QAT_HW_ECX) || defined(ENABLE_QAT_SW_ECX)
    case EVP_PKEY_X25519:
        return qat_x25519_pmeth();
#endif

#ifdef ENABLE_QAT_HW_ECX
    case EVP_PKEY_X448:
        return qat_x448_pmeth();
#endif
    default:
        WARN("Invalid nid %d\n", nid);
        return NULL;
    }
}

/******************************************************************************
 * function:
 *         qat_pkey_methods(ENGINE *e,
 *                          const EVP_PKEY_METHOD **pmeth,
 *                          const int **nids,
 *                          int nid)
 *
 * @param e      [IN] - OpenSSL engine pointer
 * @param pmeth  [IN] - EVP methods structure pointer
 * @param nids   [IN] - EVP functions nids
 * @param nid    [IN] - EVP operation id
 *
 * description:
 *   QAT engine digest operations registrar
******************************************************************************/
int qat_pkey_methods(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                     const int **nids, int nid)
{
    int i;
    if (pmeth == NULL) {
        if (unlikely(nids == NULL)) {
            WARN("Invalid input params.\n");
            return 0;
        }
        *nids = qat_evp_nids;
        return num_evp_nids;
    }

    for (i = 0; i < num_evp_nids; i++) {
        if (nid == qat_evp_nids[i]) {
            *pmeth = qat_create_pkey_meth(nid);
            return 1;
        }
    }

    WARN("NID %d not supported\n", nid);
    *pmeth = NULL;
    return 0;
}

static inline const EVP_CIPHER *qat_gcm_cipher_sw_impl(int nid)
{
    switch (nid) {
        case NID_aes_128_gcm:
            return EVP_aes_128_gcm();
        case NID_aes_192_gcm:
            return EVP_aes_192_gcm();
        case NID_aes_256_gcm:
            return EVP_aes_256_gcm();
        default:
            WARN("Invalid nid %d\n", nid);
            return NULL;
    }
}

/******************************************************************************
 * function:
 *         qat_create_gcm_cipher_meth(int nid, int keylen)
 *
 * @param nid    [IN] - Cipher NID to be created
 * @param keylen [IN] - Key length of cipher [128|192|256]
 * @retval            - EVP_CIPHER * to created cipher
 * @retval            - NULL if failure
 *
 * description:
 *   Create a new EVP_CIPHER based on requested nid for qat_hw or qat_sw
 ******************************************************************************/
const EVP_CIPHER *qat_create_gcm_cipher_meth(int nid, int keylen)
{
    EVP_CIPHER *c = NULL;
    int res = 1;

#ifdef ENABLE_QAT_SW_GCM
    if (qat_sw_ipsec) {
        if ((c = EVP_CIPHER_meth_new(nid, AES_GCM_BLOCK_SIZE, keylen)) == NULL) {
            WARN("Failed to allocate cipher methods for nid %d\n", nid);
            return NULL;
        }

        res &= EVP_CIPHER_meth_set_iv_length(c, GCM_IV_DATA_LEN);
        res &= EVP_CIPHER_meth_set_flags(c, VAESGCM_FLAG);
        res &= EVP_CIPHER_meth_set_init(c, vaesgcm_ciphers_init);
        res &= EVP_CIPHER_meth_set_do_cipher(c, vaesgcm_ciphers_do_cipher);
        res &= EVP_CIPHER_meth_set_cleanup(c, vaesgcm_ciphers_cleanup);
        res &= EVP_CIPHER_meth_set_impl_ctx_size(c, sizeof(vaesgcm_ctx));
        res &= EVP_CIPHER_meth_set_set_asn1_params(c, NULL);
        res &= EVP_CIPHER_meth_set_get_asn1_params(c, NULL);
        res &= EVP_CIPHER_meth_set_ctrl(c, vaesgcm_ciphers_ctrl);
        qat_sw_gcm_offload = 1;
        DEBUG("QAT SW AES_GCM registration\n");
    }
#endif

#ifdef ENABLE_QAT_HW_GCM
    if (!qat_sw_gcm_offload && qat_hw_offload) {
        if (nid == NID_aes_192_gcm)
            return qat_gcm_cipher_sw_impl(nid);

	if ((c = EVP_CIPHER_meth_new(nid, AES_GCM_BLOCK_SIZE, keylen)) == NULL) {
            WARN("Failed to allocate cipher methods for nid %d\n", nid);
            return NULL;
        }

        res &= EVP_CIPHER_meth_set_iv_length(c, AES_GCM_IV_LEN);
        res &= EVP_CIPHER_meth_set_flags(c, QAT_GCM_FLAGS);
        res &= EVP_CIPHER_meth_set_init(c, qat_aes_gcm_init);
        res &= EVP_CIPHER_meth_set_do_cipher(c, qat_aes_gcm_cipher);
        res &= EVP_CIPHER_meth_set_cleanup(c, qat_aes_gcm_cleanup);
        res &= EVP_CIPHER_meth_set_impl_ctx_size(c, sizeof(qat_gcm_ctx));
        res &= EVP_CIPHER_meth_set_set_asn1_params(c, EVP_CIPH_FLAG_DEFAULT_ASN1 ?
                                                   NULL : EVP_CIPHER_set_asn1_iv);
        res &= EVP_CIPHER_meth_set_get_asn1_params(c, EVP_CIPH_FLAG_DEFAULT_ASN1 ?
                                                   NULL : EVP_CIPHER_get_asn1_iv);
        res &= EVP_CIPHER_meth_set_ctrl(c, qat_aes_gcm_ctrl);
        qat_hw_gcm_offload = 1;
        DEBUG("QAT HW AES_GCM registration\n");
     }
#endif

    if (0 == res) {
        WARN("Failed to set cipher methods for nid %d\n", nid);
        EVP_CIPHER_meth_free(c);
        c = NULL;
    }

    if (!qat_sw_gcm_offload && !qat_hw_gcm_offload) {
        DEBUG("OpenSSL SW AES_GCM registration\n");
        return qat_gcm_cipher_sw_impl(nid);
    }

    return c;
}

void qat_create_ciphers(void)
{
    int i;

    for (i = 0; i < num_cc; i++) {
        if (info[i].cipher == NULL) {
            switch (info[i].nid) {
# if defined(ENABLE_QAT_HW_GCM) || defined(ENABLE_QAT_SW_GCM)
            case NID_aes_128_gcm:
            case NID_aes_192_gcm:
            case NID_aes_256_gcm:
                info[i].cipher = (EVP_CIPHER *)
                    qat_create_gcm_cipher_meth(info[i].nid, info[i].keylen);
                break;
#endif

#ifdef QAT_HW
# ifdef ENABLE_QAT_HW_CHACHAPOLY
            case NID_chacha20_poly1305:
                info[i].cipher = (EVP_CIPHER *)
                    chachapoly_cipher_meth(info[i].nid, info[i].keylen);
                break;
# endif

# ifdef ENABLE_QAT_HW_CIPHERS
            case NID_aes_128_cbc_hmac_sha1:
            case NID_aes_128_cbc_hmac_sha256:
            case NID_aes_256_cbc_hmac_sha1:
            case NID_aes_256_cbc_hmac_sha256:
                info[i].cipher = (EVP_CIPHER *)
                    qat_create_cipher_meth(info[i].nid, info[i].keylen);
                break;
# endif
#endif
            default:
                /* Do nothing */
                break;
            }
        }
    }

}

void qat_free_ciphers(void)
{
    int i;

    for (i = 0; i < num_cc; i++) {
        if (info[i].cipher != NULL) {
            switch (info[i].nid) {
            case NID_aes_128_gcm:
            case NID_aes_192_gcm:
            case NID_aes_256_gcm:
#ifdef ENABLE_QAT_SW_GCM
                if (qat_sw_gcm_offload)
                    EVP_CIPHER_meth_free(info[i].cipher);
#endif
#ifdef ENABLE_QAT_HW_GCM
                if (qat_hw_gcm_offload && info[i].nid != NID_aes_192_gcm)
                    EVP_CIPHER_meth_free(info[i].cipher);
#endif
                break;
            case NID_chacha20_poly1305:
#ifndef DISABLE_QAT_HW_CHACHAPOLY
                EVP_CIPHER_meth_free(info[i].cipher);
#endif
                break;
            case NID_aes_128_cbc_hmac_sha1:
            case NID_aes_128_cbc_hmac_sha256:
            case NID_aes_256_cbc_hmac_sha1:
            case NID_aes_256_cbc_hmac_sha256:
#ifndef DISABLE_QAT_HW_CIPHERS
                EVP_CIPHER_meth_free(info[i].cipher);
#endif
                break;
            }
            info[i].cipher = NULL;
        }
    }
    qat_hw_gcm_offload = 0;
    qat_sw_gcm_offload = 0;
}

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
int qat_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
    int i;

    if (unlikely((nids == NULL) && ((cipher == NULL) || (nid < 0)))) {
        WARN("Invalid input param.\n");
        if (cipher != NULL)
            *cipher = NULL;
        return 0;
    }

    /* No specific cipher => return a list of supported nids ... */
    if (cipher == NULL) {
        *nids = qat_cipher_nids;
        /* num ciphers supported (size of array/size of 1 element) */
        return (sizeof(qat_cipher_nids) / sizeof(qat_cipher_nids[0]));
    }

    for (i = 0; i < num_cc; i++) {
        if (nid == info[i].nid) {
            if (info[i].cipher == NULL)
                qat_create_ciphers();
            *cipher = info[i].cipher;
            return 1;
        }
    }

    WARN("NID %d not supported\n", nid);
    *cipher = NULL;
    return 0;
}

EC_KEY_METHOD *qat_get_EC_methods(void)
{
    if (qat_ec_method != NULL)
        return qat_ec_method;

    EC_KEY_METHOD *def_ec_meth = (EC_KEY_METHOD *)EC_KEY_get_default_method();

    PFUNC_SIGN sign_pfunc = NULL;
    PFUNC_SIGN_SETUP sign_setup_pfunc = NULL;
    PFUNC_SIGN_SIG sign_sig_pfunc = NULL;
    PFUNC_VERIFY verify_pfunc = NULL;
    PFUNC_VERIFY_SIG verify_sig_pfunc = NULL;
    PFUNC_COMP_KEY comp_key_pfunc = NULL;
    PFUNC_GEN_KEY gen_key_pfunc = NULL;

    if ((qat_ec_method = EC_KEY_METHOD_new(qat_ec_method)) == NULL) {
        WARN("Unable to allocate qat EC_KEY_METHOD\n");
        QATerr(QAT_F_QAT_GET_EC_METHODS, QAT_R_QAT_GET_EC_METHOD_MALLOC_FAILURE);
        return NULL;
    }

#ifdef ENABLE_QAT_HW_ECDSA
    if (qat_hw_offload) {
        EC_KEY_METHOD_set_sign(qat_ec_method,
                               qat_ecdsa_sign,
                               NULL,
                               qat_ecdsa_do_sign);
        EC_KEY_METHOD_set_verify(qat_ec_method,
                                 qat_ecdsa_verify,
                                 qat_ecdsa_do_verify);
        qat_hw_ecdsa_offload = 1;
        DEBUG("QAT HW ECDSA Registration succeeded\n");
    }
#endif

#ifdef ENABLE_QAT_SW_ECDSA
    if (!qat_hw_ecdsa_offload &&
       (mbx_get_algo_info(MBX_ALGO_ECDHE_NIST_P256) &&
        mbx_get_algo_info(MBX_ALGO_ECDHE_NIST_P384) &&
        mbx_get_algo_info(MBX_ALGO_ECDSA_NIST_P256) &&
        mbx_get_algo_info(MBX_ALGO_ECDSA_NIST_P384))) {
        EC_KEY_METHOD_set_sign(qat_ec_method,
                               mb_ecdsa_sign,
                               mb_ecdsa_sign_setup,
                               mb_ecdsa_sign_sig);
        /* Verify not supported in crypto_mb, Use SW implementation */
        EC_KEY_METHOD_get_verify(def_ec_meth,
                                 &verify_pfunc,
                                 &verify_sig_pfunc);
        EC_KEY_METHOD_set_verify(qat_ec_method,
                                 verify_pfunc,
                                 verify_sig_pfunc);
        qat_sw_ecdsa_offload = 1;
        DEBUG("QAT SW ECDSA registration succeeded\n");
    }
#endif

    if ((qat_hw_ecdsa_offload == 0) && (qat_sw_ecdsa_offload == 0)) {
        EC_KEY_METHOD_get_sign(def_ec_meth,
                               &sign_pfunc,
                               &sign_setup_pfunc,
                               &sign_sig_pfunc);
        EC_KEY_METHOD_set_sign(qat_ec_method,
                               sign_pfunc,
                               sign_setup_pfunc,
                               sign_sig_pfunc);
        EC_KEY_METHOD_get_verify(def_ec_meth,
                                 &verify_pfunc,
                                 &verify_sig_pfunc);
        EC_KEY_METHOD_set_verify(qat_ec_method,
                                 verify_pfunc,
                                 verify_sig_pfunc);
        DEBUG("QAT_HW and QAT_SW ECDSA not supported! Using OpenSSL SW method\n");
    }

#ifdef ENABLE_QAT_HW_ECDH
    if (qat_hw_offload) {
        EC_KEY_METHOD_set_keygen(qat_ec_method, qat_ecdh_generate_key);
        EC_KEY_METHOD_set_compute_key(qat_ec_method, qat_engine_ecdh_compute_key);
        qat_hw_ecdh_offload = 1;
        DEBUG("QAT HW ECDH Registration succeeded\n");
    }
#endif

#ifdef ENABLE_QAT_SW_ECDH
    if (!qat_hw_ecdh_offload &&
       (mbx_get_algo_info(MBX_ALGO_ECDHE_NIST_P256) &&
        mbx_get_algo_info(MBX_ALGO_ECDHE_NIST_P384) &&
        mbx_get_algo_info(MBX_ALGO_ECDSA_NIST_P256) &&
        mbx_get_algo_info(MBX_ALGO_ECDSA_NIST_P384))) {
        EC_KEY_METHOD_set_keygen(qat_ec_method, mb_ecdh_generate_key);
        EC_KEY_METHOD_set_compute_key(qat_ec_method, mb_ecdh_compute_key);
        qat_sw_ecdh_offload = 1;
        DEBUG("QAT SW ECDH registration succeeded\n");
    }
#endif

    if ((qat_hw_ecdh_offload == 0) && (qat_sw_ecdh_offload == 0)) {
         EC_KEY_METHOD_get_keygen(def_ec_meth, &gen_key_pfunc);
         EC_KEY_METHOD_set_keygen(qat_ec_method, gen_key_pfunc);
         EC_KEY_METHOD_get_compute_key(def_ec_meth, &comp_key_pfunc);
         EC_KEY_METHOD_set_compute_key(qat_ec_method, comp_key_pfunc);
         DEBUG("QAT_HW and QAT_SW ECDH not supported! Using OpenSSL SW method\n");
    }

    return qat_ec_method;
}


void qat_free_EC_methods(void)
{
    if (NULL != qat_ec_method) {
        EC_KEY_METHOD_free(qat_ec_method);
        qat_ec_method = NULL;
        qat_hw_ecdh_offload = 0;
        qat_hw_ecdsa_offload = 0;
        qat_sw_ecdh_offload = 0;
        qat_sw_ecdsa_offload = 0;
    }
}

#ifndef ENABLE_QAT_HW_SMALL_PKT_OFFLOAD
/******************************************************************************
* function:
*         qat_pkt_threshold_table_set_threshold(const char *cn, int threshold)
*
* @param cn        [IN] - Object contains EVP operation id
* @param threshold [IN] - Threshold packet size
*
* description:
*   Sets Threshold Packet Size for Small Packet Offload
******************************************************************************/
int qat_pkt_threshold_table_set_threshold(const char *cn , int threshold)
{
    int i = 0;
    int nid;

    if(threshold < 0)
        threshold = 0;
    else if (threshold > 16384)
        threshold = 16384;

    DEBUG("Set small packet threshold for %s: %d\n", cn, threshold);

    nid = OBJ_sn2nid(cn);

    for (i = 0; i < pkt_threshold_table_size; i++) {
        if (qat_pkt_threshold_table[i].nid == nid) {
            qat_pkt_threshold_table[i].threshold = threshold;
            return 1;
        }
    }

    WARN("nid %d not found in threshold table\n", nid);
    return 0;
}

/******************************************************************************
* function:
*         qat_pkt_threshold_table_get_threshold(int nid)
*
* @param nid  [IN] - EVP operation id
*
* description:
*   Gets Threshold Packet Size for Small Packet Offload
******************************************************************************/
int qat_pkt_threshold_table_get_threshold(int nid)
{
    int i = 0;

    for (i = 0; i < pkt_threshold_table_size; i++) {
        if (qat_pkt_threshold_table[i].nid == nid) {
            return qat_pkt_threshold_table[i].threshold;
        }
    }

    WARN("nid %d not found in threshold table", nid);
    return 0;
}
#endif
