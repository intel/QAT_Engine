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
# include "qat_hw_gcm.h"
# include "qat_hw_sha3.h"
# include "qat_hw_chachapoly.h"
#endif

#ifdef QAT_SW_IPSEC
# include "qat_sw_gcm.h"
#endif

#ifdef QAT_SW
# include "qat_sw_ecx.h"
# include "crypto_mb/cpu_features.h"
#endif

typedef struct _chained_info {
    const int nid;
    EVP_CIPHER *cipher;
    const int keylen;
} chained_info;

static chained_info info[] = {
#ifdef QAT_HW
# ifdef ENABLE_QAT_HW_CIPHERS
    {NID_aes_128_cbc_hmac_sha1, NULL, AES_KEY_SIZE_128},
    {NID_aes_128_cbc_hmac_sha256, NULL, AES_KEY_SIZE_128},
    {NID_aes_256_cbc_hmac_sha1, NULL, AES_KEY_SIZE_256},
    {NID_aes_256_cbc_hmac_sha256, NULL, AES_KEY_SIZE_256},
# endif
# ifdef ENABLE_QAT_HW_GCM
    {NID_aes_128_gcm, NULL, AES_KEY_SIZE_128},
    {NID_aes_256_gcm, NULL, AES_KEY_SIZE_256},
# endif
# ifdef ENABLE_QAT_HW_CHACHAPOLY
    {NID_chacha20_poly1305, NULL, CHACHA_KEY_SIZE},
# endif
#endif
#ifdef ENABLE_QAT_SW_GCM
    {NID_aes_128_gcm, NULL, AES_KEY_SIZE_128},
    {NID_aes_192_gcm, NULL, AES_KEY_SIZE_192},
    {NID_aes_256_gcm, NULL, AES_KEY_SIZE_256},
#endif
};

static const unsigned int num_cc = sizeof(info) / sizeof(chained_info);

/* Qat Symmetric cipher function register */
int qat_cipher_nids[] = {
#ifdef QAT_HW
# ifdef ENABLE_QAT_HW_CIPHERS
    NID_aes_128_cbc_hmac_sha1,
    NID_aes_128_cbc_hmac_sha256,
    NID_aes_256_cbc_hmac_sha1,
    NID_aes_256_cbc_hmac_sha256,
# endif
# ifdef ENABLE_QAT_HW_GCM
    NID_aes_128_gcm,
    NID_aes_256_gcm,
# endif
# if OPENSSL_VERSION_NUMBER > 0x10101000L
#  ifdef ENABLE_QAT_HW_CHACHAPOLY
    NID_chacha20_poly1305,
#  endif
# endif
#endif
#ifdef ENABLE_QAT_SW_GCM
    NID_aes_128_gcm,
    NID_aes_192_gcm,
    NID_aes_256_gcm,
#endif
};

/* Supported EVP nids */
int qat_evp_nids[] = {
# ifdef ENABLE_QAT_HW_PRF
    EVP_PKEY_TLS1_PRF,
#endif
# if OPENSSL_VERSION_NUMBER > 0x10101000L
#  ifdef ENABLE_QAT_HW_HKDF
    EVP_PKEY_HKDF,
#  endif
#  if defined(ENABLE_QAT_HW_ECX) || defined(ENABLE_QAT_SW_ECX)
    EVP_PKEY_X25519,
#  endif
# ifdef QAT_HW
    EVP_PKEY_X448
#  endif
# endif
};
const int num_evp_nids = sizeof(qat_evp_nids) / sizeof(qat_evp_nids[0]);

typedef struct _digest_data {
    const int m_type;
    const int pkey_type;
} sha3_data;

static sha3_data data[] = {
#if OPENSSL_VERSION_NUMBER > 0x10101000L
# ifdef QAT_HW
    { NID_sha3_224,  NID_RSA_SHA3_224},
    { NID_sha3_256,  NID_RSA_SHA3_256},
    { NID_sha3_384,  NID_RSA_SHA3_384},
    { NID_sha3_512,  NID_RSA_SHA3_512},
# endif
#endif
};

/* QAT SHA3 function register */
int qat_sha3_nids[] = {
#if OPENSSL_VERSION_NUMBER > 0x10101000L
# ifdef QAT_HW
    NID_sha3_224,
    NID_sha3_256,
    NID_sha3_384,
    NID_sha3_512,
# endif
#endif
};
const int num_sha3_nids = sizeof(qat_sha3_nids) / sizeof(qat_sha3_nids[0]);

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
# if OPENSSL_VERSION_NUMBER > 0x10101000L
#  ifdef ENABLE_QAT_HW_SHA3
    {NID_sha3_224, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_sha3_256, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_sha3_384, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_sha3_512, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
#  endif
# endif
# ifdef ENABLE_QAT_HW_CHACHAPOLY
    {NID_chacha20_poly1305, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
# endif
};

static int pkt_threshold_table_size =
    (sizeof(qat_pkt_threshold_table) / sizeof(qat_pkt_threshold_table[0]));
#endif

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
#if OPENSSL_VERSION_NUMBER > 0x10101000L
        case NID_sha3_224:
        case NID_sha3_256:
        case NID_sha3_384:
        case NID_sha3_512:
# ifdef QAT_HW
#  ifdef ENABLE_QAT_HW_SHA3
            if (qat_hw_offload)
                return qat_create_sha3_meth(nid , pkeytype);
#  endif
# endif
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
        *nids = qat_sha3_nids;
        return num_sha3_nids;
    }

    for (i = 0; i < num_sha3_nids; i++) {
        if (nid == qat_sha3_nids[i]) {
            *md = qat_create_digest_meth( data[i].m_type , data[i].pkey_type);
            return 1;
        }
    }

    WARN("NID %d not supported\n", nid);
    *md = NULL;
    return 0;
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
# ifdef ENABLE_QAT_HW_PRF
        case EVP_PKEY_TLS1_PRF:
            return qat_prf_pmeth();
# endif
# if OPENSSL_VERSION_NUMBER > 0x10101000L
# ifdef ENABLE_QAT_HW_HKDF
        case EVP_PKEY_HKDF:
            return qat_hkdf_pmeth();
# endif
        case EVP_PKEY_X25519:
# ifdef ENABLE_QAT_HW_ECX
            if(qat_hw_offload)
                return qat_x25519_pmeth();
# elif ENABLE_QAT_SW_ECX
            if (mbx_get_algo_info(MBX_ALGO_X25519))
                return multibuff_x25519_pmeth();
# endif
# ifdef QAT_HW
        case EVP_PKEY_X448:
            if (qat_hw_offload)
                return qat_x448_pmeth();
# endif
# endif
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

void qat_create_ciphers(void)
{
    int i;

    for (i = 0; i < num_cc; i++) {
        if (info[i].cipher == NULL) {
            switch (info[i].nid) {
            case NID_aes_128_gcm:
            case NID_aes_192_gcm:
            case NID_aes_256_gcm:
#ifdef ENABLE_QAT_SW_GCM
                if(qat_sw_ipsec)
                   info[i].cipher = (EVP_CIPHER *)
                       vaesgcm_create_cipher_meth(info[i].nid, info[i].keylen);
#endif
#ifdef ENABLE_QAT_HW_GCM
                if (qat_hw_offload) {
                    if (info[i].nid != NID_aes_192_gcm)
                        info[i].cipher = (EVP_CIPHER *)
                            qat_create_gcm_cipher_meth(info[i].nid, info[i].keylen);
                }
#endif
                break;

#ifdef QAT_HW
# if OPENSSL_VERSION_NUMBER > 0x10101000L
#  ifdef ENABLE_QAT_HW_CHACHAPOLY
            case NID_chacha20_poly1305:
                if (qat_hw_offload)
                    info[i].cipher = (EVP_CIPHER *)
                        chachapoly_cipher_meth(info[i].nid, info[i].keylen);
                break;
#  endif
# endif

# ifdef ENABLE_QAT_HW_CIPHERS
            case NID_aes_128_cbc_hmac_sha1:
            case NID_aes_128_cbc_hmac_sha256:
            case NID_aes_256_cbc_hmac_sha1:
            case NID_aes_256_cbc_hmac_sha256:
                if (qat_hw_offload)
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
                EVP_CIPHER_meth_free(info[i].cipher);
#endif
#ifdef ENABLE_QAT_HW_GCM
                if (info[i].nid != NID_aes_192_gcm)
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
    do {
        if (qat_pkt_threshold_table[i].nid == nid) {
            qat_pkt_threshold_table[i].threshold = threshold;
            return 1;
        }
    } while (++i < pkt_threshold_table_size);

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
    do {
        if (qat_pkt_threshold_table[i].nid == nid) {
            return qat_pkt_threshold_table[i].threshold;
        }
    } while (++i < pkt_threshold_table_size);

    WARN("nid %d not found in threshold table", nid);
    return 0;
}
#endif
