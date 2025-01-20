/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2021-2025 Intel Corporation.
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
 * @file qat_prov_sign_sm2.h
 *
 * This file is for structures and functions declarations for SM2 PROVIDER.
 *
 *****************************************************************************/
#ifndef QAT_PROV_SIGN_SM2_H
# define QAT_PROV_SIGN_SM2_H
# include "qat_prov_ec.h"
# include "qat_prov_hkdf_packet.h"
# ifdef QAT_OPENSSL_3

# define OSSL_MAX_NAME_SIZE           50 /* Algorithm name */
# define OSSL_MAX_PROPQUERY_SIZE     256 /* Property query strings */
# define OSSL_MAX_ALGORITHM_ID_SIZE  256 /* AlgorithmIdentifier DER */

#define DER_OID_V_sm2_with_SM3 QAT_DER_P_OBJECT, 8, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x75
#define DER_OID_SZ_sm2_with_SM3 10


typedef struct {
    OSSL_LIB_CTX *libctx;
    char *propq;
    EC_KEY *ec;

    /*
     * Flag to termine if the 'z' digest needs to be computed and fed to the
     * hash function.
     * This flag should be set on initialization and the compuation should
     * be performed only once, on first update.
     */
    unsigned int flag_compute_z_digest : 1;

    char mdname[OSSL_MAX_NAME_SIZE];

    /* The Algorithm Identifier of the combined signature algorithm */
    unsigned char aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE];
#if OPENSSL_VERSION_NUMBER < 0x30400000
    unsigned char *aid;
#endif
    size_t  aid_len;

    /* main digest */
    EVP_MD *md;
    EVP_MD_CTX *mdctx;
    size_t mdsize;

    /* SM2 ID used for calculating the Z value */
    unsigned char *id;
    size_t id_len;
    const unsigned char *tbs;
    size_t tbs_len;
} QAT_PROV_SM2_CTX;
int qat_sm2sig_compute_z_digest(QAT_PROV_SM2_CTX *ctx);
#ifdef ENABLE_QAT_HW_SM2
int qat_hw_sm2_compute_z_digest(uint8_t *out,
                              const EVP_MD *digest,
                              const uint8_t *id,
                              const size_t id_len,
                              const EC_KEY *key);
#endif
#ifdef ENABLE_QAT_SW_SM2
int qat_sm2_compute_z_digest(uint8_t *out,
                              const EVP_MD *digest,
                              const uint8_t *id,
                              const size_t id_len,
                              const EC_KEY *key);
#endif

# endif
#endif /* QAT_PROV_SIGN_SM2_H */
