/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2021 Intel Corporation.
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
 * @file qat_sw_ec.c
 *
 * This file provides multibuffer support for ECDH & ECDSA
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#define __USE_GNU

#include <pthread.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

/* Local includes */
#include "e_qat.h"
#include "e_qat_err.h"
#include "qat_utils.h"
#include "qat_events.h"
#include "qat_fork.h"
#include "qat_sw_ec.h"
#include "qat_sw_request.h"

/* Crypto_mb includes */
#include "crypto_mb/ec_nistp256.h"
#include "crypto_mb/ec_nistp384.h"

#ifdef ENABLE_QAT_SW_ECDSA
# ifdef DISABLE_QAT_SW_ECDSA
#  undef DISABLE_QAT_SW_ECDSA
# endif
#endif

#ifndef DISABLE_QAT_SW_ECDSA
static int mb_ecdsa_sign(int type, const unsigned char *dgst, int dlen,
                         unsigned char *sig, unsigned int *siglen,
                         const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);
static int mb_ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in,
                               BIGNUM **kinvp, BIGNUM **rp);
static ECDSA_SIG *mb_ecdsa_sign_sig(const unsigned char *dgst, int dlen,
                                    const BIGNUM *in_kinv, const BIGNUM *in_r,
                                    EC_KEY *eckey);

#endif

#ifndef DISABLE_QAT_SW_ECDH
static int mb_ecdh_compute_key(unsigned char **out, size_t *outlen,
                               const EC_POINT *pub_key, const EC_KEY *ecdh);
static int mb_ecdh_generate_key(EC_KEY *ecdh);
#endif

typedef int (*PFUNC_COMP_KEY)(unsigned char **,
                              size_t *,
                              const EC_POINT *,
                              const EC_KEY *);

typedef int (*PFUNC_GEN_KEY)(EC_KEY *);

typedef int (*PFUNC_SIGN)(int,
                          const unsigned char *,
                          int,
                          unsigned char *,
                          unsigned int *,
                          const BIGNUM *,
                          const BIGNUM *,
                          EC_KEY *);

typedef int (*PFUNC_SIGN_SETUP)(EC_KEY *,
                                BN_CTX *,
                                BIGNUM **,
                                BIGNUM **);

typedef ECDSA_SIG *(*PFUNC_SIGN_SIG)(const unsigned char *,
                                     int,
                                     const BIGNUM *,
                                     const BIGNUM *,
                                     EC_KEY *);

typedef int (*PFUNC_VERIFY)(int,
                            const unsigned char *,
                            int,
                            const unsigned char *,
                            int,
                            EC_KEY *);

typedef int (*PFUNC_VERIFY_SIG)(const unsigned char *,
                                int,
                                const ECDSA_SIG *,
                                EC_KEY *eckey);

static EC_KEY_METHOD *mb_ec_method = NULL;

EC_KEY_METHOD *mb_get_EC_methods(void)
{
    if (mb_ec_method != NULL)
        return mb_ec_method;

    EC_KEY_METHOD *def_ec_meth = (EC_KEY_METHOD *)EC_KEY_get_default_method();
#ifdef DISABLE_QAT_SW_ECDSA
    PFUNC_SIGN sign_pfunc = NULL;
    PFUNC_SIGN_SETUP sign_setup_pfunc = NULL;
    PFUNC_SIGN_SIG sign_sig_pfunc = NULL;
#endif
    PFUNC_VERIFY verify_pfunc = NULL;
    PFUNC_VERIFY_SIG verify_sig_pfunc = NULL;
#ifdef DISABLE_QAT_SW_ECDH
    PFUNC_GEN_KEY gen_key_pfunc = NULL;
    PFUNC_COMP_KEY comp_key_pfunc = NULL;
#endif

    if ((mb_ec_method = EC_KEY_METHOD_new(mb_ec_method)) == NULL) {
        WARN("Unable to allocate qat EC_KEY_METHOD\n");
        QATerr(QAT_F_MB_GET_EC_METHODS, QAT_R_MB_GET_EC_METHOD_MALLOC_FAILURE);
        return NULL;
    }

#ifndef DISABLE_QAT_SW_ECDSA
    EC_KEY_METHOD_set_sign(mb_ec_method,
                           mb_ecdsa_sign,
                           mb_ecdsa_sign_setup,
                           mb_ecdsa_sign_sig);
#else
    EC_KEY_METHOD_get_sign(def_ec_meth,
                           &sign_pfunc,
                           &sign_setup_pfunc,
                           &sign_sig_pfunc);
    EC_KEY_METHOD_set_sign(mb_ec_method,
                           sign_pfunc,
                           sign_setup_pfunc,
                           sign_sig_pfunc);
#endif

    /* Verify not supported in crypto_mb, Use SW implemenation */
    EC_KEY_METHOD_get_verify(def_ec_meth,
                             &verify_pfunc,
                             &verify_sig_pfunc);
    EC_KEY_METHOD_set_verify(mb_ec_method,
                             verify_pfunc,
                             verify_sig_pfunc);

#ifndef DISABLE_QAT_SW_ECDH
    EC_KEY_METHOD_set_keygen(mb_ec_method, mb_ecdh_generate_key);
    EC_KEY_METHOD_set_compute_key(mb_ec_method, mb_ecdh_compute_key);
#else
    EC_KEY_METHOD_get_keygen(def_ec_meth, &gen_key_pfunc);
    EC_KEY_METHOD_set_keygen(mb_ec_method, gen_key_pfunc);
    EC_KEY_METHOD_get_compute_key(def_ec_meth, &comp_key_pfunc);
    EC_KEY_METHOD_set_compute_key(mb_ec_method, comp_key_pfunc);
#endif

    return mb_ec_method;
}

void mb_free_EC_methods(void)
{
    if (NULL != mb_ec_method) {
        EC_KEY_METHOD_free(mb_ec_method);
        mb_ec_method = NULL;
    } else {
        WARN("Unable to free qat EC_KEY_METHOD\n");
        QATerr(QAT_F_MB_FREE_EC_METHODS, QAT_R_MB_FREE_EC_METHOD_FAILURE);
    }
}

static inline int mb_ec_check_curve(int curve_type)
{
    int ret = 0;

    switch (curve_type) {
    case NID_X9_62_prime256v1:
        ret = EC_P256_LENGTH;
        break;
    case NID_secp384r1:
        ret = EC_P384_LENGTH;
        break;
    default:
        break;
    }
    return ret;
}

#ifndef DISABLE_QAT_SW_ECDSA
void process_ecdsa_sign_reqs(int bit_len)
{
    ecdsa_sign_op_data *ecdsa_sign_req_array[MULTIBUFF_BATCH] = {0};
    unsigned char *sign_r[MULTIBUFF_BATCH] = {0};
    unsigned char *sign_s[MULTIBUFF_BATCH] = {0};;
    const unsigned char *digest[MULTIBUFF_BATCH] = {0};
    const BIGNUM *eph_key[MULTIBUFF_BATCH] = {0};
    const BIGNUM *priv_key[MULTIBUFF_BATCH] = {0};
    unsigned int sts = 0;
    int local_request_no = 0;
    int req_num = 0;

    START_RDTSC(&ecdsa_cycles_sign_execute);

    /* Build Arrays of pointers for call */
    switch (bit_len) {
    case EC_P256_LENGTH:
        DEBUG("Dequeue ECDSA p256 sign reqs.\n");
        while ((ecdsa_sign_req_array[req_num] =
                mb_queue_ecdsap256_sign_dequeue(&ecdsap256_sign_queue)) != NULL) {
            sign_r[req_num] = ecdsa_sign_req_array[req_num]->sign_r;
            sign_s[req_num] = ecdsa_sign_req_array[req_num]->sign_s;
            digest[req_num] = ecdsa_sign_req_array[req_num]->digest;
            eph_key[req_num] = ecdsa_sign_req_array[req_num]->eph_key;
            priv_key[req_num] = ecdsa_sign_req_array[req_num]->priv_key;

            req_num++;
            if (req_num == MULTIBUFF_MIN_BATCH)
                break;
        }
        break;
    case EC_P384_LENGTH:
        DEBUG("Dequeue ECDSA p384 sign reqs.\n");
        while ((ecdsa_sign_req_array[req_num] =
                mb_queue_ecdsap384_sign_dequeue(&ecdsap384_sign_queue)) != NULL) {
            sign_r[req_num] = ecdsa_sign_req_array[req_num]->sign_r;
            sign_s[req_num] = ecdsa_sign_req_array[req_num]->sign_s;
            digest[req_num] = ecdsa_sign_req_array[req_num]->digest;
            eph_key[req_num] = ecdsa_sign_req_array[req_num]->eph_key;
            priv_key[req_num] = ecdsa_sign_req_array[req_num]->priv_key;

            req_num++;
            if (req_num == MULTIBUFF_MIN_BATCH)
                break;
        }
        break;
    }
    local_request_no = req_num;

    switch (bit_len) {
    case EC_P256_LENGTH:
        DEBUG("Submitting %d ECDSA p256 sign requests\n", local_request_no);
        sts = mbx_nistp256_ecdsa_sign_ssl_mb8(sign_r,
                                              sign_s,
                                              digest,
                                              eph_key,
                                              priv_key,
                                              NULL);
        break;
    case EC_P384_LENGTH:
        DEBUG("Submitting %d ECDSA p384 sign requests\n", local_request_no);
        sts = mbx_nistp384_ecdsa_sign_ssl_mb8(sign_r,
                                              sign_s,
                                              digest,
                                              eph_key,
                                              priv_key,
                                              NULL);
        break;
    }
    for (req_num = 0; req_num < local_request_no; req_num++) {
        if (ecdsa_sign_req_array[req_num]->sts != NULL) {
            if (MBX_GET_STS(sts, req_num) == MBX_STATUS_OK) {
                DEBUG("Multibuffer ECDSA Sign request[%d] success\n", req_num);
                *ecdsa_sign_req_array[req_num]->sts = 1;
            } else {
                WARN("Multibuffer ECDSA Sign request[%d] failure - sts %d\n",
                      req_num, MBX_GET_STS(sts, req_num));
                *ecdsa_sign_req_array[req_num]->sts = 0;
            }
        }

        if (ecdsa_sign_req_array[req_num]->job) {
            qat_wake_job(ecdsa_sign_req_array[req_num]->job,
                         ASYNC_STATUS_OK);
        }
        OPENSSL_cleanse(ecdsa_sign_req_array[req_num],
                        sizeof(ecdsa_sign_op_data));
        mb_flist_ecdsa_sign_push(&ecdsa_sign_freelist,
                                 ecdsa_sign_req_array[req_num]);
    }

# ifdef QAT_SW_HEURISTIC_TIMEOUT
    switch (bit_len) {
    case EC_P256_LENGTH:
        mb_ecdsap256_sign_req_rates.req_this_period += local_request_no;
        break;
    case EC_P384_LENGTH:
        mb_ecdsap384_sign_req_rates.req_this_period += local_request_no;
        break;
    }
# endif

    STOP_RDTSC(&ecdsa_cycles_sign_execute, 1, "[ECDSA:sign_execute]");
    DEBUG("Processed Final Request\n");
}

void process_ecdsa_sign_setup_reqs(int bit_len)
{
    ecdsa_sign_setup_op_data *ecdsa_sign_setup_req_array[MULTIBUFF_BATCH] = {0};
    BIGNUM *k_inv[MULTIBUFF_BATCH] = {0};
    BIGNUM *sig_rp[MULTIBUFF_BATCH] = {0};
    const BIGNUM *eph_key[MULTIBUFF_BATCH] = {0};
    unsigned int sts = 0;
    int local_request_no = 0;
    int req_num = 0;

    START_RDTSC(&ecdsa_cycles_sign_setup_execute);

    /* Build Arrays of pointers for call */
    switch (bit_len) {
    case EC_P256_LENGTH:
        DEBUG("Dequeue ECDSA p256 sign setup reqs.\n");
        while ((ecdsa_sign_setup_req_array[req_num] =
                mb_queue_ecdsap256_sign_setup_dequeue(&ecdsap256_sign_setup_queue)) != NULL) {
            k_inv[req_num] = ecdsa_sign_setup_req_array[req_num]->k_inv;
            sig_rp[req_num] = ecdsa_sign_setup_req_array[req_num]->sig_rp;
            eph_key[req_num] = ecdsa_sign_setup_req_array[req_num]->eph_key;

            req_num++;
            if (req_num == MULTIBUFF_MIN_BATCH)
                break;
        }
        break;
    case EC_P384_LENGTH:
        DEBUG("Dequeue ECDSA p384 sign setup reqs.\n");
        while ((ecdsa_sign_setup_req_array[req_num] =
                mb_queue_ecdsap384_sign_setup_dequeue(&ecdsap384_sign_setup_queue)) != NULL) {
            k_inv[req_num] = ecdsa_sign_setup_req_array[req_num]->k_inv;
            sig_rp[req_num] = ecdsa_sign_setup_req_array[req_num]->sig_rp;
            eph_key[req_num] = ecdsa_sign_setup_req_array[req_num]->eph_key;

            req_num++;
            if (req_num == MULTIBUFF_MIN_BATCH)
                break;
        }
        break;
    }
    local_request_no = req_num;

    switch (bit_len) {
    case EC_P256_LENGTH:
        DEBUG("Submitting %d ECDSA p256 sign setup requests\n", local_request_no);
        sts = mbx_nistp256_ecdsa_sign_setup_ssl_mb8(k_inv,
                                                    sig_rp,
                                                    eph_key,
                                                    NULL);
        break;
    case EC_P384_LENGTH:
        DEBUG("Submitting %d ECDSA p384 sign setup requests\n", local_request_no);
        sts = mbx_nistp384_ecdsa_sign_setup_ssl_mb8(k_inv,
                                                    sig_rp,
                                                    eph_key,
                                                    NULL);
        break;
    }
    for (req_num = 0; req_num < local_request_no; req_num++) {
        if (ecdsa_sign_setup_req_array[req_num]->sts != NULL) {
            if (MBX_GET_STS(sts, req_num) == MBX_STATUS_OK) {
                DEBUG("Multibuffer ECDSA Sign setup request[%d] success\n", req_num);
                *ecdsa_sign_setup_req_array[req_num]->sts = 1;
            } else {
                WARN("Multibuffer ECDSA Sign setup request[%d] failure - sts %d\n",
                      req_num, MBX_GET_STS(sts, req_num));
                *ecdsa_sign_setup_req_array[req_num]->sts = 0;
            }
        }

        if (ecdsa_sign_setup_req_array[req_num]->job) {
            qat_wake_job(ecdsa_sign_setup_req_array[req_num]->job,
                         ASYNC_STATUS_OK);
        }
        OPENSSL_cleanse(ecdsa_sign_setup_req_array[req_num],
                        sizeof(ecdsa_sign_setup_op_data));
        mb_flist_ecdsa_sign_setup_push(&ecdsa_sign_setup_freelist,
                                       ecdsa_sign_setup_req_array[req_num]);
    }

# ifdef QAT_SW_HEURISTIC_TIMEOUT
    switch (bit_len) {
    case EC_P256_LENGTH:
        mb_ecdsap256_sign_setup_req_rates.req_this_period += local_request_no;
        break;
    case EC_P384_LENGTH:
        mb_ecdsap384_sign_setup_req_rates.req_this_period += local_request_no;
        break;
    }
# endif

    STOP_RDTSC(&ecdsa_cycles_sign_setup_execute, 1, "[ECDSA:sign_setup_execute]");
    DEBUG("Processed Final Request\n");
}

void process_ecdsa_sign_sig_reqs(int bit_len)
{
    ecdsa_sign_sig_op_data *ecdsa_sign_sig_req_array[MULTIBUFF_BATCH] = {0};
    unsigned char *sign_r[MULTIBUFF_BATCH] = {0};
    unsigned char *sign_s[MULTIBUFF_BATCH] = {0};;
    const unsigned char *digest[MULTIBUFF_BATCH] = {0};
    const BIGNUM *k_inv[MULTIBUFF_BATCH] = {0};
    const BIGNUM *sig_rp[MULTIBUFF_BATCH] = {0};
    const BIGNUM *priv_key[MULTIBUFF_BATCH] = {0};
    unsigned int sts = 0;
    int local_request_no = 0;
    int req_num = 0;

    START_RDTSC(&ecdsa_cycles_sign_sig_execute);

    /* Build Arrays of pointers for call */
    switch (bit_len) {
    case EC_P256_LENGTH:
        DEBUG("Dequeue ECDSA p256 sign sig reqs.\n");
        while ((ecdsa_sign_sig_req_array[req_num] =
                mb_queue_ecdsap256_sign_sig_dequeue(&ecdsap256_sign_sig_queue)) != NULL) {
            sign_r[req_num] = ecdsa_sign_sig_req_array[req_num]->sign_r;
            sign_s[req_num] = ecdsa_sign_sig_req_array[req_num]->sign_s;
            digest[req_num] = ecdsa_sign_sig_req_array[req_num]->digest;
            sig_rp[req_num] = ecdsa_sign_sig_req_array[req_num]->sig_rp;
            k_inv[req_num] = ecdsa_sign_sig_req_array[req_num]->k_inv;
            priv_key[req_num] = ecdsa_sign_sig_req_array[req_num]->priv_key;

            req_num++;
            if (req_num == MULTIBUFF_MIN_BATCH)
                break;
        }
        break;
    case EC_P384_LENGTH:
        DEBUG("Dequeue ECDSA p384 sign sig reqs.\n");
        while ((ecdsa_sign_sig_req_array[req_num] =
                mb_queue_ecdsap384_sign_sig_dequeue(&ecdsap384_sign_sig_queue)) != NULL) {
            sign_r[req_num] = ecdsa_sign_sig_req_array[req_num]->sign_r;
            sign_s[req_num] = ecdsa_sign_sig_req_array[req_num]->sign_s;
            digest[req_num] = ecdsa_sign_sig_req_array[req_num]->digest;
            sig_rp[req_num] = ecdsa_sign_sig_req_array[req_num]->sig_rp;
            k_inv[req_num] = ecdsa_sign_sig_req_array[req_num]->k_inv;
            priv_key[req_num] = ecdsa_sign_sig_req_array[req_num]->priv_key;

            req_num++;
            if (req_num == MULTIBUFF_MIN_BATCH)
                break;
        }
        break;
    }
    local_request_no = req_num;

    switch (bit_len) {
    case EC_P256_LENGTH:
        DEBUG("Submitting %d ECDSA p256 sign sig requests\n", local_request_no);
        sts = mbx_nistp256_ecdsa_sign_complete_ssl_mb8(sign_r,
                                                       sign_s,
                                                       digest,
                                                       sig_rp,
                                                       k_inv,
                                                       priv_key,
                                                       NULL);
        break;
    case EC_P384_LENGTH:
        DEBUG("Submitting %d ECDSA p384 sign sig requests\n", local_request_no);
        sts = mbx_nistp384_ecdsa_sign_complete_ssl_mb8(sign_r,
                                                       sign_s,
                                                       digest,
                                                       sig_rp,
                                                       k_inv,
                                                       priv_key,
                                                       NULL);
        break;
    }
    for (req_num = 0; req_num < local_request_no; req_num++) {
        if (ecdsa_sign_sig_req_array[req_num]->sts != NULL) {
            if (MBX_GET_STS(sts, req_num) == MBX_STATUS_OK) {
                DEBUG("Multibuffer ECDSA Sign sig request[%d] success\n", req_num);
                *ecdsa_sign_sig_req_array[req_num]->sts = 1;
            } else {
                WARN("Multibuffer ECDSA Sign sig request[%d] failure - sts %d\n",
                      req_num, MBX_GET_STS(sts, req_num));
                *ecdsa_sign_sig_req_array[req_num]->sts = 0;
            }
        }

        if (ecdsa_sign_sig_req_array[req_num]->job) {
            qat_wake_job(ecdsa_sign_sig_req_array[req_num]->job,
                         ASYNC_STATUS_OK);
        }
        OPENSSL_cleanse(ecdsa_sign_sig_req_array[req_num],
                        sizeof(ecdsa_sign_sig_op_data));
        mb_flist_ecdsa_sign_sig_push(&ecdsa_sign_sig_freelist,
                                     ecdsa_sign_sig_req_array[req_num]);
    }

# ifdef QAT_SW_HEURISTIC_TIMEOUT
    mb_ecdsap256_sign_sig_req_rates.req_this_period += local_request_no;
# endif

    STOP_RDTSC(&ecdsa_cycles_sign_sig_execute, 1, "[ECDSA:sign_sig_execute]");
    DEBUG("Processed Final Request\n");
}
#endif

#ifndef DISABLE_QAT_SW_ECDH
void process_ecdh_keygen_reqs(int bit_len)
{
    ecdh_keygen_op_data *ecdh_keygen_req_array[MULTIBUFF_BATCH] = {0};
    BIGNUM *ecdh_keygen_x[MULTIBUFF_BATCH] = {0};
    BIGNUM *ecdh_keygen_y[MULTIBUFF_BATCH] = {0};
    BIGNUM *ecdh_keygen_z[MULTIBUFF_BATCH] = {0};
    const BIGNUM* ecdh_keygen_privkey[MULTIBUFF_BATCH] = {0};
    unsigned int ecdh_sts = 0;
    int local_request_no = 0;
    int req_num = 0;

    START_RDTSC(&ecdh_cycles_keygen_execute);

    /* Build Arrays of pointers for call */

    switch (bit_len) {
    case EC_P256_LENGTH:
        DEBUG("Dequeue ECDHP256 keygen reqs.\n");
        while ((ecdh_keygen_req_array[req_num] =
                mb_queue_ecdhp256_keygen_dequeue(&ecdhp256_keygen_queue)) != NULL) {
        ecdh_keygen_x[req_num] = ecdh_keygen_req_array[req_num]->x;
        ecdh_keygen_y[req_num] = ecdh_keygen_req_array[req_num]->y;
        ecdh_keygen_z[req_num] = ecdh_keygen_req_array[req_num]->z;
        ecdh_keygen_privkey[req_num] = ecdh_keygen_req_array[req_num]->priv_key;

        req_num++;
        if (req_num == MULTIBUFF_MIN_BATCH)
            break;
        }
        break;
    case EC_P384_LENGTH:
        DEBUG("Dequeue ECDHP384 keygen reqs.\n");
        while ((ecdh_keygen_req_array[req_num] =
                mb_queue_ecdhp384_keygen_dequeue(&ecdhp384_keygen_queue)) != NULL) {
        ecdh_keygen_x[req_num] = ecdh_keygen_req_array[req_num]->x;
        ecdh_keygen_y[req_num] = ecdh_keygen_req_array[req_num]->y;
        ecdh_keygen_z[req_num] = ecdh_keygen_req_array[req_num]->z;
        ecdh_keygen_privkey[req_num] = ecdh_keygen_req_array[req_num]->priv_key;

	    req_num++;
        if (req_num == MULTIBUFF_MIN_BATCH)
            break;
        }
        break;
    }

    local_request_no = req_num;


    switch (bit_len) {
    case EC_P256_LENGTH:
       DEBUG("Submitting %d ECDH p256 Keygen requests\n", local_request_no);
        ecdh_sts = mbx_nistp256_ecpublic_key_ssl_mb8(ecdh_keygen_x,
                                                     ecdh_keygen_y,
                                                     ecdh_keygen_z,
                                                     ecdh_keygen_privkey,
                                                     NULL);
        break;
    case EC_P384_LENGTH:
        DEBUG("Submitting %d ECDH p384 Keygen requests\n", local_request_no);
        ecdh_sts = mbx_nistp384_ecpublic_key_ssl_mb8(ecdh_keygen_x,
                                                     ecdh_keygen_y,
                                                     ecdh_keygen_z,
                                                     ecdh_keygen_privkey,
                                                     NULL);
         break;
    }

    for (req_num = 0; req_num < local_request_no; req_num++) {
         if (ecdh_keygen_req_array[req_num]->sts != NULL) {
             if (MBX_GET_STS(ecdh_sts, req_num) == MBX_STATUS_OK) {
                 DEBUG("Multibuffer keygen request[%d] success\n", req_num);
                 *ecdh_keygen_req_array[req_num]->sts = 1;
            } else {
                WARN("Multibuffer keygen request[%d] failure, sts %d \n",
                     req_num, MBX_GET_STS(ecdh_sts, req_num));
                *ecdh_keygen_req_array[req_num]->sts = 0;
            }
        }

        if (ecdh_keygen_req_array[req_num]->job) {
            qat_wake_job(ecdh_keygen_req_array[req_num]->job,
                         ASYNC_STATUS_OK);
        }
        OPENSSL_cleanse(ecdh_keygen_req_array[req_num],
                        sizeof(ecdh_keygen_op_data));
        mb_flist_ecdh_keygen_push(&ecdh_keygen_freelist,
                                  ecdh_keygen_req_array[req_num]);
    }

# ifdef QAT_SW_HEURISTIC_TIMEOUT
    switch (bit_len) {
    case EC_P256_LENGTH:
        mb_ecdhp256_keygen_req_rates.req_this_period += local_request_no;
        break;
    case EC_P384_LENGTH:
        mb_ecdhp384_keygen_req_rates.req_this_period += local_request_no;
        break;
    }
# endif

    STOP_RDTSC(&ecdh_cycles_keygen_execute, 1, "[ECDH:keygen_execute]");
    DEBUG("Processed Final Request\n");
}

void process_ecdh_compute_reqs(int bit_len)
{
    ecdh_compute_op_data *ecdh_compute_req_array[MULTIBUFF_BATCH] = {0};
    unsigned char *ecdh_compute_shared_key[MULTIBUFF_BATCH] = {0};
    const BIGNUM *ecdh_compute_privkey[MULTIBUFF_BATCH] = {0};
    const BIGNUM *ecdh_compute_x[MULTIBUFF_BATCH] = {0};
    const BIGNUM *ecdh_compute_y[MULTIBUFF_BATCH] = {0};
    const BIGNUM *ecdh_compute_z[MULTIBUFF_BATCH] = {0};
    unsigned int ecdh_sts = 0;
    int local_request_no = 0;
    int req_num = 0;

    START_RDTSC(&ecdh_cycles_compute_execute);

    /* Build Arrays of pointers for call */

    switch (bit_len) {
    case EC_P256_LENGTH:
	    DEBUG("Dequeue ECDHP256 compute reqs.\n");
        while ((ecdh_compute_req_array[req_num] =
                mb_queue_ecdhp256_compute_dequeue(&ecdhp256_compute_queue)) != NULL) {
        ecdh_compute_shared_key[req_num] = ecdh_compute_req_array[req_num]->shared_key;
        ecdh_compute_privkey[req_num] = ecdh_compute_req_array[req_num]->priv_key;
        ecdh_compute_x[req_num] = ecdh_compute_req_array[req_num]->x;
        ecdh_compute_y[req_num] = ecdh_compute_req_array[req_num]->y;
        ecdh_compute_z[req_num] = ecdh_compute_req_array[req_num]->z;

        req_num++;
        if (req_num == MULTIBUFF_MIN_BATCH)
            break;
        }
        break;
	case EC_P384_LENGTH:
        DEBUG("Dequeue ECDHP384 compute reqs.\n");
        while ((ecdh_compute_req_array[req_num] =
                mb_queue_ecdhp384_compute_dequeue(&ecdhp384_compute_queue)) != NULL) {
        ecdh_compute_shared_key[req_num] = ecdh_compute_req_array[req_num]->shared_key;
        ecdh_compute_privkey[req_num] = ecdh_compute_req_array[req_num]->priv_key;
        ecdh_compute_x[req_num] = ecdh_compute_req_array[req_num]->x;
        ecdh_compute_y[req_num] = ecdh_compute_req_array[req_num]->y;
        ecdh_compute_z[req_num] = ecdh_compute_req_array[req_num]->z;

        req_num++;
        if (req_num == MULTIBUFF_MIN_BATCH)
            break;
        }
        break;
    }

    local_request_no = req_num;

    switch (bit_len) {
	case EC_P256_LENGTH:
        DEBUG("Submitting %d ECDH p256 Compute requests\n", local_request_no);
        ecdh_sts = mbx_nistp256_ecdh_ssl_mb8(ecdh_compute_shared_key,
                                             ecdh_compute_privkey,
                                             ecdh_compute_x,
                                             ecdh_compute_y,
                                             ecdh_compute_z, /* Use Jacobian coordinates */
                                             NULL);
        break;
	case EC_P384_LENGTH:
        DEBUG("Submitting %d ECDH p384 Compute requests\n", local_request_no);
        ecdh_sts = mbx_nistp384_ecdh_ssl_mb8(ecdh_compute_shared_key,
                                             ecdh_compute_privkey,
                                             ecdh_compute_x,
                                             ecdh_compute_y,
                                             ecdh_compute_z, /* Use Jacobian coordinates */
                                             NULL);
	    break;
    }
    for (req_num = 0; req_num < local_request_no; req_num++) {
        if (ecdh_compute_req_array[req_num]->sts != NULL) {
            if (MBX_GET_STS(ecdh_sts, req_num) == MBX_STATUS_OK) {
                DEBUG("Multibuffer compute request[%d] success\n", req_num);
                *ecdh_compute_req_array[req_num]->sts = 1;
            } else {
                WARN("Multibuffer compute request[%d] failure, sts %d \n",
                      req_num, MBX_GET_STS(ecdh_sts, req_num));
                *ecdh_compute_req_array[req_num]->sts = 0;
            }
        }

        if (ecdh_compute_req_array[req_num]->job) {
            qat_wake_job(ecdh_compute_req_array[req_num]->job, ASYNC_STATUS_OK);
        }
        OPENSSL_cleanse(ecdh_compute_req_array[req_num],
                        sizeof(ecdh_compute_op_data));
        mb_flist_ecdh_compute_push(&ecdh_compute_freelist,
                                   ecdh_compute_req_array[req_num]);
    }

# ifdef QAT_SW_HEURISTIC_TIMEOUT
    switch (bit_len) {
    case EC_P256_LENGTH:
        mb_ecdhp256_compute_req_rates.req_this_period += local_request_no;
        break;
    case EC_P384_LENGTH:
        mb_ecdhp384_compute_req_rates.req_this_period += local_request_no;
        break;
    }

# endif

    STOP_RDTSC(&ecdh_cycles_compute_execute, 1, "[ECDH:compute_execute]");
    DEBUG("Processed Final Request\n");
}
#endif

#ifndef DISABLE_QAT_SW_ECDSA
int mb_ecdsa_sign(int type, const unsigned char *dgst, int dlen,
                  unsigned char *sig, unsigned int *siglen,
                  const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey)
{
    int ret = 0, len = 0, job_ret = 0, sts = 0, alloc_buf = 0, bit_len = 0;
    BN_CTX *ctx = NULL;
    ECDSA_SIG *s;
    ASYNC_JOB *job;
    size_t buflen;
    static __thread int req_num = 0;
    const EC_GROUP *group;
    BIGNUM *k = NULL;
    const BIGNUM *priv_key, *order;
    const EC_POINT *pub_key = NULL;
    BIGNUM *ecdsa_sig_r = NULL, *ecdsa_sig_s = NULL;
    unsigned char *dgst_buf = NULL;
    PFUNC_SIGN sign_pfunc = NULL;
    ecdsa_sign_op_data *ecdsa_sign_req = NULL;

    DEBUG("Entering \n");
    if (unlikely(dgst == NULL || dlen <= 0 ||
                 eckey == NULL)) {
        *siglen = 0;
        WARN("Invalid Input param\n");
        QATerr(QAT_F_MB_ECDSA_SIGN, QAT_R_INPUT_PARAM_INVALID);
        return ret;
    }

    group = EC_KEY_get0_group(eckey);
    priv_key = EC_KEY_get0_private_key(eckey);
    pub_key = EC_KEY_get0_public_key(eckey);

    if (group == NULL || priv_key == NULL || pub_key == NULL) {
        WARN("Either group, priv_key or pub_key are NULL\n");
        QATerr(QAT_F_MB_ECDSA_SIGN, QAT_R_GROUP_PRIV_KEY_PUB_KEY_NULL);
        return ret;
    }

    /* Check if curve is p256 or p384 */
    if ((bit_len = mb_ec_check_curve(EC_GROUP_get_curve_name(group))) == 0) {
        DEBUG("Curve type not supported, using SW Method %d\n",
               EC_GROUP_get_curve_name(group));
        goto use_sw_method;
    }

    /* Check if we are running asynchronously */
    if ((job = ASYNC_get_current_job()) == NULL) {
        DEBUG("Running synchronously using sw method\n");
        goto use_sw_method;
    }

    /* Setup asynchronous notifications */
    if (!qat_setup_async_event_notification(0)) {
        DEBUG("Failed to setup async notifications, using sw method\n");
        goto use_sw_method;
    }

    if (!EC_KEY_can_sign(eckey)) {
        WARN("Curve doesn't support Signing\n");
        QATerr(QAT_F_MB_ECDSA_SIGN, QAT_R_CURVE_DOES_NOT_SUPPORT_SIGNING);
        return ret;
    }

    while ((ecdsa_sign_req =
            mb_flist_ecdsa_sign_pop(&ecdsa_sign_freelist)) == NULL) {
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
    }

    DEBUG("Started request: %p\n", ecdsa_sign_req);
    START_RDTSC(&ecdsa_cycles_sign_setup);

    /* Buffer up the requests and call the new functions when we have enough
     * requests buffered up */

    if ((s = ECDSA_SIG_new()) == NULL) {
        mb_flist_ecdsa_sign_push(&ecdsa_sign_freelist, ecdsa_sign_req);
        WARN("Failure to allocate ECDSA_SIG\n");
        QATerr(QAT_F_MB_ECDSA_SIGN, QAT_R_ECDSA_SIG_MALLOC_FAILURE);
        return ret;
    }

    ecdsa_sig_r = BN_new();
    ecdsa_sig_s = BN_new();

    /* NULL checking of ecdsa_sig_r & ecdsa_sig_s done in ECDSA_SIG_set0() */
    if (ECDSA_SIG_set0(s, ecdsa_sig_r, ecdsa_sig_s) == 0) {
        mb_flist_ecdsa_sign_push(&ecdsa_sign_freelist, ecdsa_sign_req);
        WARN("Failure to allocate r and s values to assign to the ECDSA_SIG\n");
        QATerr(QAT_F_MB_ECDSA_SIGN, QAT_R_ECDSA_SIG_SET_R_S_FAILURE);
        goto err;
    }

    if ((ctx = BN_CTX_new()) == NULL) {
        mb_flist_ecdsa_sign_push(&ecdsa_sign_freelist, ecdsa_sign_req);
        WARN("Failure to allocate ctx\n");
        QATerr(QAT_F_MB_ECDSA_SIGN, QAT_R_CTX_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);

    if ((order = EC_GROUP_get0_order(group)) ==  NULL) {
        mb_flist_ecdsa_sign_push(&ecdsa_sign_freelist, ecdsa_sign_req);
        WARN("Failure to get order from group\n");
        QATerr(QAT_F_MB_ECDSA_SIGN, QAT_R_GET_ORDER_FAILURE);
        goto err;
    }

    len = BN_num_bits(order);
    buflen = (len + 7) / 8;

    /* If digest size is less, expand length with zero as crypto_mb
     * expects digest being sign length */
    if (8 * dlen < len) {
        dgst_buf = OPENSSL_zalloc(buflen);
        if (dgst_buf == NULL) {
            mb_flist_ecdsa_sign_push(&ecdsa_sign_freelist, ecdsa_sign_req);
            WARN("Failure to allocate dgst_buf\n");
            QATerr(QAT_F_MB_ECDSA_SIGN, QAT_R_ECDSA_MALLOC_FAILURE);
            goto err;
        }
        alloc_buf = 1;
        memcpy(dgst_buf + buflen - dlen, dgst, dlen);
    } else {
        dgst_buf = (unsigned char *)dgst;
    }

    if (kinv == NULL || r == NULL) {
        /* Get random k */
        do {
            if (!BN_priv_rand_range(k, order)) {
                mb_flist_ecdsa_sign_push(&ecdsa_sign_freelist, ecdsa_sign_req);
                WARN("Failure in BN_priv_rand_range\n");
                QATerr(QAT_F_MB_ECDSA_SIGN, QAT_R_RAND_GENERATE_FAILURE);
                goto err;
            }
        } while (BN_is_zero(k));
    } else {
        BN_mod_inverse(k, kinv, order, ctx);
        DEBUG("Not Generating Random K\n");
    }

    ecdsa_sign_req->sign_r = sig;
    ecdsa_sign_req->sign_s = sig + buflen;
    ecdsa_sign_req->digest = dgst_buf;
    ecdsa_sign_req->eph_key = k;
    ecdsa_sign_req->priv_key = priv_key;
    ecdsa_sign_req->job = job;
    ecdsa_sign_req->sts = &sts;

    switch (bit_len) {
    case EC_P256_LENGTH:
        mb_queue_ecdsap256_sign_enqueue(&ecdsap256_sign_queue, ecdsa_sign_req);
        break;
    case EC_P384_LENGTH:
        mb_queue_ecdsap384_sign_enqueue(&ecdsap384_sign_queue, ecdsa_sign_req);
        break;
    }
    STOP_RDTSC(&ecdsa_cycles_sign_setup, 1, "[ECDSA:sign_setup]");

    if (!enable_external_polling && (++req_num % MULTIBUFF_MAX_BATCH) == 0) {
        DEBUG("Signal Polling thread, req_num %d\n", req_num);
        if (qat_kill_thread(multibuff_timer_poll_func_thread, SIGUSR1) != 0) {
            WARN("qat_kill_thread error\n");
            /* If we fail the pthread_kill carry on as the timeout
             * will catch processing the request in the polling thread */
        }
    }

    DEBUG("Pausing: %p status = %d\n", ecdsa_sign_req, sts);
    do {
        /* If we get a failure on qat_pause_job then we will
         * not flag an error here and quit because we have
         * an asynchronous request in flight.
         * We don't want to start cleaning up data
         * structures that are still being used. If
         * qat_pause_job fails we will just yield and
         * loop around and try again until the request
         * completes and we can continue. */
        if ((job_ret = qat_pause_job(job, ASYNC_STATUS_OK)) == 0)
            pthread_yield();
    } while (QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DEBUG("Finished: %p status = %d\n", ecdsa_sign_req, sts);

    if (sts) {
        /* Convert the buffers to BN */
        BN_bin2bn(sig, buflen, ecdsa_sig_r);
        BN_bin2bn(sig + buflen, buflen, ecdsa_sig_s);

        *siglen = i2d_ECDSA_SIG(s, &sig);
        DEBUG("siglen %d, dlen %d\n", *siglen, dlen);
        ECDSA_SIG_free(s);
        ret = 1;
    } else {
        WARN("Failure in ECDSA Sign\n");
        QATerr(QAT_F_MB_ECDSA_SIGN, QAT_R_ECDSA_SIGN_FAILURE);
        goto err;
    }

err:
    if (!ret) {
        ECDSA_SIG_free(s);
        if (siglen != NULL)
            *siglen = 0;
    }

    if (alloc_buf)
        OPENSSL_free(dgst_buf);

    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;

use_sw_method:
    EC_KEY_METHOD_get_sign((EC_KEY_METHOD *) EC_KEY_OpenSSL(),
                            &sign_pfunc, NULL, NULL);
    if (sign_pfunc == NULL) {
        WARN("sign_pfunc is NULL\n");
        QATerr(QAT_F_MB_ECDSA_SIGN, QAT_R_SW_GET_SIGN_PFUNC_NULL);
        return ret;
    }

    return (*sign_pfunc)(type, dgst, dlen, sig, siglen, kinv, r, eckey);
}

int mb_ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in,
                        BIGNUM **kinvp, BIGNUM **rp)
{
    int ret = 0, job_ret = 0, sts = 0, bit_len = 0;
    const EC_GROUP *group;
    const BIGNUM *priv_key;
    ASYNC_JOB *job;
    static __thread int req_num = 0;
    BIGNUM *k = NULL, *r = NULL;
    PFUNC_SIGN_SETUP sign_setup_pfunc = NULL;
    ecdsa_sign_setup_op_data *ecdsa_sign_setup_req = NULL;

    DEBUG("Entering\n" );
    if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL
        || (priv_key = EC_KEY_get0_private_key(eckey)) == NULL) {
        WARN("eckey, group or priv_key is  NULL\n");
        QATerr(QAT_F_MB_ECDSA_SIGN_SETUP, QAT_R_EC_KEY_GROUP_PRIV_KEY_NULL);
        return 0;
    }

    /* Check if curve is p256 or p384 */
    if ((bit_len = mb_ec_check_curve(EC_GROUP_get_curve_name(group))) == 0) {
        DEBUG("Curve type not supported, using SW Method %d\n",
               EC_GROUP_get_curve_name(group));
        goto use_sw_method;
    }

    /* Check if we are running asynchronously */
    if ((job = ASYNC_get_current_job()) == NULL) {
        DEBUG("Running synchronously using sw method\n");
        goto use_sw_method;
    }

    /* Setup asynchronous notifications */
    if (!qat_setup_async_event_notification(0)) {
        DEBUG("Failed to setup async notifications, using sw method\n");
        goto use_sw_method;
    }

    if (!EC_KEY_can_sign(eckey)) {
        WARN("Curve doesn't support Signing\n");
        QATerr(QAT_F_MB_ECDSA_SIGN_SETUP, QAT_R_CURVE_DOES_NOT_SUPPORT_SIGNING);
        return ret;
    }

    while ((ecdsa_sign_setup_req =
            mb_flist_ecdsa_sign_setup_pop(&ecdsa_sign_setup_freelist)) == NULL) {
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
    }

    DEBUG("Started request: %p\n", ecdsa_sign_setup_req);
    START_RDTSC(&ecdsa_cycles_sign_setup_setup);

    /* Buffer up the requests and call the new functions when we have enough
     * requests buffered up */

    k = BN_new();
    r = BN_new();
    if (k == NULL || r == NULL) {
        mb_flist_ecdsa_sign_setup_push(&ecdsa_sign_setup_freelist, ecdsa_sign_setup_req);
        WARN("Failure to allocate k or r\n");
        QATerr(QAT_F_MB_ECDSA_SIGN_SETUP, QAT_R_ECDSA_MALLOC_FAILURE);
        goto err;
    }

    ecdsa_sign_setup_req->k_inv = k;
    ecdsa_sign_setup_req->sig_rp = r;
    ecdsa_sign_setup_req->eph_key = priv_key;
    ecdsa_sign_setup_req->job = job;
    ecdsa_sign_setup_req->sts = &sts;

    switch (bit_len) {
    case EC_P256_LENGTH:
        mb_queue_ecdsap256_sign_setup_enqueue(&ecdsap256_sign_setup_queue, ecdsa_sign_setup_req);
        break;
    case EC_P384_LENGTH:
        mb_queue_ecdsap384_sign_setup_enqueue(&ecdsap384_sign_setup_queue, ecdsa_sign_setup_req);
        break;
    }
    STOP_RDTSC(&ecdsa_cycles_sign_setup_setup, 1, "[ECDSA:sign_setup_setup]");

    if (!enable_external_polling && (++req_num % MULTIBUFF_MAX_BATCH) == 0) {
        DEBUG("Signal Polling thread, req_num %d\n", req_num);
        if (qat_kill_thread(multibuff_timer_poll_func_thread, SIGUSR1) != 0) {
            WARN("qat_kill_thread error\n");
            /* If we fail the pthread_kill carry on as the timeout
             * will catch processing the request in the polling thread */
        }
    }

    DEBUG("Pausing: %p status = %d\n", ecdsa_sign_setup_req, sts);
    do {
        /* If we get a failure on qat_pause_job then we will
         * not flag an error here and quit because we have
         * an asynchronous request in flight.
         * We don't want to start cleaning up data
         * structures that are still being used. If
         * qat_pause_job fails we will just yield and
         * loop around and try again until the request
         * completes and we can continue. */
        if ((job_ret = qat_pause_job(job, ASYNC_STATUS_OK)) == 0)
            pthread_yield();
    } while (QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DEBUG("Finished: %p status = %d\n", ecdsa_sign_setup_req, sts);

    /* Clear old values */
    BN_clear_free(*rp);
    BN_clear_free(*kinvp);

    if (sts) {
        /* Save the pre-computed values  */
        *rp = r;
        *kinvp = k;
        ret = 1;
    } else {
        WARN("Failure in ECDSA Sign\n");
        QATerr(QAT_F_MB_ECDSA_SIGN_SETUP, QAT_R_ECDSA_SIGN_FAILURE);
        goto err;
    }
    return ret;

err:
    if (!ret) {
        BN_clear_free(k);
        BN_clear_free(r);
    }
    return ret;

use_sw_method:
    EC_KEY_METHOD_get_sign((EC_KEY_METHOD *) EC_KEY_OpenSSL(),
                            NULL, &sign_setup_pfunc, NULL);
    if (sign_setup_pfunc == NULL) {
        WARN("sign_setup_pfunc is NULL\n");
        QATerr(QAT_F_MB_ECDSA_SIGN_SETUP, QAT_R_SW_GET_SIGN_SETUP_PFUNC_NULL);
        return ret;
    }

    return (*sign_setup_pfunc)(eckey, ctx_in, kinvp, rp);
}

ECDSA_SIG *mb_ecdsa_sign_sig(const unsigned char *dgst, int dlen,
                             const BIGNUM *in_kinv, const BIGNUM *in_r,
                             EC_KEY *eckey)
{
    int ok = 0, len = 0, job_ret = 0, sts = 0, alloc_buf = 0,  bit_len = 0;
    BN_CTX *ctx = NULL;
    ECDSA_SIG *ret;
    ASYNC_JOB *job;
    size_t buflen;
    static __thread int req_num = 0;
    const EC_GROUP *group;
    const BIGNUM *priv_key, *order;
    const EC_POINT *pub_key = NULL;
    unsigned char *sig_buf = NULL, *dgst_buf = NULL;
    BIGNUM *ecdsa_sig_r = NULL, *ecdsa_sig_s = NULL;
    BIGNUM *kinv = NULL, *rp = NULL;
    PFUNC_SIGN_SIG sign_sig_pfunc = NULL;
    ecdsa_sign_sig_op_data *ecdsa_sign_sig_req = NULL;

    DEBUG("Entering\n" );
    if (unlikely(dgst == NULL || dlen <= 0 ||
                 eckey == NULL)) {
        WARN("Invalid Input param\n");
        QATerr(QAT_F_MB_ECDSA_SIGN_SIG, QAT_R_INPUT_PARAM_INVALID);
        return NULL;
    }

    group = EC_KEY_get0_group(eckey);
    priv_key = EC_KEY_get0_private_key(eckey);
    pub_key = EC_KEY_get0_public_key(eckey);

    if (group == NULL || priv_key == NULL || pub_key == NULL) {
        WARN("Either group, priv_key or pub_key are NULL\n");
        QATerr(QAT_F_MB_ECDSA_SIGN_SIG, QAT_R_GROUP_PRIV_KEY_PUB_KEY_NULL);
        return NULL;
    }

    /* Check if curve is p256 or p384 */
    if ((bit_len = mb_ec_check_curve(EC_GROUP_get_curve_name(group))) == 0) {
        DEBUG("Curve type not supported, using SW Method %d\n",
               EC_GROUP_get_curve_name(group));
        goto use_sw_method;
    }

    /* Check if we are running asynchronously */
    if ((job = ASYNC_get_current_job()) == NULL) {
        DEBUG("Running synchronously using sw method\n");
        goto use_sw_method;
    }

    /* Setup asynchronous notifications */
    if (!qat_setup_async_event_notification(0)) {
        DEBUG("Failed to setup async notifications, using sw method\n");
        goto use_sw_method;
    }

    if (!EC_KEY_can_sign(eckey)) {
        WARN("Curve doesn't support Signing\n");
        QATerr(QAT_F_MB_ECDSA_SIGN_SIG, QAT_R_CURVE_DOES_NOT_SUPPORT_SIGNING);
        return NULL;
    }

    while ((ecdsa_sign_sig_req =
            mb_flist_ecdsa_sign_sig_pop(&ecdsa_sign_sig_freelist)) == NULL) {
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
    }

    DEBUG("Started request: %p\n", ecdsa_sign_sig_req);
    START_RDTSC(&ecdsa_cycles_sign_sig_setup);

    /* Buffer up the requests and call the new functions when we have enough
     * requests buffered up */

    ret = ECDSA_SIG_new();
    if (ret == NULL) {
        mb_flist_ecdsa_sign_sig_push(&ecdsa_sign_sig_freelist, ecdsa_sign_sig_req);
        WARN("Failure to allocate sig\n");
        QATerr(QAT_F_MB_ECDSA_SIGN_SIG, QAT_R_MALLOC_FAILURE);
        return NULL;
    }

    ecdsa_sig_r = BN_new();
    ecdsa_sig_s = BN_new();

    /* NULL checking of ecdsa_sig_r & ecdsa_sig_s done in ECDSA_SIG_set0() */
    if (ECDSA_SIG_set0(ret, ecdsa_sig_r, ecdsa_sig_s) == 0) {
        mb_flist_ecdsa_sign_sig_push(&ecdsa_sign_sig_freelist, ecdsa_sign_sig_req);
        WARN("Failure to allocate r and s values to assign to the ECDSA_SIG\n");
        QATerr(QAT_F_MB_ECDSA_SIGN_SIG, QAT_R_ECDSA_SIG_SET_R_S_FAILURE);
        goto err;
    }

    if ((ctx = BN_CTX_new()) == NULL) {
        mb_flist_ecdsa_sign_sig_push(&ecdsa_sign_sig_freelist, ecdsa_sign_sig_req);
        WARN("Failure to allocate ctx\n");
        QATerr(QAT_F_MB_ECDSA_SIGN_SIG, QAT_R_CTX_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    if ((order = EC_GROUP_get0_order(group)) ==  NULL) {
        mb_flist_ecdsa_sign_sig_push(&ecdsa_sign_sig_freelist, ecdsa_sign_sig_req);
        WARN("Failure to get order from group\n");
        QATerr(QAT_F_MB_ECDSA_SIGN_SIG, QAT_R_GET_ORDER_FAILURE);
        goto err;
    }

    len = BN_num_bits(order);
    buflen = (len + 7) / 8;

    /* If digest size is less, expand length with zero as crypto_mb
     * expects digest being sign length */
    if (8 * dlen < len) {
        dgst_buf = OPENSSL_zalloc(buflen);
        if (dgst_buf == NULL) {
            mb_flist_ecdsa_sign_sig_push(&ecdsa_sign_sig_freelist, ecdsa_sign_sig_req);
            WARN("Failure to allocate dgst_buf\n");
            QATerr(QAT_F_MB_ECDSA_SIGN_SIG, QAT_R_ECDSA_MALLOC_FAILURE);
            goto err;
        }
        alloc_buf = 1;
        memcpy(dgst_buf + buflen - dlen, dgst, dlen);
    } else {
        dgst_buf = (unsigned char *)dgst;
    }

    if (in_kinv == NULL || in_r == NULL) {
        if (!ECDSA_sign_setup(eckey, ctx, &kinv, &rp)) {
            mb_flist_ecdsa_sign_sig_push(&ecdsa_sign_sig_freelist, ecdsa_sign_sig_req);
            WARN("Failure in sign setup\n");
            QATerr(QAT_F_MB_ECDSA_SIGN_SIG, QAT_R_ECDSA_SIGN_SETUP_FAILURE);
            goto err;
        }
        in_kinv = kinv;
        in_r = rp;
    }

    sig_buf = OPENSSL_malloc(buflen + buflen);
    if (sig_buf == NULL) {
        mb_flist_ecdsa_sign_sig_push(&ecdsa_sign_sig_freelist, ecdsa_sign_sig_req);
        WARN("Failure to allocate sig_buf\n");
        QATerr(QAT_F_MB_ECDSA_SIGN_SIG, QAT_R_ECDSA_MALLOC_FAILURE);
        goto err;
    }

    ecdsa_sign_sig_req->sign_r = sig_buf;
    ecdsa_sign_sig_req->sign_s = sig_buf + buflen;
    ecdsa_sign_sig_req->digest = dgst_buf;
    ecdsa_sign_sig_req->sig_rp = in_r;
    ecdsa_sign_sig_req->k_inv = in_kinv;
    ecdsa_sign_sig_req->priv_key = priv_key;
    ecdsa_sign_sig_req->job = job;
    ecdsa_sign_sig_req->sts = &sts;

    switch (bit_len) {
    case EC_P256_LENGTH:
        mb_queue_ecdsap256_sign_sig_enqueue(&ecdsap256_sign_sig_queue, ecdsa_sign_sig_req);
        break;
    case EC_P384_LENGTH:
        mb_queue_ecdsap384_sign_sig_enqueue(&ecdsap384_sign_sig_queue, ecdsa_sign_sig_req);
        break;
    }
    STOP_RDTSC(&ecdsa_cycles_sign_sig_setup, 1, "[ECDSA:sign_sig_setup]");

    if (!enable_external_polling && (++req_num % MULTIBUFF_MAX_BATCH) == 0) {
        DEBUG("Signal Polling thread, req_num %d\n", req_num);
        if (qat_kill_thread(multibuff_timer_poll_func_thread, SIGUSR1) != 0) {
            WARN("qat_kill_thread error\n");
            /* If we fail the pthread_kill carry on as the timeout
             * will catch processing the request in the polling thread */
        }
    }

    DEBUG("Pausing: %p status = %d\n", ecdsa_sign_sig_req, sts);
    do {
        /* If we get a failure on qat_pause_job then we will
         * not flag an error here and quit because we have
         * an asynchronous request in flight.
         * We don't want to start cleaning up data
         * structures that are still being used. If
         * qat_pause_job fails we will just yield and
         * loop around and try again until the request
         * completes and we can continue. */
        if ((job_ret = qat_pause_job(job, ASYNC_STATUS_OK)) == 0)
            pthread_yield();
    } while (QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DEBUG("Finished: %p status = %d\n", ecdsa_sign_sig_req, sts);

    /* Convert the buffers to BN */
    BN_bin2bn(sig_buf, buflen, ecdsa_sig_r);
    BN_bin2bn(sig_buf + buflen, buflen, ecdsa_sig_s);
    ok = 1;

err:
    if (!ok) {
        ECDSA_SIG_free(ret);
        ret = NULL;
    }

    if (sig_buf)
        OPENSSL_free(sig_buf);

    if (alloc_buf)
        OPENSSL_free(dgst_buf);

    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return ret;

use_sw_method:
    EC_KEY_METHOD_get_sign((EC_KEY_METHOD *) EC_KEY_OpenSSL(),
                            NULL, NULL, &sign_sig_pfunc);
    if (sign_sig_pfunc == NULL) {
        WARN("sign_sig_pfunc is NULL\n");
        QATerr(QAT_F_MB_ECDSA_SIGN_SIG, QAT_R_SW_GET_SIGN_SIG_PFUNC_NULL);
        return NULL;
    }

    return (*sign_sig_pfunc)(dgst, dlen, in_kinv, in_r, eckey);
}
#endif

#ifndef DISABLE_QAT_SW_ECDH
int mb_ecdh_generate_key(EC_KEY *ecdh)
{
    BN_CTX *ctx = NULL;
    const EC_GROUP *group;
    EC_POINT *pub_key = NULL;
    BIGNUM *priv_key = NULL;
    const BIGNUM *order;
    BIGNUM *x = NULL, *y = NULL, *z = NULL;
    int ret = 0, job_ret = 0, sts = 0, bit_len = 0;
    int alloc_priv = 0, alloc_pub = 0;
    PFUNC_GEN_KEY gen_key_pfunc = NULL;
    ecdh_keygen_op_data *ecdh_keygen_req = NULL;
    ASYNC_JOB *job;
    static __thread int req_num = 0;

    if (unlikely(ecdh == NULL || ((group = EC_KEY_get0_group(ecdh)) == NULL))) {
        WARN("Either ecdh or group are NULL\n");
        QATerr(QAT_F_MB_ECDH_GENERATE_KEY, QAT_R_ECDH_GROUP_NULL);
        return ret;
    }

    /* Check if curve is p256 or p384 */
    if ((bit_len = mb_ec_check_curve(EC_GROUP_get_curve_name(group))) == 0) {
        DEBUG("Curve type not supported, using SW Method %d\n",
               EC_GROUP_get_curve_name(group));
        goto use_sw_method;
    }

    /* Check if we are running asynchronously */
    if ((job = ASYNC_get_current_job()) == NULL) {
        DEBUG("Running synchronously using sw method\n");
        goto use_sw_method;
    }

    /* Setup asynchronous notifications */
    if (!qat_setup_async_event_notification(0)) {
        DEBUG("Failed to setup async notifications, using sw method\n");
        goto use_sw_method;
    }

    while ((ecdh_keygen_req =
            mb_flist_ecdh_keygen_pop(&ecdh_keygen_freelist)) == NULL) {
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
    }

    DEBUG("Started request: %p\n", ecdh_keygen_req);
    START_RDTSC(&ecdh_cycles_keygen_setup);

    if ((ctx = BN_CTX_new()) == NULL) {
        mb_flist_ecdh_keygen_push(&ecdh_keygen_freelist, ecdh_keygen_req);
        WARN("Failure to allocate ctx\n");
        QATerr(QAT_F_MB_ECDH_GENERATE_KEY, QAT_R_CTX_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    if ((order = EC_GROUP_get0_order(group)) ==  NULL) {
        mb_flist_ecdh_keygen_push(&ecdh_keygen_freelist, ecdh_keygen_req);
        WARN("Failure to retrieve order\n");
        QATerr(QAT_F_MB_ECDH_GENERATE_KEY, QAT_R_GET_ORDER_FAILURE);
        goto err;
    }

    if ((priv_key = (BIGNUM *)EC_KEY_get0_private_key(ecdh)) == NULL) {
        priv_key = BN_new();
        if (priv_key == NULL) {
            mb_flist_ecdh_keygen_push(&ecdh_keygen_freelist, ecdh_keygen_req);
            WARN("Failure to get priv_key\n");
            QATerr(QAT_F_MB_ECDH_GENERATE_KEY, QAT_R_GET_PRIV_KEY_FAILURE);
            goto err;
        }
        alloc_priv = 1;
    }

    do {
        if (!BN_priv_rand_range(priv_key, order)) {
            mb_flist_ecdh_keygen_push(&ecdh_keygen_freelist, ecdh_keygen_req);
            WARN("Failure to generate random value\n");
            QATerr(QAT_F_MB_ECDH_GENERATE_KEY,
                   QAT_R_PRIV_KEY_RAND_GENERATE_FAILURE);
            goto err;
        }
    } while (BN_is_zero(priv_key)) ;

    if (alloc_priv) {
        if (!EC_KEY_set_private_key(ecdh, priv_key)) {
            mb_flist_ecdh_keygen_push(&ecdh_keygen_freelist, ecdh_keygen_req);
            WARN("Failure to set private key\n");
            QATerr(QAT_F_MB_ECDH_GENERATE_KEY, QAT_R_SET_PRIV_KEY_FAILURE);
            goto err;
        }
    }

    if ((pub_key = (EC_POINT *)EC_KEY_get0_public_key(ecdh)) == NULL) {
        pub_key = EC_POINT_new(group);
        if (pub_key == NULL) {
            mb_flist_ecdh_keygen_push(&ecdh_keygen_freelist, ecdh_keygen_req);
            WARN("Failure to allocate pub_key\n");
            QATerr(QAT_F_MB_ECDH_GENERATE_KEY, QAT_R_PUB_KEY_MALLOC_FAILURE);
            goto err;
        }
        alloc_pub = 1;
    }

    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    z = BN_CTX_get(ctx);

    if (x == NULL || y == NULL || z == NULL) {
        mb_flist_ecdh_keygen_push(&ecdh_keygen_freelist, ecdh_keygen_req);
        WARN("Failed to allocate x or y or z\n");
        QATerr(QAT_F_MB_ECDH_GENERATE_KEY, QAT_R_X_Y_Z_MALLOC_FAILURE);
        goto err;
    }

    ecdh_keygen_req->x = x;
    ecdh_keygen_req->y = y;
    ecdh_keygen_req->z = z;
    ecdh_keygen_req->priv_key = priv_key;
    ecdh_keygen_req->job = job;
    ecdh_keygen_req->sts = &sts;

    switch (bit_len) {
    case EC_P256_LENGTH:
        mb_queue_ecdhp256_keygen_enqueue(&ecdhp256_keygen_queue, ecdh_keygen_req);
        break;
    case EC_P384_LENGTH:
        mb_queue_ecdhp384_keygen_enqueue(&ecdhp384_keygen_queue, ecdh_keygen_req);
        break;
    }
    STOP_RDTSC(&ecdh_cycles_keygen_setup, 1, "[ECDH:keygen_setup]");

    if (!enable_external_polling && (++req_num % MULTIBUFF_MAX_BATCH) == 0) {
        DEBUG("Signal Polling thread, req_num %d\n", req_num);
        if (qat_kill_thread(multibuff_timer_poll_func_thread, SIGUSR1) != 0) {
            WARN("qat_kill_thread error\n");
            /* If we fail the pthread_kill carry on as the timeout
             * will catch processing the request in the polling thread */
        }
    }

    DEBUG("Pausing: %p status = %d\n", ecdh_keygen_req, sts);
    do {
        /* If we get a failure on qat_pause_job then we will
         * not flag an error here and quit because we have
         * an asynchronous request in flight.
         * We don't want to start cleaning up data
         * structures that are still being used. If
         * qat_pause_job fails we will just yield and
         * loop around and try again until the request
         * completes and we can continue. */
        if ((job_ret = qat_pause_job(job, ASYNC_STATUS_OK)) == 0)
            pthread_yield();
    } while (QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DEBUG("Finished: %p status = %d\n", ecdh_keygen_req, sts);

    if (!EC_POINT_set_Jprojective_coordinates_GFp(group, pub_key, x, y, z, ctx)) {
       WARN("Failure to set the Jacobian coordinates for public Key\n");
       goto err;
    }

    if (sts) {
        if (!EC_KEY_set_public_key(ecdh, pub_key)) {
            WARN("Error setting pub_key\n");
            QATerr(QAT_F_MB_ECDH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        ret = 1;
    } else {
        WARN("Failure in Keygen\n");
        QATerr(QAT_F_MB_ECDH_GENERATE_KEY, QAT_R_KEYGEN_FAILURE);
        goto err;
    }

err:
    if (alloc_pub)
        EC_POINT_free(pub_key);
    if (alloc_priv)
        BN_clear_free(priv_key);
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;

use_sw_method:
    EC_KEY_METHOD_get_keygen((EC_KEY_METHOD *) EC_KEY_OpenSSL(), &gen_key_pfunc);
    if (gen_key_pfunc == NULL) {
        WARN("get keygen failed\n");
        QATerr(QAT_F_MB_ECDH_GENERATE_KEY, QAT_R_SW_GET_KEYGEN_PFUNC_NULL);
        return ret;
    } else {
        return (*gen_key_pfunc)(ecdh);
    }
}

int mb_ecdh_compute_key(unsigned char **out,
                        size_t *outlen,
                        const EC_POINT *pub_key,
                        const EC_KEY *ecdh)
{
    BN_CTX *ctx;
    const BIGNUM *priv_key;
    const EC_GROUP *group;
    unsigned char *buf = NULL;
    int ret = 0,job_ret = 0, sts = 0, bit_len = 0;
    BIGNUM *x = NULL, *y = NULL, *z = NULL;
    PFUNC_COMP_KEY comp_key_pfunc = NULL;
    ecdh_compute_op_data *ecdh_compute_req = NULL;
    ASYNC_JOB *job;
    size_t buflen;
    static __thread int req_num = 0;

    if (unlikely(ecdh == NULL || pub_key == NULL ||
                ((priv_key = EC_KEY_get0_private_key(ecdh)) == NULL) ||
                ((group = EC_KEY_get0_group(ecdh)) == NULL))) {
        WARN("Either ecdh or pub_key or priv_key or group is NULL\n");
        QATerr(QAT_F_MB_ECDH_COMPUTE_KEY, QAT_R_ECDH_PRIV_KEY_PUB_KEY_NULL);
        return ret;
    }

    /* Check if curve is p256 or p384 */
    if ((bit_len = mb_ec_check_curve(EC_GROUP_get_curve_name(group))) == 0) {
        DEBUG("Curve type not supported, using SW Method %d\n",
               EC_GROUP_get_curve_name(group));
        goto use_sw_method;
    }

    /* Check if we are running asynchronously */
    if ((job = ASYNC_get_current_job()) == NULL) {
        DEBUG("Running synchronously using sw method\n");
        goto use_sw_method;
    }

    /* Setup asynchronous notifications */
    if (!qat_setup_async_event_notification(0)) {
        DEBUG("Failed to setup async notifications, using sw method\n");
        goto use_sw_method;
    }

    while ((ecdh_compute_req =
            mb_flist_ecdh_compute_pop(&ecdh_compute_freelist)) == NULL) {
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
    }

    DEBUG("Started request: %p\n", ecdh_compute_req);
    START_RDTSC(&ecdh_cycles_compute_setup);

    if ((ctx = BN_CTX_new()) == NULL) {
        mb_flist_ecdh_compute_push(&ecdh_compute_freelist, ecdh_compute_req);
        WARN("Failure to allocate ctx\n");
        QATerr(QAT_F_MB_ECDH_COMPUTE_KEY, QAT_R_CTX_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    z = BN_CTX_get(ctx);

    if (x == NULL || y == NULL || z == NULL) {
        mb_flist_ecdh_compute_push(&ecdh_compute_freelist, ecdh_compute_req);
        WARN("Failed to allocate x or y or z\n");
        QATerr(QAT_F_MB_ECDH_COMPUTE_KEY, QAT_R_X_Y_Z_MALLOC_FAILURE);
        goto err;
    }

    buflen = (EC_GROUP_get_degree(group) + 7) / 8;

    if ((buf = OPENSSL_zalloc(buflen)) == NULL) {
        mb_flist_ecdh_compute_push(&ecdh_compute_freelist, ecdh_compute_req);
        WARN("Failed to allocate buf\n");
        QATerr(QAT_F_MB_ECDH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_POINT_get_Jprojective_coordinates_GFp(group, pub_key, x, y, z,ctx)) {
        mb_flist_ecdh_compute_push(&ecdh_compute_freelist, ecdh_compute_req);
        WARN("Failure to get the Jacobian coordinates for public Key\n");
        QATerr(QAT_F_MB_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ecdh_compute_req->shared_key = buf;
    ecdh_compute_req->priv_key = priv_key;
    ecdh_compute_req->x = x;
    ecdh_compute_req->y = y;
    ecdh_compute_req->z = z;
    ecdh_compute_req->job = job;
    ecdh_compute_req->sts = &sts;

    switch (bit_len) {
    case EC_P256_LENGTH:
        mb_queue_ecdhp256_compute_enqueue(&ecdhp256_compute_queue, ecdh_compute_req);
        break;
    case EC_P384_LENGTH:
        mb_queue_ecdhp384_compute_enqueue(&ecdhp384_compute_queue, ecdh_compute_req);
        break;
    }
    STOP_RDTSC(&ecdh_cycles_compute_setup, 1, "[ECDH:compute_setup]");

    if (!enable_external_polling && (++req_num % MULTIBUFF_MAX_BATCH) == 0) {
        DEBUG("Signal Polling thread, req_num %d\n", req_num);
        if (qat_kill_thread(multibuff_timer_poll_func_thread, SIGUSR1) != 0) {
            WARN("qat_kill_thread error\n");
            /* If we fail the pthread_kill carry on as the timeout
             * will catch processing the request in the polling thread */
        }
    }

    DEBUG("Pausing: %p status = %d\n", ecdh_compute_req, sts);
    do {
        /* If we get a failure on qat_pause_job then we will
         * not flag an error here and quit because we have
         * an asynchronous request in flight.
         * We don't want to start cleaning up data
         * structures that are still being used. If
         * qat_pause_job fails we will just yield and
         * loop around and try again until the request
         * completes and we can continue. */
        if ((job_ret = qat_pause_job(job, ASYNC_STATUS_OK)) == 0)
            pthread_yield();
    } while (QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DEBUG("Finished: %p status = %d\n", ecdh_compute_req, sts);

    if (sts) {
        *out = buf;
        *outlen = buflen;
        buf = NULL;
        ret = 1;
    } else {
        WARN("Failure in compute key\n");
        QATerr(QAT_F_MB_ECDH_COMPUTE_KEY, QAT_R_COMPUTE_FAILURE);
        goto err;
    }

err:
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        OPENSSL_free(buf);
    }
    return ret;

use_sw_method:
    EC_KEY_METHOD_get_compute_key((EC_KEY_METHOD *)EC_KEY_OpenSSL(), &comp_key_pfunc);
    if (comp_key_pfunc == NULL) {
        WARN("comp_key_pfunc is NULL\n");
        QATerr(QAT_F_MB_ECDH_COMPUTE_KEY, QAT_R_SW_GET_COMPUTE_KEY_PFUNC_NULL);
        return ret;
    }
    return (*comp_key_pfunc)(out, outlen, pub_key, ecdh);
}
#endif
