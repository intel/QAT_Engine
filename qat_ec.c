/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2020 Intel Corporation.
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
 * @file qat_ec.c
 *
 * This file provides support for ECDH & ECDSA
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <pthread.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <signal.h>

#include <openssl/ecdh.h>
#include <openssl/async.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_ec.h"
#include "cpa_cy_ecdsa.h"
#include "e_qat.h"
#include "qat_callback.h"
#include "qat_polling.h"
#include "qat_events.h"
#include "qat_asym_common.h"
#ifdef USE_QAT_CONTIG_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
# include "cmn_mem_drv_inf.h"
#endif
#include "e_qat_err.h"
#include "qat_utils.h"
#include "qat_ec.h"

#ifdef OPENSSL_ENABLE_QAT_ECDSA
# ifdef OPENSSL_DISABLE_QAT_ECDSA
#  undef OPENSSL_DISABLE_QAT_ECDSA
# endif
#endif

#ifdef OPENSSL_ENABLE_QAT_ECDH
# ifdef OPENSSL_DISABLE_QAT_ECDH
#  undef OPENSSL_DISABLE_QAT_ECDH
# endif
#endif


#ifndef OPENSSL_DISABLE_QAT_ECDSA
static int qat_ecdsa_sign(int type, const unsigned char *dgst, int dlen,
                          unsigned char *sig, unsigned int *siglen,
                          const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);

static ECDSA_SIG *qat_ecdsa_do_sign(const unsigned char *dgst, int dlen,
                                    const BIGNUM *in_kinv, const BIGNUM *in_r,
                                    EC_KEY *eckey);

static int qat_ecdsa_verify(int type, const unsigned char *dgst, int dgst_len,
                            const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);

static int qat_ecdsa_do_verify(const unsigned char *dgst, int dgst_len,
                               const ECDSA_SIG *sig, EC_KEY *eckey);
#endif


#ifndef OPENSSL_DISABLE_QAT_ECDH
/* Qat engine ECDH methods declaration */
static int qat_ecdh_compute_key(unsigned char **outX, size_t *outlenX,
                                unsigned char **outY, size_t *outlenY,
                                const EC_POINT *pub_key, const EC_KEY *ecdh,
                                int *fallback);

static int qat_engine_ecdh_compute_key(unsigned char **out, size_t *outlen,
                                       const EC_POINT *pub_key, const EC_KEY *ecdh);

static int qat_ecdh_generate_key(EC_KEY *ecdh);
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

static EC_KEY_METHOD *qat_ec_method = NULL;

EC_KEY_METHOD *qat_get_EC_methods(void)
{
    if (qat_ec_method != NULL)
        return qat_ec_method;

#if defined (OPENSSL_DISABLE_QAT_ECDSA) || defined (OPENSSL_DISABLE_QAT_ECDH)
    EC_KEY_METHOD *def_ec_meth = (EC_KEY_METHOD *)EC_KEY_get_default_method();
#endif
#ifdef OPENSSL_DISABLE_QAT_ECDSA
    PFUNC_SIGN sign_pfunc = NULL;
    PFUNC_SIGN_SETUP sign_setup_pfunc = NULL;
    PFUNC_SIGN_SIG sign_sig_pfunc = NULL;
    PFUNC_VERIFY verify_pfunc = NULL;
    PFUNC_VERIFY_SIG verify_sig_pfunc = NULL;
#endif
#ifdef OPENSSL_DISABLE_QAT_ECDH
    PFUNC_COMP_KEY comp_key_pfunc = NULL;
    PFUNC_GEN_KEY gen_key_pfunc = NULL;
#endif

    if ((qat_ec_method = EC_KEY_METHOD_new(qat_ec_method)) == NULL) {
        WARN("Unable to allocate qat EC_KEY_METHOD\n");
        QATerr(QAT_F_QAT_GET_EC_METHODS, QAT_R_QAT_GET_EC_METHOD_MALLOC_FAILURE);
        return NULL;
    }

#ifndef OPENSSL_DISABLE_QAT_ECDSA
    EC_KEY_METHOD_set_sign(qat_ec_method,
                           qat_ecdsa_sign,
                           NULL,
                           qat_ecdsa_do_sign);
    EC_KEY_METHOD_set_verify(qat_ec_method,
                             qat_ecdsa_verify,
                             qat_ecdsa_do_verify);
#else
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
#endif

#ifndef OPENSSL_DISABLE_QAT_ECDH
    EC_KEY_METHOD_set_keygen(qat_ec_method, qat_ecdh_generate_key);
    EC_KEY_METHOD_set_compute_key(qat_ec_method, qat_engine_ecdh_compute_key);
#else
    EC_KEY_METHOD_get_keygen(def_ec_meth, &gen_key_pfunc);
    EC_KEY_METHOD_set_keygen(qat_ec_method, gen_key_pfunc);
    EC_KEY_METHOD_get_compute_key(def_ec_meth, &comp_key_pfunc);
    EC_KEY_METHOD_set_compute_key(qat_ec_method, comp_key_pfunc);
#endif

    return qat_ec_method;
}

void qat_free_EC_methods(void)
{
    if (NULL != qat_ec_method) {
        EC_KEY_METHOD_free(qat_ec_method);
        qat_ec_method = NULL;
    } else {
        WARN("Unable to free qat EC_KEY_METHOD\n");
        QATerr(QAT_F_QAT_FREE_EC_METHODS, QAT_R_QAT_FREE_EC_METHOD_FAILURE);
    }
}


#if !defined (OPENSSL_DISABLE_QAT_ECDSA) || !defined (OPENSSL_DISABLE_QAT_ECDH)
CpaCyEcFieldType qat_get_field_type(const EC_GROUP *group)
{
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
        == NID_X9_62_prime_field)
        return CPA_CY_EC_FIELD_TYPE_PRIME;
    else
        return CPA_CY_EC_FIELD_TYPE_BINARY;
}

int qat_get_curve(const EC_GROUP *group, BIGNUM *p, BIGNUM *a,
                  BIGNUM *b, BN_CTX *ctx, CpaCyEcFieldType fieldType)
{
# if OPENSSL_VERSION_NUMBER > 0x10200000L
    if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {
        WARN("Failure to get the curve\n");
        return 0;
    }
# else
    if (fieldType == CPA_CY_EC_FIELD_TYPE_PRIME) {
        if (!EC_GROUP_get_curve_GFp(group, p, a, b, ctx)) {
            WARN("Failure to get the curve for a prime field\n");
            return 0;
        }
    } else {
        if (!EC_GROUP_get_curve_GF2m(group, p, a, b, ctx)) {
            WARN("Failure to get the curve for a binary field\n");
            return 0;
        }
    }
# endif
    return 1;
}

int qat_get_affine_coordinates(const EC_GROUP *group, const EC_POINT *p,
                               BIGNUM *x, BIGNUM *y, BN_CTX *ctx,
                               CpaCyEcFieldType fieldType)
{
# if OPENSSL_VERSION_NUMBER > 0x10200000L
    if (!EC_POINT_get_affine_coordinates(group, p, x, y, ctx)) {
        WARN("Failure to get the affine coordinates for fieldType %d\n", fieldType);
        return 0;
    }
# else
    if (fieldType == CPA_CY_EC_FIELD_TYPE_PRIME) {
        if (!EC_POINT_get_affine_coordinates_GFp(group, p, x, y, ctx)) {
            WARN("Failure to get the curve for a prime field\n");
            return 0;
        }
    } else {
        if (!EC_POINT_get_affine_coordinates_GF2m(group, p, x, y, ctx)) {
            WARN("Failure to get the curve for a binary field\n");
            return 0;
        }
    }
# endif
    return 1;
}

int qat_set_affine_coordinates(const EC_GROUP *group, EC_POINT *p,
                               BIGNUM *x, BIGNUM *y, BN_CTX *ctx,
                               CpaCyEcFieldType fieldType)
{
# if OPENSSL_VERSION_NUMBER > 0x10200000L
    if (!EC_POINT_set_affine_coordinates(group, p, x, y, ctx)) {
        WARN("Failure to set the affine coordinates for fieldType %d\n", fieldType);
        return 0;
    }
# else
    if (fieldType == CPA_CY_EC_FIELD_TYPE_PRIME) {
        if (!EC_POINT_set_affine_coordinates_GFp(group, p, x, y, ctx)) {
            WARN("Failure to set the affine coordinates for prime field\n");
            return 0;
        }
    } else {
        if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
            NID_X9_62_characteristic_two_field) {
            if (!EC_POINT_set_affine_coordinates_GF2m(group, p, x, y, ctx)) {
                WARN("Failure to set the affine coordinates for binary field\n");
                return 0;
            }
        } else {
            WARN("Error unknown field type for curve\n");
            QATerr(QAT_F_QAT_SET_AFFINE_COORDINATES, QAT_R_ECDH_UNKNOWN_FIELD_TYPE);
            return 0;
        }
    }
# endif
    return 1;
}
#endif

#ifndef OPENSSL_DISABLE_QAT_ECDH
/* Callback to indicate QAT completion of EC point multiply */
static void qat_ecCallbackFn(void *pCallbackTag, CpaStatus status, void *pOpData,
                             CpaBoolean multiplyStatus, CpaFlatBuffer * pXk,
                             CpaFlatBuffer * pYk)
{
    if (enable_heuristic_polling) {
        QAT_ATOMIC_DEC(num_asym_requests_in_flight);
    }
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, multiplyStatus);
}

int qat_ecdh_compute_key(unsigned char **outX, size_t *outlenX,
                         unsigned char **outY, size_t *outlenY,
                         const EC_POINT *pub_key, const EC_KEY *ecdh,
                         int *fallback)
{
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    BIGNUM *xg = NULL, *yg = NULL;
    const BIGNUM *priv_key = NULL;
    const EC_GROUP *group = NULL;
    int ret = -1, job_ret = 0;
    size_t buflen;

    int inst_num = QAT_INVALID_INSTANCE;
    CpaCyEcPointMultiplyOpData *opData = NULL;
    CpaBoolean bEcStatus;
    CpaFlatBuffer *pResultX = NULL;
    CpaFlatBuffer *pResultY = NULL;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
    CpaStatus status;
    op_done_t op_done;
    thread_local_variables_t *tlv = NULL;

    DEBUG("- Started\n");

    if (unlikely(ecdh == NULL ||
                 ((priv_key = EC_KEY_get0_private_key(ecdh)) == NULL)
                 || pub_key == NULL)) {
        WARN("Either ecdh or priv_key or pub_key is NULL\n");
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_ECDH_PRIV_KEY_PUB_KEY_NULL);
        return ret;
    }

    if (fallback == NULL) {
        WARN("NULL fallback pointer passed in.\n");
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_FALLBACK_POINTER_NULL);
        return ret;
    }

    if ((outX != NULL && outlenX == NULL) ||
        (outY != NULL && outlenY == NULL)) {
        WARN("Either outX, outY, outlenX or outlenY are NULL\n");
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_OUTX_OUTY_LEN_NULL);
        return ret;
    }

    if ((group = EC_KEY_get0_group(ecdh)) == NULL) {
        WARN("group is NULL\n");
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_GET_GROUP_FAILURE);
        return ret;
    }

    opData = (CpaCyEcPointMultiplyOpData *)
        OPENSSL_zalloc(sizeof(CpaCyEcPointMultiplyOpData));
    if (opData == NULL) {
        WARN("Failure to allocate opData\n");
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_OPDATA_MALLOC_FAILURE);
        return ret;
    }

    opData->k.pData = NULL;
    opData->xg.pData = NULL;
    opData->yg.pData = NULL;
    opData->a.pData = NULL;
    opData->b.pData = NULL;
    opData->q.pData = NULL;

    /* To instruct the Quickassist API not to use co-factor */
    opData->h.pData = NULL;
    opData->h.dataLenInBytes = 0;

    /* Populate the parameters required for EC point multiply */
    if ((ctx = BN_CTX_new()) == NULL) {
        WARN("Failure to allocate ctx\n");
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_CTX_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    xg = BN_CTX_get(ctx);
    yg = BN_CTX_get(ctx);

    if (yg == NULL) {
        WARN("Failed to allocate p, a, b, xg or yg\n");
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_P_A_B_XG_YG_MALLOC_FAILURE);
        goto err;
    }

    buflen = (EC_GROUP_get_degree(group) + 7) / 8;
    pResultX = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (pResultX == NULL) {
        WARN("Failure to allocate pResultX\n");
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_PRESULTX_MALLOC_FAILURE);
        goto err;
    }
    pResultX->pData = qaeCryptoMemAlloc(buflen, __FILE__, __LINE__);
    if (pResultX->pData == NULL) {
        WARN("Failure to allocate pResultX->pData\n");
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_PRESULTX_PDATA_MALLOC_FAILURE);
        goto err;
    }
    pResultX->dataLenInBytes = (Cpa32U) buflen;
    pResultY = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (!pResultY) {
        WARN("Failure to allocate pResultY\n");
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_PRESULTY_MALLOC_FAILURE);
        goto err;
    }
    pResultY->pData = qaeCryptoMemAlloc(buflen, __FILE__, __LINE__);
    if (pResultY->pData == NULL) {
        WARN("Failure to allocate pResultY->pData\n");
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_PRESULTY_PDATA_MALLOC_FAILURE);
        goto err;
    }
    pResultY->dataLenInBytes = (Cpa32U) buflen;

    opData->fieldType = qat_get_field_type(group);

    if (!qat_get_curve(group, p, a, b, ctx, opData->fieldType)) {
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!qat_get_affine_coordinates(group, pub_key, xg, yg, ctx,
                                    opData->fieldType)) {
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if ((qat_BN_to_FB(&(opData->k), (BIGNUM *)priv_key) != 1) ||
        (qat_BN_to_FB(&(opData->xg), xg) != 1) ||
        (qat_BN_to_FB(&(opData->yg), yg) != 1) ||
        (qat_BN_to_FB(&(opData->a), a) != 1) ||
        (qat_BN_to_FB(&(opData->b), b) != 1) ||
        (qat_BN_to_FB(&(opData->q), p) != 1)) {
        WARN("Failure to convert priv_key, xg, yg, a, b or p to a flatbuffer\n");
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_PRIV_KEY_XG_YG_A_B_P_CONVERT_TO_FB_FAILURE);
        goto err;
    }

    /*
     * This is a special handling required for curves with 'a' co-efficient
     * of 0. The translation to a flatbuffer results in a zero sized field
     * but the Quickassist API expects a flatbuffer of size 1 with a value
     * of zero. As a special case we will create that manually.
     */
    if (opData->a.pData == NULL && opData->a.dataLenInBytes == 0) {
        opData->a.pData = qaeCryptoMemAlloc(1, __FILE__, __LINE__);
        if (opData->a.pData == NULL) {
            WARN("Failure to allocate opData->a.pData\n");
            QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_OPDATA_A_PDATA_MALLOC_FAILURE);
            goto err;
        }
        opData->a.dataLenInBytes = 1;
        opData->a.pData[0] = 0;
    }

    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
            WARN("could not create local variables\n");
            QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            goto err;
    }

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (pthread_kill(timer_poll_func_thread, SIGUSR1) != 0) {
                WARN("pthread_kill error\n");
                QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                goto err;
            }
        }
    }
    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(0) == 0) {
            WARN("Failed to setup async event notification\n");
            QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
            goto err;
        }
    }
    CRYPTO_QAT_LOG("KX - %s\n", __func__);

    /* Invoke the crypto engine API for EC Point Multiply */
    do {
        if ((inst_num = get_next_inst_num()) == QAT_INVALID_INSTANCE) {
            WARN("Failed to get an instance\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                *fallback = 1;
            } else {
                QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            }
            if (op_done.job != NULL) {
                qat_clear_async_event_notification();
            }
            qat_cleanup_op_done(&op_done);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
            goto err;
        }

        CRYPTO_QAT_LOG("KX - %s\n", __func__);
        DUMP_EC_POINT_MULTIPLY(qat_instance_handles[inst_num], opData, pResultX, pResultY);
        status = cpaCyEcPointMultiply(qat_instance_handles[inst_num],
                                      qat_ecCallbackFn,
                                      &op_done,
                                      opData,
                                      &bEcStatus, pResultX, pResultY);

        if (status == CPA_STATUS_RETRY) {
            if (op_done.job == NULL) {
                usleep(ulPollInterval +
                       (qatPerformOpRetries %
                        QAT_RETRY_BACKOFF_MODULO_DIVISOR));
                qatPerformOpRetries++;
                if (iMsgRetry != QAT_INFINITE_MAX_NUM_RETRIES) {
                    if (qatPerformOpRetries >= iMsgRetry) {
                        WARN("No. of retries exceeded max retry : %d\n", iMsgRetry);
                        break;
                    }
                }
            } else {
                if ((qat_wake_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0) ||
                    (qat_pause_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0)) {
                    WARN("qat_wake_job or qat_pause_job failed\n");
                    break;
                }
            }
        }
    }
    while (status == CPA_STATUS_RETRY );

    if (status != CPA_STATUS_SUCCESS) {
        WARN("Failed to submit request to qat - status = %d\n", status);
        if (qat_get_sw_fallback_enabled() &&
            (status == CPA_STATUS_RESTARTING || status == CPA_STATUS_FAIL)) {
            CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            *fallback = 1;
        } else {
            QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        }
        if (op_done.job != NULL) {
            qat_clear_async_event_notification();
        }
        qat_cleanup_op_done(&op_done);
        QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
        goto err;
    }
    if (qat_get_sw_fallback_enabled()) {
        CRYPTO_QAT_LOG("Submit success qat inst_num %d device_id %d - %s\n",
                       inst_num,
                       qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                       __func__);
    }

    if (enable_heuristic_polling) {
        QAT_ATOMIC_INC(num_asym_requests_in_flight);
    }

    do {
        if(op_done.job != NULL) {
            /* If we get a failure on qat_pause_job then we will
               not flag an error here and quit because we have
               an asynchronous request in flight.
               We don't want to start cleaning up data
               structures that are still being used. If
               qat_pause_job fails we will just yield and
               loop around and try again until the request
               completes and we can continue. */
            if ((job_ret = qat_pause_job(op_done.job, ASYNC_STATUS_OK)) == 0)
                pthread_yield();
        } else {
            pthread_yield();
        }
    }
    while (!op_done.flag ||
           QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DUMP_EC_POINT_MULTIPLY_OUTPUT(bEcStatus, pResultX, pResultY);
    QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);

    if (op_done.verifyResult != CPA_TRUE) {
        WARN("Verification of request failed\n");
        if (qat_get_sw_fallback_enabled() && op_done.status == CPA_STATUS_FAIL) {
            CRYPTO_QAT_LOG("Verification of result failed for qat inst_num %d device_id %d - fallback to SW - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            *fallback = 1;
        } else {
            QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        }
        qat_cleanup_op_done(&op_done);
        goto err;
    }

    qat_cleanup_op_done(&op_done);

    /* KDF, is done in the caller now just copy out bytes */
    if (outX != NULL) {
        *outlenX = pResultX->dataLenInBytes;
        *outX = OPENSSL_zalloc(*outlenX);
        if (*outX == NULL) {
            WARN("Failure to allocate outX\n");
            QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_OUTX_MALLOC_FAILURE);
            goto err;
        }
        memcpy(*outX, pResultX->pData, *outlenX);
    }

    if (outY != NULL) {
        if (*outlenY != pResultY->dataLenInBytes) {
            WARN("Failed length check of pResultY->dataLenInBytes\n");
            QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_PRESULTY_LENGTH_CHECK_FAILURE);
            goto err;
        }
        *outY = OPENSSL_zalloc(*outlenY);
        if (*outY == NULL) {
            WARN("Failure to allocate outY\n");
            QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_OUTY_MALLOC_FAILURE);
            goto err;
        }
        memcpy(*outY, pResultY->pData, pResultY->dataLenInBytes);
    }
    ret = *outlenX;

 err:
    if (pResultX) {
        QAT_CHK_CLNSE_QMFREE_FLATBUFF(*pResultX);
        OPENSSL_free(pResultX);
    }
    if (pResultY) {
        QAT_CHK_CLNSE_QMFREE_FLATBUFF(*pResultY);
        OPENSSL_free(pResultY);
    }
    QAT_CHK_CLNSE_QMFREE_FLATBUFF(opData->k);
    QAT_CHK_QMFREE_FLATBUFF(opData->xg);
    QAT_CHK_QMFREE_FLATBUFF(opData->yg);
    QAT_CHK_QMFREE_FLATBUFF(opData->a);
    QAT_CHK_QMFREE_FLATBUFF(opData->b);
    QAT_CHK_QMFREE_FLATBUFF(opData->q);
    if (opData)
        OPENSSL_free(opData);
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    DEBUG("- Finished\n");
    return ret;
}


int qat_engine_ecdh_compute_key(unsigned char **out,
                                size_t *outlen,
                                const EC_POINT *pub_key,
                                const EC_KEY *ecdh)
{
    int fallback = 0;
    int ret = -1;
    PFUNC_COMP_KEY comp_key_pfunc = NULL;
    const EC_GROUP *group = NULL;
    const BIGNUM *priv_key = NULL;

    DEBUG("- Started\n");

    EC_KEY_METHOD_get_compute_key((EC_KEY_METHOD *)EC_KEY_OpenSSL(), &comp_key_pfunc);
    if (comp_key_pfunc == NULL) {
        WARN("comp_key_pfunc is NULL\n");
        QATerr(QAT_F_QAT_ENGINE_ECDH_COMPUTE_KEY, QAT_R_SW_GET_COMPUTE_KEY_PFUNC_NULL);
        return ret;
    }

    if (qat_get_qat_offload_disabled()) {
        DEBUG("- Switched to software mode\n");
        return (*comp_key_pfunc)(out, outlen, pub_key, ecdh);
    }

    if (ecdh == NULL || (priv_key = EC_KEY_get0_private_key(ecdh)) == NULL) {
        WARN("Either ecdh or priv_key is NULL\n");
        QATerr(QAT_F_QAT_ENGINE_ECDH_COMPUTE_KEY, QAT_R_ECDH_PRIVATE_KEY_NULL);
        return ret;
    }

    if ((group = EC_KEY_get0_group(ecdh)) == NULL) {
        WARN("group is NULL\n");
        QATerr(QAT_F_QAT_ENGINE_ECDH_COMPUTE_KEY, QAT_R_GET_GROUP_FAILURE);
        return ret;
    }

    /* Unsupported curve: X25519.
     * Detect and call it's software implementation.
     */
    if (EC_GROUP_get_curve_name(group) == NID_X25519) {
        return (*comp_key_pfunc)(out, outlen, pub_key, ecdh);
    }

    ret = qat_ecdh_compute_key(out, outlen, NULL, NULL, pub_key, ecdh, &fallback);
    if (fallback == 1) {
        WARN("- Fallback to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
        return (*comp_key_pfunc)(out, outlen, pub_key, ecdh);
    }
    DEBUG("- Finished\n");
    return ret;
}


int qat_ecdh_generate_key(EC_KEY *ecdh)
{
    int ok = 0;
    int alloc_priv = 0, alloc_pub = 0;
    int field_size = 0, field_type = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *priv_key = NULL, *order = NULL, *x_bn = NULL,
           *y_bn = NULL, *tx_bn = NULL, *ty_bn = NULL;
    EC_POINT *pub_key = NULL;
    const EC_POINT *gen;
    const EC_GROUP *group;
    unsigned char *temp_xbuf = NULL;
    unsigned char *temp_ybuf = NULL;
    size_t temp_xfield_size = 0;
    size_t temp_yfield_size = 0;
    PFUNC_GEN_KEY gen_key_pfunc = NULL;
    int fallback = 0;

    DEBUG("- Started\n");

    EC_KEY_METHOD_get_keygen((EC_KEY_METHOD *) EC_KEY_OpenSSL(), &gen_key_pfunc);
    if (gen_key_pfunc == NULL) {
        WARN("get keygen failed\n");
        QATerr(QAT_F_QAT_ECDH_GENERATE_KEY, QAT_R_SW_GET_KEYGEN_PFUNC_NULL);
        return 0;
    }

    if (qat_get_qat_offload_disabled()) {
        DEBUG("- Switched to software mode\n");
        return (*gen_key_pfunc)(ecdh);
    }

    if (unlikely(ecdh == NULL || ((group = EC_KEY_get0_group(ecdh)) == NULL))) {
        WARN("Either ecdh or group are NULL\n");
        QATerr(QAT_F_QAT_ECDH_GENERATE_KEY, QAT_R_ECDH_GROUP_NULL);
        return 0;
    }

    /* Unsupported curve: X25519.
     * Detect and call it's software implementation.
     */
    if (EC_GROUP_get_curve_name(group) == NID_X25519) {
        return (*gen_key_pfunc)(ecdh);
    }

    if ((ctx = BN_CTX_new()) == NULL) {
        WARN("Failure to allocate ctx\n");
        QATerr(QAT_F_QAT_ECDH_GENERATE_KEY, QAT_R_CTX_MALLOC_FAILURE);
        goto err;
    }
    BN_CTX_start(ctx);
    if ((order = BN_CTX_get(ctx)) == NULL) {
        WARN("Failure to allocate order\n");
        QATerr(QAT_F_QAT_ECDH_GENERATE_KEY, QAT_R_ORDER_MALLOC_FAILURE);
        goto err;
    }

    if ((priv_key = (BIGNUM *)EC_KEY_get0_private_key(ecdh)) == NULL) {
        priv_key = BN_new();
        if (priv_key == NULL) {
            WARN("Failure to get priv_key\n");
            QATerr(QAT_F_QAT_ECDH_GENERATE_KEY, QAT_R_GET_PRIV_KEY_FAILURE);
            goto err;
        }
        alloc_priv = 1;
    }

    if (!EC_GROUP_get_order(group, order, ctx)) {
        WARN("Failure to retrieve order\n");
        QATerr(QAT_F_QAT_ECDH_GENERATE_KEY, QAT_R_RETRIEVE_ORDER_FAILURE);
        goto err;
    }
    do
        if (!BN_rand_range(priv_key, order)) {
            WARN("Failure to generate random value\n");
            QATerr(QAT_F_QAT_ECDH_GENERATE_KEY, QAT_R_PRIV_KEY_RAND_GENERATE_FAILURE);
            goto err;
        }
    while (BN_is_zero(priv_key)) ;

    if (alloc_priv) {
        if (!EC_KEY_set_private_key(ecdh, priv_key)) {
            WARN("Failure to set private key\n");
            QATerr(QAT_F_QAT_ECDH_GENERATE_KEY, QAT_R_SET_PRIV_KEY_FAILURE);
            goto err;
        }
    }

    if ((pub_key = (EC_POINT *)EC_KEY_get0_public_key(ecdh)) == NULL) {
        pub_key = EC_POINT_new(group);
        if (pub_key == NULL) {
            WARN("Failure to allocate pub_key\n");
            QATerr(QAT_F_QAT_ECDH_GENERATE_KEY, QAT_R_PUB_KEY_MALLOC_FAILURE);
            goto err;
        }
        alloc_pub = 1;
    }

    field_size = EC_GROUP_get_degree(group);
    if (field_size <= 0) {
        WARN("invalid field_size: %d\n", field_size);
        QATerr(QAT_F_QAT_ECDH_GENERATE_KEY, QAT_R_FIELD_SIZE_INVALID);
        goto err;
    }
    gen = EC_GROUP_get0_generator(group);
    temp_xfield_size = temp_yfield_size = (field_size + 7) / 8;

    if ((qat_ecdh_compute_key(&temp_xbuf,
                              &temp_xfield_size,
                              &temp_ybuf,
                              &temp_yfield_size,
                              gen,
                              ecdh,
                              &fallback) <= 0)
        || (fallback == 1)) {
        /*
         * No QATerr is raised here because errors are already handled in
         * qat_ecdh_compute_key()
         */
        goto err;
    }

    x_bn = BN_CTX_get(ctx);
    y_bn = BN_CTX_get(ctx);
    tx_bn = BN_CTX_get(ctx);
    ty_bn = BN_CTX_get(ctx);

    if (ty_bn == NULL) {
        WARN("Failure to allocate ctx x_bn, y_bn, tx_bn or ty_bn\n");
        QATerr(QAT_F_QAT_ECDH_GENERATE_KEY, QAT_R_X_Y_TX_TY_BN_MALLOC_FAILURE);
        goto err;
    }

    x_bn = BN_bin2bn(temp_xbuf, temp_xfield_size, x_bn);
    y_bn = BN_bin2bn(temp_ybuf, temp_yfield_size, y_bn);

    field_type = qat_get_field_type(group);

    if (!qat_set_affine_coordinates(group, pub_key, x_bn, y_bn, ctx, field_type)) {
        QATerr(QAT_F_QAT_ECDH_GENERATE_KEY, QAT_R_ECDH_SET_AFFINE_COORD_FAILED);
        goto err;
    }
    if (!qat_get_affine_coordinates(group, pub_key, tx_bn, ty_bn, ctx, field_type)) {
        QATerr(QAT_F_QAT_ECDH_GENERATE_KEY, QAT_R_ECDH_GET_AFFINE_COORD_FAILED);
        goto err;
    }

    /*
    * Check if retrieved coordinates match originals: if not values are
    * out of range.
    */
    if (BN_cmp(x_bn, tx_bn) || BN_cmp(y_bn, ty_bn)) {
        WARN("Retrieved coordinates do not match the originals\n");
        QATerr(QAT_F_QAT_ECDH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!EC_KEY_set_public_key(ecdh, pub_key)) {
        WARN("Error setting pub_key\n");
        QATerr(QAT_F_QAT_ECDH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ok = 1;

 err:
    if (alloc_pub)
        EC_POINT_free(pub_key);
    if (alloc_priv)
        BN_clear_free(priv_key);
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (temp_xbuf != NULL)
        OPENSSL_free(temp_xbuf);
    if (temp_ybuf != NULL)
        OPENSSL_free(temp_ybuf);

    DEBUG("- Finished\n");

    if (fallback == 1) {
        DEBUG("- Switched to software mode\n");
        return (*gen_key_pfunc)(ecdh);
    }
    return ok;
}
#endif /* #ifndef OPENSSL_DISABLE_QAT_ECDH */

#ifndef OPENSSL_DISABLE_QAT_ECDSA
/* Callback to indicate QAT completion of ECDSA Sign */
static void qat_ecdsaSignCallbackFn(void *pCallbackTag, CpaStatus status,
                                    void *pOpData, CpaBoolean bEcdsaSignStatus,
                                    CpaFlatBuffer * pResultR,
                                    CpaFlatBuffer * pResultS)
{
    if (enable_heuristic_polling) {
        QAT_ATOMIC_DEC(num_asym_requests_in_flight);
    }
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, bEcdsaSignStatus);
}

/* Callback to indicate QAT completion of ECDSA Verify */
static void qat_ecdsaVerifyCallbackFn(void *pCallbackTag, CpaStatus status,
                                      void *pOpData, CpaBoolean bEcdsaVerifyStatus)
{
    if (enable_heuristic_polling) {
        QAT_ATOMIC_DEC(num_asym_requests_in_flight);
    }
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, bEcdsaVerifyStatus);
}


int qat_ecdsa_sign(int type, const unsigned char *dgst, int dlen,
                   unsigned char *sig, unsigned int *siglen,
                   const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey)
{
    ECDSA_SIG *s;

    if (unlikely(dgst == NULL ||
                 dlen <= 0)) { /* Check these input params before passing to
                                * RAND_seed(). Rest of the input params. are
                                * checked by qat_ecdsa_do_sign().
                                */
        WARN("Invalid input param.\n");
        if (siglen != NULL)
            *siglen = 0;
        QATerr(QAT_F_QAT_ECDSA_SIGN, QAT_R_INPUT_PARAM_INVALID);
        return 0;
    }
    s = qat_ecdsa_do_sign(dgst, dlen, kinv, r, eckey);
    if (s == NULL) {
        WARN("Error ECDSA Sign Operation Failed\n");
        if (siglen != NULL)
            *siglen = 0;
        QATerr(QAT_F_QAT_ECDSA_SIGN, QAT_R_QAT_ECDSA_DO_SIGN_FAIL);
        return 0;
    }
    *siglen = i2d_ECDSA_SIG(s, &sig);
    ECDSA_SIG_free(s);
    return 1;
}


ECDSA_SIG *qat_ecdsa_do_sign(const unsigned char *dgst, int dgst_len,
                             const BIGNUM *in_kinv, const BIGNUM *in_r,
                             EC_KEY *eckey)
{
    int ok = 0, i, job_ret = 0, fallback = 0;
    BIGNUM *m = NULL, *order = NULL;
    BN_CTX *ctx = NULL;
    const EC_GROUP *group;
    ECDSA_SIG *ret = NULL;
    BIGNUM *ecdsa_sig_r = NULL, *ecdsa_sig_s = NULL;
    const BIGNUM *priv_key;
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *k = NULL;
    BIGNUM *xg = NULL, *yg = NULL;
    const EC_POINT *pub_key = NULL;
    PFUNC_SIGN_SIG sign_sig_pfunc = NULL;

    CpaFlatBuffer *pResultR = NULL;
    CpaFlatBuffer *pResultS = NULL;
    int inst_num = QAT_INVALID_INSTANCE;
    CpaCyEcdsaSignRSOpData *opData = NULL;
    CpaBoolean bEcdsaSignStatus;
    CpaStatus status;
    size_t buflen;
    op_done_t op_done;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
    const EC_POINT *ec_point = NULL;
    thread_local_variables_t *tlv = NULL;

    DEBUG("- Started\n");

    if (unlikely(dgst == NULL ||
                 dgst_len <= 0 ||
                 eckey == NULL)) {
        WARN("Invalid input param.\n");
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, QAT_R_INPUT_PARAM_INVALID);
        return NULL;
    }

    EC_KEY_METHOD_get_sign((EC_KEY_METHOD *) EC_KEY_OpenSSL(),
                           NULL, NULL, &sign_sig_pfunc);
    if (sign_sig_pfunc == NULL) {
        WARN("sign_sig_pfunc is NULL\n");
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, QAT_R_SW_GET_SIGN_SIG_PFUNC_NULL);
        return ret;
    }

    if (qat_get_qat_offload_disabled()) {
        DEBUG("- Switched to software mode\n");
        return (*sign_sig_pfunc)(dgst, dgst_len, in_kinv, in_r, eckey);
    }

    group = EC_KEY_get0_group(eckey);
    priv_key = EC_KEY_get0_private_key(eckey);
    pub_key = EC_KEY_get0_public_key(eckey);

    if (group == NULL || priv_key == NULL || pub_key == NULL) {
        WARN("Either group, priv_key or pub_key are NULL\n");
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, QAT_R_GROUP_PRIV_KEY_PUB_KEY_NULL);
        return ret;
    }

    if ((ec_point = EC_GROUP_get0_generator(group)) == NULL) {
        WARN("Failure to retrieve ec_point\n");
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, QAT_R_EC_POINT_RETRIEVE_FAILURE);
        return ret;
    }

    opData = (CpaCyEcdsaSignRSOpData *)
        OPENSSL_zalloc(sizeof(CpaCyEcdsaSignRSOpData));
    if (opData == NULL) {
        WARN("Failure to allocate opData\n");
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, QAT_R_OPDATA_MALLOC_FAILURE);
        return ret;
    }

    if ((ret = ECDSA_SIG_new()) == NULL) {
        WARN("Failure to allocate ECDSA_SIG\n");
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, QAT_R_ECDSA_SIG_MALLOC_FAILURE);
        goto err;
    }

    ecdsa_sig_r = BN_new();
    ecdsa_sig_s = BN_new();
    /* NULL checking of ecdsa_sig_r & ecdsa_sig_s done in ECDSA_SIG_set0() */
    if (ECDSA_SIG_set0(ret, ecdsa_sig_r, ecdsa_sig_s) == 0) {
        WARN("Failure to allocate r and s values to assign to the ECDSA_SIG\n");
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, QAT_R_ECDSA_SIG_SET_R_S_FAILURE);
        goto err;
    }

    if ((ctx = BN_CTX_new()) == NULL) {
        WARN("Failure to allocate ctx\n");
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, QAT_R_CTX_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    xg = BN_CTX_get(ctx);
    yg = BN_CTX_get(ctx);
    m = BN_CTX_get(ctx);
    k = BN_CTX_get(ctx);
    order = BN_CTX_get(ctx);

    if (order == NULL) {
        WARN("Failure to allocate p, a, b, xg, yg, m, k, r or order\n");
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, QAT_R_P_A_B_XG_YG_M_K_R_ORDER_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_GROUP_get_order(group, order, ctx)) {
        WARN("Failure to get order from group\n");
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_EC_LIB);
        goto err;
    }
    i = BN_num_bits(order);

    /*
     * Need to truncate digest if it is too long: first truncate whole bytes.
     */
    if (8 * dgst_len > i)
        dgst_len = (i + 7) / 8;

    if (!BN_bin2bn(dgst, dgst_len, m)) {
        WARN("Failure to convert dgst to m\n");
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_BN_LIB);
        goto err;
    }

    /* If still too long truncate remaining bits with a shift */
    if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7))) {
        WARN("Failure to truncate m\n");
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_BN_LIB);
        goto err;
    }

    opData->fieldType = qat_get_field_type(group);

    if (!qat_get_curve(group, p, a, b, ctx, opData->fieldType)) {
       QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
       goto err;
    }

    if (!qat_get_affine_coordinates(group, ec_point, xg, yg, ctx,
                                    opData->fieldType)) {
       QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
       goto err;
    }

    if (qat_BN_to_FB(&(opData->d), (BIGNUM *)priv_key) != 1 ||
        qat_BN_to_FB(&(opData->m), m) != 1 ||
        qat_BN_to_FB(&(opData->xg), xg) != 1 ||
        qat_BN_to_FB(&(opData->yg), yg) != 1 ||
        qat_BN_to_FB(&(opData->a), a) != 1 ||
        qat_BN_to_FB(&(opData->b), b) != 1 ||
        qat_BN_to_FB(&(opData->q), p) != 1) {
        WARN("Failed to convert d, m, xg, yg, a, b or p to a flatbuffer\n");
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, QAT_R_PRIV_KEY_M_XG_YG_A_B_P_CONVERT_TO_FB_FAILURE);
        goto err;
    }

    /*
     * This is a special handling required for curves with 'a' co-efficient
     * of 0. The translation to a flatbuffer results in a zero sized field
     * but the Quickassist API expects a flatbuffer of size 1 with a value
     * of zero. As a special case we will create that manually.
     */
    if (opData->a.pData == NULL && opData->a.dataLenInBytes == 0) {
        opData->a.pData = qaeCryptoMemAlloc(1, __FILE__, __LINE__);
        if (opData->a.pData == NULL) {
            WARN("Failure to allocate opData->a.pData\n");
            QATerr(QAT_F_QAT_ECDSA_DO_SIGN, QAT_R_OPDATA_PDATA_MALLOC_FAILURE);
            goto err;
        }
        opData->a.dataLenInBytes = 1;
        opData->a.pData[0] = 0;
    }

    if (in_kinv == NULL || in_r == NULL) {
        do
            if (!BN_rand_range(k, order)) {
                WARN("Failure to get random number k\n");
                QATerr(QAT_F_QAT_ECDSA_DO_SIGN, QAT_R_K_RAND_GENERATE_FAILURE);
                goto err;
            }
        while (BN_is_zero(k));

        if ((qat_BN_to_FB(&(opData->k), k)) != 1) {
            WARN("Failed to convert k to a flatbuffer\n");
            QATerr(QAT_F_QAT_ECDSA_DO_SIGN, QAT_R_K_CONVERT_TO_FB_FAILURE);
            goto err;
        }

        if ((qat_BN_to_FB(&(opData->n), order)) != 1) {
            WARN("Failed to convert order to a flatbuffer\n");
            QATerr(QAT_F_QAT_ECDSA_DO_SIGN, QAT_R_K_ORDER_CONVERT_TO_FB_FAILURE);
            goto err;
        }

    } else {
        if ((qat_BN_to_FB(&(opData->k), (BIGNUM *)in_kinv)) != 1) {
            WARN("Failed to convert in_kinv to a flatbuffer\n");
            QATerr(QAT_F_QAT_ECDSA_DO_SIGN, QAT_R_IN_KINV_CONVERT_TO_FB_FAILURE);
            goto err;
        }

        if ((qat_BN_to_FB(&(opData->n), (BIGNUM *)in_r)) != 1) {
            WARN("Failed to convert in_r to a flatbuffer\n");
            QATerr(QAT_F_QAT_ECDSA_DO_SIGN, QAT_R_IN_R_CONVERT_TO_FB_FAILURE);
            goto err;
        }

    }

    buflen = EC_GROUP_get_degree(group);
    pResultR = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (pResultR == NULL) {
        WARN("Failure to allocate pResultR\n");
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, QAT_R_PRESULTR_MALLOC_FAILURE);
        goto err;
    }
    pResultR->pData = qaeCryptoMemAlloc(buflen, __FILE__, __LINE__);
    if (pResultR->pData == NULL) {
        WARN("Failure to allocate pResultR->pData\n");
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, QAT_R_PRESULTR_PDATA_MALLOC_FAILURE);
        goto err;
    }
    pResultR->dataLenInBytes = (Cpa32U) buflen;
    pResultS = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (pResultS == NULL) {
        WARN("Failure to allocate pResultS\n");
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, QAT_R_PRESULTS_MALLOC_FAILURE);
        goto err;
    }
    pResultS->pData = qaeCryptoMemAlloc(buflen, __FILE__, __LINE__);
    if (pResultS->pData == NULL) {
        WARN("Failure to allocate pResultS->pData\n");
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, QAT_R_PRESULTS_PDATA_MALLOC_FAILURE);
        goto err;
    }
    pResultS->dataLenInBytes = (Cpa32U) buflen;

    /* perform ECDSA sign */

    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
            WARN("could not create local variables\n");
            QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
            goto err;
    }

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (pthread_kill(timer_poll_func_thread, SIGUSR1) != 0) {
                WARN("pthread_kill error\n");
                QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                goto err;
            }
        }
    }
    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(0) == 0) {
            WARN("Failure to setup async event notifications\n");
            QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
            goto err;
        }
    }

    CRYPTO_QAT_LOG("AU - %s\n", __func__);
    do {
        if ((inst_num = get_next_inst_num()) == QAT_INVALID_INSTANCE) {
            WARN("Failure to get another instance\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                fallback = 1;
            } else {
                QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
            }
            if (op_done.job != NULL) {
                qat_clear_async_event_notification();
            }
            qat_cleanup_op_done(&op_done);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
            goto err;
        }

        CRYPTO_QAT_LOG("AU - %s\n", __func__);
        DUMP_ECDSA_SIGN(qat_instance_handles[inst_num], opData, pResultR, pResultS);
        status = cpaCyEcdsaSignRS(qat_instance_handles[inst_num],
                                  qat_ecdsaSignCallbackFn,
                                  &op_done,
                                  opData,
                                  &bEcdsaSignStatus, pResultR, pResultS);

        if (status == CPA_STATUS_RETRY) {
            if (op_done.job == NULL) {
                usleep(ulPollInterval +
                        (qatPerformOpRetries %
                         QAT_RETRY_BACKOFF_MODULO_DIVISOR));
                qatPerformOpRetries++;
                if (iMsgRetry != QAT_INFINITE_MAX_NUM_RETRIES) {
                    if (qatPerformOpRetries >= iMsgRetry) {
                        WARN("No. of retries exceeded max retry : %d\n", iMsgRetry);
                        break;
                    }
                }
            } else {
                if ((qat_wake_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0) ||
                    (qat_pause_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0)) {
                    WARN("qat_wake_job or qat_pause_job failed\n");
                    break;
                }
            }
        }
    }
    while (status == CPA_STATUS_RETRY);

    if (status != CPA_STATUS_SUCCESS) {
        WARN("Failed to submit request to qat - status = %d\n", status);
        if (qat_get_sw_fallback_enabled() &&
            (status == CPA_STATUS_RESTARTING || status == CPA_STATUS_FAIL)) {
            CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            fallback = 1;
        } else {
            QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        }
        if (op_done.job != NULL) {
            qat_clear_async_event_notification();
        }
        qat_cleanup_op_done(&op_done);
        QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
        goto err;
    }
    if (qat_get_sw_fallback_enabled()) {
        CRYPTO_QAT_LOG("Submit success qat inst_num %d device_id %d - %s\n", inst_num,
                       qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                       __func__);
    }

    if (enable_heuristic_polling) {
        QAT_ATOMIC_INC(num_asym_requests_in_flight);
    }

    do {
        if(op_done.job != NULL) {
            /* If we get a failure on qat_pause_job then we will
               not flag an error here and quit because we have
               an asynchronous request in flight.
               We don't want to start cleaning up data
               structures that are still being used. If
               qat_pause_job fails we will just yield and
               loop around and try again until the request
               completes and we can continue. */
            if ((job_ret = qat_pause_job(op_done.job, ASYNC_STATUS_OK)) == 0)
                pthread_yield();
        } else {
            pthread_yield();
        }
    }
    while (!op_done.flag ||
           QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DUMP_ECDSA_SIGN_OUTPUT(bEcdsaSignStatus, pResultR, pResultS);
    QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);

    if (op_done.verifyResult != CPA_TRUE) {
        WARN("Verification of result failed\n");
        if (qat_get_sw_fallback_enabled() && op_done.status == CPA_STATUS_FAIL) {
            CRYPTO_QAT_LOG("Verification of result failed for qat inst_num %d device_id %d - fallback to SW - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            fallback = 1;
        } else {
            QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        }
        qat_cleanup_op_done(&op_done);
        goto err;
    }

    qat_cleanup_op_done(&op_done);

    /* Convert the flatbuffer results back to a BN */
    BN_bin2bn(pResultR->pData, pResultR->dataLenInBytes, ecdsa_sig_r);
    BN_bin2bn(pResultS->pData, pResultS->dataLenInBytes, ecdsa_sig_s);

    ok = 1;

 err:
    if (!ok) {
        ECDSA_SIG_free(ret);
        ret = NULL;
    }

    if (pResultR) {
        QAT_CHK_QMFREE_FLATBUFF(*pResultR);
        OPENSSL_free(pResultR);
    }
    if (pResultS) {
        QAT_CHK_QMFREE_FLATBUFF(*pResultS);
        OPENSSL_free(pResultS);
    }

    if (opData) {
        QAT_CHK_QMFREE_FLATBUFF(opData->n);
        QAT_CHK_QMFREE_FLATBUFF(opData->m);
        QAT_CHK_QMFREE_FLATBUFF(opData->xg);
        QAT_CHK_QMFREE_FLATBUFF(opData->yg);
        QAT_CHK_QMFREE_FLATBUFF(opData->a);
        QAT_CHK_QMFREE_FLATBUFF(opData->b);
        QAT_CHK_QMFREE_FLATBUFF(opData->q);
        QAT_CHK_CLNSE_QMFREE_FLATBUFF(opData->k);
        QAT_CHK_CLNSE_QMFREE_FLATBUFF(opData->d);
        OPENSSL_free(opData);
    }

    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    if (fallback) {
        WARN("- Fallback to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
        return (*sign_sig_pfunc)(dgst, dgst_len, in_kinv, in_r, eckey);
    }
    DEBUG("- Finished\n");
    return ret;
}


/*-
 * returns
 *      1: correct signature
 *      0: incorrect signature
 *     -1: error
 */
int qat_ecdsa_verify(int type, const unsigned char *dgst, int dgst_len,
                     const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)
{
    ECDSA_SIG *s;
    const unsigned char *p = sigbuf;
    unsigned char *der = NULL;
    int derlen = -1;
    int ret = -1;

    s = ECDSA_SIG_new();
    if (s == NULL) {
        WARN("Failure to allocate ECDSA_SIG s\n");
        QATerr(QAT_F_QAT_ECDSA_VERIFY, QAT_R_S_NULL);
        return (ret);
    }
    if (d2i_ECDSA_SIG(&s, &p, sig_len) == NULL) {
        WARN("Failure to convert sig_buf and sig_len to s\n");
        QATerr(QAT_F_QAT_ECDSA_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = i2d_ECDSA_SIG(s, &der);
    if (derlen != sig_len || memcmp(sigbuf, der, derlen) != 0) {
        WARN("Failure ECDSA_SIG s contains trailing garbage\n");
        QATerr(QAT_F_QAT_ECDSA_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ret = qat_ecdsa_do_verify(dgst, dgst_len, s, eckey);
 err:
    OPENSSL_clear_free(der, derlen);
    ECDSA_SIG_free(s);
    return ret;
}


int qat_ecdsa_do_verify(const unsigned char *dgst, int dgst_len,
                        const ECDSA_SIG *sig, EC_KEY *eckey)
{
    int ret = -1, i, job_ret = 0, fallback = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *order = NULL, *m = NULL;
    const EC_GROUP *group;
    const EC_POINT *pub_key;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    BIGNUM *xg = NULL, *yg = NULL, *xp = NULL, *yp = NULL;
    const EC_POINT *ec_point;
    const BIGNUM *sig_r = NULL, *sig_s = NULL;
    PFUNC_VERIFY_SIG verify_sig_pfunc = NULL;

    int inst_num = QAT_INVALID_INSTANCE;
    CpaCyEcdsaVerifyOpData *opData = NULL;
    CpaBoolean bEcdsaVerifyStatus;
    CpaStatus status;
    op_done_t op_done;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
    thread_local_variables_t *tlv = NULL;

    DEBUG("- Started\n");
    if (unlikely(dgst == NULL || dgst_len <= 0)) {
        WARN("Invalid input param.\n");
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, QAT_R_INPUT_PARAM_INVALID);
        return ret;
    }

    EC_KEY_METHOD_get_verify((EC_KEY_METHOD *) EC_KEY_OpenSSL(),
                             NULL, &verify_sig_pfunc);
    if (verify_sig_pfunc == NULL) {
        WARN("verify_sig_pfunc is NULL\n");
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, QAT_R_SW_GET_VERIFY_SIG_PFUNC_NULL);
        return ret;
    }

    if (qat_get_qat_offload_disabled()) {
        DEBUG("- Switched to software mode\n");
        return (*verify_sig_pfunc)(dgst, dgst_len, sig, eckey);
    }

    /* check input values */
    if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL ||
        (pub_key = EC_KEY_get0_public_key(eckey)) == NULL || sig == NULL) {
        WARN("eckey, group, pub_key or sig are NULL\n");
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, QAT_R_ECKEY_GROUP_PUBKEY_SIG_NULL);
        return ret;
    }

    if ((ec_point = EC_GROUP_get0_generator(group)) == NULL) {
        WARN("Failure to retrieve ec_point\n");
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, QAT_R_RETRIEVE_EC_POINT_FAILURE);
        return ret;
    }

    opData = (CpaCyEcdsaVerifyOpData *)
        OPENSSL_zalloc(sizeof(CpaCyEcdsaVerifyOpData));
    if (opData == NULL) {
        WARN("Failure to allocate opData\n");
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, QAT_R_OPDATA_MALLOC_FAILURE);
        return ret;
    }

    if ((ctx = BN_CTX_new()) == NULL) {
        WARN("Failure to allocate ctx\n");
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, QAT_R_CTX_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    xg = BN_CTX_get(ctx);
    yg = BN_CTX_get(ctx);
    xp = BN_CTX_get(ctx);
    yp = BN_CTX_get(ctx);
    m = BN_CTX_get(ctx);
    order = BN_CTX_get(ctx);

    if (order == NULL) {
        WARN("Failure to allocate p, a, b, xg, yg, xp, yp, m or order\n");
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, QAT_R_P_A_B_XG_YG_XP_YP_M_ORDER_FAILURE);
        goto err;
    }

    if (!EC_GROUP_get_order(group, order, ctx)) {
        WARN("Failure to get order from group\n");
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
        goto err;
    }

    ECDSA_SIG_get0((ECDSA_SIG *)sig, &sig_r, &sig_s);
    if (BN_is_zero(sig_r) ||
        BN_is_negative(sig_r) ||
        BN_ucmp(sig_r, order) >= 0 ||
        BN_is_zero(sig_s) ||
        BN_is_negative(sig_s) ||
        BN_ucmp(sig_s, order) >= 0) {
        WARN("ECDSA_SIG sig is invalid\n");
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        ret = 0;                /* signature is invalid */
        goto err;
    }
    /* digest -> m */
    i = BN_num_bits(order);
    /*
     * Need to truncate digest if it is too long: first truncate whole bytes.
     */
    if (8 * dgst_len > i)
        dgst_len = (i + 7) / 8;

    if (!BN_bin2bn(dgst, dgst_len, m)) {
        WARN("Failure to convert dgst to m\n");
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
        goto err;
    }
    /* If still too long truncate remaining bits with a shift */
    if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7))) {
        WARN("Failure to truncate m\n");
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
        goto err;
    }

    opData->fieldType = qat_get_field_type(group);

    if (!qat_get_curve(group, p, a, b, ctx, opData->fieldType)) {
       QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
       goto err;
    }

    if (!qat_get_affine_coordinates(group, ec_point, xg, yg, ctx,
                                    opData->fieldType)) {
       QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
       goto err;
    }

    if (!qat_get_affine_coordinates(group, pub_key, xp, yp, ctx,
                                    opData->fieldType)) {
       QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
       goto err;
    }

    if ((qat_BN_to_FB(&(opData->m), m) != 1) ||
        (qat_BN_to_FB(&(opData->xg), xg) != 1) ||
        (qat_BN_to_FB(&(opData->yg), yg) != 1) ||
        (qat_BN_to_FB(&(opData->a), a) != 1) ||
        (qat_BN_to_FB(&(opData->b), b) != 1) ||
        (qat_BN_to_FB(&(opData->q), p) != 1) ||
        (qat_BN_to_FB(&(opData->n), order) != 1) ||
        (qat_BN_to_FB(&(opData->r), (BIGNUM *)sig_r) != 1) ||
        (qat_BN_to_FB(&(opData->s), (BIGNUM *)sig_s) != 1) ||
        (qat_BN_to_FB(&(opData->xp), xp) != 1) ||
        (qat_BN_to_FB(&(opData->yp), yp) != 1)) {
        WARN("Failed to convert m, xg, yg, a, b, p, order, sig_r, sig_s, xp or yp to a flatbuffer\n");
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY,
               QAT_R_CURVE_COORDINATE_PARAMS_CONVERT_TO_FB_FAILURE);
        goto err;
    }

    /*
     * This is a special handling required for curves with 'a' co-efficient
     * of 0. The translation to a flatbuffer results in a zero sized field
     * but the Quickassist API expects a flatbuffer of size 1 with a value
     * of zero. As a special case we will create that manually.
     */

    if (opData->a.pData == NULL && opData->a.dataLenInBytes == 0) {
        opData->a.pData = qaeCryptoMemAlloc(1, __FILE__, __LINE__);
        if (opData->a.pData == NULL) {
            WARN("Failure to allocate opData->a.pData\n");
            QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, QAT_R_OPDATA_DATA_MALLOC_FAILURE);
            goto err;
        }
        opData->a.dataLenInBytes = 1;
        opData->a.pData[0] = 0;
    }

    /* perform ECDSA verify */

    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
            WARN("could not create local variables\n");
            QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
            goto err;
    }

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (pthread_kill(timer_poll_func_thread, SIGUSR1) != 0) {
                WARN("pthread_kill error\n");
                QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                goto err;
            }
        }
    }
    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(0) == 0) {
            WARN("Failure to setup async event notifications\n");
            QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
            goto err;
        }
    }

    CRYPTO_QAT_LOG("AU - %s\n", __func__);
    do {
        if ((inst_num = get_next_inst_num()) == QAT_INVALID_INSTANCE) {
            WARN("Failure to get another instance\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                fallback = 1;
            } else {
                QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
            }
            if (op_done.job != NULL) {
                qat_clear_async_event_notification();
            }
            qat_cleanup_op_done(&op_done);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
            goto err;
        }

        CRYPTO_QAT_LOG("AU - %s\n", __func__);
        DUMP_ECDSA_VERIFY(qat_instance_handles[inst_num], opData);
        status = cpaCyEcdsaVerify(qat_instance_handles[inst_num],
                                  qat_ecdsaVerifyCallbackFn,
                                  &op_done, opData, &bEcdsaVerifyStatus);

        if (status == CPA_STATUS_RETRY) {
            if (op_done.job == NULL) {
                usleep(ulPollInterval +
                       (qatPerformOpRetries %
                        QAT_RETRY_BACKOFF_MODULO_DIVISOR));
                qatPerformOpRetries++;
                if (iMsgRetry != QAT_INFINITE_MAX_NUM_RETRIES) {
                    if (qatPerformOpRetries >= iMsgRetry) {
                        WARN("No. of retries exceeded max retry : %d\n", iMsgRetry);
                        break;
                    }
                }
            } else {
                if ((qat_wake_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0) ||
                    (qat_pause_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0)) {
                    WARN("qat_wake_job or qat_pause_job failed\n");
                    break;
                }
            }
        }
    }
    while (status == CPA_STATUS_RETRY);

    if (status != CPA_STATUS_SUCCESS) {
        WARN("Failed to submit request to qat - status = %d\n", status);
        if (qat_get_sw_fallback_enabled() &&
            (status == CPA_STATUS_RESTARTING || status == CPA_STATUS_FAIL)) {
            CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            fallback = 1;
        } else {
            QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        }
        if (op_done.job != NULL) {
            qat_clear_async_event_notification();
        }
        qat_cleanup_op_done(&op_done);
        QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
        goto err;
    }
    if (qat_get_sw_fallback_enabled()) {
        CRYPTO_QAT_LOG("Submit success qat inst_num %d device_id %d - %s\n",
                       inst_num,
                       qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                       __func__);
    }

    if (enable_heuristic_polling) {
        QAT_ATOMIC_INC(num_asym_requests_in_flight);
    }

    do {
        if(op_done.job != NULL) {
            /* If we get a failure on qat_pause_job then we will
               not flag an error here and quit because we have
               an asynchronous request in flight.
               We don't want to start cleaning up data
               structures that are still being used. If
               qat_pause_job fails we will just yield and
               loop around and try again until the request
               completes and we can continue. */
            if ((job_ret = qat_pause_job(op_done.job, ASYNC_STATUS_OK)) == 0)
                pthread_yield();
        } else {
            pthread_yield();
        }
    }
    while (!op_done.flag ||
           QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DEBUG("bEcdsaVerifyStatus = %u\n", bEcdsaVerifyStatus);
    QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);

    if (op_done.verifyResult == CPA_TRUE)
        ret = 1;
    else if (qat_get_sw_fallback_enabled() && op_done.status == CPA_STATUS_FAIL) {
        CRYPTO_QAT_LOG("Verification of result failed for qat inst_num %d device_id %d - fallback to SW - %s\n",
                       inst_num,
                       qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                       __func__);
        fallback = 1;
    }

    qat_cleanup_op_done(&op_done);

 err:
    if (opData) {
        QAT_CHK_QMFREE_FLATBUFF(opData->r);
        QAT_CHK_QMFREE_FLATBUFF(opData->s);
        QAT_CHK_QMFREE_FLATBUFF(opData->n);
        QAT_CHK_QMFREE_FLATBUFF(opData->m);
        QAT_CHK_QMFREE_FLATBUFF(opData->xg);
        QAT_CHK_QMFREE_FLATBUFF(opData->yg);
        QAT_CHK_QMFREE_FLATBUFF(opData->a);
        QAT_CHK_QMFREE_FLATBUFF(opData->b);
        QAT_CHK_QMFREE_FLATBUFF(opData->q);
        QAT_CHK_QMFREE_FLATBUFF(opData->xp);
        QAT_CHK_QMFREE_FLATBUFF(opData->yp);
        OPENSSL_free(opData);
    }

    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    if (fallback) {
        WARN("- Fallback to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
        return (*verify_sig_pfunc)(dgst, dgst_len, sig, eckey);
    }
    DEBUG("- Finished\n");
    return ret;
}
#endif /* #ifndef OPENSSL_DISABLE_QAT_ECDSA */
