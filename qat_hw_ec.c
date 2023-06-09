/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2023 Intel Corporation.
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
 * @file qat_hw_ec.c
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
#ifdef QAT_BORINGSSL
#include <openssl/ecdsa.h>
#include <openssl/bytestring.h>
#endif /* QAT_BORINGSSL */
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "cpa.h"
#include "cpa_types.h"
#ifdef QAT_BORINGSSL
#include "icp_sal_poll.h"
#endif
#include "cpa_cy_ec.h"
#include "cpa_cy_ecdsa.h"
#include "e_qat.h"
#include "qat_hw_callback.h"
#include "qat_hw_polling.h"
#include "qat_events.h"
#include "qat_hw_asym_common.h"
#ifdef USE_QAT_CONTIG_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_USDM_MEM
# include "qat_hw_usdm_inf.h"
#endif
#include "qat_utils.h"
#include "qat_hw_ec.h"
#include "qat_evp.h"
#if defined(ENABLE_QAT_SW_ECDH) || defined(ENABLE_QAT_SW_ECDSA)
# include "qat_sw_ec.h"
#endif

# define QAT_EC_MIN_RANGE 256

#ifdef ENABLE_QAT_FIPS
# include "qat_prov_cmvp.h"

# ifdef ENABLE_QAT_HW_ECDSA
extern int qat_fips_kat_test;
static const unsigned char kvalue[] = {
    0x23, 0xAF, 0x40, 0x74, 0xC9, 0x0A, 0x02, 0xB3,
    0xE6, 0x1D, 0x28, 0x6D, 0x5C, 0x87, 0xF4, 0x25,
    0xE6, 0xBD, 0xD8, 0x1B
};
# endif
#endif

CpaCyEcFieldType qat_get_field_type(const EC_GROUP *group)
{
    /* For BoringSSL,EC_METHOD_get_field_type only support NID_X9_62_prime_field
    * and EC_METHOD_get_field_type return NID_X9_62_prime_field directly
    */
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
        == NID_X9_62_prime_field)
        return CPA_CY_EC_FIELD_TYPE_PRIME;
    else
        return CPA_CY_EC_FIELD_TYPE_BINARY;
}

#if defined(QAT20_OOT) || defined(QAT_HW_INTREE)
int qat_get_curve(CpaCyEcFieldType fieldType)
{
    if (fieldType == CPA_CY_EC_FIELD_TYPE_PRIME)
        return CPA_CY_EC_CURVE_TYPE_WEIERSTRASS_PRIME;
    else if (fieldType == CPA_CY_EC_FIELD_TYPE_BINARY)
        return CPA_CY_EC_CURVE_TYPE_WEIERSTRASS_BINARY;
    else
        return CPA_CY_EC_CURVE_TYPE_WEIERSTRASS_KOBLITZ_BINARY;
}
#endif

#ifdef ENABLE_QAT_HW_ECDH
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
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *h = NULL;
    const BIGNUM *priv_key = NULL;
    const EC_GROUP *group = NULL;
    int ret = 0, job_ret = 0;
    size_t buflen = 0;

    int inst_num = QAT_INVALID_INSTANCE;
    BIGNUM *xP = NULL, *yP = NULL;
# if defined(QAT20_OOT) || defined(QAT_HW_INTREE)
    CpaCyEcGenericPointMultiplyOpData *pOpData = NULL;
# else
    CpaCyEcPointMultiplyOpData *opData = NULL;
# endif
    CpaBoolean bEcStatus = 0;
    CpaFlatBuffer *pResultX = NULL;
    CpaFlatBuffer *pResultY = NULL;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
    CpaStatus status = CPA_STATUS_FAIL;
    op_done_t op_done;
    thread_local_variables_t *tlv = NULL;
    int curve_name;

    DEBUG("QAT HW ECDH Started\n");
#ifdef ENABLE_QAT_FIPS
    qat_fips_get_approved_status();
#endif
    START_RDTSC(&qat_hw_ecdh_derive_req_prepare);

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

    curve_name = EC_GROUP_get_curve_name(group);
# if defined(QAT20_OOT) || defined(QAT_HW_INTREE)
    pOpData = (CpaCyEcGenericPointMultiplyOpData *)
               OPENSSL_zalloc(sizeof(CpaCyEcGenericPointMultiplyOpData));
    if (pOpData == NULL) {
        WARN("Failure to allocate pOpData\n");
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_POPDATA_MALLOC_FAILURE);
        return ret;
    }

    pOpData->pCurve = (CpaCyEcCurve *) qaeCryptoMemAlloc(sizeof(CpaCyEcCurve),
                                         __FILE__, __LINE__);
    if (pOpData->pCurve == NULL) {
        WARN("Failure to allocate pOpData->pCurve\n");
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_POPDATA_PCURVE_MALLOC_FAILURE);
        OPENSSL_free(pOpData);
        return ret;
    }

    if (outY != NULL)
        pOpData->generator = CPA_TRUE;
    else
        pOpData->generator = CPA_FALSE;

    pOpData->k.pData = NULL;
    pOpData->xP.pData = NULL;
    pOpData->yP.pData = NULL;
    pOpData->pCurve->parameters.weierstrassParameters.a.pData = NULL;
    pOpData->pCurve->parameters.weierstrassParameters.b.pData = NULL;
    pOpData->pCurve->parameters.weierstrassParameters.p.pData = NULL;
    pOpData->pCurve->parameters.weierstrassParameters.h.pData = NULL;
    pOpData->pCurve->parameters.weierstrassParameters.h.dataLenInBytes = 0;
# else
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
    opData->h.pData = NULL;
    opData->h.dataLenInBytes = 0;
# endif

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
    h = BN_CTX_get(ctx);
    xP = BN_CTX_get(ctx);
    yP = BN_CTX_get(ctx);

    if (yP == NULL) {
        WARN("Failed to allocate p, a, b, xP or yP\n");
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_P_A_B_XP_YP_MALLOC_FAILURE);
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

    if (!EC_GROUP_get_cofactor(group, h, ctx)) {
        WARN("Failure in get cofactor\n");
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_GET_COFACTOR_FAILURE);
        goto err;
    }

    if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {
        WARN("Failure to get the curve\n");
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!EC_POINT_get_affine_coordinates(group, pub_key, xP, yP, ctx)) {
        WARN("Failure to get the affine coordinates\n");
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

# if defined(QAT20_OOT) || defined(QAT_HW_INTREE)
    pOpData->pCurve->parameters.weierstrassParameters.fieldType = qat_get_field_type(group);
    pOpData->pCurve->curveType = qat_get_curve(pOpData->pCurve->parameters.weierstrassParameters.fieldType);

    if ((qat_BN_to_FB(&(pOpData->k), (BIGNUM *)priv_key) != 1) ||
        (qat_BN_to_FB(&(pOpData->xP), xP) != 1) ||
        (qat_BN_to_FB(&(pOpData->yP), yP) != 1) ||
        (qat_BN_to_FB(&(pOpData->pCurve->parameters.weierstrassParameters.a), a) != 1) ||
        (qat_BN_to_FB(&(pOpData->pCurve->parameters.weierstrassParameters.b), b) != 1) ||
        (qat_BN_to_FB(&(pOpData->pCurve->parameters.weierstrassParameters.p), p) != 1)) {
        WARN("Failure to convert priv_key, xP, yP, a, b or p to flatbuffer\n");
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_PRIV_KEY_XP_YP_A_B_P_CONVERT_TO_FB_FAILURE);
        goto err;
     }

#ifndef QAT_OPENSSL_PROVIDER
     /* Pass Co-factor to Opdata */
     if (pOpData->pCurve->parameters.weierstrassParameters.fieldType
         == CPA_CY_EC_FIELD_TYPE_PRIME) {
         if (qat_BN_to_FB(&(pOpData->pCurve->parameters.weierstrassParameters.h), h) != 1) {
             WARN("Failure to convert h to flatbuffer\n");
             QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_H_CONVERT_TO_FB_FAILURE);
             goto err;
         }
     }
#else
     if (qat_BN_to_FB(&(pOpData->pCurve->parameters.weierstrassParameters.h), h) != 1) {
	 WARN("Failure to convert h to flatbuffer\n");
	 QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_H_CONVERT_TO_FB_FAILURE);
	 goto err;
     }
#endif

    /*
     * This is a special handling required for curves with 'a' co-efficient
     * of 0. The translation to a flatbuffer results in a zero sized field
     * but the Quickassist API expects a flatbuffer of size 1 with a value
     * of zero. As a special case we will create that manually.
     */

    if (pOpData->pCurve->parameters.weierstrassParameters.a.pData == NULL &&
        pOpData->pCurve->parameters.weierstrassParameters.a.dataLenInBytes == 0) {
        pOpData->pCurve->parameters.weierstrassParameters.a.pData =
                qaeCryptoMemAlloc(1, __FILE__, __LINE__);
        if (pOpData->pCurve->parameters.weierstrassParameters.a.pData == NULL) {
            WARN("Failure to allocate pOpData->pCurve->parameters.weierstrassParameters.a.pData\n");
            QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_POPDATA_A_PDATA_MALLOC_FAILURE);
            goto err;
        }
        pOpData->pCurve->parameters.weierstrassParameters.a.dataLenInBytes = 1;
        pOpData->pCurve->parameters.weierstrassParameters.a.pData[0] = 0;
    }
# else
    opData->fieldType = qat_get_field_type(group);

    if ((qat_BN_to_FB(&(opData->k), (BIGNUM *)priv_key) != 1) ||
        (qat_BN_to_FB(&(opData->xg), xP) != 1) ||
        (qat_BN_to_FB(&(opData->yg), yP) != 1) ||
        (qat_BN_to_FB(&(opData->a), a) != 1) ||
        (qat_BN_to_FB(&(opData->b), b) != 1) ||
        (qat_BN_to_FB(&(opData->q), p) != 1)) {
        WARN("Failure to convert priv_key, xg, yg, a, b or p to flatbuffer\n");
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_PRIV_KEY_XG_YG_A_B_P_CONVERT_TO_FB_FAILURE);
        goto err;
    }

    /* Pass Co-factor to Opdata */
    if (opData->fieldType == CPA_CY_EC_FIELD_TYPE_PRIME) {
        if (qat_BN_to_FB(&(opData->h), h) != 1) {
            WARN("Failure to convert h to flatbuffer\n");
            QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_H_CONVERT_TO_FB_FAILURE);
            goto err;
        }
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
# endif

    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
            WARN("could not create local variables\n");
            QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            goto err;
    }

    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(op_done.job) == 0) {
            WARN("Failed to setup async event notification\n");
            QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            goto err;
        }
    }
    CRYPTO_QAT_LOG("KX - %s\n", __func__);
    STOP_RDTSC(&qat_hw_ecdh_derive_req_prepare, 1, "[QAT HW ECDH: prepare]");

    /* Invoke the crypto engine API for EC Point Multiply */
    do {
        START_RDTSC(&qat_hw_ecdh_derive_req_submit);
        if ((inst_num = get_next_inst_num(INSTANCE_TYPE_CRYPTO_ASYM))
             == QAT_INVALID_INSTANCE) {
            WARN("Failed to get an instance\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                *fallback = 1;
            } else {
                QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            }
            if (op_done.job != NULL) {
                qat_clear_async_event_notification(op_done.job);
            }
            qat_cleanup_op_done(&op_done);
            goto err;
        }

        CRYPTO_QAT_LOG("KX - %s\n", __func__);
# if defined(QAT20_OOT) || defined(QAT_HW_INTREE)
        DUMP_EC_GENERIC_POINT_MULTIPLY(qat_instance_handles[inst_num], pOpData, pResultX, pResultY);
        status = cpaCyEcGenericPointMultiply(qat_instance_handles[inst_num],
                                             qat_ecCallbackFn,
                                             &op_done,
                                             pOpData,
                                             &bEcStatus, pResultX, pResultY);
# else
        DUMP_EC_POINT_MULTIPLY(qat_instance_handles[inst_num], opData, pResultX, pResultY);
        status = cpaCyEcPointMultiply(qat_instance_handles[inst_num],
                                      qat_ecCallbackFn,
                                      &op_done,
                                      opData,
                                      &bEcStatus, pResultX, pResultY);
# endif
        STOP_RDTSC(&qat_hw_ecdh_derive_req_submit, 1, "[QAT HW ECDH: submit]");
        if (status == CPA_STATUS_RETRY) {
            if (qat_ecdh_coexist &&
                ((curve_name == NID_X9_62_prime256v1) ||
                (curve_name == NID_secp384r1))) {
                START_RDTSC(&qat_hw_ecdh_derive_req_retry);
                if (op_done.job) {
                    DEBUG("cpaCyEcPointMultiply Retry \n");
                    if (outY) { /* key generation */
                        ++num_ecdh_keygen_retry;
                        qat_sw_ecdh_keygen_req += QAT_RETRY_COUNT;
                    } else { /* compute key */
                        ++num_ecdh_derive_retry;
                        qat_sw_ecdh_derive_req += QAT_RETRY_COUNT;
                    }
                    *fallback = 1;
                    qat_cleanup_op_done(&op_done);
                    STOP_RDTSC(&qat_hw_ecdh_derive_req_retry, 1, "[QAT HW ECDH: retry]");
                    goto err;
                }
            } else {
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
        } else if (status == CPA_STATUS_UNSUPPORTED) {
            WARN("Algorithm Unsupported in QAT_HW! Using OpenSSL SW\n");
            *fallback = 1;
        } else {
            QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        }
        if (op_done.job != NULL) {
            qat_clear_async_event_notification(op_done.job);
        }
        qat_cleanup_op_done(&op_done);
        goto err;
    }

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (sem_post(&hw_polling_thread_sem) != 0) {
                WARN("hw sem_post failed!, hw_polling_thread_sem address: %p.\n",
                      &hw_polling_thread_sem);
                QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                goto err;
            }
        }
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

    if (qat_ecdh_coexist) {
        if (outY) {
            ++num_ecdh_hw_keygen_reqs;
        }
        else {
            ++num_ecdh_hw_derive_reqs;
        }
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
                sched_yield();
        } else {
            sched_yield();
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
        if (unlikely(pResultX->pData == NULL)) {
            WARN("pResultX->pData is NULL\n");
            QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
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
        if (unlikely(pResultY->pData == NULL)) {
            WARN("pResultY->pData is NULL\n");
            QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        memcpy(*outY, pResultY->pData, pResultY->dataLenInBytes);
    }
    ret = *outlenX;

 err:
    START_RDTSC(&qat_hw_ecdh_derive_req_cleanup);
    if (pResultX) {
        QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(*pResultX);
        OPENSSL_free(pResultX);
    }
    if (pResultY) {
        QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(*pResultY);
        OPENSSL_free(pResultY);
    }

# if defined(QAT20_OOT) || defined(QAT_HW_INTREE)
    if (pOpData) {
        QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(pOpData->k);
        QAT_CHK_QMFREE_FLATBUFF(pOpData->xP);
        QAT_CHK_QMFREE_FLATBUFF(pOpData->yP);
        QAT_CHK_QMFREE_FLATBUFF(pOpData->pCurve->parameters.weierstrassParameters.a);
        QAT_CHK_QMFREE_FLATBUFF(pOpData->pCurve->parameters.weierstrassParameters.b);
        QAT_CHK_QMFREE_FLATBUFF(pOpData->pCurve->parameters.weierstrassParameters.p);
        QAT_CHK_QMFREE_FLATBUFF(pOpData->pCurve->parameters.weierstrassParameters.h);
        QAT_QMEMFREE_BUFF(pOpData->pCurve);
        OPENSSL_free(pOpData);
    }
# else
    if (opData) {
        QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(opData->k);
        QAT_CHK_QMFREE_FLATBUFF(opData->xg);
        QAT_CHK_QMFREE_FLATBUFF(opData->yg);
        QAT_CHK_QMFREE_FLATBUFF(opData->a);
        QAT_CHK_QMFREE_FLATBUFF(opData->b);
        QAT_CHK_QMFREE_FLATBUFF(opData->q);
        QAT_CHK_QMFREE_FLATBUFF(opData->h);
        OPENSSL_free(opData);
    }
# endif
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    STOP_RDTSC(&qat_hw_ecdh_derive_req_cleanup, 1, "[QAT HW ECDH: cleanup]");
    DEBUG("- Finished\n");
    return ret;
}


int qat_engine_ecdh_compute_key(unsigned char **out,
                                size_t *outlen,
                                const EC_POINT *pub_key,
                                const EC_KEY *ecdh)
{
    int fallback = 0, ret = 0;
    PFUNC_COMP_KEY comp_key_pfunc = NULL;
    const EC_GROUP *group = NULL;
    const BIGNUM *priv_key = NULL;
#ifndef QAT_INSECURE_ALGO
    int bitlen = 0;
#endif

    DEBUG("QAT HW ECDH Started\n");

    EC_KEY_METHOD_get_compute_key((EC_KEY_METHOD *)EC_KEY_OpenSSL(), &comp_key_pfunc);
    if (comp_key_pfunc == NULL) {
        WARN("comp_key_pfunc is NULL\n");
        QATerr(QAT_F_QAT_ENGINE_ECDH_COMPUTE_KEY, QAT_R_SW_GET_COMPUTE_KEY_PFUNC_NULL);
        return ret;
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

    if (qat_sw_ecdh_derive_req > 0 || qat_get_qat_offload_disabled()) {
        fallback = 1;
        goto exit;
    }

#ifndef QAT_INSECURE_ALGO
    /* Bits < 256 is not supported in QAT_HW */
    bitlen = EC_GROUP_order_bits(group);
    if (bitlen < QAT_EC_MIN_RANGE) {
        DEBUG("Curve-Bitlen %d not supported! Using OPENSSL_SW\n", bitlen);
        fallback = 1;
        goto exit;
    }
#endif

    ret = qat_ecdh_compute_key(out, outlen, NULL, NULL, pub_key, ecdh, &fallback);

exit:
    if (fallback == 1) {
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
#ifdef ENABLE_QAT_SW_ECDH
        int curve_name = EC_GROUP_get_curve_name(group);
        if (qat_ecdh_coexist && 
            ((curve_name == NID_X9_62_prime256v1) || 
             (curve_name == NID_secp384r1))) {
            DEBUG("- Switched to QAT_SW mode\n");
            if (qat_sw_ecdh_derive_req > 0)
                --qat_sw_ecdh_derive_req;
            return mb_ecdh_compute_key(out, outlen, pub_key, ecdh);
        }
#endif
        WARN("- Fallback to software mode.\n");
        return (*comp_key_pfunc)(out, outlen, pub_key, ecdh);
    }
    DEBUG("- Finished\n");
    return ret;
}


int qat_ecdh_generate_key(EC_KEY *ecdh)
{
    int ok = 0, alloc_priv = 0, alloc_pub = 0;
    int field_size = 0, fallback = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *priv_key = NULL, *order = NULL, *x_bn = NULL,
           *y_bn = NULL, *tx_bn = NULL, *ty_bn = NULL;
    EC_POINT *pub_key = NULL;
    const EC_POINT *gen;
    const EC_GROUP *group = NULL;
    unsigned char *temp_xbuf = NULL;
    unsigned char *temp_ybuf = NULL;
    size_t temp_xfield_size = 0;
    size_t temp_yfield_size = 0;
    PFUNC_GEN_KEY gen_key_pfunc = NULL;
#ifndef QAT_INSECURE_ALGO
    int bitlen = 0;
#endif

    DEBUG("QAT HW ECDH Started\n");

    EC_KEY_METHOD_get_keygen((EC_KEY_METHOD *) EC_KEY_OpenSSL(), &gen_key_pfunc);
    if (gen_key_pfunc == NULL) {
        WARN("get keygen failed\n");
        QATerr(QAT_F_QAT_ECDH_GENERATE_KEY, QAT_R_SW_GET_KEYGEN_PFUNC_NULL);
        return 0;
    }

    if (unlikely(ecdh == NULL || ((group = EC_KEY_get0_group(ecdh)) == NULL))) {
        WARN("Either ecdh or group are NULL\n");
        QATerr(QAT_F_QAT_ECDH_GENERATE_KEY, QAT_R_ECDH_GROUP_NULL);
        return 0;
    }

    if (qat_sw_ecdh_keygen_req > 0 || qat_get_qat_offload_disabled()) {
        fallback = 1;
        goto exit;
    }

#ifndef QAT_INSECURE_ALGO
    /* Bits < 256 is not supported in QAT_HW */
    bitlen = EC_GROUP_order_bits(group);
    if (bitlen < QAT_EC_MIN_RANGE) {
        DEBUG("Curve-Bitlen %d not supported! Using OPENSSL_SW\n", bitlen);
        fallback = 1;
        goto exit;
    }
#endif

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

    if (!EC_POINT_set_affine_coordinates(group, pub_key, x_bn, y_bn, ctx)) {
        WARN("Failure to get the affine coordinates\n");
        QATerr(QAT_F_QAT_ECDH_GENERATE_KEY, QAT_R_ECDH_SET_AFFINE_COORD_FAILED);
        goto err;
    }

    if (!EC_POINT_get_affine_coordinates(group, pub_key, tx_bn, ty_bn, ctx)) {
        WARN("Failure to get the affine coordinates\n");
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

exit:
    if (fallback == 1) {
#ifdef ENABLE_QAT_SW_ECDH
        int curve_name = EC_GROUP_get_curve_name(group);
        if (qat_ecdh_coexist && 
            ((curve_name == NID_X9_62_prime256v1) || 
             (curve_name == NID_secp384r1))) {
            DEBUG("- Switched to QAT_SW mode\n");
            if (qat_sw_ecdh_keygen_req > 0)
                --qat_sw_ecdh_keygen_req;
            return mb_ecdh_generate_key(ecdh);
        }
#endif
        DEBUG("- Switched to software mode\n");
        return (*gen_key_pfunc)(ecdh);
    }
    return ok;
}
#endif /* #ifdef ENABLE_QAT_HW_ECDH */

#ifdef ENABLE_QAT_HW_ECDSA
#ifndef QAT_BORINGSSL
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
#else
static void qat_ecdsaSignCallbackFn(void *pCallbackTag, CpaStatus status,
                                    void *pOpData, CpaBoolean bEcdsaSignStatus,
                                    CpaFlatBuffer * pResultR,
                                    CpaFlatBuffer * pResultS)
{
    CpaBufferList pBuffer;
    CpaFlatBuffer *ret_sig = NULL;
    ECDSA_SIG *s = NULL;
    size_t bytes_len = 0;
    pBuffer.pBuffers = NULL;
    op_done_t *opDone = NULL;

    if (!bEcdsaSignStatus) {
        WARN("ECDSA sign failed, status %d verifyResult %d\n", status, bEcdsaSignStatus);
        goto err;
    }

    opDone = (op_done_t *)pCallbackTag;
    if (unlikely(opDone == NULL)) {
        WARN("opDone is empty in ECDSA callback\n");
        goto err;
    }

    /* Sync mode */
    if (!opDone->job) {
        return qat_crypto_callbackFn(pCallbackTag, status,
                        CPA_CY_SYM_OP_CIPHER, pOpData, NULL, bEcdsaSignStatus);
    }

    /* Async mode */
    if (!opDone->job->waitctx || !opDone->job->waitctx->data) {
        WARN("Async job context or data buffer is empty\n");
        goto err;
    }

    ret_sig = (CpaFlatBuffer *)(opDone->job->waitctx->data);
    pBuffer.pBuffers = ret_sig;

    s = ECDSA_SIG_new();
    if (!s) {
        WARN("Failure to allocate ECDSA_SIG in ECDSA callback\n");
        goto err;
    }

    BN_bin2bn(pResultR->pData, pResultR->dataLenInBytes, s->r);
    BN_bin2bn(pResultS->pData, pResultS->dataLenInBytes, s->s);

    CBB cbb;
    CBB_zero(&cbb);
    if (!CBB_init_fixed(&cbb, ret_sig->pData, ret_sig->dataLenInBytes) ||
        !ECDSA_SIG_marshal(&cbb, s) ||
        !CBB_finish(&cbb, NULL, &bytes_len)) {
        CBB_cleanup(&cbb);
    }
    ret_sig->dataLenInBytes = bytes_len;

err:
    if (s)
        ECDSA_SIG_free(s);
    if (pResultR) {
        QAT_CHK_QMFREE_FLATBUFF(*pResultR);
        OPENSSL_free(pResultR);
    }
    if (pResultS) {
        QAT_CHK_QMFREE_FLATBUFF(*pResultS);
        OPENSSL_free(pResultS);
    }

    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          &pBuffer, bEcdsaSignStatus);
}

static void ec_decrypt_op_buf_free(CpaCyEcdsaSignRSOpData * opData,
                        CpaFlatBuffer* out_buf)
{
    if (out_buf) {
        if (out_buf->pData) {
            qaeCryptoMemFreeNonZero(out_buf->pData);
        }
        OPENSSL_free(out_buf);
    }

    if (opData) {
        QAT_CHK_QMFREE_FLATBUFF(opData->n);
        QAT_CHK_QMFREE_FLATBUFF(opData->m);
        QAT_CHK_QMFREE_FLATBUFF(opData->xg);
        QAT_CHK_QMFREE_FLATBUFF(opData->yg);
        QAT_CHK_QMFREE_FLATBUFF(opData->a);
        QAT_CHK_QMFREE_FLATBUFF(opData->b);
        QAT_CHK_QMFREE_FLATBUFF(opData->q);
        QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(opData->k);
        QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(opData->d);
        OPENSSL_free(opData);
    }
}
#endif /* QAT_BORINGSSL */

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


#ifndef QAT_BORINGSSL
int qat_ecdsa_sign(int type, const unsigned char *dgst, int dlen,
                   unsigned char *sig, unsigned int *siglen,
                   const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey)
{
    ECDSA_SIG *s;
#ifdef ENABLE_QAT_SW_ECDSA
    const EC_GROUP *group = NULL;
    int curve_name;
#endif

    if (unlikely(dgst == NULL ||
                 eckey == NULL ||
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

#ifdef ENABLE_QAT_SW_ECDSA
    group = EC_KEY_get0_group(eckey);
    if(!group) {
        WARN("Failed to get the group from eckey.\n");
        QATerr(QAT_F_QAT_ECDSA_SIGN, QAT_R_GROUP_NULL);
        return 0;
    }

    curve_name = EC_GROUP_get_curve_name(group);
    if (qat_ecdsa_coexist) {
        /* Use QAT SW if the curve is P256 or QAT device not enough.*/
        if (curve_name == NID_X9_62_prime256v1 || qat_get_qat_offload_disabled()) {
            return mb_ecdsa_sign(type, dgst, dlen, sig, siglen, kinv, r, eckey);
        }

        if ((qat_sw_ecdsa_sign_req > 0) && (curve_name == NID_secp384r1)) {
            --qat_sw_ecdsa_sign_req;
            return mb_ecdsa_sign(type, dgst, dlen, sig, siglen, kinv, r, eckey);
        }
    }
#endif

    s = qat_ecdsa_do_sign(dgst, dlen, kinv, r, eckey);
    if (s == NULL) {
#ifdef ENABLE_QAT_SW_ECDSA
        /* Switch to QAT_SW only for P384 curve. */
        if (qat_ecdsa_coexist && (curve_name == NID_secp384r1)) {
            --qat_sw_ecdsa_sign_req;
            return mb_ecdsa_sign(type, dgst, dlen, sig, siglen, kinv, r, eckey);
        }
#endif
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
#endif /* QAT_BORINGSSL */


ECDSA_SIG *qat_ecdsa_do_sign(const unsigned char *dgst, int dgst_len,
                             const BIGNUM *in_kinv, const BIGNUM *in_r,
                             EC_KEY *eckey)
{
    int ok = 0, i, job_ret = 0, fallback = 0;
    BIGNUM *m = NULL, *order = NULL;
    BN_CTX *ctx = NULL;
    const EC_GROUP *group = NULL;
    ECDSA_SIG *ret = NULL;
    BIGNUM *ecdsa_sig_r = NULL, *ecdsa_sig_s = NULL;
    const BIGNUM *priv_key = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *k = NULL;
    BIGNUM *xg = NULL, *yg = NULL;
    const EC_POINT *pub_key = NULL;
    PFUNC_SIGN_SIG sign_sig_pfunc = NULL;

    CpaFlatBuffer *pResultR = NULL;
    CpaFlatBuffer *pResultS = NULL;
#ifdef QAT_BORINGSSL
    CpaFlatBuffer *ret_sig = NULL;
    op_done_t *op_done_bssl = NULL;
#endif /* QAT_BORINGSSL */
    int inst_num = QAT_INVALID_INSTANCE;
    CpaCyEcdsaSignRSOpData *opData = NULL;
    CpaBoolean bEcdsaSignStatus = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    size_t buflen = 0;
    op_done_t op_done;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
    const EC_POINT *ec_point = NULL;
    thread_local_variables_t *tlv = NULL;
    int curve_name;
#ifndef QAT_INSECURE_ALGO
    int bitlen = 0;
#endif

    DEBUG("QAT HW ECDSA Started\n");
#ifdef ENABLE_QAT_FIPS
    qat_fips_get_approved_status();
#endif
    START_RDTSC(&qat_hw_ecdsa_sign_req_prepare);

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

    /* For the scenario of QAT HW initialization fail. */
    if (fallback_to_qat_sw || fallback_to_openssl) {
        WARN("- Fallback to software mode.\n");
        return (*sign_sig_pfunc)(dgst, dgst_len, in_kinv, in_r, eckey);
    }

    if (qat_get_qat_offload_disabled()) {
        fallback = 1;
        goto err;
    }

    group = EC_KEY_get0_group(eckey);
    priv_key = EC_KEY_get0_private_key(eckey);
    pub_key = EC_KEY_get0_public_key(eckey);

    if (group == NULL || priv_key == NULL || pub_key == NULL) {
        WARN("Either group, priv_key or pub_key are NULL\n");
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, QAT_R_GROUP_PRIV_KEY_PUB_KEY_NULL);
        return ret;
    }

#ifndef QAT_INSECURE_ALGO
    /* Bits < 256 is not supported in QAT_HW */
    bitlen = EC_GROUP_order_bits(group);
    if (bitlen < QAT_EC_MIN_RANGE) {
        DEBUG("Curve-Bitlen %d not supported! Using OPENSSL_SW\n", bitlen);
        return (*sign_sig_pfunc)(dgst, dgst_len, in_kinv, in_r, eckey);
    }
#endif

    curve_name = EC_GROUP_get_curve_name(group);
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

#ifdef QAT_BORINGSSL
    if (!EC_GROUP_get_curve_GFp(group, p, a, b, ctx)) {
#else
    if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {
#endif /* QAT_BORINGSSL */
        WARN("Failure to get the curve\n");
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!EC_POINT_get_affine_coordinates(group, ec_point, xg, yg, ctx)) {
        WARN("Failure to get the affine coordinates\n");
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

#ifdef ENABLE_QAT_FIPS
    if (in_kinv == NULL || in_r == NULL) {
        if (qat_fips_kat_test == 0) {
            do
                if (!BN_rand_range(k, order)) {
                    WARN("Failure to get random number k\n");
                    QATerr(QAT_F_QAT_ECDSA_DO_SIGN, QAT_R_K_RAND_GENERATE_FAILURE);
                    goto err;
                }
            while (BN_is_zero(k));
        } else {
            if (!BN_bin2bn(kvalue, sizeof(kvalue), k)) {
                WARN("Failure to get k value\n");
                goto err;
            }
        }
#else
    if (in_kinv == NULL || in_r == NULL) {
        do
            if (!BN_rand_range(k, order)) {
                WARN("Failure to get random number k\n");
                QATerr(QAT_F_QAT_ECDSA_DO_SIGN, QAT_R_K_RAND_GENERATE_FAILURE);
                goto err;
            }
        while (BN_is_zero(k));
#endif

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

    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(op_done.job) == 0) {
            WARN("Failure to setup async event notifications\n");
            QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            goto err;
        }
    }

#ifdef QAT_BORINGSSL
    if (op_done.job) {
        ret_sig = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
        if (ret_sig == NULL) {
            WARN("Failure to allocate ret_sig\n");
            goto err;
        }
        ret_sig->pData = qaeCryptoMemAlloc(ECDSA_size(eckey), __FILE__, __LINE__);
        if (ret_sig->pData == NULL) {
            WARN("Failure to allocate ret_sig->pData\n");
            goto err;
        }
        ret_sig->dataLenInBytes = (Cpa32U)ECDSA_size(eckey);

        op_done.job->waitctx->data = ret_sig;
        op_done_bssl = (op_done_t *)op_done.job->copy_op_done(&op_done,
                        sizeof(op_done),
                        (void (*)(void *, void *))ec_decrypt_op_buf_free);
    }
#endif /* QAT_BORINGSSL */

    STOP_RDTSC(&qat_hw_ecdsa_sign_req_prepare, 1, "[QAT HW ECDSA: prepare]");

    CRYPTO_QAT_LOG("AU - %s\n", __func__);

    do {
        START_RDTSC(&qat_hw_ecdsa_sign_req_submit);
        if ((inst_num = get_next_inst_num(INSTANCE_TYPE_CRYPTO_ASYM))
             == QAT_INVALID_INSTANCE) {
            WARN("Failure to get another instance\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                fallback = 1;
            } else {
                QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
            }
            if (op_done.job != NULL) {
#ifdef QAT_BORINGSSL
                op_done.job->free_op_done(op_done_bssl);
#endif
                qat_clear_async_event_notification(op_done.job);
            }
            qat_cleanup_op_done(&op_done);
            goto err;
        }

        CRYPTO_QAT_LOG("AU - %s\n", __func__);
        DUMP_ECDSA_SIGN(qat_instance_handles[inst_num], opData, pResultR, pResultS);
#ifndef QAT_BORINGSSL
        status = cpaCyEcdsaSignRS(qat_instance_handles[inst_num],
                                  qat_ecdsaSignCallbackFn,
                                  &op_done,
                                  opData,
                                  &bEcdsaSignStatus, pResultR, pResultS);
#else
        if (op_done.job) {
            status = cpaCyEcdsaSignRS(qat_instance_handles[inst_num],
                                qat_ecdsaSignCallbackFn,
                                op_done_bssl,
                                opData,
                                &bEcdsaSignStatus, pResultR, pResultS);
        }
        else {
            DEBUG("Running sync mode for ECDSA request\n");
            status = cpaCyEcdsaSignRS(qat_instance_handles[inst_num],
                                    qat_ecdsaSignCallbackFn,
                                    &op_done,
                                    opData,
                                    &bEcdsaSignStatus, pResultR, pResultS);
        }
#endif /* QAT_BORINGSSL */
        STOP_RDTSC(&qat_hw_ecdsa_sign_req_submit, 1, "[QAT HW ECDSA: submit]");
        if (status == CPA_STATUS_RETRY) {
            DEBUG("cpaCyEcdsaSignRS Retry \n");
            if (qat_ecdsa_coexist && (curve_name == NID_secp384r1)) {
                START_RDTSC(&qat_hw_ecdsa_sign_req_retry);
                ++num_ecdsa_sign_retry;
                qat_sw_ecdsa_sign_req += QAT_RETRY_COUNT;

                fallback = 1;
                qat_cleanup_op_done(&op_done);
                STOP_RDTSC(&qat_hw_ecdsa_sign_req_retry, 1, "[QAT HW ECDSA: retry]");
                goto err;
            } else {
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
    #ifndef QAT_BORINGSSL
                    if ((qat_wake_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0) ||
                        (qat_pause_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0)) {
                        WARN("qat_wake_job or qat_pause_job failed\n");
                        break;
                    }
    #endif
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
        } else if (status == CPA_STATUS_UNSUPPORTED) {
            WARN("Algorithm Unsupported in QAT_HW! Using OpenSSL SW\n");
            fallback = 1;
        } else {
            QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        }
        if (op_done.job != NULL) {
#ifdef QAT_BORINGSSL
            op_done.job->free_op_done(op_done_bssl);
#endif
            qat_clear_async_event_notification(op_done.job);
        }
        qat_cleanup_op_done(&op_done);
        goto err;
    }

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (sem_post(&hw_polling_thread_sem) != 0) {
                WARN("hw sem_post failed!, hw_polling_thread_sem address: %p.\n",
                      &hw_polling_thread_sem);
                QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
#ifdef QAT_BORINGSSL
                if (op_done.job)
                    op_done.job->free_op_done(op_done_bssl);
#endif
                goto err;
            }
        }
    }

#ifdef QAT_BORINGSSL
    if (op_done.job != NULL) {
        qat_cleanup_op_done(&op_done);
        if (ctx) {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
        }
        return ret;
    }
#endif
    if (qat_get_sw_fallback_enabled()) {
        CRYPTO_QAT_LOG("Submit success qat inst_num %d device_id %d - %s\n", inst_num,
                       qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                       __func__);
    }

    if (enable_heuristic_polling) {
        QAT_ATOMIC_INC(num_asym_requests_in_flight);
    }

    if (qat_ecdsa_coexist) {
        ++num_ecdsa_hw_sign_reqs;
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
                sched_yield();
        } else {
#ifdef QAT_BORINGSSL
            /* Support inline polling in current scenario */
            if(getEnableInlinePolling()) {
                icp_sal_CyPollInstance(qat_instance_handles[inst_num], 0);
                ECDSA_INLINE_POLLING_USLEEP();
            } else {
                sched_yield();
            }
#else
            sched_yield();
#endif /* QAT_BORINGSSL */
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
    START_RDTSC(&qat_hw_ecdsa_sign_req_cleanup);
    if (!ok) {
        ECDSA_SIG_free(ret);
        ret = NULL;
    }

#ifdef QAT_BORINGSSL
    if (ret_sig) {
        QAT_CHK_QMFREE_FLATBUFF(*ret_sig);
        OPENSSL_free(ret_sig);
    }
#endif /* QAT_BORINGSSL */

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
        QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(opData->k);
        QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(opData->d);
        OPENSSL_free(opData);
    }

    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    STOP_RDTSC(&qat_hw_ecdsa_sign_req_cleanup, 1, "[QAT HW ECDSA: cleanup]");

    if (fallback) {
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
        if (qat_ecdsa_coexist) {
            DEBUG("- Switch to QAT_SW mode.\n");
            return NULL;
        } else {
            WARN("- Fallback to software mode.\n");
            return (*sign_sig_pfunc)(dgst, dgst_len, in_kinv, in_r, eckey);
        }
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
        return ret;
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
    OPENSSL_free(der);
    ECDSA_SIG_free(s);
    return ret;
}


int qat_ecdsa_do_verify(const unsigned char *dgst, int dgst_len,
                        const ECDSA_SIG *sig, EC_KEY *eckey)
{
    int ret = -1, job_ret = 0, fallback = 0, i = 0;
    BN_CTX *ctx = NULL;
    const EC_GROUP *group = NULL;
    const EC_POINT *pub_key = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    const EC_POINT *ec_point = NULL;
    PFUNC_VERIFY_SIG verify_sig_pfunc = NULL;
    int inst_num = QAT_INVALID_INSTANCE;
    BIGNUM *xg = NULL, *yg = NULL, *xp = NULL, *yp = NULL;
    BIGNUM *order = NULL, *m = NULL;
    const BIGNUM *sig_r = NULL, *sig_s = NULL;
    CpaCyEcdsaVerifyOpData *opData = NULL;
    CpaBoolean bEcdsaVerifyStatus = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    op_done_t op_done;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
    thread_local_variables_t *tlv = NULL;
#ifndef QAT_INSECURE_ALGO
    int bitlen = 0;
#endif

    DEBUG("QAT HW ECDSA Started\n");
#ifdef ENABLE_QAT_FIPS
    qat_fips_get_approved_status();
#endif
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

#ifndef QAT_INSECURE_ALGO
    /* Bits < 256 is not supported in QAT_HW */
    bitlen = EC_GROUP_order_bits(group);
    if (bitlen < QAT_EC_MIN_RANGE) {
        DEBUG("Curve-Bitlen %d not supported! Using OPENSSL_SW\n", bitlen);
        return (*verify_sig_pfunc)(dgst, dgst_len, sig, eckey);
    }
#endif

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

#ifdef QAT_BORINGSSL
    if (!EC_GROUP_get_curve_GFp(group, p, a, b, ctx)) {
#else
    if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {
#endif /* QAT_BORINGSSL */
        WARN("Failure to get the curve\n");
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!EC_POINT_get_affine_coordinates(group, ec_point, xg, yg, ctx)) {
        WARN("Failure to get the affine coordinates\n");
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!EC_POINT_get_affine_coordinates(group, pub_key, xp, yp, ctx)) {
        WARN("Failure to get the affine coordinates\n");
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

    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(op_done.job) == 0) {
            WARN("Failure to setup async event notifications\n");
            QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            goto err;
        }
    }

    CRYPTO_QAT_LOG("AU - %s\n", __func__);
    do {
        if ((inst_num = get_next_inst_num(INSTANCE_TYPE_CRYPTO_ASYM))
             == QAT_INVALID_INSTANCE) {
            WARN("Failure to get another instance\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                fallback = 1;
            } else {
                QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
            }
            if (op_done.job != NULL) {
                qat_clear_async_event_notification(op_done.job);
            }
            qat_cleanup_op_done(&op_done);
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
        } else if (status == CPA_STATUS_UNSUPPORTED) {
            WARN("Algorithm Unsupported in QAT_HW! Using OpenSSL SW\n");
            fallback = 1;
        } else {
            QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        }
        if (op_done.job != NULL) {
            qat_clear_async_event_notification(op_done.job);
        }
        qat_cleanup_op_done(&op_done);
        goto err;
    }

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (sem_post(&hw_polling_thread_sem) != 0) {
                WARN("hw sem_post failed!, hw_polling_thread_sem address: %p.\n",
                      &hw_polling_thread_sem);
                QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                goto err;
            }
        }
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
                sched_yield();
        } else {
            sched_yield();
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

#ifdef QAT_BORINGSSL
/* Referred to boringssl/crypto/ecdsa_extra/ecdsa_asn1.c
 */
int qat_ecdsa_sign_bssl(const uint8_t *digest, size_t digest_len, uint8_t *sig,
                        unsigned int *sig_len, EC_KEY *eckey) {

  int ret = 0;
  DEBUG("Start qat_ecdsa_sign_bssl\n");
  ASYNC_JOB* current_job = (ASYNC_JOB*)ASYNC_get_current_job();
  ECDSA_SIG *s = qat_ecdsa_do_sign(digest, digest_len, NULL, NULL, eckey);

  if (s == NULL) {
    *sig_len = 0;
    goto err;
  }

  if (current_job) {
    *sig_len = 0;
    ret = -1;
    goto err;
  }

  CBB cbb;
  CBB_zero(&cbb);
  size_t len;
  if (!CBB_init_fixed(&cbb, sig, ECDSA_size(eckey)) ||
      !ECDSA_SIG_marshal(&cbb, s) ||
      !CBB_finish(&cbb, NULL, &len)) {
    OPENSSL_PUT_ERROR(ECDSA, ECDSA_R_ENCODE_ERROR);
    CBB_cleanup(&cbb);
    *sig_len = 0;
    goto err;
  }
  *sig_len = (unsigned)len;
  ret = 1;

err:
  if (current_job) {
      current_job->tlv_destructor(NULL);
  }
  ECDSA_SIG_free(s);
  return ret;
}
#endif /* QAT_BORINGSSL */
#endif /* #ifdef ENABLE_QAT_HW_ECDSA */
