/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2024 Intel Corporation.
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
 * @file qat_utils.h
 *
 * This file provides an interface to utilities for the QAT engine in OpenSSL
 *
 *****************************************************************************/

#ifndef QAT_UTILS_H
# define QAT_UTILS_H

# include <stdio.h>
# include <pthread.h>
# include <unistd.h>
# include <stdint.h>
# ifdef QAT_HW
#  include "cpa.h"
#  include "cpa_cy_sym.h"
# endif

# define QAT_BYTE_ALIGNMENT 64
# define NANO_TO_MICROSECS 1000
# define NSEC_TO_SEC 1000000000L

/* For best performance data buffers should be 64-byte aligned */
# define QAT_CONTIG_MEM_ALIGN(x)                              \
         (void *)(((uintptr_t)(x) + QAT_BYTE_ALIGNMENT - 1) & \
         (~(uintptr_t)(QAT_BYTE_ALIGNMENT-1)))

extern FILE *qatDebugLogFile;

# ifdef QAT_DEBUG_FILE_PATH
extern pthread_mutex_t debug_file_mutex;
extern int debug_file_ref_count;
void crypto_qat_debug_init_log();
void crypto_qat_debug_close_log();

#  define QAT_DEBUG_LOG_INIT() crypto_qat_debug_init_log()
#  define QAT_DEBUG_LOG_CLOSE() crypto_qat_debug_close_log()
# else
#  define QAT_DEBUG_LOG_INIT()    \
do {                              \
    if (qatDebugLogFile == NULL)  \
        qatDebugLogFile = stderr; \
} while(0)
#  define QAT_DEBUG_LOG_CLOSE()
# endif

/*
 * Add -DQAT_TESTS_LOG to ./config to enable debug logging to the
 * CRYPTO_QAT_LOG_FILE
 */
# ifdef QAT_TESTS_LOG
#  define QAT_MAX_TEST_FILE_NAME_LENGTH 1024
extern FILE *cryptoQatLogger;
extern pthread_mutex_t test_file_mutex;
extern int test_file_ref_count;

void crypto_qat_testing_init_log();
void crypto_qat_testing_close_log();

#  define CRYPTO_INIT_QAT_LOG() crypto_qat_testing_init_log()
#  define CRYPTO_CLOSE_QAT_LOG() crypto_qat_testing_close_log()
#  define CRYPTO_QAT_LOG(...)                       \
do {                                                \
    pthread_mutex_lock(&test_file_mutex);           \
    if (test_file_ref_count) {                      \
        if (cryptoQatLogger != NULL) {              \
            fprintf(cryptoQatLogger, __VA_ARGS__);  \
            fflush(cryptoQatLogger);                \
        }                                           \
    }                                               \
    pthread_mutex_unlock(&test_file_mutex);         \
} while(0)
# else
#  define CRYPTO_QAT_LOG(...)
#  define CRYPTO_CLOSE_QAT_LOG()
#  define CRYPTO_INIT_QAT_LOG()
# endif

/* Debug and warning messages for the QAT engine */
# ifdef QAT_DEBUG
void qat_hex_dump(const char *func, const char *var, const unsigned char p[],
                  int l);

#  define DEBUG(fmt_str, ...)                                  \
    do {                                                       \
        struct timespec ts = { 0 };                            \
        clock_gettime(CLOCK_MONOTONIC, &ts);                   \
        fprintf(qatDebugLogFile,"[DEBUG][%lld.%06ld] PID [%d]" \
                " Thread [%lx][%s:%d:%s()] "fmt_str,           \
                (long long)ts.tv_sec,                          \
                ts.tv_nsec / NANO_TO_MICROSECS,                \
                getpid(), (long)pthread_self(),  __FILE__,     \
                __LINE__,__func__,##__VA_ARGS__);              \
        fflush(qatDebugLogFile);                               \
    } while (0)
#  define DUMPL(var,p,l) qat_hex_dump(__func__,var,p,l);
# else
#  define DEBUG(...)
#  define DUMPL(...)
# endif

# if defined(QAT_WARN) || defined(QAT_DEBUG)
#  define WARN(fmt_str, ...)                                  \
    do {                                                      \
        struct timespec ts = { 0 };                           \
        clock_gettime(CLOCK_MONOTONIC, &ts);                  \
        fprintf(qatDebugLogFile,"[WARN][%lld.%06ld] PID [%d]" \
                " Thread [%lx][%s:%d:%s()] "fmt_str,          \
                (long long)ts.tv_sec,                         \
                ts.tv_nsec / NANO_TO_MICROSECS,               \
                getpid(), (long)pthread_self(),  __FILE__,    \
                __LINE__,__func__,##__VA_ARGS__);             \
        fflush(qatDebugLogFile);                              \
    } while (0)
# else
#  define WARN(...)
# endif

# define INFO(fmt_str, ...)                                   \
    do {                                                      \
        fprintf(stderr,fmt_str, ##__VA_ARGS__);               \
        fflush(stderr);                                       \
    } while (0)

# ifdef QAT_DEBUG
#  define DUMP_DH_GEN_PHASE1(instance_handle, opData, pPV)                     \
    do {                                                                       \
        fprintf(qatDebugLogFile,"DH Generate Phase 1 Request: %p\n", opData);  \
        fprintf(qatDebugLogFile,"instance_handle = %p\n", instance_handle);    \
        DUMPL("primeP.pData", opData->primeP.pData,                            \
               opData->primeP.dataLenInBytes);                                 \
        DUMPL("baseG.pData", opData->baseG.pData,                              \
               opData->baseG.dataLenInBytes);                                  \
        DUMPL("privateValueX.pData", opData->privateValueX.pData,              \
               opData->privateValueX.dataLenInBytes);                          \
        fprintf(qatDebugLogFile, "pPV->dataLenInBytes = %u pPV->pData = %p\n", \
                pPV->dataLenInBytes, pPV->pData);                              \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_DH_GEN_PHASE2(instance_handle, opData, pSecretKey)              \
    do {                                                                       \
        fprintf(qatDebugLogFile,"DH Generate Phase 2 Request: %p\n", opData);  \
        fprintf(qatDebugLogFile,"instance_handle = %p\n", instance_handle);    \
        DUMPL("primeP.pData", opData->primeP.pData,                            \
               opData->primeP.dataLenInBytes);                                 \
        DUMPL("remoteOctetStringPV.pData",                                     \
               opData->remoteOctetStringPV.pData,                              \
               opData->remoteOctetStringPV.dataLenInBytes);                    \
        DUMPL("privateValueX.pData", opData->privateValueX.pData,              \
               opData->privateValueX.dataLenInBytes);                          \
        fprintf(qatDebugLogFile,"pSecretKey->dataLenInBytes = %u "             \
                "pSecretKey->pData = %p\n",                                    \
                pSecretKey->dataLenInBytes, pSecretKey->pData);                \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_DH_GEN_PHASE1_OUTPUT(pPV)                                       \
    do {                                                                       \
        fprintf(qatDebugLogFile,"DH Generate Phase 1 Output: %p\n", pPV);      \
        DUMPL("pPV->pData", pPV->pData, pPV->dataLenInBytes);                  \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_DH_GEN_PHASE2_OUTPUT(pSecretKey)                                \
    do {                                                                       \
        fprintf(qatDebugLogFile,"DH Generate Phase 2 Output: %p\n",            \
                pSecretKey);                                                   \
        DUMPL("pSecretKey->pData",                                             \
               pSecretKey->pData, pSecretKey->dataLenInBytes);                 \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_EC_POINT_MULTIPLY(instance_handle, opData, pResultX, pResultY)  \
    do {                                                                       \
        fprintf(qatDebugLogFile,"EC Point Multiply Request: %p\n", opData);    \
        fprintf(qatDebugLogFile,"instance_handle = %p\n", instance_handle);    \
        DUMPL("k.pData", opData->k.pData, opData->k.dataLenInBytes);           \
        DUMPL("xg.pData", opData->xg.pData, opData->xg.dataLenInBytes);        \
        DUMPL("yg.pData", opData->yg.pData, opData->yg.dataLenInBytes);        \
        DUMPL("a.pData", opData->a.pData, opData->a.dataLenInBytes);           \
        DUMPL("b.pData", opData->b.pData, opData->b.dataLenInBytes);           \
        DUMPL("q.pData", opData->q.pData, opData->q.dataLenInBytes);           \
        DUMPL("h.pData", opData->h.pData, opData->h.dataLenInBytes);           \
        fprintf(qatDebugLogFile,"opData: fieldType = %d\n", opData->fieldType);\
        fprintf(qatDebugLogFile,"pResultX->dataLenInBytes = %u "               \
                "pResultX->pData = %p\n",                                      \
                pResultX->dataLenInBytes, pResultX->pData);                    \
        fprintf(qatDebugLogFile,"pResultY->dataLenInBytes = %u "               \
                "pResultY->pData = %p\n",                                      \
                pResultY->dataLenInBytes, pResultY->pData);                    \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_EC_GENERIC_POINT_MULTIPLY(instance_handle, pOpData, pResultX, pResultY) \
    do {                                                                      \
        fprintf(qatDebugLogFile,"EC Point Multiply Request: %p\n", pOpData);  \
        fprintf(qatDebugLogFile,"instance_handle = %p\n", instance_handle);   \
        DUMPL("k.pData",  pOpData->k.pData, pOpData->k.dataLenInBytes);       \
        DUMPL("xP.pData", pOpData->xP.pData, pOpData->xP.dataLenInBytes);     \
        DUMPL("yP.pData", pOpData->yP.pData, pOpData->yP.dataLenInBytes);     \
        DUMPL("a.pData", pOpData->pCurve->parameters.weierstrassParameters.a.pData, \
               pOpData->pCurve->parameters.weierstrassParameters.a.dataLenInBytes); \
        DUMPL("b.pData", pOpData->pCurve->parameters.weierstrassParameters.b.pData, \
               pOpData->pCurve->parameters.weierstrassParameters.b.dataLenInBytes); \
        DUMPL("q.pData", pOpData->pCurve->parameters.weierstrassParameters.p.pData, \
               pOpData->pCurve->parameters.weierstrassParameters.p.dataLenInBytes); \
        DUMPL("h.pData", pOpData->pCurve->parameters.weierstrassParameters.h.pData, \
               pOpData->pCurve->parameters.weierstrassParameters.a.dataLenInBytes); \
        fprintf(qatDebugLogFile,"pOpData: generator = %d\n", pOpData->generator);   \
        fprintf(qatDebugLogFile,"pResultX->dataLenInBytes = %u "                    \
               "pResultX->pData = %p\n",                                            \
                pResultX->dataLenInBytes, pResultX->pData);                         \
        fprintf(qatDebugLogFile,"pResultY->dataLenInBytes = %u "                    \
                "pResultY->pData = %p\n",                                           \
                pResultY->dataLenInBytes, pResultY->pData);                         \
        fflush(qatDebugLogFile);                                                    \
    } while (0)

#  define DUMP_EC_SM2_POINT_MULTIPLY(instance_handle, pOpData, pResultX, pResultY) \
    do {                                                                      \
        fprintf(qatDebugLogFile,"EC SM2 Point Multiply Request: %p\n", pOpData);  \
        fprintf(qatDebugLogFile,"instance_handle = %p\n", instance_handle);   \
        DUMPL("k.pData",  pOpData->k.pData, pOpData->k.dataLenInBytes);       \
        DUMPL("x.pData", pOpData->x.pData, pOpData->x.dataLenInBytes);     \
        DUMPL("y.pData", pOpData->y.pData, pOpData->y.dataLenInBytes);     \
        fprintf(qatDebugLogFile,"pResultX->dataLenInBytes = %u "                    \
               "pResultX->pData = %p\n",                                            \
                pResultX->dataLenInBytes, pResultX->pData);                         \
        fprintf(qatDebugLogFile,"pResultY->dataLenInBytes = %u "                    \
                "pResultY->pData = %p\n",                                           \
                pResultY->dataLenInBytes, pResultY->pData);                         \
        fflush(qatDebugLogFile);                                                    \
    } while (0)

#  define DUMP_EC_MONTEDWDS_POINT_MULTIPLY(instance_handle, opData, pXk, pYk)  \
    do {                                                                       \
        fprintf(qatDebugLogFile,"EC ECX Point Multiply Request: %p\n", opData);\
        fprintf(qatDebugLogFile,"instance_handle = %p\n", instance_handle);    \
        DUMPL("k.pData", opData->k.pData, opData->k.dataLenInBytes);           \
        DUMPL("x.pData", opData->x.pData, opData->x.dataLenInBytes);           \
        fprintf(qatDebugLogFile,"opData: curveType = %d\n", opData->curveType);\
        fprintf(qatDebugLogFile,"opData: generator = %d\n", opData->generator);\
        fprintf(qatDebugLogFile,"pXk->dataLenInBytes = %u "                    \
                "pXk->pData = %p\n", pXk->dataLenInBytes, pXk->pData);         \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_EC_POINT_MULTIPLY_OUTPUT(bEcStatus, pResultX, pResultY)         \
    do {                                                                       \
        fprintf(qatDebugLogFile,"EC Point Multiply Output: pResultX %p \n",    \
                pResultX);                          \
        fprintf(qatDebugLogFile,"bEcStatus = %u\n", bEcStatus);                \
        DUMPL("pResultX->pData", pResultX->pData, pResultX->dataLenInBytes);   \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_EC_GENERIC_POINT_MULTIPLY_OUTPUT(bEcStatus, pResultX, pResultY) \
    do {                                                                       \
        fprintf(qatDebugLogFile,"EC Point Multiply Output: pResultX %p \n",    \
                pResultX);                          \
        fprintf(qatDebugLogFile,"bEcStatus = %u\n", bEcStatus);                \
        DUMPL("pResultX->pData", pResultX->pData, pResultX->dataLenInBytes);   \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_ECDSA_SIGN(instance_handle, opData, pResultR, pResultS)         \
    do {                                                                       \
        fprintf(qatDebugLogFile,"ECDSA Sign Request: %p\n", opData);           \
        fprintf(qatDebugLogFile,"instance_handle = %p\n", instance_handle);    \
        DUMPL("xg.pData", opData->xg.pData, opData->xg.dataLenInBytes);        \
        DUMPL("yg.pData", opData->yg.pData, opData->yg.dataLenInBytes);        \
        DUMPL("n.pData", opData->n.pData, opData->n.dataLenInBytes);           \
        DUMPL("q.pData", opData->q.pData, opData->q.dataLenInBytes);           \
        DUMPL("a.pData", opData->a.pData, opData->a.dataLenInBytes);           \
        DUMPL("b.pData", opData->b.pData, opData->b.dataLenInBytes);           \
        DUMPL("k.pData", opData->k.pData, opData->k.dataLenInBytes);           \
        DUMPL("m.pData", opData->m.pData, opData->m.dataLenInBytes);           \
        DUMPL("d.pData", opData->d.pData, opData->d.dataLenInBytes);           \
        fprintf(qatDebugLogFile,"opData: fieldType = %d\n", opData->fieldType);\
        fprintf(qatDebugLogFile,"pResultR->dataLenInBytes = %u "               \
                "pResultR->pData = %p\n",                                      \
                pResultR->dataLenInBytes, pResultR->pData);                    \
        fprintf(qatDebugLogFile,"pResultS->dataLenInBytes = %u "               \
                "pResultS->pData = %p\n",                                      \
                pResultS->dataLenInBytes, pResultS->pData);                    \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_ECDSA_SIGN_OUTPUT(bEcdsaSignStatus, pResultR, pResultS)         \
    do {                                                                       \
        fprintf(qatDebugLogFile,"ECDSA Sign Output:"                           \
                " pResultR %p, pResultS %p\n",                                 \
                pResultR, pResultS);                                           \
        fprintf(qatDebugLogFile, "bEcdsaSignStatus = %u\n", bEcdsaSignStatus); \
        DUMPL("pResultR->pData", pResultR->pData, pResultR->dataLenInBytes);   \
        DUMPL("pResultS->pData", pResultS->pData, pResultS->dataLenInBytes);   \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_ECDSA_VERIFY(instance_handle, opData)                           \
    do {                                                                       \
        fprintf(qatDebugLogFile,"ECDSA Verify Request: %p\n", opData);         \
        fprintf(qatDebugLogFile,"instance_handle = %p\n", instance_handle);    \
        DUMPL("xg.pData", opData->xg.pData, opData->xg.dataLenInBytes);        \
        DUMPL("yg.pData", opData->yg.pData, opData->yg.dataLenInBytes);        \
        DUMPL("n.pData", opData->n.pData, opData->n.dataLenInBytes);           \
        DUMPL("q.pData", opData->q.pData, opData->q.dataLenInBytes);           \
        DUMPL("a.pData", opData->a.pData, opData->a.dataLenInBytes);           \
        DUMPL("b.pData", opData->b.pData, opData->b.dataLenInBytes);           \
        DUMPL("m.pData", opData->m.pData, opData->m.dataLenInBytes);           \
        DUMPL("r.pData", opData->r.pData, opData->r.dataLenInBytes);           \
        DUMPL("s.pData", opData->s.pData, opData->s.dataLenInBytes);           \
        DUMPL("xp.pData", opData->xp.pData, opData->xp.dataLenInBytes);        \
        DUMPL("yp.pData", opData->yp.pData, opData->yp.dataLenInBytes);        \
        fprintf(qatDebugLogFile,"opData: fieldType = %d\n", opData->fieldType);\
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_DSA_SIGN(instance_handle, op_done, opData, bDsaSignStatus,      \
                        pResultR, pResultS)                                    \
    do {                                                                       \
        fprintf(qatDebugLogFile,"DSA Sign Request: %p\n", opData);             \
        fprintf(qatDebugLogFile,"instance_handle = %p\n", instance_handle);    \
        fprintf(qatDebugLogFile,"op_done = %p\n", op_done);                    \
        DUMPL("P.pData", opData->P.pData, opData->P.dataLenInBytes);           \
        DUMPL("Q.pData", opData->Q.pData, opData->Q.dataLenInBytes);           \
        DUMPL("G.pData", opData->G.pData, opData->G.dataLenInBytes);           \
        DUMPL("X.pData", opData->X.pData, opData->X.dataLenInBytes);           \
        DUMPL("K.pData", opData->K.pData, opData->K.dataLenInBytes);           \
        DUMPL("Z.pData", opData->Z.pData, opData->Z.dataLenInBytes);           \
        fprintf(qatDebugLogFile,"bDsaSignStatus = %p\n", bDsaSignStatus);      \
        fprintf(qatDebugLogFile,"pResultR->dataLenInBytes = %u\n",             \
                pResultR->dataLenInBytes);                                     \
        fprintf(qatDebugLogFile,"pResultR->pData = %p\n", pResultR->pData);    \
        fprintf(qatDebugLogFile,"pResultS->dataLenInBytes = %u\n",             \
                pResultS->dataLenInBytes);                                     \
        fprintf(qatDebugLogFile,"pResultS->pData = %p\n", pResultS->pData);    \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_DSA_SIGN_OUTPUT(bDsaSignStatus, pResultR, pResultS)             \
    do {                                                                       \
        fprintf(qatDebugLogFile,"DSA Sign Output:  pResultR %p, pResultS %p\n",\
                pResultR, pResultS);                                           \
        fprintf(qatDebugLogFile,"bDsaSignStatus = %u\n", bDsaSignStatus);      \
        DUMPL("pResultR->pData", pResultR->pData, pResultR->dataLenInBytes);   \
        DUMPL("pResultS->pData", pResultS->pData, pResultS->dataLenInBytes);   \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_DSA_VERIFY(instance_handle, op_done, opData, bDsaVerifyStatus)  \
    do {                                                                       \
        fprintf(qatDebugLogFile,"DSA Verify Request: %p\n", opData);           \
        fprintf(qatDebugLogFile,"instance_handle = %p\n", instance_handle);    \
        fprintf(qatDebugLogFile,"op_done = %p\n", op_done);                    \
        DUMPL("P.pData", opData->P.pData, opData->P.dataLenInBytes);           \
        DUMPL("Q.pData", opData->Q.pData, opData->Q.dataLenInBytes);           \
        DUMPL("G.pData", opData->G.pData, opData->G.dataLenInBytes);           \
        DUMPL("Y.pData", opData->Y.pData, opData->Y.dataLenInBytes);           \
        DUMPL("Z.pData", opData->Z.pData, opData->Z.dataLenInBytes);           \
        DUMPL("R.pData", opData->R.pData, opData->R.dataLenInBytes);           \
        DUMPL("S.pData", opData->S.pData, opData->S.dataLenInBytes);           \
        fprintf(qatDebugLogFile,"bDsaVerifyStatus = %p\n", bDsaVerifyStatus);  \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_RSA_ENCRYPT(instance_handle, op_done, opData, output_buf)       \
    do {                                                                       \
        fprintf(qatDebugLogFile,"RSA Encrypt Request: %p\n", opData);          \
        fprintf(qatDebugLogFile,"instance_handle = %p\n", instance_handle);    \
        fprintf(qatDebugLogFile,"op_done = %p\n", op_done);                    \
        DUMPL("opData->pPublicKey->modulusN.pData",                            \
               opData->pPublicKey->modulusN.pData,                             \
               opData->pPublicKey->modulusN.dataLenInBytes);                   \
        DUMPL("opData->pPublicKey->publicExponentE.pData",                     \
               opData->pPublicKey->publicExponentE.pData,                      \
               opData->pPublicKey->publicExponentE.dataLenInBytes);            \
        DUMPL("opData->inputData.pData", opData->inputData.pData,              \
               opData->inputData.dataLenInBytes);                              \
        fprintf(qatDebugLogFile,"output_buf = %p\n", output_buf);              \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_RSA_ENCRYPT_OUTPUT(output_buf)                                  \
    do {                                                                       \
        fprintf(qatDebugLogFile,"RSA Encrypt Output: %p\n", output_buf);       \
        DUMPL("output_buf", output_buf->pData, output_buf->dataLenInBytes);    \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_RSA_DECRYPT(instance_handle, op_done, opData, output_buf)       \
    do {                                                                       \
        fprintf(qatDebugLogFile,"RSA Decrypt Request: %p\n", opData);          \
        fprintf(qatDebugLogFile,"instance_handle = %p\n", instance_handle);    \
        fprintf(qatDebugLogFile,"op_done = %p\n", op_done);                    \
        fprintf(qatDebugLogFile,"opData: pRecipientPrivateKey->version = %d\n",\
                opData->pRecipientPrivateKey->version);                        \
        fprintf(qatDebugLogFile,"opData: pRecipientPrivateKey"                 \
                "->privateKeyRepType = %d\n",                                  \
                opData->pRecipientPrivateKey->privateKeyRepType);              \
        DUMPL("opData: pRecipientPrivateKey->privateKeyRep1.modulusN.pData",   \
               opData->pRecipientPrivateKey->privateKeyRep1.modulusN.pData,    \
               opData->pRecipientPrivateKey->privateKeyRep1.modulusN.          \
               dataLenInBytes);                                                \
        DUMPL("opData: pRecipientPrivateKey->privateKeyRep1.privateExponentD." \
              "pData", opData->pRecipientPrivateKey->privateKeyRep1.           \
               privateExponentD.pData, opData->pRecipientPrivateKey->          \
               privateKeyRep1.privateExponentD.dataLenInBytes);                \
        DUMPL("opData: pRecipientPrivateKey->privateKeyRep2.prime1P.pData",    \
               opData->pRecipientPrivateKey->privateKeyRep2.prime1P.pData,     \
               opData->pRecipientPrivateKey->privateKeyRep2.prime1P.           \
               dataLenInBytes);                                                \
        DUMPL("opData: pRecipientPrivateKey->privateKeyRep2.prime2Q.pData",    \
               opData->pRecipientPrivateKey->privateKeyRep2.prime2Q.pData,     \
               opData->pRecipientPrivateKey->privateKeyRep2.prime2Q.           \
               dataLenInBytes);                                                \
        DUMPL("opData: pRecipientPrivateKey->privateKeyRep2.exponent1Dp."      \
              "pData",                                                         \
               opData->pRecipientPrivateKey->privateKeyRep2.exponent1Dp.pData, \
               opData->pRecipientPrivateKey->privateKeyRep2.exponent1Dp.       \
               dataLenInBytes);                                                \
        DUMPL("opData: pRecipientPrivateKey->privateKeyRep2.exponent2Dq."      \
              "pData",                                                         \
               opData->pRecipientPrivateKey->privateKeyRep2.exponent2Dq.pData, \
               opData->pRecipientPrivateKey->privateKeyRep2.exponent2Dq.       \
               dataLenInBytes);                                                \
        DUMPL("opData: pRecipientPrivateKey->privateKeyRep2.coefficientQInv."  \
              "pData",                                                         \
               opData->pRecipientPrivateKey->privateKeyRep2.coefficientQInv.   \
               pData, opData->pRecipientPrivateKey->privateKeyRep2.            \
               coefficientQInv.dataLenInBytes);                                \
        DUMPL("opData: inputData.pData", opData->inputData.pData,              \
               opData->inputData.dataLenInBytes);                              \
        fprintf(qatDebugLogFile,"output_buf = %p\n", output_buf);              \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_RSA_DECRYPT_OUTPUT(output_buf)                                  \
    do {                                                                       \
        fprintf(qatDebugLogFile,"RSA Decrypt Output: %p\n", output_buf);       \
        DUMPL("output_buf", output_buf->pData, output_buf->dataLenInBytes);    \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_KEYGEN_TLS(instance_handle, generated_key)                      \
    do {                                                                       \
        fprintf(qatDebugLogFile,"TLS Keygen Request: \n");                     \
        fprintf(qatDebugLogFile,"instance_handle = %p\n", instance_handle);    \
        DUMPL("generated_key->pData", generated_key->pData,                    \
               generated_key->dataLenInBytes);                                 \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_KEYGEN_TLS_OUTPUT(generated_key)                                \
    do {                                                                       \
        fprintf(qatDebugLogFile,"TLS Keygen Output: %p\n", generated_key);     \
        DUMPL("generated_key->pData", generated_key->pData,                    \
               generated_key->dataLenInBytes);                                 \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_SESSION_SETUP_DATA(ssd)                                         \
    do {                                                                       \
        fprintf(qatDebugLogFile,"Symmetric crypto session setup data: %p\n",   \
                ssd);                                                          \
        DUMPL("Cipher Key", ssd->cipherSetupData.pCipherKey,                   \
               ssd->cipherSetupData.cipherKeyLenInBytes);                      \
        if (ssd->symOperation != CPA_CY_SYM_OP_CIPHER) {                       \
            DUMPL("MAC Key", ssd->hashSetupData.authModeSetupData.authKey,     \
                   ssd->hashSetupData.                                         \
                   authModeSetupData.authKeyLenInBytes);                       \
        }                                                                      \
        fprintf(qatDebugLogFile,"ssd->sessionPriority = %d\n",                 \
                ssd->sessionPriority);                                         \
        fprintf(qatDebugLogFile,"ssd->symOperation = %d\n",                    \
                ssd->symOperation);                                            \
        fprintf(qatDebugLogFile,"ssd->cipherSetupData.cipherAlgorithm = %d\n", \
                ssd->cipherSetupData.cipherAlgorithm);                         \
        fprintf(qatDebugLogFile,"ssd->cipherSetupData.cipherKeyLenInBytes "    \
                "= %u\n", ssd->cipherSetupData.cipherKeyLenInBytes);           \
        fprintf(qatDebugLogFile,"ssd->cipherSetupData.pCipherKey = %p\n",      \
                ssd->cipherSetupData.pCipherKey);                              \
        fprintf(qatDebugLogFile,"ssd->cipherSetupData.cipherDirection = %d\n", \
                ssd->cipherSetupData.cipherDirection);                         \
        fprintf(qatDebugLogFile,"ssd->hashSetupData.hashAlgorithm = %d\n",     \
                ssd->hashSetupData.hashAlgorithm);                             \
        fprintf(qatDebugLogFile,"ssd->hashSetupData.hashMode = %d\n",          \
                ssd->hashSetupData.hashMode);                                  \
        fprintf(qatDebugLogFile,"ssd->hashSetupData.digestResultLenInBytes "   \
                "= %u\n", ssd->hashSetupData.digestResultLenInBytes);          \
        fprintf(qatDebugLogFile,"ssd->hashSetupData.authModeSetupData.authKey "\
                "= %p\n", ssd->hashSetupData.authModeSetupData.authKey);       \
        fprintf(qatDebugLogFile,"ssd->hashSetupData.authModeSetupData"         \
                ".authKeyLenInBytes = %u\n",                                   \
                ssd->hashSetupData.authModeSetupData.authKeyLenInBytes);       \
        fprintf(qatDebugLogFile,"ssd->hashSetupData.authModeSetupData"         \
                ".aadLenInBytes = %u\n",                                       \
                ssd->hashSetupData.authModeSetupData.aadLenInBytes);           \
        fprintf(qatDebugLogFile,"ssd->hashSetupData.nestedModeSetupData"       \
                ".pInnerPrefixData = %p\n",                                    \
                ssd->hashSetupData.nestedModeSetupData.pInnerPrefixData);      \
        fprintf(qatDebugLogFile,"ssd->hashSetupData.nestedModeSetupData"       \
                ".innerPrefixLenInBytes= %u\n",                                \
                ssd->hashSetupData.nestedModeSetupData.innerPrefixLenInBytes); \
        fprintf(qatDebugLogFile,"ssd->hashSetupData.nestedModeSetupData."      \
                "outerHashAlgorithm = %d\n", ssd->hashSetupData.               \
                nestedModeSetupData.outerHashAlgorithm);                       \
        fprintf(qatDebugLogFile,"ssd->hashSetupData.nestedModeSetupData"       \
                ".pOuterPrefixData = %p\n",                                    \
                ssd->hashSetupData.nestedModeSetupData.pOuterPrefixData);      \
        fprintf(qatDebugLogFile,"ssd->hashSetupData.nestedModeSetupData"       \
                ".outerPrefixLenInBytes= %u\n",                                \
                ssd->hashSetupData.nestedModeSetupData.outerPrefixLenInBytes); \
        fprintf(qatDebugLogFile,"ssd->algChainOrder = %d\n",                   \
                ssd->algChainOrder);                                           \
        fprintf(qatDebugLogFile,"ssd->digestIsAppended = %d\n",                \
                ssd->digestIsAppended);                                        \
        fprintf(qatDebugLogFile,"ssd->verifyDigest = %d\n",                    \
                ssd->verifyDigest);                                            \
        fprintf(qatDebugLogFile,"ssd->partialsNotRequired = %d\n",             \
                ssd->partialsNotRequired);                                     \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_SYM_PERFORM_OP(instance_handle, pOpData, pSrcBuffer,            \
        pDstBuffer)                                                            \
    do {                                                                       \
        unsigned int index = 0;                                                \
        fprintf(qatDebugLogFile,"Symmetric crypto perform op req: %p\n",       \
                pOpData);                                                      \
        fprintf(qatDebugLogFile,"Instance Handle = %p\n", instance_handle);    \
        fprintf(qatDebugLogFile,"pOpData->packetType = %d\n",                  \
                pOpData->packetType);                                          \
        DUMPL("Cipher IV", pOpData->pIv, pOpData->ivLenInBytes);               \
        fprintf(qatDebugLogFile,"pOpData->cryptoStartSrcOffsetInBytes = %u\n", \
                pOpData->cryptoStartSrcOffsetInBytes);                         \
        fprintf(qatDebugLogFile,"pOpData->messageLenToCipherInBytes = %u\n",   \
                pOpData->messageLenToCipherInBytes);                           \
        fprintf(qatDebugLogFile,"pOpData->hashStartSrcOffsetInBytes = %u\n",   \
                pOpData->hashStartSrcOffsetInBytes);                           \
        fprintf(qatDebugLogFile,"pOpData->messageLenToHashInBytes = %u\n",     \
                pOpData->messageLenToHashInBytes);                             \
        fprintf(qatDebugLogFile,"pOpData->pDigestResult = %p\n",               \
                pOpData->pDigestResult);                                       \
        for (index = 0; index < pSrcBuffer->numBuffers; index++) {             \
            DUMPL("pSrcBuffer->pBuffers[%u].pData",                            \
                   pSrcBuffer->pBuffers[index].pData,                          \
                   pSrcBuffer->pBuffers[index].dataLenInBytes);                \
        }                                                                      \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_SYM_PERFORM_OP_OUTPUT(pVerifyResult, pDstBuffer)                \
    do {                                                                       \
        unsigned int index = 0;                                                \
        fprintf(qatDebugLogFile,"Symmetric crypto perform op Output: %p\n",    \
                pDstBuffer);                                                   \
        fprintf(qatDebugLogFile,"pVerifyResult = %d\n", *pVerifyResult);       \
        for (index = 0; index < pDstBuffer->numBuffers; index++) {             \
            DUMPL("pDstBuffer->pBuffers[%u].pData",                            \
                   pDstBuffer->pBuffers[index].pData,                          \
                   pDstBuffer->pBuffers[index].dataLenInBytes);                \
        }                                                                      \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_SYM_PERFORM_OP_GCM_CCM(instance_handle, pOpData, pSrcBuffer,    \
                                  pDstBuffer)                                  \
    do {                                                                       \
        unsigned int index = 0;                                                \
        fprintf(qatDebugLogFile,"Symmetric crypto perform op req: %p\n",       \
                &pOpData);                                                     \
        fprintf(qatDebugLogFile,"Instance Handle = %p\n", instance_handle);    \
        fprintf(qatDebugLogFile,"pOpData.packetType = %d\n",                   \
                pOpData.packetType);                                           \
        DUMPL("Cipher IV", pOpData.pIv, pOpData.ivLenInBytes);                 \
        fprintf(qatDebugLogFile,"pOpData.cryptoStartSrcOffsetInBytes = %u\n",  \
                pOpData.cryptoStartSrcOffsetInBytes);                          \
        fprintf(qatDebugLogFile,"pOpData.messageLenToCipherInBytes = %u\n",    \
                pOpData.messageLenToCipherInBytes);                            \
        fprintf(qatDebugLogFile,"pOpData.hashStartSrcOffsetInBytes = %u\n",    \
                pOpData.hashStartSrcOffsetInBytes);                            \
        fprintf(qatDebugLogFile,"pOpData.messageLenToHashInBytes = %u\n",      \
                pOpData.messageLenToHashInBytes);                              \
        fprintf(qatDebugLogFile,"pOpData.pDigestResult = %p\n",                \
                pOpData.pDigestResult);                                        \
        for (index = 0; index < pSrcBuffer.numBuffers; index++) {              \
            DUMPL("pSrcBuffer.pBuffers[%u].pData",                             \
                   pSrcBuffer.pBuffers[index].pData,                           \
                   pSrcBuffer.pBuffers[index].dataLenInBytes);                 \
        }                                                                      \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_SYM_PERFORM_OP_GCM_CCM_OUTPUT(pDstBuffer)                       \
    do {                                                                       \
        unsigned int index = 0;                                                \
        fprintf(qatDebugLogFile,"Symmetric crypto perform op Output: %p\n",    \
                &pDstBuffer);                                                  \
        for (index = 0; index < pDstBuffer.numBuffers; index++) {              \
            DUMPL("pDstBuffer.pBuffers[%u].pData",                             \
                   pDstBuffer.pBuffers[index].pData,                           \
                   pDstBuffer.pBuffers[index].dataLenInBytes);                 \
        }                                                                      \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_PRF_OP_DATA(prfOpData)                                          \
    do {                                                                       \
        fprintf(qatDebugLogFile,"PRF Op Data: %p\n", &prfOpData);              \
        if (prfOpData.tlsOp ==                                                 \
            CPA_CY_KEY_TLS_OP_MASTER_SECRET_DERIVE)                            \
            fprintf(qatDebugLogFile,"tlsOp: MASTER_SECRET_DERIVE\n");          \
        else if (prfOpData.tlsOp ==                                            \
                 CPA_CY_KEY_TLS_OP_KEY_MATERIAL_DERIVE)                        \
            fprintf(qatDebugLogFile,"tlsOp: KEY_MATERIAL_DERIVE\n");           \
        else if (prfOpData.tlsOp ==                                            \
                 CPA_CY_KEY_TLS_OP_CLIENT_FINISHED_DERIVE)                     \
            fprintf(qatDebugLogFile,"tlsOp: CLIENT_FINISHED_DERIVE\n");        \
        else if (prfOpData.tlsOp ==                                            \
                 CPA_CY_KEY_TLS_OP_SERVER_FINISHED_DERIVE)                     \
            fprintf(qatDebugLogFile,"tlsOp: SERVER_FINISHED_DERIVE\n");        \
        else if (prfOpData.tlsOp ==                                            \
                 CPA_CY_KEY_TLS_OP_USER_DEFINED)                               \
            fprintf(qatDebugLogFile,"tlsOp: USER_DEFINED:\n");                 \
        DUMPL("Secret", prfOpData.secret.pData,                                \
              prfOpData.secret.dataLenInBytes);                                \
        DUMPL("Seed", prfOpData.seed.pData,                                    \
              prfOpData.seed.dataLenInBytes);                                  \
        DUMPL("User Label", prfOpData.userLabel.pData,                         \
              prfOpData.userLabel.dataLenInBytes);                             \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_HKDF_OP_DATA(hkdfOpData)                                        \
    do {                                                                       \
        fprintf(qatDebugLogFile,"HKDF Op Data: %p\n", &hkdfOpData);            \
        if (hkdfOpData->hkdfKeyOp == CPA_CY_HKDF_KEY_EXTRACT_EXPAND)           \
            fprintf(qatDebugLogFile,"hkdfOp: HKDF_EXTRACT_AND_EXPAND \n");     \
        if (hkdfOpData->hkdfKeyOp == CPA_CY_HKDF_KEY_EXTRACT)                  \
            fprintf(qatDebugLogFile,"hkdfOp: HKDF_EXTRACT \n");                \
        if (hkdfOpData->hkdfKeyOp == CPA_CY_HKDF_KEY_EXPAND)                   \
            fprintf(qatDebugLogFile,"hkdfOp: HKDF_EXPAND \n");                 \
        DUMPL("Secret", hkdfOpData->secret, hkdfOpData->secretLen);            \
        DUMPL("Seed", hkdfOpData->seed, hkdfOpData->seedLen);                  \
        DUMPL("Info", hkdfOpData->info  , hkdfOpData->infoLen);                \
    } while (0)

#  define DUMP_SYM_PERFORM_OP_SHA3(instance_handle, pOpData, pSrcBuffer,       \
                                   pDstBuffer)                                 \
    do {                                                                       \
        fprintf(qatDebugLogFile,"Symmetric SHA3 hash perform op req: %p\n",    \
                &pOpData);                                                     \
        fprintf(qatDebugLogFile,"Instance Handle = %p\n", instance_handle);    \
        fprintf(qatDebugLogFile,"pOpData.packetType = %d\n",                   \
                pOpData->packetType);                                          \
        fprintf(qatDebugLogFile,"pOpData.cryptoStartSrcOffsetInBytes = %u\n",  \
                pOpData->cryptoStartSrcOffsetInBytes);                         \
        fprintf(qatDebugLogFile,"pOpData.messageLenToCipherInBytes = %u\n",    \
                pOpData->messageLenToCipherInBytes);                           \
        fprintf(qatDebugLogFile,"pOpData.hashStartSrcOffsetInBytes = %u\n",    \
                pOpData->hashStartSrcOffsetInBytes);                           \
        fprintf(qatDebugLogFile,"pOpData.messageLenToHashInBytes = %u\n",      \
                pOpData->messageLenToHashInBytes);                             \
        fprintf(qatDebugLogFile,"pOpData.pDigestResult = %p\n",                \
                pOpData->pDigestResult);                                       \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_CP_PERFORM_OP(instance_handle, pOpData, pSrcBuffer,             \
        pDstBuffer)                                                            \
    do {                                                                       \
        unsigned int index = 0;                                                \
        fprintf(qatDebugLogFile,"Symmetric crypto perform op req: %p\n",       \
                pOpData);                                                      \
        fprintf(qatDebugLogFile,"Instance Handle = %p\n", instance_handle);    \
        fprintf(qatDebugLogFile,"pOpData->packetType = %d\n",                  \
                pOpData->packetType);                                          \
        DUMPL("Cipher IV", pOpData->pIv, pOpData->ivLenInBytes);               \
        fprintf(qatDebugLogFile,"pOpData->cryptoStartSrcOffsetInBytes = %u\n", \
                pOpData->cryptoStartSrcOffsetInBytes);                         \
        fprintf(qatDebugLogFile,"pOpData->messageLenToCipherInBytes = %u\n",   \
                pOpData->messageLenToCipherInBytes);                           \
        fprintf(qatDebugLogFile,"pOpData->hashStartSrcOffsetInBytes = %u\n",   \
                pOpData->hashStartSrcOffsetInBytes);                           \
        fprintf(qatDebugLogFile,"pOpData->messageLenToHashInBytes = %u\n",     \
                pOpData->messageLenToHashInBytes);                             \
        fprintf(qatDebugLogFile,"pOpData->pDigestResult = %p\n",               \
                pOpData->pDigestResult);                                       \
        for (index = 0; index < pSrcBuffer.numBuffers; index++) {              \
            DUMPL("pSrcBuffer->pBuffers[%u].pData",                            \
                   pSrcBuffer.pBuffers[index].pData,                           \
                   pSrcBuffer.pBuffers[index].dataLenInBytes);                 \
        }                                                                      \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_SYM_PERFORM_OP_SHA3_OUTPUT(pOpData, pDstBuffer)                 \
    do {                                                                       \
        fprintf(qatDebugLogFile,"Symmetric SHA3 hash perform op Output: %p\n", \
                &pDstBuffer);                                                  \
        fprintf(qatDebugLogFile,"pOpData->pDigestResult = %p\n",               \
                pOpData->pDigestResult);                                       \
        DUMPL("pOpData->pDigestResult",                                        \
               pOpData->pDigestResult,                                         \
               pOpData->messageLenToHashInBytes);                              \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_CP_PERFORM_OP_OUTPUT(pVerifyResult, pDstBuffer)                 \
    do {                                                                       \
        unsigned int index = 0;                                                \
        fprintf(qatDebugLogFile,"Symmetric crypto perform op Output:\n");      \
        fprintf(qatDebugLogFile,"pVerifyResult = %d\n", *pVerifyResult);       \
        for (index = 0; index < pDstBuffer.numBuffers; index++) {              \
            DUMPL("pDstBuffer->pBuffers[%u].pData",                            \
                   pDstBuffer.pBuffers[index].pData,                           \
                   pDstBuffer.pBuffers[index].dataLenInBytes);                 \
        }                                                                      \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_INSTANCE_MAPPING(title, map_instance, num_instances)            \
    do {                                                                       \
        unsigned int index = 0;                                                \
        fprintf(qatDebugLogFile,"%s: ", title);                                \
                                                                               \
        for (index = 0; index < num_instances; index++) {                      \
            fprintf(qatDebugLogFile, "%d ", map_instance[index]);              \
        }                                                                      \
        fprintf(qatDebugLogFile, "\n");                                        \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  ifdef ENABLE_QAT_HW_KPT
#   define DUMP_KPT_WRAPPING_DATA(eswk, len_eswk, sig, len_sig, iv, len_iv,    \
                                  aad, len_aad)                                \
    do {                                                                       \
        fprintf(qatDebugLogFile,"KPT Wrapping Metadata\n");                    \
        DUMPL("ESWK", eswk, len_eswk);                                         \
        DUMPL("Signature", sig, len_sig);                                      \
        DUMPL("IV", iv, len_iv);                                               \
        DUMPL("AAD", aad, len_aad);                                            \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#   define DUMP_KPT_RSA_DECRYPT(instance_handle, kpt_handle,                  \
                                op_done, opData, output_buf)                  \
    do {                                                                      \
       fprintf(qatDebugLogFile,"RSA Decrypt Request: %p\n", opData);          \
       fprintf(qatDebugLogFile,"instance_handle = %p\n", instance_handle);    \
       fprintf(qatDebugLogFile,"KPT handle = 0x%lx\n", kpt_handle);           \
       fprintf(qatDebugLogFile,"op_done = %p\n", op_done);                    \
       fprintf(qatDebugLogFile,"opData: pRecipientPrivateKey->version = %d\n",\
               opData->pRecipientPrivateKey->version);                        \
       fprintf(qatDebugLogFile,"opData: pRecipientPrivateKey"                 \
               "->privateKeyRepType = %d\n",                                  \
               opData->pRecipientPrivateKey->privateKeyRepType);              \
       DUMPL("opData: pRecipientPrivateKey->privateKeyRep1.privateKey.pData", \
              opData->pRecipientPrivateKey->privateKeyRep1.privateKey.pData,  \
              opData->pRecipientPrivateKey->privateKeyRep1.privateKey.        \
              dataLenInBytes);                                                \
       DUMPL("opData: pRecipientPrivateKey->privateKeyRep2.privateKey.pData", \
              opData->pRecipientPrivateKey->privateKeyRep2.privateKey.pData,  \
              opData->pRecipientPrivateKey->privateKeyRep2.privateKey.        \
              dataLenInBytes);                                                \
       DUMPL("opData: inputData.pData", opData->inputData.pData,              \
              opData->inputData.dataLenInBytes);                              \
       fprintf(qatDebugLogFile,"output_buf = %p\n", output_buf);              \
       fflush(qatDebugLogFile);                                               \
    } while (0)

#   define DUMP_KPT_ECDSA_SIGN(instance_handle, kpt_handle,                    \
                               opData, pResultR, pResultS)                     \
    do {                                                                       \
        fprintf(qatDebugLogFile,"KPT ECDSA Sign Request: %p\n", opData);       \
        fprintf(qatDebugLogFile,"instance_handle ptr = %p\n", instance_handle);\
        fprintf(qatDebugLogFile,"KPT handle = 0x%lx\n", kpt_handle);           \
        DUMPL("m.pData", opData->m.pData, opData->m.dataLenInBytes);           \
        DUMPL("WPK data", opData->privateKey.pData,                            \
              opData->privateKey.dataLenInBytes);                              \
        fprintf(qatDebugLogFile,"pResultR->dataLenInBytes = %u "               \
                "pResultR->pData = %p\n",                                      \
                pResultR->dataLenInBytes, pResultR->pData);                    \
        fprintf(qatDebugLogFile,"pResultS->dataLenInBytes = %u "               \
                "pResultS->pData = %p\n",                                      \
                pResultS->dataLenInBytes, pResultS->pData);                    \
        fflush(qatDebugLogFile);                                               \
    } while (0)
#  endif

#  define DUMP_SM2_SIGN(instance_handle, opData, pResultR, pResultS)           \
    do {                                                                       \
        fprintf(qatDebugLogFile,"SM2 Sign Request: %p\n", opData);             \
        fprintf(qatDebugLogFile,"instance_handle = %p\n", instance_handle);    \
        DUMPL("k.pData", opData->k.pData, opData->k.dataLenInBytes);           \
        DUMPL("e.pData", opData->e.pData, opData->e.dataLenInBytes);           \
        DUMPL("d.pData", opData->d.pData, opData->d.dataLenInBytes);           \
        fprintf(qatDebugLogFile,"opData: fieldType = %d\n", opData->fieldType);\
        fprintf(qatDebugLogFile,"pResultR->dataLenInBytes = %u "               \
                "pResultR->pData = %p\n",                                      \
                pResultR->dataLenInBytes, pResultR->pData);                    \
        fprintf(qatDebugLogFile,"pResultS->dataLenInBytes = %u "               \
                "pResultS->pData = %p\n",                                      \
                pResultS->dataLenInBytes, pResultS->pData);                    \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_SM2_SIGN_OUTPUT(bSM2SignStatus, pResultR, pResultS)             \
    do {                                                                       \
        fprintf(qatDebugLogFile,"SM2 Sign Output:"                             \
                " pResultR %p, pResultS %p\n",                                 \
                pResultR, pResultS);                                           \
        fprintf(qatDebugLogFile, "bSM2SignStatus = %u\n", bSM2SignStatus);     \
        DUMPL("pResultR->pData", pResultR->pData, pResultR->dataLenInBytes);   \
        DUMPL("pResultS->pData", pResultS->pData, pResultS->dataLenInBytes);   \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_SM2_VERIFY(instance_handle, opData)                             \
    do {                                                                       \
        fprintf(qatDebugLogFile,"SM2 Verify Request: %p\n", opData);           \
        fprintf(qatDebugLogFile,"instance_handle = %p\n", instance_handle);    \
        DUMPL("e.pData", opData->e.pData, opData->e.dataLenInBytes);           \
        DUMPL("r.pData", opData->r.pData, opData->r.dataLenInBytes);           \
        DUMPL("s.pData", opData->s.pData, opData->s.dataLenInBytes);           \
        DUMPL("xP.pData", opData->xP.pData, opData->xP.dataLenInBytes);        \
        DUMPL("yP.pData", opData->yP.pData, opData->yP.dataLenInBytes);        \
        fprintf(qatDebugLogFile,"opData: fieldType = %d\n", opData->fieldType);\
        fflush(qatDebugLogFile);                                               \
    } while (0)

# else
#  ifdef ENABLE_QAT_HW_KPT
#   define DUMP_KPT_WRAPPING_DATA(...)
#   define DUMP_KPT_RSA_DECRYPT(...)
#   define DUMP_KPT_ECDSA_SIGN(...)
#  endif
#  define DUMP_DH_GEN_PHASE1(...)
#  define DUMP_DH_GEN_PHASE2(...)
#  define DUMP_DH_GEN_PHASE1_OUTPUT(...)
#  define DUMP_DH_GEN_PHASE2_OUTPUT(...)
#  define DUMP_EC_POINT_MULTIPLY(...)
#  define DUMP_EC_GENERIC_POINT_MULTIPLY(...)
#  define DUMP_EC_MONTEDWDS_POINT_MULTIPLY(...)
#  define DUMP_EC_POINT_MULTIPLY_OUTPUT(...)
#  define DUMP_EC_GENERIC_POINT_MULTIPLY_OUTPUT(...)
#  define DUMP_EC_SM2_POINT_MULTIPLY(...)
#  define DUMP_ECDSA_SIGN(...)
#  define DUMP_ECDSA_SIGN_OUTPUT(...)
#  define DUMP_ECDSA_VERIFY(...)
#  define DUMP_DSA_SIGN(...)
#  define DUMP_DSA_SIGN_OUTPUT(...)
#  define DUMP_DSA_VERIFY(...)
#  define DUMP_RSA_ENCRYPT(...)
#  define DUMP_RSA_ENCRYPT_OUTPUT(...)
#  define DUMP_RSA_DECRYPT(...)
#  define DUMP_RSA_DECRYPT_OUTPUT(...)
#  define DUMP_KEYGEN_TLS(...)
#  define DUMP_KEYGEN_TLS_OUTPUT(...)
#  define DUMP_SESSION_SETUP_DATA(...)
#  define DUMP_SYM_PERFORM_OP(...)
#  define DUMP_SYM_PERFORM_OP_OUTPUT(...)
#  define DUMP_SYM_PERFORM_OP_GCM_CCM(...)
#  define DUMP_SYM_PERFORM_OP_GCM_CCM_OUTPUT(...)
#  define DUMP_PRF_OP_DATA(...)
#  define DUMP_HKDF_OP_DATA(...)
#  define DUMP_SYM_PERFORM_OP_SHA3(...)
#  define DUMP_SYM_PERFORM_OP_SHA3_OUTPUT(...)
#  define DUMP_CP_PERFORM_OP(...)
#  define DUMP_CP_PERFORM_OP_OUTPUT(...)
#  define DUMP_INSTANCE_MAPPING(...)
#  define DUMP_SM2_SIGN(...)
#  define DUMP_SM2_SIGN_OUTPUT(...)
#  define DUMP_SM2_VERIFY(...)
# endif                         /* QAT_DEBUG */

# ifdef QAT_CPU_CYCLES_COUNT
#  define GCC_ALWAYS_INLINE static __attribute__((always_inline)) inline

typedef struct rdtsc_prof {
    volatile uint64_t clk_start;
    volatile uint64_t clk_avgc; /* count to calculate an average */
    volatile double clk_avg;    /* cumulative sum to calculate an average */
    volatile double clk_diff_cost_adjusted;
    volatile double cost;
    volatile uint32_t bytes;
    volatile int started;
} rdtsc_prof_t;

extern rdtsc_prof_t rsa_cycles_priv_enc_setup;
extern rdtsc_prof_t rsa_cycles_priv_dec_setup;
extern rdtsc_prof_t rsa_cycles_priv_execute;
extern rdtsc_prof_t rsa_cycles_pub_enc_setup;
extern rdtsc_prof_t rsa_cycles_pub_dec_setup;
extern rdtsc_prof_t rsa_cycles_pub_execute;
extern rdtsc_prof_t x25519_cycles_keygen_setup;
extern rdtsc_prof_t x25519_cycles_keygen_execute;
extern rdtsc_prof_t x25519_cycles_derive_setup;
extern rdtsc_prof_t x25519_cycles_derive_execute;
extern rdtsc_prof_t ecdsa_cycles_sign_setup;
extern rdtsc_prof_t ecdsa_cycles_sign_execute;
extern rdtsc_prof_t ecdsa_cycles_sign_setup_setup;
extern rdtsc_prof_t ecdsa_cycles_sign_setup_execute;
extern rdtsc_prof_t ecdsa_cycles_sign_sig_setup;
extern rdtsc_prof_t ecdsa_cycles_sign_sig_execute;
extern rdtsc_prof_t ecdh_cycles_keygen_setup;
extern rdtsc_prof_t ecdh_cycles_keygen_execute;
extern rdtsc_prof_t ecdh_cycles_compute_setup;
extern rdtsc_prof_t ecdh_cycles_compute_execute;
extern rdtsc_prof_t sm2ecdh_cycles_keygen_setup;
extern rdtsc_prof_t sm2ecdh_cycles_keygen_execute;
extern rdtsc_prof_t sm2ecdh_cycles_compute_setup;
extern rdtsc_prof_t sm2ecdh_cycles_compute_execute;
extern rdtsc_prof_t sm3_cycles_init_setup;
extern rdtsc_prof_t sm3_cycles_init_execute;
extern rdtsc_prof_t sm3_cycles_update_setup;
extern rdtsc_prof_t sm3_cycles_update_execute;
extern rdtsc_prof_t sm3_cycles_final_setup;
extern rdtsc_prof_t sm3_cycles_final_execute;
extern rdtsc_prof_t ecdsa_cycles_verify_setup;
extern rdtsc_prof_t ecdsa_cycles_verify_execute;
extern rdtsc_prof_t sm4_gcm_cycles_init_setup;
extern rdtsc_prof_t sm4_gcm_cycles_init_execute;
extern rdtsc_prof_t sm4_gcm_cycles_encrypt_setup;
extern rdtsc_prof_t sm4_gcm_cycles_encrypt_execute;
extern rdtsc_prof_t sm4_gcm_cycles_decrypt_setup;
extern rdtsc_prof_t sm4_gcm_cycles_decrypt_execute;
extern rdtsc_prof_t sm4_gcm_cycles_get_tag_setup;
extern rdtsc_prof_t sm4_gcm_cycles_get_tag_execute;
extern rdtsc_prof_t sm4_gcm_cycles_update_iv_setup;
extern rdtsc_prof_t sm4_gcm_cycles_update_iv_execute;
extern rdtsc_prof_t sm4_gcm_cycles_update_aad_setup;
extern rdtsc_prof_t sm4_gcm_cycles_update_aad_execute;
extern rdtsc_prof_t sm4_gcm_cycles_cipher_setup;
extern rdtsc_prof_t sm4_gcm_cycles_cipher_execute;
extern rdtsc_prof_t sm4_gcm_cycles_ctrl_setup;
extern rdtsc_prof_t sm4_gcm_cycles_ctrl_execute;
extern rdtsc_prof_t sm4_gcm_cycles_cleanup_setup;
extern rdtsc_prof_t sm4_gcm_cycles_cleanup_execute;
extern rdtsc_prof_t sm4_ccm_cycles_init_setup;
extern rdtsc_prof_t sm4_ccm_cycles_init_execute;
extern rdtsc_prof_t sm4_ccm_cycles_encrypt_setup;
extern rdtsc_prof_t sm4_ccm_cycles_encrypt_execute;
extern rdtsc_prof_t sm4_ccm_cycles_decrypt_setup;
extern rdtsc_prof_t sm4_ccm_cycles_decrypt_execute;
extern rdtsc_prof_t sm4_ccm_cycles_ctrl_setup;
extern rdtsc_prof_t sm4_ccm_cycles_ctrl_execute;
extern rdtsc_prof_t sm4_ccm_cycles_cleanup_setup;
extern rdtsc_prof_t sm4_ccm_cycles_cleanup_execute;
extern rdtsc_prof_t sm4_ccm_cycles_get_tag_setup;
extern rdtsc_prof_t sm4_ccm_cycles_get_tag_execute;
extern rdtsc_prof_t sm4_ccm_cycles_update_aad_setup;
extern rdtsc_prof_t sm4_ccm_cycles_update_aad_execute;
extern rdtsc_prof_t qat_hw_rsa_dec_req_prepare;
extern rdtsc_prof_t qat_hw_rsa_dec_req_submit;
extern rdtsc_prof_t qat_hw_rsa_dec_req_retry;
extern rdtsc_prof_t qat_hw_rsa_dec_req_cleanup;
extern rdtsc_prof_t qat_hw_ecdsa_sign_req_prepare;
extern rdtsc_prof_t qat_hw_ecdsa_sign_req_submit;
extern rdtsc_prof_t qat_hw_ecdsa_sign_req_retry;
extern rdtsc_prof_t qat_hw_ecdsa_sign_req_cleanup;
extern rdtsc_prof_t qat_hw_ecdh_derive_req_prepare;
extern rdtsc_prof_t qat_hw_ecdh_derive_req_submit;
extern rdtsc_prof_t qat_hw_ecdh_derive_req_retry;
extern rdtsc_prof_t qat_hw_ecdh_derive_req_cleanup;
extern rdtsc_prof_t qat_hw_ecx_derive_req_prepare;
extern rdtsc_prof_t qat_hw_ecx_derive_req_submit;
extern rdtsc_prof_t qat_hw_ecx_derive_req_retry;
extern rdtsc_prof_t qat_hw_ecx_derive_req_cleanup;

extern int print_cycle_count;

/**
 * * LFENCE used to serialize code execution (no OOO)
 * * Load buffers get are empty after lfence, no deliberate restrictions put on store buffers
 * */

GCC_ALWAYS_INLINE uint64_t rdtsc_start(void)
{
    uint32_t cycles_high;
    uint32_t cycles_low;

    asm volatile ("lfence\n\t"
                  "rdtscp\n\t"
                  "mov %%edx, %0\n\t"
                  "mov %%eax, %1\n\t":"=r" (cycles_high), "=r"(cycles_low)
                  ::"%rax", "%rdx", "%rcx");

    return (((uint64_t)cycles_high << 32) | cycles_low);
}

GCC_ALWAYS_INLINE uint64_t rdtsc_end(void)
{
    uint32_t cycles_high;
    uint32_t cycles_low;

    asm volatile ("rdtscp\n\t"
                  "mov %%edx, %0\n\t"
                  "mov %%eax, %1\n\t"
                  "lfence\n\t":"=r" (cycles_high), "=r"(cycles_low)
                  ::"%rax", "%rdx", "%rcx");

    return (((uint64_t)cycles_high << 32) | cycles_low);
}

GCC_ALWAYS_INLINE void rdtsc_prof_start(rdtsc_prof_t * p)
{
    p->started = 1;
    p->clk_start = rdtsc_start();
}

GCC_ALWAYS_INLINE void rdtsc_prof_end(rdtsc_prof_t * p,
                                      const unsigned inc, char *name)
{
    if (p->started) {
         /* int64_t not uint64_t because it may happen that
          * for low cost operations, measured time is less than
          * the subtracted average cost of measurement */
        volatile double clk_diff = (double)(rdtsc_end() - p->clk_start);
        p->clk_avgc += inc;
#  ifdef QAT_CPU_CYCLE_MEASUREMENT_COST
        p->clk_avg += (clk_diff - p->cost);
        p->clk_diff_cost_adjusted += (clk_diff - p->cost);
#  else
        p->clk_avg += clk_diff;
        p->clk_diff_cost_adjusted += clk_diff;
#  endif
        p->started = 0;
        if (inc != 0) {
            if (print_cycle_count)
                fprintf(qatDebugLogFile, "%s - cycles taken = %.1f\n",
                        name, p->clk_diff_cost_adjusted);
            p->clk_diff_cost_adjusted = 0.0;
        }
    }
}

void rdtsc_initialize(void);
void rdtsc_prof_init(rdtsc_prof_t * p, const uint32_t bytes);
void rdtsc_prof_print(rdtsc_prof_t * p, char *name);

#  define INITIALISE_RDTSC_CLOCKS()                        \
    do {                                                   \
        rdtsc_initialize();                                \
        rdtsc_prof_init(&rsa_cycles_priv_enc_setup, 0);    \
        rdtsc_prof_init(&rsa_cycles_priv_dec_setup, 0);    \
        rdtsc_prof_init(&rsa_cycles_priv_execute, 0);      \
        rdtsc_prof_init(&rsa_cycles_pub_enc_setup, 0);     \
        rdtsc_prof_init(&rsa_cycles_pub_dec_setup, 0);     \
        rdtsc_prof_init(&rsa_cycles_pub_execute, 0);       \
        rdtsc_prof_init(&x25519_cycles_keygen_setup, 0);   \
        rdtsc_prof_init(&x25519_cycles_keygen_execute, 0); \
        rdtsc_prof_init(&x25519_cycles_derive_setup, 0);   \
        rdtsc_prof_init(&x25519_cycles_derive_execute, 0); \
        rdtsc_prof_init(&ecdsa_cycles_sign_setup, 0);         \
        rdtsc_prof_init(&ecdsa_cycles_sign_execute, 0);       \
        rdtsc_prof_init(&ecdsa_cycles_sign_setup_setup, 0);   \
        rdtsc_prof_init(&ecdsa_cycles_sign_setup_execute, 0); \
        rdtsc_prof_init(&ecdsa_cycles_sign_sig_setup, 0);     \
        rdtsc_prof_init(&ecdsa_cycles_sign_sig_execute, 0);   \
        rdtsc_prof_init(&ecdh_cycles_keygen_setup, 0);    \
        rdtsc_prof_init(&ecdh_cycles_keygen_execute, 0);  \
        rdtsc_prof_init(&ecdh_cycles_compute_setup, 0);   \
        rdtsc_prof_init(&ecdh_cycles_compute_execute, 0); \
        rdtsc_prof_init(&sm2ecdh_cycles_keygen_setup, 0);    \
        rdtsc_prof_init(&sm2ecdh_cycles_keygen_execute, 0);  \
        rdtsc_prof_init(&sm2ecdh_cycles_compute_setup, 0);   \
        rdtsc_prof_init(&sm2ecdh_cycles_compute_execute, 0); \
        rdtsc_prof_init(&sm3_cycles_init_setup, 0);     \
        rdtsc_prof_init(&sm3_cycles_init_execute, 0);   \
        rdtsc_prof_init(&sm3_cycles_update_setup, 0);   \
        rdtsc_prof_init(&sm3_cycles_update_execute, 0); \
        rdtsc_prof_init(&sm3_cycles_final_setup, 0);    \
        rdtsc_prof_init(&sm3_cycles_final_execute, 0);  \
        rdtsc_prof_init(&ecdsa_cycles_verify_execute, 0);  \
        rdtsc_prof_init(&ecdsa_cycles_verify_setup, 0);   \
        rdtsc_prof_init(&sm4_gcm_cycles_init_setup, 0);     \
        rdtsc_prof_init(&sm4_gcm_cycles_init_execute, 0);   \
        rdtsc_prof_init(&sm4_gcm_cycles_encrypt_setup, 0);   \
        rdtsc_prof_init(&sm4_gcm_cycles_encrypt_execute, 0); \
        rdtsc_prof_init(&sm4_gcm_cycles_decrypt_setup, 0);   \
        rdtsc_prof_init(&sm4_gcm_cycles_decrypt_execute, 0);   \
        rdtsc_prof_init(&sm4_gcm_cycles_ctrl_setup, 0);   \
        rdtsc_prof_init(&sm4_gcm_cycles_ctrl_execute, 0);   \
        rdtsc_prof_init(&sm4_gcm_cycles_cleanup_setup, 0);   \
        rdtsc_prof_init(&sm4_gcm_cycles_cleanup_execute, 0);  \
        rdtsc_prof_init(&sm4_ccm_cycles_init_setup, 0);     \
        rdtsc_prof_init(&sm4_ccm_cycles_init_execute, 0);   \
        rdtsc_prof_init(&sm4_ccm_cycles_encrypt_setup, 0);   \
        rdtsc_prof_init(&sm4_ccm_cycles_encrypt_execute, 0); \
        rdtsc_prof_init(&sm4_ccm_cycles_decrypt_setup, 0);   \
        rdtsc_prof_init(&sm4_ccm_cycles_decrypt_execute, 0);   \
        rdtsc_prof_init(&sm4_ccm_cycles_ctrl_setup, 0);   \
        rdtsc_prof_init(&sm4_ccm_cycles_ctrl_execute, 0);   \
        rdtsc_prof_init(&sm4_ccm_cycles_cleanup_setup, 0);   \
        rdtsc_prof_init(&sm4_ccm_cycles_cleanup_execute, 0);  \
        rdtsc_prof_init(&sm4_ccm_cycles_get_tag_setup, 0);   \
        rdtsc_prof_init(&sm4_ccm_cycles_get_tag_execute, 0);   \
        rdtsc_prof_init(&sm4_ccm_cycles_update_aad_setup, 0);   \
        rdtsc_prof_init(&sm4_ccm_cycles_update_aad_execute, 0);  \
    } while (0)

#  define PRINT_RDTSC_AVERAGES() \
    do {                         \
        fprintf(qatDebugLogFile,"=========================\n");                \
        fprintf(qatDebugLogFile,"Average Cycle Counts.\n");                    \
        fprintf(qatDebugLogFile,"=========================\n");                \
        rdtsc_prof_print(&rsa_cycles_priv_enc_setup, "[RSA:priv_enc_setup]");  \
        rdtsc_prof_print(&rsa_cycles_priv_dec_setup, "[RSA:priv_dec_setup]");  \
        rdtsc_prof_print(&rsa_cycles_priv_execute, "[RSA:priv_execute]");      \
        rdtsc_prof_print(&rsa_cycles_pub_enc_setup, "[RSA:pub_enc_setup]");    \
        rdtsc_prof_print(&rsa_cycles_pub_dec_setup, "[RSA:pub_dec_setup]");    \
        rdtsc_prof_print(&rsa_cycles_pub_execute, "[RSA:pub_execute]");        \
        rdtsc_prof_print(&x25519_cycles_keygen_setup, "[X22519:keygen_setup]");       \
        rdtsc_prof_print(&x25519_cycles_keygen_execute, "[X22519:keygen_execute]");   \
        rdtsc_prof_print(&x25519_cycles_derive_setup, "[X22519:derive_setup]");       \
        rdtsc_prof_print(&x25519_cycles_derive_execute, "[X22519:derive_execute]");   \
        rdtsc_prof_print(&ecdsa_cycles_sign_setup, "[ECDSA:sign_setup]");     \
        rdtsc_prof_print(&ecdsa_cycles_sign_execute, "[ECDSA:sign_execute]"); \
        rdtsc_prof_print(&ecdsa_cycles_sign_setup_setup, "[ECDSA:sign_setup_setup]");     \
        rdtsc_prof_print(&ecdsa_cycles_sign_setup_execute, "[ECDSA:sign_setup_execute]"); \
        rdtsc_prof_print(&ecdsa_cycles_sign_sig_setup, "[ECDSA:sign_sig_setup]");         \
        rdtsc_prof_print(&ecdsa_cycles_sign_sig_execute, "[ECDSA:sign_sig_execute]");     \
        rdtsc_prof_print(&ecdh_cycles_keygen_setup, "[ECDH:keygen_setup]");       \
        rdtsc_prof_print(&ecdh_cycles_keygen_execute, "[ECDH:keygen_execute]");   \
        rdtsc_prof_print(&ecdh_cycles_compute_setup, "[ECDH:compute_setup]");     \
        rdtsc_prof_print(&ecdh_cycles_compute_execute, "[ECDH:compute_execute]"); \
        rdtsc_prof_print(&sm2ecdh_cycles_keygen_setup, "[ECDH:keygen_setup]");       \
        rdtsc_prof_print(&sm2ecdh_cycles_keygen_execute, "[ECDH:keygen_execute]");   \
        rdtsc_prof_print(&sm2ecdh_cycles_compute_setup, "[ECDH:compute_setup]");     \
        rdtsc_prof_print(&sm2ecdh_cycles_compute_execute, "[ECDH:compute_execute]"); \
        rdtsc_prof_print(&sm3_cycles_init_setup, "[SM3:init_setup]");         \
        rdtsc_prof_print(&sm3_cycles_init_execute, "[SM3:init_execute]");     \
        rdtsc_prof_print(&sm3_cycles_update_setup, "[SM3:update_setup]");     \
        rdtsc_prof_print(&sm3_cycles_update_execute, "[SM3:update_execute]"); \
        rdtsc_prof_print(&sm3_cycles_final_setup, "[SM3:final_setup]");       \
        rdtsc_prof_print(&sm3_cycles_final_execute, "[SM3:final_execute]");   \
        rdtsc_prof_print(&ecdsa_cycles_verify_setup, "[ECDSA:verify_setup]"); \
        rdtsc_prof_print(&ecdsa_cycles_verify_execute, "[ECDSA:verify_execute]");   \
        rdtsc_prof_print(&sm4_gcm_cycles_init_setup, "[SM4_GCM:init_setup]");       \
        rdtsc_prof_print(&sm4_gcm_cycles_init_execute, "[SM4_GCM:init_execute]");   \
        rdtsc_prof_print(&sm4_gcm_cycles_encrypt_setup, "[SM4_GCM:encrypt_setup]");   \
        rdtsc_prof_print(&sm4_gcm_cycles_encrypt_execute, "[SM4_GCM:encrypt_execute]"); \
        rdtsc_prof_print(&sm4_gcm_cycles_decrypt_setup, "[SM4_GCM:decrypt_setup]");   \
        rdtsc_prof_print(&sm4_gcm_cycles_decrypt_execute, "[SM4_GCM:decrypt_execute]");   \
        rdtsc_prof_print(&sm4_gcm_cycles_ctrl_setup, "[SM4_GCM:ctrl_setup]");   \
        rdtsc_prof_print(&sm4_gcm_cycles_ctrl_execute, "[SM4_GCM:ctrl_execute]");   \
        rdtsc_prof_print(&sm4_gcm_cycles_cleanup_setup, "[SM4_GCM:cleanup_setup]");   \
        rdtsc_prof_print(&sm4_gcm_cycles_cleanup_execute, "[SM4_GCM:cleanup_execute]");  \
        rdtsc_prof_print(&sm4_ccm_cycles_init_setup, "[SM4_CCM:init_setup]");       \
        rdtsc_prof_print(&sm4_ccm_cycles_init_execute, "[SM4_CCM:init_execute]");   \
        rdtsc_prof_print(&sm4_ccm_cycles_encrypt_setup, "[SM4_CCM:encrypt_setup]");   \
        rdtsc_prof_print(&sm4_ccm_cycles_encrypt_execute, "[SM4_CCM:encrypt_execute]"); \
        rdtsc_prof_print(&sm4_ccm_cycles_decrypt_setup, "[SM4_CCM:decrypt_setup]");   \
        rdtsc_prof_print(&sm4_ccm_cycles_decrypt_execute, "[SM4_CCM:decrypt_execute]");   \
        rdtsc_prof_print(&sm4_ccm_cycles_ctrl_setup, "[SM4_CCM:ctrl_setup]");   \
        rdtsc_prof_print(&sm4_ccm_cycles_ctrl_execute, "[SM4_CCM:ctrl_execute]");   \
        rdtsc_prof_print(&sm4_ccm_cycles_cleanup_setup, "[SM4_CCM:cleanup_setup]");   \
        rdtsc_prof_print(&sm4_ccm_cycles_cleanup_execute, "[SM4_CCM:cleanup_execute]");  \
        rdtsc_prof_print(&sm4_ccm_cycles_get_tag_setup, "[SM4_CCM:get_tag_setup]");   \
        rdtsc_prof_print(&sm4_ccm_cycles_get_tag_execute, "[SM4_CCM:get_tag_execute]");   \
        rdtsc_prof_print(&sm4_ccm_cycles_update_aad_setup, "[SM4_CCM:update_aad_setup]");   \
        rdtsc_prof_print(&sm4_ccm_cycles_update_aad_execute, "[SM4_CCM:update_aad_execute]");  \
        rdtsc_prof_print(&qat_hw_rsa_dec_req_prepare, "[QAT HW RSA: prepare]");   \
        rdtsc_prof_print(&qat_hw_rsa_dec_req_submit, "[QAT HW RSA: submit]");   \
        rdtsc_prof_print(&qat_hw_rsa_dec_req_retry, "[QAT HW RSA: retry]");   \
        rdtsc_prof_print(&qat_hw_rsa_dec_req_cleanup, "[QAT HW RSA: cleanup]");   \
        rdtsc_prof_print(&qat_hw_ecdsa_sign_req_prepare, "[QAT HW ECDSA: prepare]");   \
        rdtsc_prof_print(&qat_hw_ecdsa_sign_req_submit, "[QAT HW ECDSA: submit]");   \
        rdtsc_prof_print(&qat_hw_ecdsa_sign_req_retry, "[QAT HW ECDSA: retry]");   \
        rdtsc_prof_print(&qat_hw_ecdsa_sign_req_cleanup, "[QAT HW ECDSA: cleanup]");   \
        rdtsc_prof_print(&qat_hw_ecdh_derive_req_prepare, "[QAT HW ECDH: prepare]");   \
        rdtsc_prof_print(&qat_hw_ecdh_derive_req_submit, "[QAT HW ECDH: submit]");   \
        rdtsc_prof_print(&qat_hw_ecdh_derive_req_retry, "[QAT HW ECDH: retry]");   \
        rdtsc_prof_print(&qat_hw_ecdh_derive_req_cleanup, "[QAT HW ECDH: cleanup]");   \
        rdtsc_prof_print(&qat_hw_ecx_derive_req_prepare, "[QAT HW ECX: prepare]");   \
        rdtsc_prof_print(&qat_hw_ecx_derive_req_submit, "[QAT HW ECX: submit]");   \
        rdtsc_prof_print(&qat_hw_ecx_derive_req_retry, "[QAT HW ECX: retry]");   \
        rdtsc_prof_print(&qat_hw_ecx_derive_req_cleanup, "[QAT HW ECX: cleanup]");   \
    } while (0)

#  define START_RDTSC(ptr_clock)     \
    do {                             \
        rdtsc_prof_start(ptr_clock); \
    } while (0)
#  define STOP_RDTSC(ptr_clock, inc, ptr_name)    \
    do {                                          \
        rdtsc_prof_end(ptr_clock, inc, ptr_name); \
    } while (0)
# else
#  define INITIALISE_RDTSC_CLOCKS()
#  define PRINT_RDTSC_AVERAGES()
#  define START_RDTSC(ptr_clock)
#  define STOP_RDTSC(ptr_clock, inc, ptr_name)
# endif /* QAT_CPU_CYCLES_COUNT */

/* Get absolute time by relative time. */
void get_sem_wait_abs_time(struct timespec *polling_abs_timeout,
                           const struct timespec polling_timeout);

#endif /* QAT_UTILS_H */
