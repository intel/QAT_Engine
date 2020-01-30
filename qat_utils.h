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
 * @file qat_utils.h
 *
 * This file provides an interface to utilities for the QAT engine in OpenSSL
 *
 *****************************************************************************/

#ifndef QAT_UTILS_H
# define QAT_UTILS_H

# include <stdio.h>
# include <pthread.h>
# include "cpa.h"
# include "cpa_cy_sym.h"

# define QAT_BYTE_ALIGNMENT 64
/* For best performance data buffers should be 64-byte aligned */
# define QAT_CONTIG_MEM_ALIGN(x)                              \
         (void *)(((uintptr_t)(x) + QAT_BYTE_ALIGNMENT - 1) & \
         (~(uintptr_t)(QAT_BYTE_ALIGNMENT-1)))


extern FILE* qatDebugLogFile;

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

#  define DEBUG(fmt_str, ...)                                    \
    do {                                                         \
        fprintf(qatDebugLogFile,"[DEBUG][%s:%d:%s()] "fmt_str,   \
                __FILE__, __LINE__, __func__, ##__VA_ARGS__);    \
        fflush(qatDebugLogFile);                                 \
    } while (0)
#  define DUMPL(var,p,l) qat_hex_dump(__func__,var,p,l);
# else
#  define DEBUG(...)
#  define DUMPL(...)
# endif

# if defined(QAT_WARN) || defined(QAT_DEBUG)
#  define WARN(fmt_str, ...)                                     \
    do {                                                         \
        fprintf(qatDebugLogFile,"[WARNING][%s:%d:%s()] "fmt_str, \
                __FILE__, __LINE__, __func__, ##__VA_ARGS__);    \
        fflush(qatDebugLogFile);                                 \
    } while (0)
# else
#  define WARN(...)
# endif

# ifdef QAT_DEBUG
#  define DUMP_DH_GEN_PHASE1(instance_handle, opData, pPV)                     \
    do {                                                                       \
        fprintf(qatDebugLogFile,"=========================\n");                \
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
        fprintf(qatDebugLogFile,"=========================\n");                \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_DH_GEN_PHASE2(instance_handle, opData, pSecretKey)              \
    do {                                                                       \
        fprintf(qatDebugLogFile,"=========================\n");                \
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
        fprintf(qatDebugLogFile,"=========================\n");                \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_DH_GEN_PHASE1_OUTPUT(pPV)                                       \
    do {                                                                       \
        fprintf(qatDebugLogFile,"=========================\n");                \
        fprintf(qatDebugLogFile,"DH Generate Phase 1 Output: %p\n", pPV);      \
        DUMPL("pPV->pData", pPV->pData, pPV->dataLenInBytes);                  \
        fprintf(qatDebugLogFile,"=========================\n");                \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_DH_GEN_PHASE2_OUTPUT(pSecretKey)                                \
    do {                                                                       \
        fprintf(qatDebugLogFile,"=========================\n");                \
        fprintf(qatDebugLogFile,"DH Generate Phase 2 Output: %p\n",            \
                pSecretKey);                                                   \
        DUMPL("pSecretKey->pData",                                             \
               pSecretKey->pData, pSecretKey->dataLenInBytes);                 \
        fprintf(qatDebugLogFile,"=========================\n");                \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_EC_POINT_MULTIPLY(instance_handle, opData, pResultX, pResultY)  \
    do {                                                                       \
        fprintf(qatDebugLogFile,"=========================\n");                \
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
        fprintf(qatDebugLogFile,"=========================\n");                \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_EC_POINT_MULTIPLY_OUTPUT(bEcStatus, pResultX, pResultY)         \
    do {                                                                       \
        fprintf(qatDebugLogFile,"=========================\n");                \
        fprintf(qatDebugLogFile,"EC Point Multiply Output: pResultX %p, "      \
                "pResultY %p\n", pResultX, pResultY);                          \
        fprintf(qatDebugLogFile,"bEcStatus = %u\n", bEcStatus);                \
        DUMPL("pResultX->pData", pResultX->pData, pResultX->dataLenInBytes);   \
        DUMPL("pResultY->pData", pResultY->pData, pResultY->dataLenInBytes);   \
        fprintf(qatDebugLogFile,"=========================\n");                \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_ECDSA_SIGN(instance_handle, opData, pResultR, pResultS)         \
    do {                                                                       \
        fprintf(qatDebugLogFile,"=========================\n");                \
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
        fprintf(qatDebugLogFile,"=========================\n");                \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_ECDSA_SIGN_OUTPUT(bEcdsaSignStatus, pResultR, pResultS)         \
    do {                                                                       \
        fprintf(qatDebugLogFile,"=========================\n");                \
        fprintf(qatDebugLogFile,"ECDSA Sign Output:"                           \
                " pResultR %p, pResultS %p\n",                                 \
                pResultR, pResultS);                                           \
        fprintf(qatDebugLogFile, "bEcdsaSignStatus = %u\n", bEcdsaSignStatus); \
        DUMPL("pResultR->pData", pResultR->pData, pResultR->dataLenInBytes);   \
        DUMPL("pResultS->pData", pResultS->pData, pResultS->dataLenInBytes);   \
        fprintf(qatDebugLogFile,"=========================\n");                \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_ECDSA_VERIFY(instance_handle, opData)                           \
    do {                                                                       \
        fprintf(qatDebugLogFile,"=========================\n");                \
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
        fprintf(qatDebugLogFile,"=========================\n");                \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_DSA_SIGN(instance_handle, op_done, opData, bDsaSignStatus,      \
                        pResultR, pResultS)                                    \
    do {                                                                       \
        fprintf(qatDebugLogFile,"=========================\n");                \
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
        fprintf(qatDebugLogFile,"=========================\n");                \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_DSA_SIGN_OUTPUT(bDsaSignStatus, pResultR, pResultS)             \
    do {                                                                       \
        fprintf(qatDebugLogFile,"=========================\n");                \
        fprintf(qatDebugLogFile,"DSA Sign Output:  pResultR %p, pResultS %p\n",\
                pResultR, pResultS);                                           \
        fprintf(qatDebugLogFile,"bDsaSignStatus = %u\n", bDsaSignStatus);      \
        DUMPL("pResultR->pData", pResultR->pData, pResultR->dataLenInBytes);   \
        DUMPL("pResultS->pData", pResultS->pData, pResultS->dataLenInBytes);   \
        fprintf(qatDebugLogFile,"=========================\n");                \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_DSA_VERIFY(instance_handle, op_done, opData, bDsaVerifyStatus)  \
    do {                                                                       \
        fprintf(qatDebugLogFile,"=========================\n");                \
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
        fprintf(qatDebugLogFile,"=========================\n");                \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_RSA_ENCRYPT(instance_handle, op_done, opData, output_buf)       \
    do {                                                                       \
        fprintf(qatDebugLogFile,"=========================\n");                \
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
        fprintf(qatDebugLogFile,"=========================\n");                \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_RSA_ENCRYPT_OUTPUT(output_buf)                                  \
    do {                                                                       \
        fprintf(qatDebugLogFile,"=========================\n");                \
        fprintf(qatDebugLogFile,"RSA Encrypt Output: %p\n", output_buf);       \
        DUMPL("output_buf", output_buf->pData, output_buf->dataLenInBytes);    \
        fprintf(qatDebugLogFile,"=========================\n");                \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_RSA_DECRYPT(instance_handle, op_done, opData, output_buf)       \
    do {                                                                       \
        fprintf(qatDebugLogFile,"=========================\n");                \
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
        fprintf(qatDebugLogFile,"=========================\n");                \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_RSA_DECRYPT_OUTPUT(output_buf)                                  \
    do {                                                                       \
        fprintf(qatDebugLogFile,"=========================\n");                \
        fprintf(qatDebugLogFile,"RSA Decrypt Output: %p\n", output_buf);       \
        DUMPL("output_buf", output_buf->pData, output_buf->dataLenInBytes);    \
        fprintf(qatDebugLogFile,"=========================\n");                \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_KEYGEN_TLS(instance_handle, generated_key)                      \
    do {                                                                       \
        fprintf(qatDebugLogFile,"=========================\n");                \
        fprintf(qatDebugLogFile,"TLS Keygen Request: \n");                     \
        fprintf(qatDebugLogFile,"instance_handle = %p\n", instance_handle);    \
        DUMPL("generated_key->pData", generated_key->pData,                    \
               generated_key->dataLenInBytes);                                 \
        fprintf(qatDebugLogFile,"=========================\n");                \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_KEYGEN_TLS_OUTPUT(generated_key)                                \
    do {                                                                       \
        fprintf(qatDebugLogFile,"=========================\n");                \
        fprintf(qatDebugLogFile,"TLS Keygen Output: %p\n", generated_key);     \
        DUMPL("generated_key->pData", generated_key->pData,                    \
               generated_key->dataLenInBytes);                                 \
        fprintf(qatDebugLogFile,"=========================\n");                \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_SESSION_SETUP_DATA(ssd)                                         \
    do {                                                                       \
        fprintf(qatDebugLogFile,"=========================\n");                \
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
        fprintf(qatDebugLogFile,"=========================\n");                \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_SYM_PERFORM_OP(instance_handle, pOpData, pSrcBuffer,            \
        pDstBuffer)                                                            \
    do {                                                                       \
        unsigned int index = 0;                                                \
        fprintf(qatDebugLogFile,"=========================\n");                \
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
        fprintf(qatDebugLogFile,"=========================\n");                \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_SYM_PERFORM_OP_OUTPUT(pVerifyResult, pDstBuffer)                \
    do {                                                                       \
        unsigned int index = 0;                                                \
        fprintf(qatDebugLogFile,"=========================\n");                \
        fprintf(qatDebugLogFile,"Symmetric crypto perform op Output: %p\n",    \
                pDstBuffer);                                                   \
        fprintf(qatDebugLogFile,"pVerifyResult = %d\n", *pVerifyResult);       \
        for (index = 0; index < pDstBuffer->numBuffers; index++) {             \
            DUMPL("pDstBuffer->pBuffers[%u].pData",                            \
                   pDstBuffer->pBuffers[index].pData,                          \
                   pDstBuffer->pBuffers[index].dataLenInBytes);                \
        }                                                                      \
        fprintf(qatDebugLogFile,"=========================\n");                \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_PRF_OP_DATA(prfOpData)                                          \
    do {                                                                       \
        fprintf(qatDebugLogFile,"=========================\n");                \
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
        fprintf(qatDebugLogFile,"=========================\n");                \
        fflush(qatDebugLogFile);                                               \
    } while (0)

#  define DUMP_HKDF_OP_DATA(hkdfOpData)                                        \
    do {                                                                       \
        fprintf(qatDebugLogFile,"=========================\n");                \
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

# else
#  define DUMP_DH_GEN_PHASE1(...)
#  define DUMP_DH_GEN_PHASE2(...)
#  define DUMP_DH_GEN_PHASE1_OUTPUT(...)
#  define DUMP_DH_GEN_PHASE2_OUTPUT(...)
#  define DUMP_EC_POINT_MULTIPLY(...)
#  define DUMP_EC_POINT_MULTIPLY_OUTPUT(...)
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
#  define DUMP_PRF_OP_DATA(...)
#  define DUMP_HKDF_OP_DATA(...)
# endif                         /* QAT_DEBUG */

#endif                          /* QAT_UTILS_H */
