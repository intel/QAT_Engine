/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2017 Intel Corporation.
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
 * @file qat_utils.c
 *
 * This file provides an implementation of utilities for an OpenSSL engine
 *
 *****************************************************************************/

#include <stdio.h>
#include <pthread.h>
#include "cpa.h"
#include "qat_utils.h"
#include "e_qat.h"

#ifdef QAT_TESTS_LOG

FILE *cryptoQatLogger = NULL;
pthread_mutex_t debug_file_mutex = PTHREAD_MUTEX_INITIALIZER;
int debug_file_ref_count = 0;

void crypto_qat_debug_init_log()
{
    pthread_mutex_lock(&debug_file_mutex);
    if (!debug_file_ref_count) {
        cryptoQatLogger = fopen(CRYPTO_QAT_LOG_FILE, "w");

        if (NULL == cryptoQatLogger) {
            sprintf(stderr, "ERROR, unable to open %s \n",
                    CRYPTO_QAT_LOG_FILE);
            pthread_mutex_unlock(&debug_file_mutex);
            exit(1);
        }

    }
    debug_file_ref_count++;
    pthread_mutex_unlock(&debug_file_mutex);
}

void crypto_qat_debug_close_log()
{
    pthread_mutex_lock(&debug_file_mutex);
    debug_file_ref_count--;
    if (!debug_file_ref_count) {
        if (cryptoQatLogger != NULL) {
            fclose(cryptoQatLogger);
        }
    }
    pthread_mutex_unlock(&debug_file_mutex);
}
#endif                          /* QAT_TESTS_LOG */

#ifdef QAT_DEBUG
void hexDump(const char *func, const char *var, const unsigned char p[],
             int l)
{
    int i;

    fprintf(stderr, "%s: %s", func, var);
    if (NULL != p && l != 0) {
        for (i = 0; i < l; i++) {
            if (i % 16 == 0)
                fputc('\n', stderr);
            else if (i % 8 == 0)
                fputs("- ", stderr);
            fprintf(stderr, "%02x ", p[i]);
        }
    }
    fputc('\n', stderr);
}

void dumpRequest(const CpaInstanceHandle instance_handle,
                 void *pCallbackTag,
                 const CpaCySymOpData * pOpData,
                 const CpaCySymSessionSetupData * sessionData,
                 const CpaBufferList * pSrcBuffer, CpaBufferList * pDstBuffer)
{
    unsigned int index = 0;
    struct op_done_asynch *opDoneCB = (struct op_done_asynch *)pCallbackTag;

    fprintf(stderr, "\nInstance Handle:    %p\n", instance_handle);
    fprintf(stderr, "Callback Ptr:       %p\n", opDoneCB);
    fprintf(stderr, "OpData->packetType:        %s\n",
            (pOpData->packetType ==
             CPA_CY_SYM_PACKET_TYPE_FULL ? "FULL" : "PARTIAL"));
    hexDump(__func__, "Cipher Key:      ",
            sessionData->cipherSetupData.pCipherKey,
            sessionData->cipherSetupData.cipherKeyLenInBytes);
    fprintf(stderr, "Cipher Key Len:     %u\n",
            sessionData->cipherSetupData.cipherKeyLenInBytes);
    hexDump(__func__, "Cipher IV:               ", pOpData->pIv,
            pOpData->ivLenInBytes);
    if (sessionData->symOperation != CPA_CY_SYM_OP_CIPHER) {
        hexDump(__func__, "MAC Key:                 ",
                sessionData->hashSetupData.authModeSetupData.authKey,
                sessionData->hashSetupData.
                authModeSetupData.authKeyLenInBytes);
    }
    for (index = 0; index < pSrcBuffer->numBuffers; index++) {
        fprintf(stderr,
                "pSrcBuffer->pBuffers[%u].pData:                   %p\n",
                index, pSrcBuffer->pBuffers[index].pData);
        hexDump(__func__, " ", pSrcBuffer->pBuffers[index].pData,
                pSrcBuffer->pBuffers[index].dataLenInBytes);
        fprintf(stderr,
                "pSrcBuffer->pBuffers[%u].dataLenInBytes:          %u\n\n",
                index, pSrcBuffer->pBuffers[index].dataLenInBytes);
    }

    for (index = 0; index < pDstBuffer->numBuffers; index++) {
        fprintf(stderr,
                "pDstBuffer->pBuffers[%u].pData:                  %p\n",
                index, pDstBuffer->pBuffers[index].pData);
        hexDump(__func__, " ", pDstBuffer->pBuffers[index].pData,
                pDstBuffer->pBuffers[index].dataLenInBytes);
        fprintf(stderr,
                "pDstBuffer->pBuffers[%u].dataLenInBytes:         %u\n\n",
                index, pDstBuffer->pBuffers[index].dataLenInBytes);
    }

    fprintf(stderr,
            "sessionData->cipherSetupData.cipherAlgorithm:       %u\n",
            sessionData->cipherSetupData.cipherAlgorithm);
    fprintf(stderr,
            "sessionData->cipherSetupData.cipherDirection:       %u\n",
            sessionData->cipherSetupData.cipherDirection);
    fprintf(stderr,
            "sessionData->algChainOrder:                         %u\n",
            sessionData->algChainOrder);
    fprintf(stderr,
            "pOpData->cryptoStartSrcOffsetInBytes:               %u\n",
            pOpData->cryptoStartSrcOffsetInBytes);
    fprintf(stderr,
            "pOpData->messageLenToCipherInBytes:                 %u\n",
            pOpData->messageLenToCipherInBytes);
    fprintf(stderr,
            "sessionData->hashSetupData.hashAlgorithm:           %u\n",
            sessionData->hashSetupData.hashAlgorithm);
    fprintf(stderr,
            "sessionData->hashSetupData.hashMode:                %u\n",
            sessionData->hashSetupData.hashMode);
    fprintf(stderr,
            "pOpData->hashStartSrcOffsetInBytes:                 %u\n",
            pOpData->hashStartSrcOffsetInBytes);
    fprintf(stderr,
            "sessionData->hashSetupData.digestResultLenInBytes:  %u\n",
            sessionData->hashSetupData.digestResultLenInBytes);
    fprintf(stderr,
            "pOpData->messageLenToHashInBytes:                   %u\n",
            pOpData->messageLenToHashInBytes);
    fprintf(stderr,
            "pOpData->pDigestResult:                             %p\n",
            pOpData->pDigestResult);
    fprintf(stderr,
            "sessionData->verifyDigest:                          %s\n",
            (sessionData->verifyDigest ==
             CPA_TRUE ? "CPA_TRUE" : "CPA_FALSE"));
    fprintf(stderr,
            "sessionData->digestIsAppended:                      %s\n",
            (sessionData->digestIsAppended ==
             CPA_TRUE ? "CPA_TRUE" : "CPA_FALSE"));
}
#endif
