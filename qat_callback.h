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
 * @file qat_callback.h
 *
 * This file provides and interface for async events to engine
 *
 *****************************************************************************/

#ifndef QAT_CALLBACK_H
# define QAT_CALLBACK_H

# include <sys/types.h>
# include <unistd.h>

# include "cpa.h"
# include "cpa_types.h"
# include "cpa_cy_sym.h"

# if OPENSSL_VERSION_NUMBER >= 0x10100000L
# include <openssl/async.h>
# endif

/* Struct for tracking threaded QAT operation completion. */
typedef struct {
    volatile int flag;
    volatile CpaBoolean verifyResult;
    volatile ASYNC_JOB *job;
    volatile CpaStatus status;
} op_done_t;

/* Use this variant of op_done to track QAT chained cipher
 * operation completion supporting pipelines.
 */
typedef struct {
    /* Keep this as first member of the structure.
     * to allow inter-changeability by casting pointers.
     */
    op_done_t opDone;
    volatile unsigned int num_pipes;
    volatile unsigned int num_submitted;
    volatile unsigned int num_processed;
} op_done_pipe_t;

/* Use this variant of op_done to track
 * QAT RSA CRT operation completion.
 */
typedef struct {
    /* Keep this as first member of the structure.
     * to allow inter-changeability by casting pointers.
     */
    op_done_t opDone;
    unsigned int req;
    volatile unsigned int resp;
} op_done_rsa_crt_t;


/******************************************************************************
 * function:
 *         qat_init_op_done(op_done_t *opDone)
 *
 * @param opDone [IN] - pointer to op done_t callback structure.
 *
 * description:
 *   Initialise the QAT operation "done" callback structure.
 *
 ******************************************************************************/
void qat_init_op_done(op_done_t *opDone);


/******************************************************************************
 * function:
 *         qat_init_op_done_pipe(op_done_pipe_t *opdpipe, unsigned int npipes)
 *
 * @param opdpipe [IN] - pointer to op_done_pipe_t callback structure
 * @param npipes  [IN] - number of pipes in the pipeline
 *
 * description:
 *   Initialise the QAT chained operation "done" callback structure.
 *   Setup async event notification if required. The function returns
 *   1 for success and 0 for failure.
 *
 ******************************************************************************/
int qat_init_op_done_pipe(op_done_pipe_t *opDone, unsigned int npipes);


/******************************************************************************
 * function:
 *         qat_init_op_done_rsa_crt(op_done_rsa_crt_t *opdcrt)
 *
 * @param opdcrt [IN] - pointer to op_done_rsa_crt_t callback structure.
 *
 * description:
 *   Initialise the QAT RSA synchronous operation "done" callback structure.
 *   The function returns 1 for success and 0 for failure.
 *
 ******************************************************************************/
int qat_init_op_done_rsa_crt(op_done_rsa_crt_t *opdcrt);


/******************************************************************************
 * function:
 *         qat_cleanup_op_done(op_done_t *opDone)
 *
 * @param opDone [IN] - pointer to op_done_t callback structure.
 *
 * description:
 *   Cleanup the data in the "done" callback structure.
 *
 ******************************************************************************/
void qat_cleanup_op_done(op_done_t *opDone);


/******************************************************************************
 * function:
 *         qat_cleanup_op_done_pipe(op_done_pipe_t *opDone)
 *
 * @param opDone [IN] - pointer to op_done_pipe_t callback structure.
 *
 * description:
 *   Cleanup the QAT chained operation "done" callback structure.
 *
 ******************************************************************************/
void qat_cleanup_op_done_pipe(op_done_pipe_t *opDone);


/******************************************************************************
 * function:
 *         qat_cleanup_op_done_rsa_crt(op_done_rsa_crt_t *opdcrt)
 *
 * @param opdcrt [IN] - pointer to op_done_rsa_crt_t callback structure.
 *
 * description:
 *   Cleanup the QAT RSA synchronous operation "done" callback structure.
 *
 ******************************************************************************/
void qat_cleanup_op_done_rsa_crt(op_done_rsa_crt_t *opdcrt);


/******************************************************************************
 * function:
 *         qat_crypto_callbackFn(void *callbackTag, CpaStatus status,
 *                        const CpaCySymOp operationType, void *pOpData,
 *                        CpaBufferList * pDstBuffer, CpaBoolean verifyResult)
 *
 *
 * @param pCallbackTag  [IN] -  Opaque value provided by user while making
 *                              individual function call. Cast to op_done.
 * @param status        [IN] -  Status of the operation.
 * @param operationType [IN] -  Identifies the operation type requested.
 * @param pOpData       [IN] -  Pointer to structure with input parameters.
 * @param pDstBuffer    [IN] -  Destination buffer to hold the data output.
 * @param verifyResult  [IN] -  Used to verify digest result.
 *
 * description:
 *   Callback function used by cpaCySymPerformOp to indicate completion.
 *
 ******************************************************************************/
void qat_crypto_callbackFn(void *callbackTag, CpaStatus status,
                           const CpaCySymOp operationType, void *pOpData,
                           CpaBufferList * pDstBuffer,
                           CpaBoolean verifyResult);
#endif   /* QAT_CALLBACK_H */
