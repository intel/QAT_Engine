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
 * @file qat_callback.c
 *
 * This file provides implementation for callback in engine
 *
 *****************************************************************************/

/* macros defined to allow use of the cpu get and set affinity functions */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#ifndef __USE_GNU
# define __USE_GNU
#endif

/* Standard Includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* Local Includes */
#include "e_qat.h"
#include "qat_callback.h"
#include "qat_events.h"
#include "qat_utils.h"
#include "e_qat_err.h"

/* OpenSSL Includes */
#include <openssl/err.h>

/* QAT includes */
#ifdef USE_QAT_CONTIG_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
# include "cmn_mem_drv_inf.h"
#endif
#include "cpa.h"
#include "cpa_types.h"
#include "icp_sal_poll.h"

void qat_init_op_done(op_done_t *opDone)
{
    if (unlikely(opDone == NULL)) {
        WARN("opDone is NULL\n");
        QATerr(QAT_F_QAT_INIT_OP_DONE, QAT_R_OPDONE_NULL);
        return;
    }

    opDone->flag = 0;
    opDone->verifyResult = CPA_FALSE;
    opDone->status = CPA_STATUS_FAIL;

    opDone->job = ASYNC_get_current_job();

}

int qat_init_op_done_pipe(op_done_pipe_t *opdpipe, unsigned int npipes)
{
    if (unlikely((opdpipe == NULL) || (npipes == 0))) {
        WARN("opdpipe is NULL or npipes is 0.\n");
        QATerr(QAT_F_QAT_INIT_OP_DONE_PIPE, QAT_R_OPDPIPE_NULL);
        return 0;
    }

    opdpipe->num_pipes = npipes;
    opdpipe->num_submitted = 0;
    opdpipe->num_processed = 0;

    opdpipe->opDone.flag = 0;
    opdpipe->opDone.verifyResult = CPA_TRUE;
    opdpipe->opDone.job = ASYNC_get_current_job();

    /* Setup async notification if using async jobs. */
    if (opdpipe->opDone.job != NULL &&
        (qat_setup_async_event_notification(0) == 0)) {
        WARN("Failure to setup async event notifications\n");
        QATerr(QAT_F_QAT_INIT_OP_DONE_PIPE, QAT_R_SETUP_ASYNC_EVENT_FAILURE);
        qat_cleanup_op_done_pipe(opdpipe);
        return 0;
    }

    return 1;
}

int qat_init_op_done_rsa_crt(op_done_rsa_crt_t *opdcrt)
{
    if (unlikely(opdcrt == NULL)) {
        WARN("opdcrt is NULL\n");
        QATerr(QAT_F_QAT_INIT_OP_DONE_RSA_CRT, QAT_R_OPDCRT_NULL);
        return 0;
    }

    opdcrt->opDone.flag = 0;
    /* note that the initial value is true in order to judge via AND */
    opdcrt->opDone.verifyResult = CPA_TRUE;
    opdcrt->opDone.status = CPA_STATUS_SUCCESS;

    opdcrt->opDone.job = NULL;

    opdcrt->req = 0;
    opdcrt->resp = 0;

    return 1;
}

void qat_cleanup_op_done(op_done_t *opDone)
{
    if (unlikely(opDone == NULL)) {
        WARN("opDone is NULL\n");
        return;
    }

    opDone->verifyResult = CPA_FALSE;
    opDone->status = CPA_STATUS_FAIL;

    if (opDone->job) {
        opDone->job = NULL;
    }
}

void qat_cleanup_op_done_pipe(op_done_pipe_t *opdone)
{
    if (unlikely(opdone == NULL)) {
        WARN("opdone is NULL\n");
        return;
    }

    opdone->num_pipes = 0;
    opdone->num_submitted = 0;
    opdone->num_processed = 0;
    qat_cleanup_op_done(&opdone->opDone);
}

void qat_cleanup_op_done_rsa_crt(op_done_rsa_crt_t *opdcrt)
{
    if (unlikely(opdcrt == NULL)) {
        WARN("opdcrt is NULL\n");
        return;
    }

    opdcrt->req = 0;
    opdcrt->resp = 0;
    qat_cleanup_op_done(&opdcrt->opDone);
}

void qat_crypto_callbackFn(void *callbackTag, CpaStatus status,
                           const CpaCySymOp operationType, void *pOpData,
                           CpaBufferList * pDstBuffer,
                           CpaBoolean verifyResult)
{
    ASYNC_JOB *job = NULL;
    op_done_t *opDone = (op_done_t *)callbackTag;

    if (unlikely(opDone == NULL)) {
        WARN("opDone is NULL\n");
        QATerr(QAT_F_QAT_CRYPTO_CALLBACKFN, QAT_R_OPDONE_NULL);
        return;
    }

    DEBUG("status %d verifyResult %d\n", status, verifyResult);
    opDone->verifyResult = (status == CPA_STATUS_SUCCESS) && verifyResult
                            ? CPA_TRUE : CPA_FALSE;
    opDone->status = status;

    /* Cache job pointer to avoid a race condition if opDone gets cleaned up
     * in the calling thread.
     */
    job = (ASYNC_JOB *)opDone->job;

    opDone->flag = 1;
    if (job) {
        qat_wake_job(job, ASYNC_STATUS_OK);
    }
}
