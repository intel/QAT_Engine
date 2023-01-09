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
 * @file qat_hw_polling.h
 *
 * This file provides an interface for polling in QAT engine
 *
 *****************************************************************************/

#ifndef QAT_HW_POLLING_H
# define QAT_HW_POLLING_H

# include "cpa.h"
# include "cpa_types.h"

# include "e_qat.h"
# include "qat_fork.h"

# ifndef __FreeBSD__
#  include <sys/epoll.h>
# endif
# define MAX_EVENTS 32

/* Globals */
typedef struct {
    int eng_fd;
    int inst_index;
} ENGINE_EPOLL_ST;

# ifndef __FreeBSD__
extern struct epoll_event eng_epoll_events[QAT_MAX_CRYPTO_INSTANCES];
extern ENGINE_EPOLL_ST eng_poll_st[QAT_MAX_CRYPTO_INSTANCES];
# endif
extern int internal_efd;

int getQatMsgRetryCount();
useconds_t getQatPollInterval();
int getEnableInlinePolling();

/******************************************************************************
 * function:
 *         void *qat_timer_poll_func(void *ih)
 *
 * @param ih [IN] - NULL
 *
 * description:
 *   Poll the QAT instances (nanosleep version)
 *     NB: Delay in this function is set by default at runtime by an engine
 *     specific message. If not set then the default is QAT_POLL_PERIOD_IN_NS.
 *     This function uses pthread signals to wait for a signal
 *     that there is traffic to process and therefore that QAT engine polling
 *     needs to be started/resumed.
 *
 ******************************************************************************/
void *qat_timer_poll_func(void *ih);

# ifndef __FreeBSD__
void *event_poll_func(void *ih);
# endif
CpaStatus poll_instances(void);
CpaStatus poll_heartbeat(void);

#endif   /* QAT_HW_POLLING_H */
