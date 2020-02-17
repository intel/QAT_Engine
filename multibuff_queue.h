/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2020 Intel Corporation.
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
 * @file multibuff_queue.h
 *
 * This file provides the data structure for storing up multibuff requests
 * so multiple request can be processed in one operation.
 *
 *****************************************************************************/

#ifndef MULTIBUFF_QUEUE_H
# define MULTIBUFF_QUEUE_H

# include <stdio.h>
# include "multibuff_request.h"

typedef struct _mb_queue_rsa_priv
{
    pthread_mutex_t mb_queue_mutex;
    rsa_priv_op_data *head;
    rsa_priv_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_rsa_priv;

typedef struct _mb_queue_rsa_pub
{
    pthread_mutex_t mb_queue_mutex;
    rsa_pub_op_data *head;
    rsa_pub_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_rsa_pub;

int mb_queue_rsa_priv_create(mb_queue_rsa_priv *queue);
int mb_queue_rsa_priv_disable(mb_queue_rsa_priv * queue);
int mb_queue_rsa_priv_cleanup(mb_queue_rsa_priv * queue);
int mb_queue_rsa_priv_enqueue(mb_queue_rsa_priv *queue, rsa_priv_op_data *item);
rsa_priv_op_data *mb_queue_rsa_priv_dequeue(mb_queue_rsa_priv *queue);
int mb_queue_rsa_priv_get_size(mb_queue_rsa_priv *queue);

int mb_queue_rsa_pub_create(mb_queue_rsa_pub *queue);
int mb_queue_rsa_pub_disable(mb_queue_rsa_pub * queue);
int mb_queue_rsa_pub_cleanup(mb_queue_rsa_pub * queue);
int mb_queue_rsa_pub_enqueue(mb_queue_rsa_pub *queue, rsa_pub_op_data *item);
rsa_pub_op_data *mb_queue_rsa_pub_dequeue(mb_queue_rsa_pub *queue);
int mb_queue_rsa_pub_get_size(mb_queue_rsa_pub *queue);

#endif /* MULTIBUFF_QUEUE_H */
