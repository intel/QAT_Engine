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
 * @file multibuff_queue.c
 *
 * This file provides multibuff implementations of a queue
 *
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

/* Local Includes */
#include "multibuff_init.h"
#include "multibuff_queue.h"
#include "multibuff_request.h"

/* OpenSSL Includes */
#include <openssl/err.h>

int mb_queue_rsa_priv_create(mb_queue_rsa_priv *queue)
{
    if (queue == NULL)
        return 1;

    if (0 == enable_external_polling) {
        pthread_mutex_init(&queue->mb_queue_mutex, NULL);
        pthread_mutex_lock(&queue->mb_queue_mutex);
    }
    queue->head = NULL;
    queue->tail = NULL;
    queue->disabled = 0;
    queue->num_items = 0;
    if (0 == enable_external_polling) {
        pthread_mutex_unlock(&queue->mb_queue_mutex);
    }

    return 0;
}

int mb_queue_rsa_priv_disable(mb_queue_rsa_priv *queue)
{
    if (queue == NULL)
        return 1;

    if (0 == enable_external_polling) {
        pthread_mutex_lock(&queue->mb_queue_mutex);
    }
    queue->disabled = 1;
    if (0 == enable_external_polling) {
        pthread_mutex_unlock(&queue->mb_queue_mutex);
    }

    return 0;
}

int mb_queue_rsa_priv_cleanup(mb_queue_rsa_priv *queue)
{
    if (queue == NULL)
        return 1;

    if (0 == enable_external_polling) {
        pthread_mutex_destroy(&queue->mb_queue_mutex);
    }
    return 0;
}

int mb_queue_rsa_priv_enqueue(mb_queue_rsa_priv *queue, rsa_priv_op_data *item)
{
    if (queue == NULL || item == NULL)
        return 1;

    if (0 == enable_external_polling) {
        pthread_mutex_lock(&queue->mb_queue_mutex);
    }

    if (queue->disabled == 1) {
        if (0 == enable_external_polling) {
            pthread_mutex_unlock(&queue->mb_queue_mutex);
        }
        return 1;
    }

    if (queue->num_items == 0) {
        queue->tail = item;
        queue->head = item;
    } else {
        queue->tail->next = item;
        queue->tail = item;
    }
    queue->tail->next = NULL;
    queue->num_items++;

    if (0 == enable_external_polling) {
        pthread_mutex_unlock(&queue->mb_queue_mutex);
    }
    return 0;
}

rsa_priv_op_data * mb_queue_rsa_priv_dequeue(mb_queue_rsa_priv *queue)
{
    rsa_priv_op_data *item = NULL;

    if (queue == NULL)
        return NULL;

    if (0 == enable_external_polling) {
        pthread_mutex_lock(&queue->mb_queue_mutex);
    }

    if (queue->head == NULL) {
        if (0 == enable_external_polling) {
            pthread_mutex_unlock(&queue->mb_queue_mutex);
        }
        return NULL;
    }

    item = queue->head;
    queue->head = item->next;
    queue->num_items--;
    if (queue->num_items == 0)
        queue->tail = NULL;

    if (0 == enable_external_polling) {
        pthread_mutex_unlock(&queue->mb_queue_mutex);
    }

    return item;
}

int mb_queue_rsa_priv_get_size(mb_queue_rsa_priv *queue)
{
    if (queue == NULL)
        return 0;

    return queue->num_items;
}

int mb_queue_rsa_pub_create(mb_queue_rsa_pub *queue)
{
    if (queue == NULL)
        return 1;

    if (0 == enable_external_polling) {
        pthread_mutex_init(&queue->mb_queue_mutex, NULL);
        pthread_mutex_lock(&queue->mb_queue_mutex);
    }
    queue->head = NULL;
    queue->tail = NULL;
    queue->disabled = 0;
    queue->num_items = 0;
    if (0 == enable_external_polling) {
        pthread_mutex_unlock(&queue->mb_queue_mutex);
    }

    return 0;
}

int mb_queue_rsa_pub_disable(mb_queue_rsa_pub *queue)
{
    if (queue == NULL)
        return 1;

    if (0 == enable_external_polling) {
        pthread_mutex_lock(&queue->mb_queue_mutex);
    }
    queue->disabled = 1;
    if (0 == enable_external_polling) {
        pthread_mutex_unlock(&queue->mb_queue_mutex);
    }

    return 0;
}

int mb_queue_rsa_pub_cleanup(mb_queue_rsa_pub *queue)
{
    if (queue == NULL)
        return 1;

    if (0 == enable_external_polling) {
        pthread_mutex_destroy(&queue->mb_queue_mutex);
    }
    return 0;
}

int mb_queue_rsa_pub_enqueue(mb_queue_rsa_pub *queue, rsa_pub_op_data *item)
{
    if (queue == NULL || item == NULL)
        return 1;

    if (0 == enable_external_polling) {
        pthread_mutex_lock(&queue->mb_queue_mutex);
    }

    if (queue->disabled == 1) {
        if (0 == enable_external_polling) {
            pthread_mutex_unlock(&queue->mb_queue_mutex);
        }
        return 1;
    }

    if (queue->num_items == 0) {
        queue->tail = item;
        queue->head = item;
    } else {
        queue->tail->next = item;
        queue->tail = item;
    }
    queue->tail->next = NULL;
    queue->num_items++;

    if (0 == enable_external_polling) {
        pthread_mutex_unlock(&queue->mb_queue_mutex);
    }
    return 0;
}

rsa_pub_op_data * mb_queue_rsa_pub_dequeue(mb_queue_rsa_pub *queue)
{
    rsa_pub_op_data *item = NULL;

    if (queue == NULL)
        return NULL;

    if (0 == enable_external_polling) {
        pthread_mutex_lock(&queue->mb_queue_mutex);
    }

    if (queue->head == NULL) {
        if (0 == enable_external_polling) {
            pthread_mutex_unlock(&queue->mb_queue_mutex);
        }
        return NULL;
    }

    item = queue->head;
    queue->head = item->next;
    queue->num_items--;
    if (queue->num_items == 0)
        queue->tail = NULL;

    if (0 == enable_external_polling) {
        pthread_mutex_unlock(&queue->mb_queue_mutex);
    }

    return item;
}

int mb_queue_rsa_pub_get_size(mb_queue_rsa_pub *queue)
{
    if (queue == NULL)
        return 0;

    return queue->num_items;
}
