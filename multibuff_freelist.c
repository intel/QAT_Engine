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
 * @file multibuff_freelist.c
 *
 * This file provides multibuffer implementations of a freelist
 *
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

/* Local Includes */
#include "e_qat.h"
#include "multibuff_freelist.h"
#include "multibuff_request.h"
#include "e_qat_err.h"

/* OpenSSL Includes */
#include <openssl/err.h>

int mb_flist_rsa_priv_create(mb_flist_rsa_priv *freelist, int num_items)
{
    rsa_priv_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    if (0 == enable_external_polling) {
        pthread_mutex_init(&freelist->mb_flist_mutex, NULL);
    }
    freelist->head = NULL;

    while (num_items > 0) {
        item = OPENSSL_zalloc(sizeof(rsa_priv_op_data));
        if (item == NULL)
             return 1;
        if (mb_flist_rsa_priv_push(freelist, item) != 0)
             return 1;
        num_items--;
    }
    return 0;
}

int mb_flist_rsa_priv_cleanup(mb_flist_rsa_priv *freelist)
{
    rsa_priv_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    while ((item = mb_flist_rsa_priv_pop(freelist)) != NULL) {
       OPENSSL_free(item);
    }

    if (0 == enable_external_polling) {
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
    }
    return 0;
}

int mb_flist_rsa_priv_push(mb_flist_rsa_priv *freelist, rsa_priv_op_data *item)
{
    if (freelist == NULL)
        return 1;

    if (0 == enable_external_polling) {
        pthread_mutex_lock(&freelist->mb_flist_mutex);
    }

    item->next = freelist->head;
    freelist->head = item;

    if (0 == enable_external_polling) {
        pthread_mutex_unlock(&freelist->mb_flist_mutex);
    }
    return 0;
}

rsa_priv_op_data *mb_flist_rsa_priv_pop(mb_flist_rsa_priv *freelist)
{
    rsa_priv_op_data *item = NULL;

    if (freelist == NULL)
        return NULL;

    if (0 == enable_external_polling) {
        pthread_mutex_lock(&freelist->mb_flist_mutex);
    }

    if (freelist->head == NULL) {
        if (0 == enable_external_polling) {
            pthread_mutex_unlock(&freelist->mb_flist_mutex);
        }
        return NULL;
    }

    item = freelist->head;
    freelist->head = item->next;

    if (0 == enable_external_polling) {
        pthread_mutex_unlock(&freelist->mb_flist_mutex);
    }

    return item;
}

int mb_flist_rsa_pub_create(mb_flist_rsa_pub *freelist, int num_items)
{
    rsa_pub_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    if (0 == enable_external_polling) {
        pthread_mutex_init(&freelist->mb_flist_mutex, NULL);
    }
    freelist->head = NULL;

    while (num_items > 0) {
        item = OPENSSL_zalloc(sizeof(rsa_pub_op_data));
        if (item == NULL)
             return 1;
        if (mb_flist_rsa_pub_push(freelist, item) != 0)
             return 1;
        num_items--;
    }
    return 0;
}

int mb_flist_rsa_pub_cleanup(mb_flist_rsa_pub *freelist)
{
    rsa_pub_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    while ((item = mb_flist_rsa_pub_pop(freelist)) != NULL) {
       OPENSSL_free(item);
    }

    if (0 == enable_external_polling) {
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
    }
    return 0;
}

int mb_flist_rsa_pub_push(mb_flist_rsa_pub *freelist, rsa_pub_op_data *item)
{
    if (freelist == NULL)
        return 1;

    if (0 == enable_external_polling) {
        pthread_mutex_lock(&freelist->mb_flist_mutex);
    }

    item->next = freelist->head;
    freelist->head = item;

    if (0 == enable_external_polling) {
        pthread_mutex_unlock(&freelist->mb_flist_mutex);
    }
    return 0;
}

rsa_pub_op_data * mb_flist_rsa_pub_pop(mb_flist_rsa_pub *freelist)
{
    rsa_pub_op_data *item = NULL;

    if (freelist == NULL)
        return NULL;

    if (0 == enable_external_polling) {
        pthread_mutex_lock(&freelist->mb_flist_mutex);
    }

    if (freelist->head == NULL) {
        if (0 == enable_external_polling) {
            pthread_mutex_unlock(&freelist->mb_flist_mutex);
        }
        return NULL;
    }

    item = freelist->head;
    freelist->head = item->next;

    if (0 == enable_external_polling) {
        pthread_mutex_unlock(&freelist->mb_flist_mutex);
    }

    return item;
}
