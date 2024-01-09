/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2020-2024 Intel Corporation.
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
 * @file qat_sw_freelist.c
 *
 * This file provides multibuffer implementations of a freelist
 *
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

/* Local Includes */
#include "e_qat.h"
#include "qat_sw_freelist.h"
#include "qat_sw_request.h"
#include "qat_utils.h"

/* OpenSSL Includes */
#include <openssl/err.h>

mb_flist_rsa_priv * mb_flist_rsa_priv_create()
{
    mb_flist_rsa_priv *freelist = NULL;
    rsa_priv_op_data *item = NULL;
    int num_items = MULTIBUFF_MAX_INFLIGHTS;

    freelist = OPENSSL_zalloc(sizeof(mb_flist_rsa_priv));
    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_init(&freelist->mb_flist_mutex, NULL);

    DEBUG("Freelist Created %p\n", freelist);
    freelist->head = NULL;

    while (num_items > 0) {
        item = OPENSSL_zalloc(sizeof(rsa_priv_op_data));
        if (item == NULL) {
            mb_flist_rsa_priv_cleanup(freelist);
            return NULL;
        }
        if (mb_flist_rsa_priv_push(freelist, item) != 0) {
            mb_flist_rsa_priv_cleanup(freelist);
            return NULL;
        }
        num_items--;
    }
    return freelist;
}

int mb_flist_rsa_priv_cleanup(mb_flist_rsa_priv *freelist)
{
    rsa_priv_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    while ((item = mb_flist_rsa_priv_pop(freelist)) != NULL) {
       OPENSSL_free(item);
    }

    if (!enable_external_polling) {
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
        OPENSSL_free(freelist);
    }
    return 0;
}

int mb_flist_rsa_priv_push(mb_flist_rsa_priv *freelist, rsa_priv_op_data *item)
{
    if (freelist == NULL)
        return 1;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    item->next = freelist->head;
    freelist->head = item;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return 0;
}

rsa_priv_op_data *mb_flist_rsa_priv_pop(mb_flist_rsa_priv *freelist)
{
    rsa_priv_op_data *item = NULL;

    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    if (freelist->head == NULL) {
        if (!enable_external_polling)
            pthread_mutex_unlock(&freelist->mb_flist_mutex);
        return NULL;
    }

    item = freelist->head;
    freelist->head = item->next;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return item;
}

mb_flist_rsa_pub * mb_flist_rsa_pub_create()
{
    mb_flist_rsa_pub *freelist = NULL;
    rsa_pub_op_data *item = NULL;
    int num_items = MULTIBUFF_MAX_INFLIGHTS;

    freelist = OPENSSL_zalloc(sizeof(mb_flist_rsa_pub));
    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_init(&freelist->mb_flist_mutex, NULL);

    DEBUG("Freelist Created %p\n", freelist);
    freelist->head = NULL;

    while (num_items > 0) {
        item = OPENSSL_zalloc(sizeof(rsa_pub_op_data));
        if (item == NULL) {
            mb_flist_rsa_pub_cleanup(freelist);
            return NULL;
        }
        if (mb_flist_rsa_pub_push(freelist, item) != 0) {
            mb_flist_rsa_pub_cleanup(freelist);
            return NULL;
        }
        num_items--;
    }
    return freelist;
}

int mb_flist_rsa_pub_cleanup(mb_flist_rsa_pub *freelist)
{
    rsa_pub_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    while ((item = mb_flist_rsa_pub_pop(freelist)) != NULL) {
       OPENSSL_free(item);
    }

    if (!enable_external_polling) {
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
        OPENSSL_free(freelist);
    }
    return 0;
}

int mb_flist_rsa_pub_push(mb_flist_rsa_pub *freelist, rsa_pub_op_data *item)
{
    if (freelist == NULL)
        return 1;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    item->next = freelist->head;
    freelist->head = item;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return 0;
}

rsa_pub_op_data * mb_flist_rsa_pub_pop(mb_flist_rsa_pub *freelist)
{
    rsa_pub_op_data *item = NULL;

    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    if (freelist->head == NULL) {
        if (!enable_external_polling)
            pthread_mutex_unlock(&freelist->mb_flist_mutex);
        return NULL;
    }

    item = freelist->head;
    freelist->head = item->next;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return item;
}

mb_flist_x25519_keygen * mb_flist_x25519_keygen_create()
{
    mb_flist_x25519_keygen *freelist = NULL;
    x25519_keygen_op_data *item = NULL;
    int num_items = MULTIBUFF_MAX_INFLIGHTS;

    freelist = OPENSSL_zalloc(sizeof(mb_flist_x25519_keygen));
    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_init(&freelist->mb_flist_mutex, NULL);

    DEBUG("Freelist Created %p\n", freelist);
    freelist->head = NULL;

    while (num_items > 0) {
        item = OPENSSL_zalloc(sizeof(x25519_keygen_op_data));
        if (item == NULL) {
            mb_flist_x25519_keygen_cleanup(freelist);
            return NULL;
        }
        if (mb_flist_x25519_keygen_push(freelist, item) != 0) {
            mb_flist_x25519_keygen_cleanup(freelist);
            return NULL;
        }
        num_items--;
    }
    return freelist;
}

int mb_flist_x25519_keygen_cleanup(mb_flist_x25519_keygen *freelist)
{
    x25519_keygen_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    while ((item = mb_flist_x25519_keygen_pop(freelist)) != NULL) {
       OPENSSL_free(item);
    }

    if (!enable_external_polling) {
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
        OPENSSL_free(freelist);
    }
    return 0;
}

int mb_flist_x25519_keygen_push(mb_flist_x25519_keygen *freelist,
                                x25519_keygen_op_data *item)
{
    if (freelist == NULL)
        return 1;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    item->next = freelist->head;
    freelist->head = item;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return 0;
}

x25519_keygen_op_data *mb_flist_x25519_keygen_pop(mb_flist_x25519_keygen *freelist)
{
    x25519_keygen_op_data *item = NULL;

    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    if (freelist->head == NULL) {
        if (!enable_external_polling)
            pthread_mutex_unlock(&freelist->mb_flist_mutex);
        return NULL;
    }

    item = freelist->head;
    freelist->head = item->next;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return item;
}

mb_flist_x25519_derive *mb_flist_x25519_derive_create()
{
    mb_flist_x25519_derive *freelist = NULL;
    x25519_derive_op_data *item = NULL;
    int num_items = MULTIBUFF_MAX_INFLIGHTS;

    freelist = OPENSSL_zalloc(sizeof(mb_flist_x25519_derive));
    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_init(&freelist->mb_flist_mutex, NULL);

    DEBUG("Freelist Created %p\n", freelist);
    freelist->head = NULL;

    while (num_items > 0) {
        item = OPENSSL_zalloc(sizeof(x25519_derive_op_data));
        if (item == NULL) {
            mb_flist_x25519_derive_cleanup(freelist);
            return NULL;
        }
        if (mb_flist_x25519_derive_push(freelist, item) != 0) {
            mb_flist_x25519_derive_cleanup(freelist);
            return NULL;
        }
        num_items--;
    }
    return freelist;
}

int mb_flist_x25519_derive_cleanup(mb_flist_x25519_derive *freelist)
{
    x25519_derive_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    while ((item = mb_flist_x25519_derive_pop(freelist)) != NULL) {
       OPENSSL_free(item);
    }

    if (!enable_external_polling) {
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
        OPENSSL_free(freelist);
    }
    return 0;
}

int mb_flist_x25519_derive_push(mb_flist_x25519_derive *freelist,
                                x25519_derive_op_data *item)
{
    if (freelist == NULL)
        return 1;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    item->next = freelist->head;
    freelist->head = item;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return 0;
}

x25519_derive_op_data *mb_flist_x25519_derive_pop(mb_flist_x25519_derive *freelist)
{
    x25519_derive_op_data *item = NULL;

    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    if (freelist->head == NULL) {
        if (!enable_external_polling) {
            pthread_mutex_unlock(&freelist->mb_flist_mutex);
        }
        return NULL;
    }

    item = freelist->head;
    freelist->head = item->next;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return item;
}

mb_flist_ecdsa_sign * mb_flist_ecdsa_sign_create()
{
    mb_flist_ecdsa_sign *freelist = NULL;
    ecdsa_sign_op_data *item = NULL;
    int num_items = MULTIBUFF_MAX_INFLIGHTS;

    freelist = OPENSSL_zalloc(sizeof(mb_flist_ecdsa_sign));
    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_init(&freelist->mb_flist_mutex, NULL);

    DEBUG("Freelist Created %p\n", freelist);
    freelist->head = NULL;

    while (num_items > 0) {
        item = OPENSSL_zalloc(sizeof(ecdsa_sign_op_data));
        if (item == NULL) {
            mb_flist_ecdsa_sign_cleanup(freelist);
            return NULL;
        }
        if (mb_flist_ecdsa_sign_push(freelist, item) != 0) {
            mb_flist_ecdsa_sign_cleanup(freelist);
            return NULL;
        }
        num_items--;
    }
    return freelist;
}

int mb_flist_ecdsa_sign_cleanup(mb_flist_ecdsa_sign *freelist)
{
    ecdsa_sign_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    while ((item = mb_flist_ecdsa_sign_pop(freelist)) != NULL) {
       OPENSSL_free(item);
    }

    if (!enable_external_polling) {
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
        OPENSSL_free(freelist);
    }
    return 0;
}

int mb_flist_ecdsa_sign_push(mb_flist_ecdsa_sign *freelist,
                             ecdsa_sign_op_data *item)
{
    if (freelist == NULL)
        return 1;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    item->next = freelist->head;
    freelist->head = item;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return 0;
}

ecdsa_sign_op_data
    *mb_flist_ecdsa_sign_pop(mb_flist_ecdsa_sign *freelist)
{
    ecdsa_sign_op_data *item = NULL;

    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    if (freelist->head == NULL) {
        if (!enable_external_polling)
            pthread_mutex_unlock(&freelist->mb_flist_mutex);
        return NULL;
    }

    item = freelist->head;
    freelist->head = item->next;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return item;
}

mb_flist_ecdsa_sign_setup * mb_flist_ecdsa_sign_setup_create()
{
    mb_flist_ecdsa_sign_setup *freelist = NULL;
    ecdsa_sign_setup_op_data *item = NULL;
    int num_items = MULTIBUFF_MAX_INFLIGHTS;

    freelist = OPENSSL_zalloc(sizeof(mb_flist_ecdsa_sign_setup));
    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_init(&freelist->mb_flist_mutex, NULL);

    DEBUG("Freelist Created %p\n", freelist);
    freelist->head = NULL;

    while (num_items > 0) {
        item = OPENSSL_zalloc(sizeof(ecdsa_sign_setup_op_data));
        if (item == NULL) {
            mb_flist_ecdsa_sign_setup_cleanup(freelist);
            return NULL;
        }
        if (mb_flist_ecdsa_sign_setup_push(freelist, item) != 0) {
            mb_flist_ecdsa_sign_setup_cleanup(freelist);
            return NULL;
        }
        num_items--;
    }
    return freelist;
}

int mb_flist_ecdsa_sign_setup_cleanup(mb_flist_ecdsa_sign_setup *freelist)
{
    ecdsa_sign_setup_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    while ((item = mb_flist_ecdsa_sign_setup_pop(freelist)) != NULL) {
       OPENSSL_free(item);
    }

    if (!enable_external_polling) {
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
        OPENSSL_free(freelist);
    }
    return 0;
}

int mb_flist_ecdsa_sign_setup_push(mb_flist_ecdsa_sign_setup *freelist,
                                   ecdsa_sign_setup_op_data *item)
{
    if (freelist == NULL)
        return 1;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    item->next = freelist->head;
    freelist->head = item;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return 0;
}

ecdsa_sign_setup_op_data
    *mb_flist_ecdsa_sign_setup_pop(mb_flist_ecdsa_sign_setup *freelist)
{
    ecdsa_sign_setup_op_data *item = NULL;

    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    if (freelist->head == NULL) {
        if (!enable_external_polling)
            pthread_mutex_unlock(&freelist->mb_flist_mutex);
        return NULL;
    }

    item = freelist->head;
    freelist->head = item->next;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return item;
}

mb_flist_ecdsa_sign_sig * mb_flist_ecdsa_sign_sig_create()
{
    mb_flist_ecdsa_sign_sig *freelist = NULL;
    ecdsa_sign_sig_op_data *item = NULL;
    int num_items = MULTIBUFF_MAX_INFLIGHTS;

    freelist = OPENSSL_zalloc(sizeof(mb_flist_ecdsa_sign_sig));
    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_init(&freelist->mb_flist_mutex, NULL);

    DEBUG("Freelist Created %p\n", freelist);
    freelist->head = NULL;

    while (num_items > 0) {
        item = OPENSSL_zalloc(sizeof(ecdsa_sign_sig_op_data));
        if (item == NULL) {
            mb_flist_ecdsa_sign_sig_cleanup(freelist);
            return NULL;
        }
        if (mb_flist_ecdsa_sign_sig_push(freelist, item) != 0) {
            mb_flist_ecdsa_sign_sig_cleanup(freelist);
            return NULL;
        }
        num_items--;
    }
    return freelist;
}

int mb_flist_ecdsa_sign_sig_cleanup(mb_flist_ecdsa_sign_sig *freelist)
{
    ecdsa_sign_sig_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    while ((item = mb_flist_ecdsa_sign_sig_pop(freelist)) != NULL) {
       OPENSSL_free(item);
    }

    if (!enable_external_polling) {
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
        OPENSSL_free(freelist);
    }
    return 0;
}

int mb_flist_ecdsa_sign_sig_push(mb_flist_ecdsa_sign_sig *freelist,
                                 ecdsa_sign_sig_op_data *item)
{
    if (freelist == NULL)
        return 1;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    item->next = freelist->head;
    freelist->head = item;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return 0;
}

ecdsa_sign_sig_op_data
    *mb_flist_ecdsa_sign_sig_pop(mb_flist_ecdsa_sign_sig *freelist)
{
    ecdsa_sign_sig_op_data *item = NULL;

    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    if (freelist->head == NULL) {
        if (!enable_external_polling)
            pthread_mutex_unlock(&freelist->mb_flist_mutex);
        return NULL;
    }

    item = freelist->head;
    freelist->head = item->next;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return item;
}

mb_flist_ecdsa_verify * mb_flist_ecdsa_verify_create()
{
    mb_flist_ecdsa_verify *freelist = NULL;
    ecdsa_verify_op_data *item = NULL;
    int num_items = MULTIBUFF_MAX_INFLIGHTS;

    freelist = OPENSSL_zalloc(sizeof(mb_flist_ecdsa_verify));
    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_init(&freelist->mb_flist_mutex, NULL);

    DEBUG("Freelist Created %p\n", freelist);
    freelist->head = NULL;

    while (num_items > 0) {
        item = OPENSSL_zalloc(sizeof(ecdsa_verify_op_data));
        if (item == NULL) {
            mb_flist_ecdsa_verify_cleanup(freelist);
            return NULL;
        }
        if (mb_flist_ecdsa_verify_push(freelist, item) != 0) {
            mb_flist_ecdsa_verify_cleanup(freelist);
            return NULL;
        }
        num_items--;
    }
    return freelist;
}

int mb_flist_ecdsa_verify_cleanup(mb_flist_ecdsa_verify *freelist)
{
    ecdsa_verify_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    while ((item = mb_flist_ecdsa_verify_pop(freelist)) != NULL) {
       OPENSSL_free(item);
    }

    if (!enable_external_polling) {
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
        OPENSSL_free(freelist);
    }
    return 0;
}

int mb_flist_ecdsa_verify_push(mb_flist_ecdsa_verify *freelist,
                             ecdsa_verify_op_data *item)
{
    if (freelist == NULL)
        return 1;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    item->next = freelist->head;
    freelist->head = item;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return 0;
}

ecdsa_verify_op_data
    *mb_flist_ecdsa_verify_pop(mb_flist_ecdsa_verify *freelist)
{
    ecdsa_verify_op_data *item = NULL;

    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    if (freelist->head == NULL) {
        if (!enable_external_polling)
            pthread_mutex_unlock(&freelist->mb_flist_mutex);
        return NULL;
    }

    item = freelist->head;
    freelist->head = item->next;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return item;
}

mb_flist_ecdsa_sm2_sign * mb_flist_ecdsa_sm2_sign_create()
{
    mb_flist_ecdsa_sm2_sign *freelist = NULL;
    ecdsa_sm2_sign_op_data *item = NULL;
    int num_items = MULTIBUFF_MAX_INFLIGHTS;

    freelist = OPENSSL_zalloc(sizeof(mb_flist_ecdsa_sm2_sign));
    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_init(&freelist->mb_flist_mutex, NULL);

    DEBUG("Freelist Created %p\n", freelist);
    freelist->head = NULL;

    while (num_items > 0) {
        item = OPENSSL_zalloc(sizeof(ecdsa_sm2_sign_op_data));
        if (item == NULL) {
            mb_flist_ecdsa_sm2_sign_cleanup(freelist);
            return NULL;
        }
        if (mb_flist_ecdsa_sm2_sign_push(freelist, item) != 0) {
            mb_flist_ecdsa_sm2_sign_cleanup(freelist);
            return NULL;
        }
        num_items--;
    }
    return freelist;
}

int mb_flist_ecdsa_sm2_sign_cleanup(mb_flist_ecdsa_sm2_sign *freelist)
{
    ecdsa_sm2_sign_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    while ((item = mb_flist_ecdsa_sm2_sign_pop(freelist)) != NULL) {
       OPENSSL_free(item);
    }

    if (!enable_external_polling) {
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
        OPENSSL_free(freelist);
    }
    return 0;
}

int mb_flist_ecdsa_sm2_sign_push(mb_flist_ecdsa_sm2_sign *freelist,
                             ecdsa_sm2_sign_op_data *item)
{
    if (freelist == NULL)
        return 1;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    item->next = freelist->head;
    freelist->head = item;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return 0;
}

ecdsa_sm2_sign_op_data
    *mb_flist_ecdsa_sm2_sign_pop(mb_flist_ecdsa_sm2_sign *freelist)
{
    ecdsa_sm2_sign_op_data *item = NULL;

    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    if (freelist->head == NULL) {
        if (!enable_external_polling)
            pthread_mutex_unlock(&freelist->mb_flist_mutex);
        return NULL;
    }

    item = freelist->head;
    freelist->head = item->next;


    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return item;
}

mb_flist_ecdsa_sm2_verify * mb_flist_ecdsa_sm2_verify_create()
{
    mb_flist_ecdsa_sm2_verify *freelist = NULL;
    ecdsa_sm2_verify_op_data *item = NULL;
    int num_items = MULTIBUFF_MAX_INFLIGHTS;

    freelist = OPENSSL_zalloc(sizeof(mb_flist_ecdsa_sm2_verify));
    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_init(&freelist->mb_flist_mutex, NULL);

    DEBUG("Freelist Created %p\n", freelist);
    freelist->head = NULL;

    while (num_items > 0) {
        item = OPENSSL_zalloc(sizeof(ecdsa_sm2_verify_op_data));
        if (item == NULL) {
            mb_flist_ecdsa_sm2_verify_cleanup(freelist);
            return NULL;
        }
        if (mb_flist_ecdsa_sm2_verify_push(freelist, item) != 0) {
            mb_flist_ecdsa_sm2_verify_cleanup(freelist);
            return NULL;
        }
        num_items--;
    }
    return freelist;
}

int mb_flist_ecdsa_sm2_verify_cleanup(mb_flist_ecdsa_sm2_verify *freelist)
{
    ecdsa_sm2_verify_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    while ((item = mb_flist_ecdsa_sm2_verify_pop(freelist)) != NULL) {
       OPENSSL_free(item);
    }

    if (!enable_external_polling) {
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
        OPENSSL_free(freelist);
    }
    return 0;
}

int mb_flist_ecdsa_sm2_verify_push(mb_flist_ecdsa_sm2_verify *freelist,
                             ecdsa_sm2_verify_op_data *item)
{
    if (freelist == NULL)
        return 1;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    item->next = freelist->head;
    freelist->head = item;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return 0;
}

ecdsa_sm2_verify_op_data
    *mb_flist_ecdsa_sm2_verify_pop(mb_flist_ecdsa_sm2_verify *freelist)
{
    ecdsa_sm2_verify_op_data *item = NULL;

    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    if (freelist->head == NULL) {
        if (!enable_external_polling)
            pthread_mutex_unlock(&freelist->mb_flist_mutex);
        return NULL;
    }

    item = freelist->head;
    freelist->head = item->next;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return item;
}

mb_flist_ecdh_keygen * mb_flist_ecdh_keygen_create()
{
    mb_flist_ecdh_keygen *freelist = NULL;
    ecdh_keygen_op_data *item = NULL;
    int num_items = MULTIBUFF_MAX_INFLIGHTS;

    freelist = OPENSSL_zalloc(sizeof(mb_flist_ecdh_keygen));
    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_init(&freelist->mb_flist_mutex, NULL);

    DEBUG("Freelist Created %p\n", freelist);
    freelist->head = NULL;

    while (num_items > 0) {
        item = OPENSSL_zalloc(sizeof(ecdh_keygen_op_data));
        if (item == NULL) {
            mb_flist_ecdh_keygen_cleanup(freelist);
            return NULL;
        }
        if (mb_flist_ecdh_keygen_push(freelist, item) != 0) {
            mb_flist_ecdh_keygen_cleanup(freelist);
            return NULL;
        }
        num_items--;
    }
    return freelist;
}

int mb_flist_ecdh_keygen_cleanup(mb_flist_ecdh_keygen *freelist)
{
    ecdh_keygen_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    while ((item = mb_flist_ecdh_keygen_pop(freelist)) != NULL) {
       OPENSSL_free(item);
    }

    if (!enable_external_polling) {
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
        OPENSSL_free(freelist);
    }
    return 0;
}

int mb_flist_ecdh_keygen_push(mb_flist_ecdh_keygen *freelist,
                              ecdh_keygen_op_data *item)
{
    if (freelist == NULL)
        return 1;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    item->next = freelist->head;
    freelist->head = item;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return 0;
}

ecdh_keygen_op_data
    *mb_flist_ecdh_keygen_pop(mb_flist_ecdh_keygen *freelist)
{
    ecdh_keygen_op_data *item = NULL;

    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    if (freelist->head == NULL) {
        if (!enable_external_polling)
            pthread_mutex_unlock(&freelist->mb_flist_mutex);
        return NULL;
    }

    item = freelist->head;
    freelist->head = item->next;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return item;
}

mb_flist_ecdh_compute * mb_flist_ecdh_compute_create()
{
    mb_flist_ecdh_compute *freelist = NULL;
    ecdh_compute_op_data *item = NULL;
    int num_items = MULTIBUFF_MAX_INFLIGHTS;

    freelist = OPENSSL_zalloc(sizeof(mb_flist_ecdh_compute));
    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_init(&freelist->mb_flist_mutex, NULL);

    DEBUG("Freelist Created %p\n", freelist);
    freelist->head = NULL;

    while (num_items > 0) {
        item = OPENSSL_zalloc(sizeof(ecdh_compute_op_data));
        if (item == NULL) {
            mb_flist_ecdh_compute_cleanup(freelist);
            return NULL;
        }
        if (mb_flist_ecdh_compute_push(freelist, item) != 0) {
            mb_flist_ecdh_compute_cleanup(freelist);
            return NULL;
        }
        num_items--;
    }
    return freelist;
}

int mb_flist_ecdh_compute_cleanup(mb_flist_ecdh_compute *freelist)
{
    ecdh_compute_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    while ((item = mb_flist_ecdh_compute_pop(freelist)) != NULL) {
       OPENSSL_free(item);
    }

    if (!enable_external_polling) {
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
        OPENSSL_free(freelist);
    }
    return 0;
}

int mb_flist_ecdh_compute_push(mb_flist_ecdh_compute *freelist,
                               ecdh_compute_op_data *item)
{
    if (freelist == NULL)
        return 1;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    item->next = freelist->head;
    freelist->head = item;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return 0;
}

ecdh_compute_op_data
    *mb_flist_ecdh_compute_pop(mb_flist_ecdh_compute *freelist)
{
    ecdh_compute_op_data *item = NULL;

    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    if (freelist->head == NULL) {
        if (!enable_external_polling)
            pthread_mutex_unlock(&freelist->mb_flist_mutex);
        return NULL;
    }

    item = freelist->head;
    freelist->head = item->next;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return item;
}

mb_flist_sm3_init * mb_flist_sm3_init_create()
{
    mb_flist_sm3_init *freelist = NULL;
    sm3_init_op_data *item = NULL;
    int num_items = MULTIBUFF_MAX_INFLIGHTS;

    freelist = OPENSSL_zalloc(sizeof(mb_flist_sm3_init));
    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_init(&freelist->mb_flist_mutex, NULL);

    DEBUG("Freelist Created %p\n", freelist);
    freelist->head = NULL;

    while (num_items > 0) {
        item = OPENSSL_zalloc(sizeof(sm3_init_op_data));
        if (item == NULL) {
            mb_flist_sm3_init_cleanup(freelist);
            return NULL;
        }
        if (mb_flist_sm3_init_push(freelist, item) != 0) {
            mb_flist_sm3_init_cleanup(freelist);
            return NULL;
        }
        num_items--;
    }
    return freelist;
}

int mb_flist_sm3_init_cleanup(mb_flist_sm3_init *freelist)
{
    sm3_init_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    while ((item = mb_flist_sm3_init_pop(freelist)) != NULL) {
       OPENSSL_free(item);
    }

    if (!enable_external_polling) {
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
        OPENSSL_free(freelist);
    }
    return 0;
}

int mb_flist_sm3_init_push(mb_flist_sm3_init *freelist,
                                sm3_init_op_data *item)
{
    if (freelist == NULL)
        return 1;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    item->next = freelist->head;
    freelist->head = item;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return 0;
}

sm3_init_op_data *mb_flist_sm3_init_pop(mb_flist_sm3_init *freelist)
{
    sm3_init_op_data *item = NULL;

    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    if (freelist->head == NULL) {
        if (!enable_external_polling)
            pthread_mutex_unlock(&freelist->mb_flist_mutex);
        return NULL;
    }

    item = freelist->head;
    freelist->head = item->next;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return item;
}

mb_flist_sm3_update * mb_flist_sm3_update_create()
{
    mb_flist_sm3_update *freelist = NULL;
    sm3_update_op_data *item = NULL;
    int num_items = MULTIBUFF_MAX_INFLIGHTS;

    freelist = OPENSSL_zalloc(sizeof(mb_flist_sm3_update));
    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_init(&freelist->mb_flist_mutex, NULL);

    DEBUG("Freelist Created %p\n", freelist);
    freelist->head = NULL;

    while (num_items > 0) {
        item = OPENSSL_zalloc(sizeof(sm3_update_op_data));
        if (item == NULL) {
            mb_flist_sm3_update_cleanup(freelist);
            return NULL;
        }
        if (mb_flist_sm3_update_push(freelist, item) != 0) {
            mb_flist_sm3_update_cleanup(freelist);
            return NULL;
        }
        num_items--;
    }
    return freelist;
}

int mb_flist_sm3_update_cleanup(mb_flist_sm3_update *freelist)
{
    sm3_update_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    while ((item = mb_flist_sm3_update_pop(freelist)) != NULL) {
       OPENSSL_free(item);
    }

    if (!enable_external_polling) {
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
        OPENSSL_free(freelist);
    }
    return 0;
}

int mb_flist_sm3_update_push(mb_flist_sm3_update *freelist,
                                sm3_update_op_data *item)
{
    if (freelist == NULL)
        return 1;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    item->next = freelist->head;
    freelist->head = item;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return 0;
}

sm3_update_op_data *mb_flist_sm3_update_pop(mb_flist_sm3_update *freelist)
{
    sm3_update_op_data *item = NULL;

    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    if (freelist->head == NULL) {
        if (!enable_external_polling)
            pthread_mutex_unlock(&freelist->mb_flist_mutex);
        return NULL;
    }

    item = freelist->head;
    freelist->head = item->next;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return item;
}

mb_flist_sm3_final * mb_flist_sm3_final_create()
{
    mb_flist_sm3_final *freelist = NULL;
    sm3_final_op_data *item = NULL;
    int num_items = MULTIBUFF_MAX_INFLIGHTS;

    freelist = OPENSSL_zalloc(sizeof(mb_flist_sm3_final));
    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_init(&freelist->mb_flist_mutex, NULL);

    DEBUG("Freelist Created %p\n", freelist);
    freelist->head = NULL;

    while (num_items > 0) {
        item = OPENSSL_zalloc(sizeof(sm3_final_op_data));
        if (item == NULL) {
            mb_flist_sm3_final_cleanup(freelist);
            return NULL;
        }
        if (mb_flist_sm3_final_push(freelist, item) != 0) {
            mb_flist_sm3_final_cleanup(freelist);
            return NULL;
        }
        num_items--;
    }
    return freelist;
}

int mb_flist_sm3_final_cleanup(mb_flist_sm3_final *freelist)
{
    sm3_final_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    while ((item = mb_flist_sm3_final_pop(freelist)) != NULL) {
       OPENSSL_free(item);
    }

    if (!enable_external_polling) {
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
        OPENSSL_free(freelist);
    }
    return 0;
}

int mb_flist_sm3_final_push(mb_flist_sm3_final *freelist,
                                sm3_final_op_data *item)
{
    if (freelist == NULL)
        return 1;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    item->next = freelist->head;
    freelist->head = item;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return 0;
}

sm3_final_op_data *mb_flist_sm3_final_pop(mb_flist_sm3_final *freelist)
{
    sm3_final_op_data *item = NULL;

    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    if (freelist->head == NULL) {
        if (!enable_external_polling)
            pthread_mutex_unlock(&freelist->mb_flist_mutex);
        return NULL;
    }

    item = freelist->head;
    freelist->head = item->next;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return item;
}

mb_flist_sm4_cbc_cipher *mb_flist_sm4_cbc_cipher_create()
{
    mb_flist_sm4_cbc_cipher *freelist = NULL;
    sm4_cbc_cipher_op_data *item = NULL;
    int num_items = MULTIBUFF_MAX_INFLIGHTS;

    freelist = OPENSSL_zalloc(sizeof(mb_flist_sm4_cbc_cipher));
    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_init(&freelist->mb_flist_mutex, NULL);

    DEBUG("Freelist Created %p\n", freelist);
    freelist->head = NULL;

    while (num_items > 0) {
        item = OPENSSL_zalloc(sizeof(sm4_cbc_cipher_op_data));
        if (item == NULL) {
            mb_flist_sm4_cbc_cipher_cleanup(freelist);
            return NULL;
        }
        if (mb_flist_sm4_cbc_cipher_push(freelist, item) != 0) {
            mb_flist_sm4_cbc_cipher_cleanup(freelist);
            return NULL;
        }
        num_items--;
    }
    return freelist;
}

int mb_flist_sm4_cbc_cipher_cleanup(mb_flist_sm4_cbc_cipher *freelist)
{
    sm4_cbc_cipher_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    while ((item = mb_flist_sm4_cbc_cipher_pop(freelist)) != NULL) {
       OPENSSL_free(item);
    }

    if (!enable_external_polling) {
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
        OPENSSL_free(freelist);
    }
    return 0;
}

int mb_flist_sm4_cbc_cipher_push(mb_flist_sm4_cbc_cipher *freelist,
                                  sm4_cbc_cipher_op_data *item)
{
    if (freelist == NULL)
        return 1;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    item->next = freelist->head;
    freelist->head = item;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return 0;
}

sm4_cbc_cipher_op_data
    *mb_flist_sm4_cbc_cipher_pop(mb_flist_sm4_cbc_cipher *freelist)
{
    sm4_cbc_cipher_op_data *item = NULL;

    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    if (freelist->head == NULL) {
        if (!enable_external_polling)
            pthread_mutex_unlock(&freelist->mb_flist_mutex);
        return NULL;
    }

    item = freelist->head;
    freelist->head = item->next;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return item;
}

#ifdef ENABLE_QAT_SW_SM4_GCM
mb_flist_sm4_gcm_encrypt *mb_flist_sm4_gcm_encrypt_create()
{
    mb_flist_sm4_gcm_encrypt *freelist = NULL;
    sm4_gcm_encrypt_op_data *item = NULL;
    int num_items = MULTIBUFF_MAX_INFLIGHTS;

    freelist = OPENSSL_zalloc(sizeof(mb_flist_sm4_gcm_encrypt));
    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_init(&freelist->mb_flist_mutex, NULL);

    DEBUG("Freelist Created %p\n", freelist);
    freelist->head = NULL;

    while (num_items > 0) {
        item = OPENSSL_zalloc(sizeof(sm4_gcm_encrypt_op_data));
        if (item == NULL) {
            mb_flist_sm4_gcm_encrypt_cleanup(freelist);
            return NULL;
        }
        if (mb_flist_sm4_gcm_encrypt_push(freelist, item) != 0) {
            mb_flist_sm4_gcm_encrypt_cleanup(freelist);
            return NULL;
        }
        num_items--;
    }
    return freelist;
}

int mb_flist_sm4_gcm_encrypt_cleanup(mb_flist_sm4_gcm_encrypt *freelist)
{
    sm4_gcm_encrypt_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    while ((item = mb_flist_sm4_gcm_encrypt_pop(freelist)) != NULL) {
       OPENSSL_free(item);
    }

    if (!enable_external_polling) {
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
        OPENSSL_free(freelist);
    }
    return 0;
}

int mb_flist_sm4_gcm_encrypt_push(mb_flist_sm4_gcm_encrypt *freelist,
                                  sm4_gcm_encrypt_op_data *item)
{
    if (freelist == NULL)
        return 1;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    item->next = freelist->head;
    freelist->head = item;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return 0;
}

sm4_gcm_encrypt_op_data
    *mb_flist_sm4_gcm_encrypt_pop(mb_flist_sm4_gcm_encrypt *freelist)
{
    sm4_gcm_encrypt_op_data *item = NULL;

    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    if (freelist->head == NULL) {
        if (!enable_external_polling)
            pthread_mutex_unlock(&freelist->mb_flist_mutex);
        return NULL;
    }

    item = freelist->head;
    freelist->head = item->next;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return item;
}

mb_flist_sm4_gcm_decrypt *mb_flist_sm4_gcm_decrypt_create()
{
    mb_flist_sm4_gcm_decrypt *freelist = NULL;
    sm4_gcm_decrypt_op_data *item = NULL;
    int num_items = MULTIBUFF_MAX_INFLIGHTS;

    freelist = OPENSSL_zalloc(sizeof(mb_flist_sm4_gcm_decrypt));
    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_init(&freelist->mb_flist_mutex, NULL);

    DEBUG("Freelist Created %p\n", freelist);
    freelist->head = NULL;

    while (num_items > 0) {
        item = OPENSSL_zalloc(sizeof(sm4_gcm_decrypt_op_data));
        if (item == NULL) {
            mb_flist_sm4_gcm_decrypt_cleanup(freelist);
            return NULL;
        }
        if (mb_flist_sm4_gcm_decrypt_push(freelist, item) != 0) {
            mb_flist_sm4_gcm_decrypt_cleanup(freelist);
            return NULL;
        }
        num_items--;
    }
    return freelist;
}

int mb_flist_sm4_gcm_decrypt_cleanup(mb_flist_sm4_gcm_decrypt *freelist)
{
    sm4_gcm_decrypt_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    while ((item = mb_flist_sm4_gcm_decrypt_pop(freelist)) != NULL) {
       OPENSSL_free(item);
    }

    if (!enable_external_polling) {
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
        OPENSSL_free(freelist);
    }
    return 0;
}

int mb_flist_sm4_gcm_decrypt_push(mb_flist_sm4_gcm_decrypt *freelist,
                                  sm4_gcm_decrypt_op_data *item)
{
    if (freelist == NULL)
        return 1;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    item->next = freelist->head;
    freelist->head = item;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return 0;
}

sm4_gcm_decrypt_op_data
    *mb_flist_sm4_gcm_decrypt_pop(mb_flist_sm4_gcm_decrypt *freelist)
{
    sm4_gcm_decrypt_op_data *item = NULL;

    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    if (freelist->head == NULL) {
        if (!enable_external_polling)
            pthread_mutex_unlock(&freelist->mb_flist_mutex);
        return NULL;
    }

    item = freelist->head;
    freelist->head = item->next;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return item;
}
#endif

#ifdef ENABLE_QAT_SW_SM4_CCM
mb_flist_sm4_ccm_encrypt *mb_flist_sm4_ccm_encrypt_create()
{
    mb_flist_sm4_ccm_encrypt *freelist = NULL;
    sm4_ccm_encrypt_op_data *item = NULL;
    int num_items = MULTIBUFF_MAX_INFLIGHTS;

    freelist = OPENSSL_zalloc(sizeof(mb_flist_sm4_ccm_encrypt));
    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_init(&freelist->mb_flist_mutex, NULL);

    DEBUG("Freelist Created %p\n", freelist);
    freelist->head = NULL;

    while (num_items > 0) {
        item = OPENSSL_zalloc(sizeof(sm4_ccm_encrypt_op_data));
        if (item == NULL) {
            mb_flist_sm4_ccm_encrypt_cleanup(freelist);
            return NULL;
        }
        if (mb_flist_sm4_ccm_encrypt_push(freelist, item) != 0) {
            mb_flist_sm4_ccm_encrypt_cleanup(freelist);
            return NULL;
        }
        num_items--;
    }
    return freelist;
}

int mb_flist_sm4_ccm_encrypt_cleanup(mb_flist_sm4_ccm_encrypt *freelist)
{
    sm4_ccm_encrypt_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    while ((item = mb_flist_sm4_ccm_encrypt_pop(freelist)) != NULL) {
       OPENSSL_free(item);
    }

    if (!enable_external_polling) {
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
        OPENSSL_free(freelist);
    }
    return 0;
}

int mb_flist_sm4_ccm_encrypt_push(mb_flist_sm4_ccm_encrypt *freelist,
                                  sm4_ccm_encrypt_op_data *item)
{
    if (freelist == NULL)
        return 1;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    item->next = freelist->head;
    freelist->head = item;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return 0;
}

sm4_ccm_encrypt_op_data
    *mb_flist_sm4_ccm_encrypt_pop(mb_flist_sm4_ccm_encrypt *freelist)
{
    sm4_ccm_encrypt_op_data *item = NULL;

    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    if (freelist->head == NULL) {
        if (!enable_external_polling)
            pthread_mutex_unlock(&freelist->mb_flist_mutex);
        return NULL;
    }

    item = freelist->head;
    freelist->head = item->next;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return item;
}

mb_flist_sm4_ccm_decrypt *mb_flist_sm4_ccm_decrypt_create()
{
    mb_flist_sm4_ccm_decrypt *freelist = NULL;
    sm4_ccm_decrypt_op_data *item = NULL;
    int num_items = MULTIBUFF_MAX_INFLIGHTS;

    freelist = OPENSSL_zalloc(sizeof(mb_flist_sm4_ccm_decrypt));
    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_init(&freelist->mb_flist_mutex, NULL);

    DEBUG("Freelist Created %p\n", freelist);
    freelist->head = NULL;

    while (num_items > 0) {
        item = OPENSSL_zalloc(sizeof(sm4_ccm_decrypt_op_data));
        if (item == NULL) {
            mb_flist_sm4_ccm_decrypt_cleanup(freelist);
            return NULL;
        }
        if (mb_flist_sm4_ccm_decrypt_push(freelist, item) != 0) {
            mb_flist_sm4_ccm_decrypt_cleanup(freelist);
            return NULL;
        }
        num_items--;
    }
    return freelist;
}

int mb_flist_sm4_ccm_decrypt_cleanup(mb_flist_sm4_ccm_decrypt *freelist)
{
    sm4_ccm_decrypt_op_data *item = NULL;

    if (freelist == NULL)
        return 1;

    while ((item = mb_flist_sm4_ccm_decrypt_pop(freelist)) != NULL) {
       OPENSSL_free(item);
    }

    if (!enable_external_polling) {
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
        OPENSSL_free(freelist);
    }
    return 0;
}

int mb_flist_sm4_ccm_decrypt_push(mb_flist_sm4_ccm_decrypt *freelist,
                                  sm4_ccm_decrypt_op_data *item)
{
    if (freelist == NULL)
        return 1;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    item->next = freelist->head;
    freelist->head = item;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return 0;
}

sm4_ccm_decrypt_op_data
    *mb_flist_sm4_ccm_decrypt_pop(mb_flist_sm4_ccm_decrypt *freelist)
{
    sm4_ccm_decrypt_op_data *item = NULL;

    if (freelist == NULL)
        return NULL;

    if (!enable_external_polling)
        pthread_mutex_lock(&freelist->mb_flist_mutex);

    if (freelist->head == NULL) {
        if (!enable_external_polling)
            pthread_mutex_unlock(&freelist->mb_flist_mutex);
        return NULL;
    }

    item = freelist->head;
    freelist->head = item->next;

    if (!enable_external_polling)
        pthread_mutex_unlock(&freelist->mb_flist_mutex);

    return item;
}
#endif
