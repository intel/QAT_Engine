/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2020-2021 Intel Corporation.
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
 * @file qat_sw_freelist.h
 *
 * This file provides the data structure for storing unused multibuff requests
 * avoiding expensive malloc/frees in the data path.
 *
 *****************************************************************************/

#ifndef QAT_SW_FREELIST_H
# define QAT_SW_FREELIST_H

# include <stdio.h>
# include "qat_sw_request.h"

typedef struct _mb_flist_rsa_priv
{
    pthread_mutex_t mb_flist_mutex;
    rsa_priv_op_data *head;
} mb_flist_rsa_priv;

typedef struct _mb_flist_rsa_pub
{
    pthread_mutex_t mb_flist_mutex;
    rsa_pub_op_data *head;
} mb_flist_rsa_pub;

typedef struct _mb_flist_x25519_keygen
{
    pthread_mutex_t mb_flist_mutex;
    x25519_keygen_op_data *head;
} mb_flist_x25519_keygen;

typedef struct _mb_flist_x25519_derive
{
    pthread_mutex_t mb_flist_mutex;
    x25519_derive_op_data *head;
} mb_flist_x25519_derive;

typedef struct _mb_flist_ecdsa_sign
{
    pthread_mutex_t mb_flist_mutex;
    ecdsa_sign_op_data *head;
} mb_flist_ecdsa_sign;

typedef struct _mb_flist_ecdsa_sign_setup
{
    pthread_mutex_t mb_flist_mutex;
    ecdsa_sign_setup_op_data *head;
} mb_flist_ecdsa_sign_setup;

typedef struct _mb_flist_ecdsa_sign_sig
{
    pthread_mutex_t mb_flist_mutex;
    ecdsa_sign_sig_op_data *head;
} mb_flist_ecdsa_sign_sig;

typedef struct _mb_flist_ecdh_keygen
{
    pthread_mutex_t mb_flist_mutex;
    ecdh_keygen_op_data *head;
} mb_flist_ecdh_keygen;

typedef struct _mb_flist_ecdh_compute
{
    pthread_mutex_t mb_flist_mutex;
    ecdh_compute_op_data *head;
} mb_flist_ecdh_compute;

int mb_flist_rsa_priv_create(mb_flist_rsa_priv *freelist, int num_items);
int mb_flist_rsa_priv_cleanup(mb_flist_rsa_priv *freelist);
int mb_flist_rsa_priv_push(mb_flist_rsa_priv *freelist, rsa_priv_op_data *item);
rsa_priv_op_data * mb_flist_rsa_priv_pop(mb_flist_rsa_priv *flist);

int mb_flist_rsa_pub_create(mb_flist_rsa_pub *freelist, int num_items);
int mb_flist_rsa_pub_cleanup(mb_flist_rsa_pub *freelist);
int mb_flist_rsa_pub_push(mb_flist_rsa_pub *freelist, rsa_pub_op_data *item);
rsa_pub_op_data * mb_flist_rsa_pub_pop(mb_flist_rsa_pub *flist);

int mb_flist_x25519_keygen_create(mb_flist_x25519_keygen *freelist, int num_items);
int mb_flist_x25519_keygen_cleanup(mb_flist_x25519_keygen *freelist);
int mb_flist_x25519_keygen_push(mb_flist_x25519_keygen *freelist,
                                x25519_keygen_op_data *item);
x25519_keygen_op_data * mb_flist_x25519_keygen_pop(mb_flist_x25519_keygen *flist);

int mb_flist_x25519_derive_create(mb_flist_x25519_derive *freelist, int num_items);
int mb_flist_x25519_derive_cleanup(mb_flist_x25519_derive *freelist);
int mb_flist_x25519_derive_push(mb_flist_x25519_derive *freelist,
                                x25519_derive_op_data *item);
x25519_derive_op_data * mb_flist_x25519_derive_pop(mb_flist_x25519_derive *flist);

int mb_flist_ecdsa_sign_create(mb_flist_ecdsa_sign *freelist, int num_items);
int mb_flist_ecdsa_sign_cleanup(mb_flist_ecdsa_sign *freelist);
int mb_flist_ecdsa_sign_push(mb_flist_ecdsa_sign *freelist,
                             ecdsa_sign_op_data *item);
ecdsa_sign_op_data
    *mb_flist_ecdsa_sign_pop(mb_flist_ecdsa_sign *flist);

int mb_flist_ecdsa_sign_setup_create(mb_flist_ecdsa_sign_setup *freelist,
                                     int num_items);
int mb_flist_ecdsa_sign_setup_cleanup(mb_flist_ecdsa_sign_setup *freelist);
int mb_flist_ecdsa_sign_setup_push(mb_flist_ecdsa_sign_setup *freelist,
                                   ecdsa_sign_setup_op_data *item);
ecdsa_sign_setup_op_data
    *mb_flist_ecdsa_sign_setup_pop(mb_flist_ecdsa_sign_setup *flist);

int mb_flist_ecdsa_sign_sig_create(mb_flist_ecdsa_sign_sig *freelist,
                                   int num_items);
int mb_flist_ecdsa_sign_sig_cleanup(mb_flist_ecdsa_sign_sig *freelist);
int mb_flist_ecdsa_sign_sig_push(mb_flist_ecdsa_sign_sig *freelist,
                                 ecdsa_sign_sig_op_data *item);
ecdsa_sign_sig_op_data
    *mb_flist_ecdsa_sign_sig_pop(mb_flist_ecdsa_sign_sig *flist);

int mb_flist_ecdh_keygen_create(mb_flist_ecdh_keygen *freelist, int num_items);
int mb_flist_ecdh_keygen_cleanup(mb_flist_ecdh_keygen *freelist);
int mb_flist_ecdh_keygen_push(mb_flist_ecdh_keygen *freelist,
                              ecdh_keygen_op_data *item);
ecdh_keygen_op_data *mb_flist_ecdh_keygen_pop(mb_flist_ecdh_keygen *flist);

int mb_flist_ecdh_compute_create(mb_flist_ecdh_compute *freelist,
                                 int num_items);
int mb_flist_ecdh_compute_cleanup(mb_flist_ecdh_compute *freelist);
int mb_flist_ecdh_compute_push(mb_flist_ecdh_compute *freelist,
                               ecdh_compute_op_data *item);
ecdh_compute_op_data *mb_flist_ecdh_compute_pop(mb_flist_ecdh_compute *flist);

#endif /* QAT_SW_FREELIST_H */
