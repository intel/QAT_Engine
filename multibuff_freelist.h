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
 * @file multibuff_freelist.h
 *
 * This file provides the data structure for storing unused multibuff requests
 * avoiding expensive malloc/frees in the data path.
 *
 *****************************************************************************/

#ifndef MULTIBUFF_FREELIST_H
# define MULTIBUFF_FREELIST_H

# include <stdio.h>
# include "multibuff_request.h"

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

#endif /* MULTIBUFF_FREELIST_H */
