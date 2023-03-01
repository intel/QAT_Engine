/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2020-2023 Intel Corporation.
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
 * @file qat_sw_queue.h
 *
 * This file provides the data structure for storing up multibuff requests
 * so multiple request can be processed in one operation.
 *
 *****************************************************************************/

#ifndef QAT_SW_QUEUE_H
# define QAT_SW_QUEUE_H

# include <stdio.h>
# include "qat_sw_request.h"

typedef struct _mb_queue_rsa2k_priv
{
    pthread_mutex_t mb_queue_mutex;
    rsa_priv_op_data *head;
    rsa_priv_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_rsa2k_priv;

typedef struct _mb_queue_rsa2k_pub
{
    pthread_mutex_t mb_queue_mutex;
    rsa_pub_op_data *head;
    rsa_pub_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_rsa2k_pub;

typedef struct _mb_queue_rsa3k_priv
{
    pthread_mutex_t mb_queue_mutex;
    rsa_priv_op_data *head;
    rsa_priv_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_rsa3k_priv;

typedef struct _mb_queue_rsa3k_pub
{
    pthread_mutex_t mb_queue_mutex;
    rsa_pub_op_data *head;
    rsa_pub_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_rsa3k_pub;

typedef struct _mb_queue_rsa4k_priv
{
    pthread_mutex_t mb_queue_mutex;
    rsa_priv_op_data *head;
    rsa_priv_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_rsa4k_priv;

typedef struct _mb_queue_rsa4k_pub
{
    pthread_mutex_t mb_queue_mutex;
    rsa_pub_op_data *head;
    rsa_pub_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_rsa4k_pub;

typedef struct _mb_queue_x25519_keygen
{
    pthread_mutex_t mb_queue_mutex;
    x25519_keygen_op_data *head;
    x25519_keygen_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_x25519_keygen;

typedef struct _mb_queue_x25519_derive
{
    pthread_mutex_t mb_queue_mutex;
    x25519_derive_op_data *head;
    x25519_derive_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_x25519_derive;

typedef struct _mb_queue_ecdsap256_sign
{
    pthread_mutex_t mb_queue_mutex;
    ecdsa_sign_op_data *head;
    ecdsa_sign_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_ecdsap256_sign;

typedef struct _mb_queue_ecdsap256_sign_setup
{
    pthread_mutex_t mb_queue_mutex;
    ecdsa_sign_setup_op_data *head;
    ecdsa_sign_setup_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_ecdsap256_sign_setup;

typedef struct _mb_queue_ecdsap256_sign_sig
{
    pthread_mutex_t mb_queue_mutex;
    ecdsa_sign_sig_op_data *head;
    ecdsa_sign_sig_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_ecdsap256_sign_sig;

typedef struct _mb_queue_ecdsap256_verify
{
    pthread_mutex_t mb_queue_mutex;
    ecdsa_verify_op_data *head;
    ecdsa_verify_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_ecdsap256_verify;

typedef struct _mb_queue_ecdsap384_sign
{
     pthread_mutex_t mb_queue_mutex;
     ecdsa_sign_op_data *head;
     ecdsa_sign_op_data *tail;
     int num_items;
     int disabled;
} mb_queue_ecdsap384_sign;

typedef struct _mb_queue_ecdsap384_sign_setup
{
     pthread_mutex_t mb_queue_mutex;
     ecdsa_sign_setup_op_data *head;
     ecdsa_sign_setup_op_data *tail;
     int num_items;
     int disabled;
} mb_queue_ecdsap384_sign_setup;

typedef struct _mb_queue_ecdsap384_sign_sig
{
    pthread_mutex_t mb_queue_mutex;
    ecdsa_sign_sig_op_data *head;
    ecdsa_sign_sig_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_ecdsap384_sign_sig;

typedef struct _mb_queue_ecdsap384_verify
{
    pthread_mutex_t mb_queue_mutex;
    ecdsa_verify_op_data *head;
    ecdsa_verify_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_ecdsap384_verify;

typedef struct _mb_queue_ecdhp256_keygen
{
    pthread_mutex_t mb_queue_mutex;
    ecdh_keygen_op_data *head;
    ecdh_keygen_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_ecdhp256_keygen;

typedef struct _mb_queue_ecdhp256_compute
{
    pthread_mutex_t mb_queue_mutex;
    ecdh_compute_op_data *head;
    ecdh_compute_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_ecdhp256_compute;

typedef struct _mb_queue_ecdhp384_keygen
{
    pthread_mutex_t mb_queue_mutex;
    ecdh_keygen_op_data *head;
    ecdh_keygen_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_ecdhp384_keygen;

typedef struct _mb_queue_ecdhp384_compute
{
    pthread_mutex_t mb_queue_mutex;
    ecdh_compute_op_data *head;
    ecdh_compute_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_ecdhp384_compute;

typedef struct _mb_queue_sm2ecdh_keygen
{
    pthread_mutex_t mb_queue_mutex;
    ecdh_keygen_op_data *head;
    ecdh_keygen_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_sm2ecdh_keygen;

typedef struct _mb_queue_sm2ecdh_compute
{
    pthread_mutex_t mb_queue_mutex;
    ecdh_compute_op_data *head;
    ecdh_compute_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_sm2ecdh_compute;

typedef struct _mb_queue_ecdsa_sm2_sign
{
    pthread_mutex_t mb_queue_mutex;
    ecdsa_sm2_sign_op_data *head;
    ecdsa_sm2_sign_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_ecdsa_sm2_sign;

typedef struct _mb_queue_ecdsa_sm2_verify
{
    pthread_mutex_t mb_queue_mutex;
    ecdsa_sm2_verify_op_data *head;
    ecdsa_sm2_verify_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_ecdsa_sm2_verify;

typedef struct _mb_queue_sm3_init
{
    pthread_mutex_t mb_queue_mutex;
    sm3_init_op_data *head;
    sm3_init_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_sm3_init;

typedef struct _mb_queue_sm3_update
{
    pthread_mutex_t mb_queue_mutex;
    sm3_update_op_data *head;
    sm3_update_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_sm3_update;

typedef struct _mb_queue_sm3_final
{
    pthread_mutex_t mb_queue_mutex;
    sm3_final_op_data *head;
    sm3_final_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_sm3_final;

typedef struct _mb_queue_sm4_cbc_cipher
{
    pthread_mutex_t mb_queue_mutex;
    sm4_cbc_cipher_op_data *head;
    sm4_cbc_cipher_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_sm4_cbc_cipher;

typedef struct _mb_queue_sm4_gcm_encrypt
{
    pthread_mutex_t mb_queue_mutex;
    sm4_gcm_encrypt_op_data *head;
    sm4_gcm_encrypt_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_sm4_gcm_encrypt;

typedef struct _mb_queue_sm4_gcm_decrypt
{
    pthread_mutex_t mb_queue_mutex;
    sm4_gcm_decrypt_op_data *head;
    sm4_gcm_decrypt_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_sm4_gcm_decrypt;

typedef struct _mb_queue_sm4_ccm_encrypt
{
    pthread_mutex_t mb_queue_mutex;
    sm4_ccm_encrypt_op_data *head;
    sm4_ccm_encrypt_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_sm4_ccm_encrypt;

typedef struct _mb_queue_sm4_ccm_decrypt
{
    pthread_mutex_t mb_queue_mutex;
    sm4_ccm_decrypt_op_data *head;
    sm4_ccm_decrypt_op_data *tail;
    int num_items;
    int disabled;
} mb_queue_sm4_ccm_decrypt;

mb_queue_rsa2k_priv * mb_queue_rsa2k_priv_create();
int mb_queue_rsa2k_priv_disable(mb_queue_rsa2k_priv * queue);
int mb_queue_rsa2k_priv_cleanup(mb_queue_rsa2k_priv * queue);
int mb_queue_rsa2k_priv_enqueue(mb_queue_rsa2k_priv *queue,
                                rsa_priv_op_data *item);
rsa_priv_op_data * mb_queue_rsa2k_priv_dequeue(mb_queue_rsa2k_priv *queue);
int mb_queue_rsa2k_priv_get_size(mb_queue_rsa2k_priv *queue);

mb_queue_rsa2k_pub * mb_queue_rsa2k_pub_create();
int mb_queue_rsa2k_pub_disable(mb_queue_rsa2k_pub * queue);
int mb_queue_rsa2k_pub_cleanup(mb_queue_rsa2k_pub * queue);
int mb_queue_rsa2k_pub_enqueue(mb_queue_rsa2k_pub *queue,
                               rsa_pub_op_data *item);
rsa_pub_op_data * mb_queue_rsa2k_pub_dequeue(mb_queue_rsa2k_pub *queue);
int mb_queue_rsa2k_pub_get_size(mb_queue_rsa2k_pub *queue);

mb_queue_rsa3k_priv * mb_queue_rsa3k_priv_create();
int mb_queue_rsa3k_priv_disable(mb_queue_rsa3k_priv * queue);
int mb_queue_rsa3k_priv_cleanup(mb_queue_rsa3k_priv * queue);
int mb_queue_rsa3k_priv_enqueue(mb_queue_rsa3k_priv *queue,
                                rsa_priv_op_data *item);
rsa_priv_op_data * mb_queue_rsa3k_priv_dequeue(mb_queue_rsa3k_priv *queue);
int mb_queue_rsa3k_priv_get_size(mb_queue_rsa3k_priv *queue);

mb_queue_rsa3k_pub * mb_queue_rsa3k_pub_create();
int mb_queue_rsa3k_pub_disable(mb_queue_rsa3k_pub * queue);
int mb_queue_rsa3k_pub_cleanup(mb_queue_rsa3k_pub * queue);
int mb_queue_rsa3k_pub_enqueue(mb_queue_rsa3k_pub *queue,
                               rsa_pub_op_data *item);
rsa_pub_op_data * mb_queue_rsa3k_pub_dequeue(mb_queue_rsa3k_pub *queue);
int mb_queue_rsa3k_pub_get_size(mb_queue_rsa3k_pub *queue);

mb_queue_rsa4k_priv * mb_queue_rsa4k_priv_create();
int mb_queue_rsa4k_priv_disable(mb_queue_rsa4k_priv * queue);
int mb_queue_rsa4k_priv_cleanup(mb_queue_rsa4k_priv * queue);
int mb_queue_rsa4k_priv_enqueue(mb_queue_rsa4k_priv *queue,
                                rsa_priv_op_data *item);
rsa_priv_op_data * mb_queue_rsa4k_priv_dequeue(mb_queue_rsa4k_priv *queue);
int mb_queue_rsa4k_priv_get_size(mb_queue_rsa4k_priv *queue);

mb_queue_rsa4k_pub * mb_queue_rsa4k_pub_create();
int mb_queue_rsa4k_pub_disable(mb_queue_rsa4k_pub * queue);
int mb_queue_rsa4k_pub_cleanup(mb_queue_rsa4k_pub * queue);
int mb_queue_rsa4k_pub_enqueue(mb_queue_rsa4k_pub *queue,
                               rsa_pub_op_data *item);
rsa_pub_op_data * mb_queue_rsa4k_pub_dequeue(mb_queue_rsa4k_pub *queue);
int mb_queue_rsa4k_pub_get_size(mb_queue_rsa4k_pub *queue);

mb_queue_x25519_keygen * mb_queue_x25519_keygen_create();
int mb_queue_x25519_keygen_disable(mb_queue_x25519_keygen * queue);
int mb_queue_x25519_keygen_cleanup(mb_queue_x25519_keygen * queue);
int mb_queue_x25519_keygen_enqueue(mb_queue_x25519_keygen *queue,
                                   x25519_keygen_op_data *item);
x25519_keygen_op_data
    *mb_queue_x25519_keygen_dequeue(mb_queue_x25519_keygen *queue);
int mb_queue_x25519_keygen_get_size(mb_queue_x25519_keygen *queue);

mb_queue_x25519_derive * mb_queue_x25519_derive_create();
int mb_queue_x25519_derive_disable(mb_queue_x25519_derive * queue);
int mb_queue_x25519_derive_cleanup(mb_queue_x25519_derive * queue);
int mb_queue_x25519_derive_enqueue(mb_queue_x25519_derive *queue,
                                   x25519_derive_op_data *item);
x25519_derive_op_data
    *mb_queue_x25519_derive_dequeue(mb_queue_x25519_derive *queue);
int mb_queue_x25519_derive_get_size(mb_queue_x25519_derive *queue);

mb_queue_ecdsap256_sign * mb_queue_ecdsap256_sign_create();
int mb_queue_ecdsap256_sign_disable(mb_queue_ecdsap256_sign * queue);
int mb_queue_ecdsap256_sign_cleanup(mb_queue_ecdsap256_sign * queue);
int mb_queue_ecdsap256_sign_enqueue(mb_queue_ecdsap256_sign *queue,
                                    ecdsa_sign_op_data *item);
ecdsa_sign_op_data
    *mb_queue_ecdsap256_sign_dequeue(mb_queue_ecdsap256_sign *queue);
int mb_queue_ecdsap256_sign_get_size(mb_queue_ecdsap256_sign *queue);

mb_queue_ecdsap256_sign_setup * mb_queue_ecdsap256_sign_setup_create();
int mb_queue_ecdsap256_sign_setup_disable(mb_queue_ecdsap256_sign_setup * queue);
int mb_queue_ecdsap256_sign_setup_cleanup(mb_queue_ecdsap256_sign_setup * queue);
int mb_queue_ecdsap256_sign_setup_enqueue(mb_queue_ecdsap256_sign_setup *queue,
                                          ecdsa_sign_setup_op_data *item);
ecdsa_sign_setup_op_data
    *mb_queue_ecdsap256_sign_setup_dequeue(mb_queue_ecdsap256_sign_setup *queue);
int mb_queue_ecdsap256_sign_setup_get_size(mb_queue_ecdsap256_sign_setup *queue);

mb_queue_ecdsap256_sign_sig * mb_queue_ecdsap256_sign_sig_create();
int mb_queue_ecdsap256_sign_sig_disable(mb_queue_ecdsap256_sign_sig * queue);
int mb_queue_ecdsap256_sign_sig_cleanup(mb_queue_ecdsap256_sign_sig * queue);
int mb_queue_ecdsap256_sign_sig_enqueue(mb_queue_ecdsap256_sign_sig *queue,
                                        ecdsa_sign_sig_op_data *item);
ecdsa_sign_sig_op_data
    *mb_queue_ecdsap256_sign_sig_dequeue(mb_queue_ecdsap256_sign_sig *queue);
int mb_queue_ecdsap256_sign_sig_get_size(mb_queue_ecdsap256_sign_sig *queue);

mb_queue_ecdsap256_verify * mb_queue_ecdsap256_verify_create();
int mb_queue_ecdsap256_verify_disable(mb_queue_ecdsap256_verify * queue);
int mb_queue_ecdsap256_verify_cleanup(mb_queue_ecdsap256_verify * queue);
int mb_queue_ecdsap256_verify_enqueue(mb_queue_ecdsap256_verify *queue,
                                    ecdsa_verify_op_data *item);
ecdsa_verify_op_data
    *mb_queue_ecdsap256_verify_dequeue(mb_queue_ecdsap256_verify *queue);
int mb_queue_ecdsap256_verify_get_size(mb_queue_ecdsap256_verify *queue);

mb_queue_ecdsap384_sign * mb_queue_ecdsap384_sign_create();
int mb_queue_ecdsap384_sign_disable(mb_queue_ecdsap384_sign * queue);
int mb_queue_ecdsap384_sign_cleanup(mb_queue_ecdsap384_sign * queue);
int mb_queue_ecdsap384_sign_enqueue(mb_queue_ecdsap384_sign *queue,
                                    ecdsa_sign_op_data *item);
ecdsa_sign_op_data
    *mb_queue_ecdsap384_sign_dequeue(mb_queue_ecdsap384_sign *queue);
int mb_queue_ecdsap384_sign_get_size(mb_queue_ecdsap384_sign *queue);

mb_queue_ecdsap384_sign_setup * mb_queue_ecdsap384_sign_setup_create();
int mb_queue_ecdsap384_sign_setup_disable(mb_queue_ecdsap384_sign_setup * queue);
int mb_queue_ecdsap384_sign_setup_cleanup(mb_queue_ecdsap384_sign_setup * queue);
int mb_queue_ecdsap384_sign_setup_enqueue(mb_queue_ecdsap384_sign_setup *queue,
                                          ecdsa_sign_setup_op_data *item);
ecdsa_sign_setup_op_data
    *mb_queue_ecdsap384_sign_setup_dequeue(mb_queue_ecdsap384_sign_setup *queue);
int mb_queue_ecdsap384_sign_setup_get_size(mb_queue_ecdsap384_sign_setup *queue);

mb_queue_ecdsap384_sign_sig * mb_queue_ecdsap384_sign_sig_create();
int mb_queue_ecdsap384_sign_sig_disable(mb_queue_ecdsap384_sign_sig * queue);
int mb_queue_ecdsap384_sign_sig_cleanup(mb_queue_ecdsap384_sign_sig * queue);
int mb_queue_ecdsap384_sign_sig_enqueue(mb_queue_ecdsap384_sign_sig *queue,
                                        ecdsa_sign_sig_op_data *item);
ecdsa_sign_sig_op_data
    *mb_queue_ecdsap384_sign_sig_dequeue(mb_queue_ecdsap384_sign_sig *queue);
int mb_queue_ecdsap384_sign_sig_get_size(mb_queue_ecdsap384_sign_sig *queue);

mb_queue_ecdsap384_verify * mb_queue_ecdsap384_verify_create();
int mb_queue_ecdsap384_verify_disable(mb_queue_ecdsap384_verify * queue);
int mb_queue_ecdsap384_verify_cleanup(mb_queue_ecdsap384_verify * queue);
int mb_queue_ecdsap384_verify_enqueue(mb_queue_ecdsap384_verify *queue,
                                    ecdsa_verify_op_data *item);
ecdsa_verify_op_data
    *mb_queue_ecdsap384_verify_dequeue(mb_queue_ecdsap384_verify *queue);
int mb_queue_ecdsap384_verify_get_size(mb_queue_ecdsap384_verify *queue);

mb_queue_ecdhp256_keygen * mb_queue_ecdhp256_keygen_create();
int mb_queue_ecdhp256_keygen_disable(mb_queue_ecdhp256_keygen * queue);
int mb_queue_ecdhp256_keygen_cleanup(mb_queue_ecdhp256_keygen * queue);
int mb_queue_ecdhp256_keygen_enqueue(mb_queue_ecdhp256_keygen *queue,
                                     ecdh_keygen_op_data *item);
ecdh_keygen_op_data
    *mb_queue_ecdhp256_keygen_dequeue(mb_queue_ecdhp256_keygen *queue);
int mb_queue_ecdhp256_keygen_get_size(mb_queue_ecdhp256_keygen *queue);

mb_queue_ecdhp256_compute * mb_queue_ecdhp256_compute_create();
int mb_queue_ecdhp256_compute_disable(mb_queue_ecdhp256_compute * queue);
int mb_queue_ecdhp256_compute_cleanup(mb_queue_ecdhp256_compute * queue);
int mb_queue_ecdhp256_compute_enqueue(mb_queue_ecdhp256_compute *queue,
                                      ecdh_compute_op_data *item);
ecdh_compute_op_data
    *mb_queue_ecdhp256_compute_dequeue(mb_queue_ecdhp256_compute *queue);
int mb_queue_ecdhp256_compute_get_size(mb_queue_ecdhp256_compute *queue);

mb_queue_ecdhp384_keygen * mb_queue_ecdhp384_keygen_create();
int mb_queue_ecdhp384_keygen_disable(mb_queue_ecdhp384_keygen * queue);
int mb_queue_ecdhp384_keygen_cleanup(mb_queue_ecdhp384_keygen * queue);
int mb_queue_ecdhp384_keygen_enqueue(mb_queue_ecdhp384_keygen *queue,
                                     ecdh_keygen_op_data *item);
ecdh_keygen_op_data
    *mb_queue_ecdhp384_keygen_dequeue(mb_queue_ecdhp384_keygen *queue);
int mb_queue_ecdhp384_keygen_get_size(mb_queue_ecdhp384_keygen *queue);

mb_queue_ecdhp384_compute * mb_queue_ecdhp384_compute_create();
int mb_queue_ecdhp384_compute_disable(mb_queue_ecdhp384_compute * queue);
int mb_queue_ecdhp384_compute_cleanup(mb_queue_ecdhp384_compute * queue);
int mb_queue_ecdhp384_compute_enqueue(mb_queue_ecdhp384_compute *queue,
                                      ecdh_compute_op_data *item);
ecdh_compute_op_data
    *mb_queue_ecdhp384_compute_dequeue(mb_queue_ecdhp384_compute *queue);
int mb_queue_ecdhp384_compute_get_size(mb_queue_ecdhp384_compute *queue);
/* SM3 Init */
mb_queue_sm3_init * mb_queue_sm3_init_create();
int mb_queue_sm3_init_disable(mb_queue_sm3_init * queue);
int mb_queue_sm3_init_cleanup(mb_queue_sm3_init * queue);
int mb_queue_sm3_init_enqueue(mb_queue_sm3_init *queue,
                                        sm3_init_op_data *item);
sm3_init_op_data
    *mb_queue_sm3_init_dequeue(mb_queue_sm3_init *queue);
int mb_queue_sm3_init_get_size(mb_queue_sm3_init *queue);

/* SM3 update */
mb_queue_sm3_update * mb_queue_sm3_update_create();
int mb_queue_sm3_update_disable(mb_queue_sm3_update * queue);
int mb_queue_sm3_update_cleanup(mb_queue_sm3_update * queue);
int mb_queue_sm3_update_enqueue(mb_queue_sm3_update *queue,
                                        sm3_update_op_data *item);
sm3_update_op_data
    *mb_queue_sm3_update_dequeue(mb_queue_sm3_update *queue);
int mb_queue_sm3_update_get_size(mb_queue_sm3_update *queue);

/* SM3 Final */
mb_queue_sm3_final * mb_queue_sm3_final_create();
int mb_queue_sm3_final_disable(mb_queue_sm3_final * queue);
int mb_queue_sm3_final_cleanup(mb_queue_sm3_final * queue);
int mb_queue_sm3_final_enqueue(mb_queue_sm3_final *queue,
                                        sm3_final_op_data *item);
sm3_final_op_data
    *mb_queue_sm3_final_dequeue(mb_queue_sm3_final *queue);
int mb_queue_sm3_final_get_size(mb_queue_sm3_final *queue);

mb_queue_sm2ecdh_keygen * mb_queue_sm2ecdh_keygen_create();
int mb_queue_sm2ecdh_keygen_disable(mb_queue_sm2ecdh_keygen * queue);
int mb_queue_sm2ecdh_keygen_cleanup(mb_queue_sm2ecdh_keygen * queue);
int mb_queue_sm2ecdh_keygen_enqueue(mb_queue_sm2ecdh_keygen *queue,
                                    ecdh_keygen_op_data *item);
ecdh_keygen_op_data
    *mb_queue_sm2ecdh_keygen_dequeue(mb_queue_sm2ecdh_keygen *queue);
int mb_queue_sm2ecdh_keygen_get_size(mb_queue_sm2ecdh_keygen *queue);

mb_queue_sm2ecdh_compute * mb_queue_sm2ecdh_compute_create();
int mb_queue_sm2ecdh_compute_disable(mb_queue_sm2ecdh_compute * queue);
int mb_queue_sm2ecdh_compute_cleanup(mb_queue_sm2ecdh_compute * queue);
int mb_queue_sm2ecdh_compute_enqueue(mb_queue_sm2ecdh_compute *queue,
                                     ecdh_compute_op_data *item);
ecdh_compute_op_data
    *mb_queue_sm2ecdh_compute_dequeue(mb_queue_sm2ecdh_compute *queue);
int mb_queue_sm2ecdh_compute_get_size(mb_queue_sm2ecdh_compute *queue);

mb_queue_ecdsa_sm2_sign * mb_queue_ecdsa_sm2_sign_create();
int mb_queue_ecdsa_sm2_sign_disable(mb_queue_ecdsa_sm2_sign * queue);
int mb_queue_ecdsa_sm2_sign_cleanup(mb_queue_ecdsa_sm2_sign * queue);
int mb_queue_ecdsa_sm2_sign_enqueue(mb_queue_ecdsa_sm2_sign *queue,
                                    ecdsa_sm2_sign_op_data *item);
ecdsa_sm2_sign_op_data
    *mb_queue_ecdsa_sm2_sign_dequeue(mb_queue_ecdsa_sm2_sign *queue);
int mb_queue_ecdsa_sm2_sign_get_size(mb_queue_ecdsa_sm2_sign *queue);

mb_queue_ecdsa_sm2_verify * mb_queue_ecdsa_sm2_verify_create();
int mb_queue_ecdsa_sm2_verify_disable(mb_queue_ecdsa_sm2_verify * queue);
int mb_queue_ecdsa_sm2_verify_cleanup(mb_queue_ecdsa_sm2_verify * queue);
int mb_queue_ecdsa_sm2_verify_enqueue(mb_queue_ecdsa_sm2_verify *queue,
                                      ecdsa_sm2_verify_op_data *item);
ecdsa_sm2_verify_op_data
    *mb_queue_ecdsa_sm2_verify_dequeue(mb_queue_ecdsa_sm2_verify *queue);
int mb_queue_ecdsa_sm2_verify_get_size(mb_queue_ecdsa_sm2_verify *queue);

/* SM4_CBC cipher */
mb_queue_sm4_cbc_cipher * mb_queue_sm4_cbc_cipher_create();
int mb_queue_sm4_cbc_cipher_disable(mb_queue_sm4_cbc_cipher * queue);
int mb_queue_sm4_cbc_cipher_cleanup(mb_queue_sm4_cbc_cipher * queue);
int mb_queue_sm4_cbc_cipher_enqueue(mb_queue_sm4_cbc_cipher *queue,
                                  sm4_cbc_cipher_op_data *item);
sm4_cbc_cipher_op_data
    *mb_queue_sm4_cbc_cipher_dequeue(mb_queue_sm4_cbc_cipher *queue);
int mb_queue_sm4_cbc_cipher_get_size(mb_queue_sm4_cbc_cipher *queue);
int mb_queue_sm4_cbc_cipher_dec_disable(mb_queue_sm4_cbc_cipher * queue);
int mb_queue_sm4_cbc_cipher_dec_cleanup(mb_queue_sm4_cbc_cipher * queue);
sm4_cbc_cipher_op_data
    *mb_queue_sm4_cbc_cipher_dec_dequeue(mb_queue_sm4_cbc_cipher *queue);

/* SM4_GCM encrypt */
mb_queue_sm4_gcm_encrypt * mb_queue_sm4_gcm_encrypt_create();
int mb_queue_sm4_gcm_encrypt_disable(mb_queue_sm4_gcm_encrypt * queue);
int mb_queue_sm4_gcm_encrypt_cleanup(mb_queue_sm4_gcm_encrypt * queue);
int mb_queue_sm4_gcm_encrypt_enqueue(mb_queue_sm4_gcm_encrypt *queue,
                                  sm4_gcm_encrypt_op_data *item);
sm4_gcm_encrypt_op_data
    *mb_queue_sm4_gcm_encrypt_dequeue(mb_queue_sm4_gcm_encrypt *queue);
int mb_queue_sm4_gcm_encrypt_get_size(mb_queue_sm4_gcm_encrypt *queue);

/* SM4_GCM decrypt */
mb_queue_sm4_gcm_decrypt * mb_queue_sm4_gcm_decrypt_create();
int mb_queue_sm4_gcm_decrypt_disable(mb_queue_sm4_gcm_decrypt * queue);
int mb_queue_sm4_gcm_decrypt_cleanup(mb_queue_sm4_gcm_decrypt * queue);
int mb_queue_sm4_gcm_decrypt_enqueue(mb_queue_sm4_gcm_decrypt *queue,
                                  sm4_gcm_decrypt_op_data *item);
sm4_gcm_decrypt_op_data
    *mb_queue_sm4_gcm_decrypt_dequeue(mb_queue_sm4_gcm_decrypt *queue);
int mb_queue_sm4_gcm_decrypt_get_size(mb_queue_sm4_gcm_decrypt *queue);

/* SM4_CCM */
mb_queue_sm4_ccm_encrypt * mb_queue_sm4_ccm_encrypt_create();
int mb_queue_sm4_ccm_encrypt_disable(mb_queue_sm4_ccm_encrypt * queue);
int mb_queue_sm4_ccm_encrypt_cleanup(mb_queue_sm4_ccm_encrypt * queue);
int mb_queue_sm4_ccm_encrypt_enqueue(mb_queue_sm4_ccm_encrypt *queue,
                                  sm4_ccm_encrypt_op_data *item);
sm4_ccm_encrypt_op_data
    *mb_queue_sm4_ccm_encrypt_dequeue(mb_queue_sm4_ccm_encrypt *queue);
int mb_queue_sm4_ccm_encrypt_get_size(mb_queue_sm4_ccm_encrypt *queue);

mb_queue_sm4_ccm_decrypt * mb_queue_sm4_ccm_decrypt_create();
int mb_queue_sm4_ccm_decrypt_disable(mb_queue_sm4_ccm_decrypt * queue);
int mb_queue_sm4_ccm_decrypt_cleanup(mb_queue_sm4_ccm_decrypt * queue);
int mb_queue_sm4_ccm_decrypt_enqueue(mb_queue_sm4_ccm_decrypt *queue,
                                  sm4_ccm_decrypt_op_data *item);
sm4_ccm_decrypt_op_data
    *mb_queue_sm4_ccm_decrypt_dequeue(mb_queue_sm4_ccm_decrypt *queue);
int mb_queue_sm4_ccm_decrypt_get_size(mb_queue_sm4_ccm_decrypt *queue);

#endif /* QAT_SW_QUEUE_H */
