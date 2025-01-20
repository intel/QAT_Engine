/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2020-2025 Intel Corporation.
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
# include "qat_sw_queue.h"
#include <semaphore.h>

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

typedef struct _mb_flist_ecdsa_verify
{
    pthread_mutex_t mb_flist_mutex;
    ecdsa_verify_op_data *head;
} mb_flist_ecdsa_verify;

typedef struct _mb_flist_ecdsa_sm2_sign
{
    pthread_mutex_t mb_flist_mutex;
    ecdsa_sm2_sign_op_data *head;
} mb_flist_ecdsa_sm2_sign;

typedef struct _mb_flist_ecdsa_sm2_verify
{
    pthread_mutex_t mb_flist_mutex;
    ecdsa_sm2_verify_op_data *head;
} mb_flist_ecdsa_sm2_verify;

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

typedef struct _mb_flist_sm3_init
{
    pthread_mutex_t mb_flist_mutex;
    sm3_init_op_data *head;
} mb_flist_sm3_init;

typedef struct _mb_flist_sm3_update
{
    pthread_mutex_t mb_flist_mutex;
    sm3_update_op_data *head;
} mb_flist_sm3_update;

typedef struct _mb_flist_sm3_final
{
    pthread_mutex_t mb_flist_mutex;
    sm3_final_op_data *head;
} mb_flist_sm3_final;

typedef struct _mb_flist_sm4_cbc_cipher
{
    pthread_mutex_t mb_flist_mutex;
    sm4_cbc_cipher_op_data *head;
} mb_flist_sm4_cbc_cipher;

# ifdef ENABLE_QAT_SW_SM4_GCM
typedef struct _mb_flist_sm4_gcm_encrypt
{
    pthread_mutex_t mb_flist_mutex;
    sm4_gcm_encrypt_op_data *head;
} mb_flist_sm4_gcm_encrypt;

typedef struct _mb_flist_sm4_gcm_decrypt
{
    pthread_mutex_t mb_flist_mutex;
    sm4_gcm_decrypt_op_data *head;
} mb_flist_sm4_gcm_decrypt;
# endif

# ifdef ENABLE_QAT_SW_SM4_CCM
typedef struct _mb_flist_sm4_ccm_encrypt
{
    pthread_mutex_t mb_flist_mutex;
    sm4_ccm_encrypt_op_data *head;
} mb_flist_sm4_ccm_encrypt;

typedef struct _mb_flist_sm4_ccm_decrypt
{
    pthread_mutex_t mb_flist_mutex;
    sm4_ccm_decrypt_op_data *head;
} mb_flist_sm4_ccm_decrypt;
# endif

typedef struct _mb_thread_data{
    pthread_t polling_thread;
    int keep_polling;
    sem_t mb_polling_thread_sem;
    /* RSA */
    mb_flist_rsa_priv *rsa_priv_freelist;
    mb_flist_rsa_pub *rsa_pub_freelist;
    mb_queue_rsa2k_priv *rsa2k_priv_queue;
    mb_queue_rsa2k_pub *rsa2k_pub_queue;
    mb_queue_rsa3k_priv *rsa3k_priv_queue;
    mb_queue_rsa3k_pub *rsa3k_pub_queue;
    mb_queue_rsa4k_priv *rsa4k_priv_queue;
    mb_queue_rsa4k_pub *rsa4k_pub_queue;

    /* X25519 */
    mb_flist_x25519_keygen *x25519_keygen_freelist;
    mb_flist_x25519_derive *x25519_derive_freelist;
    mb_queue_x25519_keygen *x25519_keygen_queue;
    mb_queue_x25519_derive *x25519_derive_queue;

    /* ECDSA p256 */
    mb_flist_ecdsa_sign *ecdsa_sign_freelist;
    mb_flist_ecdsa_sign_setup *ecdsa_sign_setup_freelist;
    mb_flist_ecdsa_sign_sig *ecdsa_sign_sig_freelist;
    mb_flist_ecdsa_verify *ecdsa_verify_freelist;
    mb_queue_ecdsap256_sign *ecdsap256_sign_queue;
    mb_queue_ecdsap256_sign_setup *ecdsap256_sign_setup_queue;
    mb_queue_ecdsap256_sign_sig *ecdsap256_sign_sig_queue;
    mb_queue_ecdsap256_verify *ecdsap256_verify_queue;

    /* ECDSA p384 */
    mb_queue_ecdsap384_sign *ecdsap384_sign_queue;
    mb_queue_ecdsap384_sign_setup *ecdsap384_sign_setup_queue;
    mb_queue_ecdsap384_sign_sig *ecdsap384_sign_sig_queue;
    mb_queue_ecdsap384_verify *ecdsap384_verify_queue;

    /* ECDSA sm2 */
    mb_flist_ecdsa_sm2_sign *ecdsa_sm2_sign_freelist;
    mb_flist_ecdsa_sm2_verify *ecdsa_sm2_verify_freelist;
    mb_queue_ecdsa_sm2_sign *ecdsa_sm2_sign_queue;
    mb_queue_ecdsa_sm2_verify *ecdsa_sm2_verify_queue;

    /* ECDH p256*/
    mb_flist_ecdh_keygen *ecdh_keygen_freelist;
    mb_flist_ecdh_compute *ecdh_compute_freelist;
    mb_queue_ecdhp256_keygen *ecdhp256_keygen_queue;
    mb_queue_ecdhp256_compute *ecdhp256_compute_queue;

    /* ECDH p384*/
    mb_queue_ecdhp384_keygen *ecdhp384_keygen_queue;
    mb_queue_ecdhp384_compute *ecdhp384_compute_queue;

    /* ECDH sm2*/
    mb_queue_sm2ecdh_keygen *sm2ecdh_keygen_queue;
    mb_queue_sm2ecdh_compute *sm2ecdh_compute_queue;

    /* SM3 */
    mb_flist_sm3_init *sm3_init_freelist;
    mb_flist_sm3_update *sm3_update_freelist;
    mb_flist_sm3_final  *sm3_final_freelist;
    mb_queue_sm3_init *sm3_init_queue;
    mb_queue_sm3_update *sm3_update_queue;
    mb_queue_sm3_final *sm3_final_queue;

    /* SM4_CBC */
    mb_flist_sm4_cbc_cipher *sm4_cbc_cipher_freelist;
    mb_flist_sm4_cbc_cipher *sm4_cbc_cipher_dec_freelist;
    mb_queue_sm4_cbc_cipher *sm4_cbc_cipher_queue;
    mb_queue_sm4_cbc_cipher *sm4_cbc_cipher_dec_queue;
    /* SM4_GCM */
# ifdef ENABLE_QAT_SW_SM4_GCM
    mb_flist_sm4_gcm_encrypt *sm4_gcm_encrypt_freelist;
    mb_flist_sm4_gcm_decrypt *sm4_gcm_decrypt_freelist;
    mb_queue_sm4_gcm_encrypt *sm4_gcm_encrypt_queue;
    mb_queue_sm4_gcm_decrypt *sm4_gcm_decrypt_queue;
# endif

    /* SM4_CCM */
# ifdef ENABLE_QAT_SW_SM4_CCM
    mb_flist_sm4_ccm_encrypt *sm4_ccm_encrypt_freelist;
    mb_flist_sm4_ccm_decrypt *sm4_ccm_decrypt_freelist;
    mb_queue_sm4_ccm_encrypt *sm4_ccm_encrypt_queue;
    mb_queue_sm4_ccm_decrypt *sm4_ccm_decrypt_queue;
# endif
} mb_thread_data;

mb_flist_rsa_priv * mb_flist_rsa_priv_create();
int mb_flist_rsa_priv_cleanup(mb_flist_rsa_priv *freelist);
int mb_flist_rsa_priv_push(mb_flist_rsa_priv *freelist, rsa_priv_op_data *item);
rsa_priv_op_data * mb_flist_rsa_priv_pop(mb_flist_rsa_priv *flist);

mb_flist_rsa_pub * mb_flist_rsa_pub_create();
int mb_flist_rsa_pub_cleanup(mb_flist_rsa_pub *freelist);
int mb_flist_rsa_pub_push(mb_flist_rsa_pub *freelist, rsa_pub_op_data *item);
rsa_pub_op_data * mb_flist_rsa_pub_pop(mb_flist_rsa_pub *flist);

mb_flist_x25519_keygen * mb_flist_x25519_keygen_create();
int mb_flist_x25519_keygen_cleanup(mb_flist_x25519_keygen *freelist);
int mb_flist_x25519_keygen_push(mb_flist_x25519_keygen *freelist,
                                x25519_keygen_op_data *item);
x25519_keygen_op_data * mb_flist_x25519_keygen_pop(mb_flist_x25519_keygen *flist);

mb_flist_x25519_derive * mb_flist_x25519_derive_create();
int mb_flist_x25519_derive_cleanup(mb_flist_x25519_derive *freelist);
int mb_flist_x25519_derive_push(mb_flist_x25519_derive *freelist,
                                x25519_derive_op_data *item);
x25519_derive_op_data * mb_flist_x25519_derive_pop(mb_flist_x25519_derive *flist);

mb_flist_ecdsa_sm2_sign * mb_flist_ecdsa_sm2_sign_create();
int mb_flist_ecdsa_sm2_sign_cleanup(mb_flist_ecdsa_sm2_sign *freelist);
int mb_flist_ecdsa_sm2_sign_push(mb_flist_ecdsa_sm2_sign *freelist,
                             ecdsa_sm2_sign_op_data *item);
ecdsa_sm2_sign_op_data
    *mb_flist_ecdsa_sm2_sign_pop(mb_flist_ecdsa_sm2_sign *flist);

mb_flist_ecdsa_sm2_verify * mb_flist_ecdsa_sm2_verify_create();
int mb_flist_ecdsa_sm2_verify_cleanup(mb_flist_ecdsa_sm2_verify *freelist);
int mb_flist_ecdsa_sm2_verify_push(mb_flist_ecdsa_sm2_verify *freelist,
                             ecdsa_sm2_verify_op_data *item);
ecdsa_sm2_verify_op_data
    *mb_flist_ecdsa_sm2_verify_pop(mb_flist_ecdsa_sm2_verify *flist);

mb_flist_ecdsa_sign * mb_flist_ecdsa_sign_create();
int mb_flist_ecdsa_sign_cleanup(mb_flist_ecdsa_sign *freelist);
int mb_flist_ecdsa_sign_push(mb_flist_ecdsa_sign *freelist,
                             ecdsa_sign_op_data *item);
ecdsa_sign_op_data
    *mb_flist_ecdsa_sign_pop(mb_flist_ecdsa_sign *flist);

mb_flist_ecdsa_sign_setup * mb_flist_ecdsa_sign_setup_create();
int mb_flist_ecdsa_sign_setup_cleanup(mb_flist_ecdsa_sign_setup *freelist);
int mb_flist_ecdsa_sign_setup_push(mb_flist_ecdsa_sign_setup *freelist,
                                   ecdsa_sign_setup_op_data *item);
ecdsa_sign_setup_op_data
    *mb_flist_ecdsa_sign_setup_pop(mb_flist_ecdsa_sign_setup *flist);

mb_flist_ecdsa_sign_sig * mb_flist_ecdsa_sign_sig_create();
int mb_flist_ecdsa_sign_sig_cleanup(mb_flist_ecdsa_sign_sig *freelist);
int mb_flist_ecdsa_sign_sig_push(mb_flist_ecdsa_sign_sig *freelist,
                                 ecdsa_sign_sig_op_data *item);
ecdsa_sign_sig_op_data
    *mb_flist_ecdsa_sign_sig_pop(mb_flist_ecdsa_sign_sig *flist);

mb_flist_ecdsa_verify * mb_flist_ecdsa_verify_create();
int mb_flist_ecdsa_verify_cleanup(mb_flist_ecdsa_verify *freelist);
int mb_flist_ecdsa_verify_push(mb_flist_ecdsa_verify *freelist,
                             ecdsa_verify_op_data *item);
ecdsa_verify_op_data
    *mb_flist_ecdsa_verify_pop(mb_flist_ecdsa_verify *flist);

mb_flist_ecdh_keygen * mb_flist_ecdh_keygen_create();
int mb_flist_ecdh_keygen_cleanup(mb_flist_ecdh_keygen *freelist);
int mb_flist_ecdh_keygen_push(mb_flist_ecdh_keygen *freelist,
                              ecdh_keygen_op_data *item);
ecdh_keygen_op_data *mb_flist_ecdh_keygen_pop(mb_flist_ecdh_keygen *flist);

mb_flist_ecdh_compute * mb_flist_ecdh_compute_create();
int mb_flist_ecdh_compute_cleanup(mb_flist_ecdh_compute *freelist);
int mb_flist_ecdh_compute_push(mb_flist_ecdh_compute *freelist,
                               ecdh_compute_op_data *item);
ecdh_compute_op_data *mb_flist_ecdh_compute_pop(mb_flist_ecdh_compute *flist);

mb_flist_sm3_init * mb_flist_sm3_init_create();
int mb_flist_sm3_init_cleanup(mb_flist_sm3_init *freelist);
int mb_flist_sm3_init_push(mb_flist_sm3_init *freelist,
                               sm3_init_op_data *item);
sm3_init_op_data *mb_flist_sm3_init_pop(mb_flist_sm3_init *flist);

mb_flist_sm3_update * mb_flist_sm3_update_create();
int mb_flist_sm3_update_cleanup(mb_flist_sm3_update *freelist);
int mb_flist_sm3_update_push(mb_flist_sm3_update *freelist,
                               sm3_update_op_data *item);
sm3_update_op_data *mb_flist_sm3_update_pop(mb_flist_sm3_update *flist);

mb_flist_sm3_final * mb_flist_sm3_final_create();
int mb_flist_sm3_final_cleanup(mb_flist_sm3_final *freelist);
int mb_flist_sm3_final_push(mb_flist_sm3_final *freelist,
                               sm3_final_op_data *item);
sm3_final_op_data *mb_flist_sm3_final_pop(mb_flist_sm3_final *flist);

mb_flist_sm4_cbc_cipher * mb_flist_sm4_cbc_cipher_create();
int mb_flist_sm4_cbc_cipher_cleanup(mb_flist_sm4_cbc_cipher *freelist);
int mb_flist_sm4_cbc_cipher_push(mb_flist_sm4_cbc_cipher *freelist,
                               sm4_cbc_cipher_op_data *item);
sm4_cbc_cipher_op_data
    *mb_flist_sm4_cbc_cipher_pop(mb_flist_sm4_cbc_cipher *flist);

# ifdef ENABLE_QAT_SW_SM4_GCM
mb_flist_sm4_gcm_encrypt * mb_flist_sm4_gcm_encrypt_create();
int mb_flist_sm4_gcm_encrypt_cleanup(mb_flist_sm4_gcm_encrypt *freelist);
int mb_flist_sm4_gcm_encrypt_push(mb_flist_sm4_gcm_encrypt *freelist,
                               sm4_gcm_encrypt_op_data *item);
sm4_gcm_encrypt_op_data
    *mb_flist_sm4_gcm_encrypt_pop(mb_flist_sm4_gcm_encrypt *flist);

mb_flist_sm4_gcm_decrypt * mb_flist_sm4_gcm_decrypt_create();
int mb_flist_sm4_gcm_decrypt_cleanup(mb_flist_sm4_gcm_decrypt *freelist);
int mb_flist_sm4_gcm_decrypt_push(mb_flist_sm4_gcm_decrypt *freelist,
                               sm4_gcm_decrypt_op_data *item);
sm4_gcm_decrypt_op_data
    *mb_flist_sm4_gcm_decrypt_pop(mb_flist_sm4_gcm_decrypt *flist);
# endif

# ifdef ENABLE_QAT_SW_SM4_CCM
mb_flist_sm4_ccm_encrypt * mb_flist_sm4_ccm_encrypt_create();
int mb_flist_sm4_ccm_encrypt_cleanup(mb_flist_sm4_ccm_encrypt *freelist);
int mb_flist_sm4_ccm_encrypt_push(mb_flist_sm4_ccm_encrypt *freelist,
                               sm4_ccm_encrypt_op_data *item);
sm4_ccm_encrypt_op_data
    *mb_flist_sm4_ccm_encrypt_pop(mb_flist_sm4_ccm_encrypt *flist);

mb_flist_sm4_ccm_decrypt * mb_flist_sm4_ccm_decrypt_create();
int mb_flist_sm4_ccm_decrypt_cleanup(mb_flist_sm4_ccm_decrypt *freelist);
int mb_flist_sm4_ccm_decrypt_push(mb_flist_sm4_ccm_decrypt *freelist,
                               sm4_ccm_decrypt_op_data *item);
sm4_ccm_decrypt_op_data
    *mb_flist_sm4_ccm_decrypt_pop(mb_flist_sm4_ccm_decrypt *flist);
# endif
#endif /* QAT_SW_FREELIST_H */
