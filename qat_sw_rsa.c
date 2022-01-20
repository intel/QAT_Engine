/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2020-2022 Intel Corporation.
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
 * @file qat_sw_rsa.c
 *
 * This file contains the engine implementation for RSA Multi-buffer operations
 *
 *****************************************************************************/

/* macros defined to allow use of the cpu get and set affinity functions */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#define __USE_GNU

#include <pthread.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "crypto_mb/rsa.h"
#include "e_qat.h"
#include "qat_sw_rsa.h"
#include "qat_events.h"
#include "qat_fork.h"
#include "qat_utils.h"

#ifdef ENABLE_QAT_SW_RSA
# ifdef DISABLE_QAT_SW_RSA
#  undef DISABLE_QAT_SW_RSA
# endif
#endif

# define RSA_MULTIBUFF_PRIV_ENC 1
# define RSA_MULTIBUFF_PRIV_DEC 2
# define RSA_MULTIBUFF_PUB_ENC  3
# define RSA_MULTIBUFF_PUB_DEC  4

/* Multibuff RSA methods declaration */
static int multibuff_rsa_priv_enc(int flen, const unsigned char *from,
                                  unsigned char *to, RSA *rsa, int padding);

static int multibuff_rsa_priv_dec(int flen, const unsigned char *from,
                                  unsigned char *to, RSA *rsa, int padding);

static int multibuff_rsa_pub_enc(int flen, const unsigned char *from,
                                 unsigned char *to, RSA *rsa, int padding);

static int multibuff_rsa_pub_dec(int flen, const unsigned char *from,
                                 unsigned char *to, RSA *rsa, int padding);

static int multibuff_rsa_init(RSA *rsa);

static int multibuff_rsa_finish(RSA *rsa);

static RSA_METHOD *multibuff_rsa_method = NULL;

RSA_METHOD *multibuff_get_RSA_methods(void)
{
    int res = 1;

    if (multibuff_rsa_method != NULL)
        return multibuff_rsa_method;

    if ((multibuff_rsa_method = RSA_meth_new("Multibuff RSA method", 0)) == NULL) {
        WARN("Failed to allocate Multibuff RSA methods\n");
        QATerr(QAT_F_MULTIBUFF_GET_RSA_METHODS, QAT_R_ALLOC_MULTIBUFF_RSA_METH_FAILURE);
        return NULL;
    }

    res &= RSA_meth_set_priv_enc(multibuff_rsa_method, multibuff_rsa_priv_enc);
    res &= RSA_meth_set_priv_dec(multibuff_rsa_method, multibuff_rsa_priv_dec);
    res &= RSA_meth_set_pub_enc(multibuff_rsa_method, multibuff_rsa_pub_enc);
    res &= RSA_meth_set_pub_dec(multibuff_rsa_method, multibuff_rsa_pub_dec);
    res &= RSA_meth_set_bn_mod_exp(multibuff_rsa_method, RSA_meth_get_bn_mod_exp(RSA_PKCS1_OpenSSL()));
    res &= RSA_meth_set_mod_exp(multibuff_rsa_method, RSA_meth_get_mod_exp(RSA_PKCS1_OpenSSL()));
    res &= RSA_meth_set_init(multibuff_rsa_method, multibuff_rsa_init);
    res &= RSA_meth_set_finish(multibuff_rsa_method, multibuff_rsa_finish);

    if (res == 0) {
        WARN("Failed to set Multibuff RSA methods\n");
        QATerr(QAT_F_MULTIBUFF_GET_RSA_METHODS, QAT_R_SET_MULTIBUFF_RSA_METH_FAILURE);
        return NULL;
    }

    DEBUG("QAT SW RSA registration succeeded\n");
    return multibuff_rsa_method;
}

void multibuff_free_RSA_methods(void)
{
#ifdef ENABLE_QAT_SW_RSA
    if (multibuff_rsa_method != NULL) {
        RSA_meth_free(multibuff_rsa_method);
        multibuff_rsa_method = NULL;
        qat_sw_rsa_offload = 0;
    }
#endif
}

/*
 * The RSA range check is performed so that if the op sizes are not in the
 * range supported by the multibuffer engine then fall back to the standard
 * software implementation.
 */

static inline int multibuff_rsa_range_check(int len)
{
    if (len == RSA_2K_LENGTH || len == RSA_3K_LENGTH ||
        len == RSA_4K_LENGTH) {
        return 1;
    } else {
        return 0;
    }
}

int multibuff_rsa_init(RSA *rsa)
{
    return RSA_meth_get_init(RSA_PKCS1_OpenSSL())(rsa);
}

int multibuff_rsa_finish(RSA *rsa)
{
    return RSA_meth_get_finish(RSA_PKCS1_OpenSSL())(rsa);
}

static int multibuff_rsa_check_padding_priv_dec(unsigned char *from,
                                                int from_len,
                                                unsigned char *to,
                                                int padding)
{
    int output_len = -1;

    switch (padding) {
    case RSA_PKCS1_PADDING:
        output_len =
            RSA_padding_check_PKCS1_type_2(to,
                                           from_len,
                                           from,
                                           from_len,
                                           from_len);
        break;
    case RSA_PKCS1_OAEP_PADDING:
        output_len =
            RSA_padding_check_PKCS1_OAEP(to,
                                         from_len,
                                         from,
                                         from_len,
                                         from_len,
                                         NULL,
                                         0);
        break;
#ifndef QAT_OPENSSL_3
    case RSA_SSLV23_PADDING:
        output_len =
            RSA_padding_check_SSLv23(to,
                                     from_len,
                                     from,
                                     from_len,
                                     from_len);
        break;
#endif
    case RSA_NO_PADDING:
        output_len =
            RSA_padding_check_none(to,
                                   from_len,
                                   from,
                                   from_len,
                                   from_len);
        break;
    default:
        break; /* Do nothing as the error will be caught
                  when checking output_len. */
    }

    return output_len;
}

static int multibuff_rsa_check_padding_pub_dec(unsigned char *from,
                                               int from_len,
                                               unsigned char *to,
                                               int padding)
{
    int output_len = -1;

    switch (padding) {
    case RSA_PKCS1_PADDING:
        output_len =
            RSA_padding_check_PKCS1_type_1(to,
                                           from_len,
                                           from,
                                           from_len,
                                           from_len);
        break;
    case RSA_X931_PADDING:
        output_len =
            RSA_padding_check_X931(to,
                                   from_len,
                                   from,
                                   from_len,
                                   from_len);
        break;
    case RSA_NO_PADDING:
        output_len =
            RSA_padding_check_none(to,
                                   from_len,
                                   from,
                                   from_len,
                                   from_len);
        break;
    default:
        break; /* Do nothing as the error will be caught
                  when checking output_len. */
    }

    return output_len;
}

static int multibuff_rsa_add_padding_priv_enc(const unsigned char *from,
                                              int from_len,
                                              unsigned char *to,
                                              int to_len,
                                              int padding)
{
    int padding_result = -1;

    switch (padding) {
    case RSA_PKCS1_PADDING:
        padding_result =
            RSA_padding_add_PKCS1_type_1(to,
                                         to_len,
                                         from,
                                         from_len);
        break;
    case RSA_X931_PADDING:
        padding_result =
            RSA_padding_add_X931(to,
                                 to_len,
                                 from,
                                 from_len);
        break;
    case RSA_NO_PADDING:
        padding_result =
            RSA_padding_add_none(to,
                                 to_len,
                                 from,
                                 from_len);
        break;
    default:
        WARN("Unknown padding type: %d\n", padding);
        QATerr(QAT_F_MULTIBUFF_RSA_ADD_PADDING_PRIV_ENC,
               QAT_R_UNKNOWN_PADDING_TYPE);
        break;
    }

    return padding_result;
}

static int multibuff_rsa_add_padding_pub_enc(const unsigned char *from,
                                             int from_len,
                                             unsigned char *to,
                                             int to_len,
                                             int padding)
{
    int padding_result = -1;

    switch (padding) {
    case RSA_PKCS1_PADDING:
        padding_result =
            RSA_padding_add_PKCS1_type_2(to,
                                         to_len,
                                         from,
                                         from_len);
        break;
    case RSA_PKCS1_OAEP_PADDING:
        padding_result =
            RSA_padding_add_PKCS1_OAEP(to,
                                       to_len,
                                       from,
                                       from_len,
                                       NULL,
                                       0);
        break;
#ifndef QAT_OPENSSL_3
    case RSA_SSLV23_PADDING:
        padding_result =
            RSA_padding_add_SSLv23(to,
                                   to_len,
                                   from,
                                   from_len);
        break;
#endif
    case RSA_NO_PADDING:
        padding_result =
            RSA_padding_add_none(to,
                                 to_len,
                                 from,
                                 from_len);
        break;
    default:
        WARN("Unknown padding type: %d\n", padding);
        QATerr(QAT_F_MULTIBUFF_RSA_ADD_PADDING_PUB_ENC,
               QAT_R_UNKNOWN_PADDING_TYPE);
        break;
    }

    return padding_result;
}

void process_RSA_priv_reqs(mb_thread_data *tlv, int rsa_bits)
{
    rsa_priv_op_data *rsa_priv_req_array[MULTIBUFF_BATCH] = {0};
    const unsigned char *rsa_priv_from[MULTIBUFF_BATCH] = {0};
    unsigned char *rsa_priv_to[MULTIBUFF_BATCH] = {0};
    const BIGNUM *rsa_lenstra_e[MULTIBUFF_BATCH] = {0};
    const BIGNUM *rsa_lenstra_n[MULTIBUFF_BATCH] = {0};
    const BIGNUM *rsa_priv_p[MULTIBUFF_BATCH] = {0};
    const BIGNUM *rsa_priv_q[MULTIBUFF_BATCH] = {0};
    const BIGNUM *rsa_priv_dmp1[MULTIBUFF_BATCH] = {0};
    const BIGNUM *rsa_priv_dmq1[MULTIBUFF_BATCH] = {0};
    const BIGNUM *rsa_priv_iqmp[MULTIBUFF_BATCH] = {0};
    unsigned int rsa_sts = 0;
    int req_num = 0;
    int local_request_no = 0;

    START_RDTSC(&rsa_cycles_priv_execute);

    switch(rsa_bits) {
    case RSA_2K_LENGTH:
        DEBUG("Dequeue RSA2K priv reqs.\n");
        while ((rsa_priv_req_array[req_num] =
                mb_queue_rsa2k_priv_dequeue(tlv->rsa2k_priv_queue)) != NULL) {
            rsa_priv_from[req_num] = rsa_priv_req_array[req_num]->from;
            if (rsa_priv_req_array[req_num]->type == RSA_MULTIBUFF_PRIV_DEC) {
                rsa_priv_to[req_num] = rsa_priv_req_array[req_num]->padded_buf;
            } else {
                rsa_priv_to[req_num] = rsa_priv_req_array[req_num]->to;
            }
            rsa_priv_p[req_num] = rsa_priv_req_array[req_num]->p;
            rsa_priv_q[req_num] = rsa_priv_req_array[req_num]->q;
            rsa_priv_dmp1[req_num] = rsa_priv_req_array[req_num]->dmp1;
            rsa_priv_dmq1[req_num] = rsa_priv_req_array[req_num]->dmq1;
            rsa_priv_iqmp[req_num] = rsa_priv_req_array[req_num]->iqmp;
            ++req_num;
            if (req_num == MULTIBUFF_MIN_BATCH)
                break;
        }
        break;
    case RSA_3K_LENGTH:
        DEBUG("Dequeue RSA3K priv reqs.\n");
        while ((rsa_priv_req_array[req_num] =
                mb_queue_rsa3k_priv_dequeue(tlv->rsa3k_priv_queue)) != NULL) {
            rsa_priv_from[req_num] = rsa_priv_req_array[req_num]->from;
            if (rsa_priv_req_array[req_num]->type == RSA_MULTIBUFF_PRIV_DEC) {
                rsa_priv_to[req_num] = rsa_priv_req_array[req_num]->padded_buf;
            } else {
                rsa_priv_to[req_num] = rsa_priv_req_array[req_num]->to;
            }
            rsa_priv_p[req_num] = rsa_priv_req_array[req_num]->p;
            rsa_priv_q[req_num] = rsa_priv_req_array[req_num]->q;
            rsa_priv_dmp1[req_num] = rsa_priv_req_array[req_num]->dmp1;
            rsa_priv_dmq1[req_num] = rsa_priv_req_array[req_num]->dmq1;
            rsa_priv_iqmp[req_num] = rsa_priv_req_array[req_num]->iqmp;
            ++req_num;
            if (req_num == MULTIBUFF_MIN_BATCH)
                break;
         }
         break;
    case RSA_4K_LENGTH:
         DEBUG("Dequeue RSA4K priv reqs.\n");
         while ((rsa_priv_req_array[req_num] =
                 mb_queue_rsa4k_priv_dequeue(tlv->rsa4k_priv_queue)) != NULL) {
             rsa_priv_from[req_num] = rsa_priv_req_array[req_num]->from;
             if (rsa_priv_req_array[req_num]->type == RSA_MULTIBUFF_PRIV_DEC) {
                 rsa_priv_to[req_num] = rsa_priv_req_array[req_num]->padded_buf;
             } else {
                 rsa_priv_to[req_num] = rsa_priv_req_array[req_num]->to;
             }
             rsa_priv_p[req_num] = rsa_priv_req_array[req_num]->p;
             rsa_priv_q[req_num] = rsa_priv_req_array[req_num]->q;
             rsa_priv_dmp1[req_num] = rsa_priv_req_array[req_num]->dmp1;
             rsa_priv_dmq1[req_num] = rsa_priv_req_array[req_num]->dmq1;
             rsa_priv_iqmp[req_num] = rsa_priv_req_array[req_num]->iqmp;
             ++req_num;
             if (req_num == MULTIBUFF_MIN_BATCH)
                 break;
         }
         break;
    }
    local_request_no = req_num;
    DEBUG("Submitting %d priv requests\n", local_request_no);

    rsa_sts = mbx_rsa_private_crt_ssl_mb8(rsa_priv_from,
                                          rsa_priv_to,
                                          rsa_priv_p,
                                          rsa_priv_q,
                                          rsa_priv_dmp1,
                                          rsa_priv_dmq1,
                                          rsa_priv_iqmp,
                                          rsa_bits);

    for (req_num = 0; req_num < local_request_no; req_num++) {
        if (rsa_priv_req_array[req_num]->sts != NULL) {
            if (MBX_GET_STS(rsa_sts, req_num) == MBX_STATUS_OK) {
                DEBUG("Multibuffer rsa priv crt req[%d] success\n", req_num);
                *rsa_priv_req_array[req_num]->sts = 1;
            } else {
                WARN("Multibuffer rsa priv crt req[%d] failure\n", req_num);
                *rsa_priv_req_array[req_num]->sts = -1;
            }
            if (rsa_priv_req_array[req_num]->disable_lenstra_check) {
                rsa_priv_from[req_num] = NULL;
                rsa_priv_to[req_num] = NULL;
                rsa_lenstra_e[req_num] = NULL;
                rsa_lenstra_n[req_num] = NULL;
            } else {
                rsa_priv_from[req_num] = (unsigned const char*) rsa_priv_to[req_num];
                rsa_priv_to[req_num] = rsa_priv_req_array[req_num]->lenstra_to;
                rsa_lenstra_e[req_num] = rsa_priv_req_array[req_num]->e;
                rsa_lenstra_n[req_num] = rsa_priv_req_array[req_num]->n;
            }
        }
    }

    rsa_sts = mbx_rsa_public_ssl_mb8(rsa_priv_from,
                                     rsa_priv_to,
                                     rsa_lenstra_e,
                                     rsa_lenstra_n,
                                     rsa_bits);

    for (req_num = 0; req_num < local_request_no; req_num++) {
        if (rsa_priv_req_array[req_num]->sts != NULL) {
            if (MBX_GET_STS(rsa_sts, req_num) == MBX_STATUS_OK) {
                if (*rsa_priv_req_array[req_num]->sts < 0) {
                    WARN("Multibuffer rsa priv req[%d] failure\n", req_num);
                    *rsa_priv_req_array[req_num]->sts = -1;
                } else {
                    DEBUG("Multibuffer rsa priv req[%d] success\n", req_num);
                    *rsa_priv_req_array[req_num]->sts = 1;
                }
                if (!rsa_priv_req_array[req_num]->disable_lenstra_check) {
                    if (CRYPTO_memcmp(rsa_priv_req_array[req_num]->from,
                                      rsa_priv_to[req_num],
                                      rsa_priv_req_array[req_num]->flen) == 0) {
                        if (*rsa_priv_req_array[req_num]->sts < 0) {
                            WARN("Lenstra check[%d] failure\n", req_num);
                            *rsa_priv_req_array[req_num]->sts = -1;
                        } else {
                            *rsa_priv_req_array[req_num]->sts = 1;
                        }
                    } else {
                        WARN("Lenstra memcmp[%d] failure\n", req_num);
                        *rsa_priv_req_array[req_num]->sts = -1;
                    }
                }
            } else {
                 WARN("mbx_rsa_public_ssl_mb8[%d] failure\n", req_num);
                *rsa_priv_req_array[req_num]->sts = -1;
            }
            /* Remove Padding here if needed */
            if (*rsa_priv_req_array[req_num]->sts == 1 &&
                    rsa_priv_req_array[req_num]->type == RSA_MULTIBUFF_PRIV_DEC) {
                *rsa_priv_req_array[req_num]->sts =
                    multibuff_rsa_check_padding_priv_dec(
                            rsa_priv_req_array[req_num]->padded_buf,
                            rsa_priv_req_array[req_num]->flen,
                            rsa_priv_req_array[req_num]->to,
                            rsa_priv_req_array[req_num]->padding);
            }
            if (rsa_priv_req_array[req_num]->job) {
                qat_wake_job(rsa_priv_req_array[req_num]->job, ASYNC_STATUS_OK);
            }
            OPENSSL_cleanse(rsa_priv_req_array[req_num], sizeof(rsa_priv_op_data));
            mb_flist_rsa_priv_push(tlv->rsa_priv_freelist, rsa_priv_req_array[req_num]);
        }
    }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
    switch (rsa_bits) {
    case RSA_2K_LENGTH:
        mb_rsa2k_priv_req_rates.req_this_period += local_request_no;
        break;
    case RSA_3K_LENGTH:
        mb_rsa3k_priv_req_rates.req_this_period += local_request_no;
        break;
    case RSA_4K_LENGTH:
        mb_rsa4k_priv_req_rates.req_this_period += local_request_no;
        break;
    }
# endif

    STOP_RDTSC(&rsa_cycles_priv_execute, 1, "[RSA:priv_execute]");
    DEBUG("Processed Final Request\n");
}

void process_RSA_pub_reqs(mb_thread_data *tlv, int rsa_bits)
{
    rsa_pub_op_data *rsa_pub_req_array[MULTIBUFF_BATCH] = {0};
    const unsigned char * rsa_pub_from[MULTIBUFF_BATCH] = {0};
    unsigned char * rsa_pub_to[MULTIBUFF_BATCH] = {0};
    const BIGNUM * rsa_pub_e[MULTIBUFF_BATCH] = {0};
    const BIGNUM * rsa_pub_n[MULTIBUFF_BATCH] = {0};
    unsigned int rsa_sts = 0;
    int local_request_no = 0;
    int req_num = 0;

    START_RDTSC(&rsa_cycles_pub_execute);

    switch(rsa_bits) {
    case RSA_2K_LENGTH:
        DEBUG("Dequeue RSA2K pub reqs.\n");
        while ((rsa_pub_req_array[req_num] =
                mb_queue_rsa2k_pub_dequeue(tlv->rsa2k_pub_queue)) != NULL) {
            rsa_pub_from[req_num] = rsa_pub_req_array[req_num]->from;
            if (rsa_pub_req_array[req_num]->type == RSA_MULTIBUFF_PUB_DEC) {
                rsa_pub_to[req_num] = rsa_pub_req_array[req_num]->padded_buf;
            } else {
                rsa_pub_to[req_num] = rsa_pub_req_array[req_num]->to;
            }
            rsa_pub_e[req_num] = rsa_pub_req_array[req_num]->e;
            rsa_pub_n[req_num] = rsa_pub_req_array[req_num]->n;
            req_num++;
            if (req_num == MULTIBUFF_MIN_BATCH)
                break;
        }
        break;
    case RSA_3K_LENGTH:
        DEBUG("Dequeue RSA3K pub reqs.\n");
        while ((rsa_pub_req_array[req_num] =
                mb_queue_rsa3k_pub_dequeue(tlv->rsa3k_pub_queue)) != NULL) {
            rsa_pub_from[req_num] = rsa_pub_req_array[req_num]->from;
            if (rsa_pub_req_array[req_num]->type == RSA_MULTIBUFF_PUB_DEC) {
                rsa_pub_to[req_num] = rsa_pub_req_array[req_num]->padded_buf;
            } else {
                rsa_pub_to[req_num] = rsa_pub_req_array[req_num]->to;
            }
            rsa_pub_e[req_num] = rsa_pub_req_array[req_num]->e;
            rsa_pub_n[req_num] = rsa_pub_req_array[req_num]->n;
            req_num++;
            if (req_num == MULTIBUFF_MIN_BATCH)
                break;
        }
        break;
    case RSA_4K_LENGTH:
        DEBUG("Dequeue RSA4K pub reqs.\n");
        while ((rsa_pub_req_array[req_num] =
                mb_queue_rsa4k_pub_dequeue(tlv->rsa4k_pub_queue)) != NULL) {
            rsa_pub_from[req_num] = rsa_pub_req_array[req_num]->from;
            if (rsa_pub_req_array[req_num]->type == RSA_MULTIBUFF_PUB_DEC) {
                rsa_pub_to[req_num] = rsa_pub_req_array[req_num]->padded_buf;
            } else {
                rsa_pub_to[req_num] = rsa_pub_req_array[req_num]->to;
            }
            rsa_pub_e[req_num] = rsa_pub_req_array[req_num]->e;
            rsa_pub_n[req_num] = rsa_pub_req_array[req_num]->n;
            req_num++;
            if (req_num == MULTIBUFF_MIN_BATCH)
                break;
            }
        break;
    }
    local_request_no = req_num;
    DEBUG("Submitting %d pub requests\n", local_request_no);

    rsa_sts = mbx_rsa_public_ssl_mb8(rsa_pub_from,
                                     rsa_pub_to,
                                     rsa_pub_e,
                                     rsa_pub_n,
                                     rsa_bits);

    for (req_num = 0; req_num < local_request_no; req_num++) {
        if (rsa_pub_req_array[req_num]->sts != NULL) {
            if (MBX_GET_STS(rsa_sts, req_num) == MBX_STATUS_OK) {
                DEBUG("Multibuffer RSA pub req[%d] success\n", req_num);
                *rsa_pub_req_array[req_num]->sts = 1;
            } else {
                DEBUG("Multibuffer RSA pub req[%d] failure\n", req_num);
                *rsa_pub_req_array[req_num]->sts = -1;
            }
            /* Remove Padding here if needed */
            if (*rsa_pub_req_array[req_num]->sts == 1 &&
                    rsa_pub_req_array[req_num]->type == RSA_MULTIBUFF_PUB_DEC) {
                *rsa_pub_req_array[req_num]->sts =
                     multibuff_rsa_check_padding_pub_dec(
                            rsa_pub_req_array[req_num]->padded_buf,
                            rsa_pub_req_array[req_num]->flen,
                            rsa_pub_req_array[req_num]->to,
                            rsa_pub_req_array[req_num]->padding);
            }
            if (rsa_pub_req_array[req_num]->job) {
                qat_wake_job(rsa_pub_req_array[req_num]->job, ASYNC_STATUS_OK);
            }
            OPENSSL_cleanse(rsa_pub_req_array[req_num], sizeof(rsa_pub_op_data));
            mb_flist_rsa_pub_push(tlv->rsa_pub_freelist, rsa_pub_req_array[req_num]);
        }
    }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
    switch (rsa_bits) {
    case RSA_2K_LENGTH:
        mb_rsa2k_pub_req_rates.req_this_period += local_request_no;
        break;
    case RSA_3K_LENGTH:
        mb_rsa3k_pub_req_rates.req_this_period += local_request_no;
        break;
    case RSA_4K_LENGTH:
        mb_rsa4k_pub_req_rates.req_this_period += local_request_no;
        break;
    }
# endif

    STOP_RDTSC(&rsa_cycles_pub_execute, 1, "[RSA:pub_execute]");
    DEBUG("Processed Final Request\n");
}

int multibuff_rsa_priv_enc(int flen, const unsigned char *from,
                           unsigned char *to, RSA *rsa, int padding)
{
    int sts = -1;
    ASYNC_JOB *job;
    int rsa_len = 0, rsa_bits = 0;
    rsa_priv_op_data *rsa_priv_req = NULL;
    int padding_result = 0;
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;
    const BIGNUM *p = NULL;
    const BIGNUM *q = NULL;
    const BIGNUM *dmp1 = NULL;
    const BIGNUM *dmq1 = NULL;
    const BIGNUM *iqmp = NULL;
    int job_ret = 0;
    mb_thread_data *tlv = NULL;
    static __thread int req_num = 0;

    /* Check input parameters */
    if (unlikely(NULL == rsa || NULL == from || NULL == to || flen <= 0)) {
        WARN("RSA key, input or output is NULL or invalid length, \
             flen = %d\n", flen);
        QATerr(QAT_F_MULTIBUFF_RSA_PRIV_ENC, QAT_R_RSA_FROM_TO_NULL);
        if (to != NULL && rsa != NULL) {
            rsa_len = RSA_size(rsa);
            OPENSSL_cleanse(to, rsa_len);
        }
        return sts;
    }

    rsa_len = RSA_size(rsa);

    /* Check the length passed in is not longer than the rsa key length.
       If it is then use the sw method synchronously. */
    if (flen > rsa_len) {
        DEBUG("The length is longer than the RSA key length, using sw method\n");
        goto use_sw_method;
    }

    /* Check if we are running asynchronously. If not use the SW method */
    if ((job = ASYNC_get_current_job()) == NULL) {
        DEBUG("Running synchronously using sw method\n");
        goto use_sw_method;
    }

    /* Setup asynchronous notifications */
    if (!qat_setup_async_event_notification(0)) {
        DEBUG("Failed to setup async notifications, using sw method\n");
        goto use_sw_method;
    }

    rsa_bits = RSA_bits((const RSA*)rsa);

    /* Check if the request key size is supported */
    if (!multibuff_rsa_range_check(rsa_bits)) {
        DEBUG("Requested key size not supported, use sw method %d\n", rsa_bits);
        goto use_sw_method;
    }

    tlv = mb_check_thread_local();
    if (NULL == tlv) {
        WARN("Could not create thread local variables\n");
        goto use_sw_method;
    }

    while ((rsa_priv_req = mb_flist_rsa_priv_pop(tlv->rsa_priv_freelist)) == NULL) {
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
    }

    DEBUG("QAT SW RSA Started %p\n", rsa_priv_req);
    START_RDTSC(&rsa_cycles_priv_enc_setup);

    /* Buffer up the requests and call the new functions when we have enough
       requests buffered up */

    RSA_get0_key((const RSA*)rsa, &n, &e, &d);
    RSA_get0_factors((const RSA*)rsa, &p, &q);
    RSA_get0_crt_params((const RSA*)rsa, &dmp1, &dmq1, &iqmp);

    /* Further checks on the inputs, these are fatal if failed */
    if (p == NULL || q == NULL ||
        dmp1 == NULL || dmq1 == NULL || iqmp == NULL) {
        mb_flist_rsa_priv_push(tlv->rsa_priv_freelist, rsa_priv_req);
        QATerr(QAT_F_MULTIBUFF_RSA_PRIV_ENC, QAT_R_P_Q_DMP_DMQ_IQMP_NULL);
        OPENSSL_cleanse(to, rsa_len);
        STOP_RDTSC(&rsa_cycles_priv_enc_setup, 1, "[RSA:priv_enc_setup]");
        WARN("Either p %p, q %p, dmp1 %p, dmq1 %p, iqmp %p are NULL\n",
             p, q, dmp1, dmq1, iqmp);
        return sts;
    }

    /* Check whether we have public key info to allow a lenstra
       check. */
    if (e == NULL ||
        e_check == NULL ||
        BN_ucmp(e, e_check) != 0) {
        DEBUG("Disabling Lenstra Check\n");
        rsa_priv_req->disable_lenstra_check = 1;
    } else {
        rsa_priv_req->disable_lenstra_check = 0;
    }

    /* padding processing */
    padding_result =
        multibuff_rsa_add_padding_priv_enc(from,
                                           flen,
                                           rsa_priv_req->padded_buf,
                                           rsa_len,
                                           padding);

    if (padding_result <= 0) {
        OPENSSL_cleanse(rsa_priv_req->padded_buf, rsa_len);
        mb_flist_rsa_priv_push(tlv->rsa_priv_freelist, rsa_priv_req);
        /* Error is raised within the padding function. */
        OPENSSL_cleanse(to, rsa_len);
        STOP_RDTSC(&rsa_cycles_priv_enc_setup, 1, "[RSA:priv_enc_setup]");
        WARN("Failed to add padding\n");
        return sts;
    }

    rsa_priv_req->type = RSA_MULTIBUFF_PRIV_ENC;
    rsa_priv_req->flen = rsa_len;
    rsa_priv_req->from = rsa_priv_req->padded_buf;
    rsa_priv_req->to = to;
    rsa_priv_req->rsa = rsa;
    rsa_priv_req->padding = padding;
    rsa_priv_req->job = job;
    rsa_priv_req->e = e;
    rsa_priv_req->n = n;
    rsa_priv_req->p = p;
    rsa_priv_req->q = q;
    rsa_priv_req->dmp1 = dmp1;
    rsa_priv_req->dmq1 = dmq1;
    rsa_priv_req->iqmp = iqmp;
    rsa_priv_req->sts = &sts;

    switch(rsa_bits) {
    case RSA_2K_LENGTH:
        mb_queue_rsa2k_priv_enqueue(tlv->rsa2k_priv_queue, rsa_priv_req);
        break;
    case RSA_3K_LENGTH:
        mb_queue_rsa3k_priv_enqueue(tlv->rsa3k_priv_queue, rsa_priv_req);
        break;
    case RSA_4K_LENGTH:
        mb_queue_rsa4k_priv_enqueue(tlv->rsa4k_priv_queue, rsa_priv_req);
        break;
    }
    STOP_RDTSC(&rsa_cycles_priv_enc_setup, 1, "[RSA:priv_enc_setup]");

    if (!enable_external_polling && (++req_num % MULTIBUFF_MAX_BATCH) == 0) {
        DEBUG("Signal Polling thread, req_num %d\n", req_num);
        if (qat_kill_thread(tlv->polling_thread, SIGUSR1) != 0) {
            WARN("qat_kill_thread error\n");
            /* If we fail the pthread_kill carry on as the timeout
               will catch processing the request in the polling thread */
        }
    }

    DEBUG("Pausing: %p status = %d\n", rsa_priv_req, sts);
    do {
        /* If we get a failure on qat_pause_job then we will
           not flag an error here and quit because we have
           an asynchronous request in flight.
           We don't want to start cleaning up data
           structures that are still being used. If
           qat_pause_job fails we will just yield and
           loop around and try again until the request
           completes and we can continue. */
        if ((job_ret = qat_pause_job(job, ASYNC_STATUS_OK)) == 0)
            pthread_yield();
    } while (QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DEBUG("Finished: %p status = %d\n", rsa_priv_req, sts);

    if (sts > 0) {
        return rsa_len;
    } else {
        WARN("Failure in Private Encrypt\n");
        QATerr(QAT_F_MULTIBUFF_RSA_PRIV_ENC, ERR_R_INTERNAL_ERROR);
        OPENSSL_cleanse(to, rsa_len);
        return sts;
    }

use_sw_method:
    sts = RSA_meth_get_priv_enc(RSA_PKCS1_OpenSSL())(flen, from, to, rsa, padding);
    DEBUG("SW Finished\n");
    return sts;
}

int multibuff_rsa_priv_dec(int flen, const unsigned char *from,
                           unsigned char *to, RSA *rsa, int padding)
{
    int sts = -1;
    ASYNC_JOB *job;
    int rsa_len = 0, rsa_bits = 0;
    rsa_priv_op_data *rsa_priv_req = NULL;
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;
    const BIGNUM *p = NULL;
    const BIGNUM *q = NULL;
    const BIGNUM *dmp1 = NULL;
    const BIGNUM *dmq1 = NULL;
    const BIGNUM *iqmp = NULL;
    int job_ret = 0;
    mb_thread_data *tlv = NULL;
    static __thread int req_num = 0;

    /* Check input parameters */
    if (unlikely(rsa == NULL || from == NULL || to == NULL ||
        (flen != (rsa_len = RSA_size(rsa))))) {
        WARN("RSA key, input or output is NULL or invalid length, \
             flen = %d\n", flen);
        QATerr(QAT_F_MULTIBUFF_RSA_PRIV_DEC, QAT_R_RSA_FROM_TO_NULL);
        if (to != NULL && rsa != NULL) {
            rsa_len = RSA_size(rsa);
            OPENSSL_cleanse(to, rsa_len);
        }
        return sts;
    }

    /* Check the length passed in is not longer than the rsa key length.
       If it is then use the sw method synchronously. */
    if (flen > rsa_len) {
        DEBUG("The length is longer than the RSA key length, using sw method\n");
        goto use_sw_method;
    }

    /* Check if we are running asynchronously. If not use the SW method */
    if ((job = ASYNC_get_current_job()) == NULL) {
        DEBUG("Running synchronously using sw method\n");
        goto use_sw_method;
    }

    /* Setup asynchronous notifications */
    if (!qat_setup_async_event_notification(0)) {
        DEBUG("Failed to setup async notifications, using sw method\n");
        goto use_sw_method;
    }

    rsa_bits = RSA_bits((const RSA*)rsa);

    /* Check if the request key size is supported */
    if (!multibuff_rsa_range_check(rsa_bits)) {
        DEBUG("Requested key size not supported, use sw method %d\n", rsa_bits);
        goto use_sw_method;
    }

    tlv = mb_check_thread_local();
    if (NULL == tlv) {
        WARN("Could not create thread local variables\n");
        goto use_sw_method;
    }

    while ((rsa_priv_req = mb_flist_rsa_priv_pop(tlv->rsa_priv_freelist)) == NULL) {
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
    }

    DEBUG("QAT SW RSA Started %p\n", rsa_priv_req);
    START_RDTSC(&rsa_cycles_priv_dec_setup);

    /* Buffer up the requests and call the new functions when we have enough
       requests buffered up */

    RSA_get0_key((const RSA*)rsa, &n, &e, &d);
    RSA_get0_factors((const RSA*)rsa, &p, &q);
    RSA_get0_crt_params((const RSA*)rsa, &dmp1, &dmq1, &iqmp);

    /* Further checks on the inputs, these are fatal if failed */
    if (p == NULL || q == NULL ||
        dmp1 == NULL || dmq1 == NULL || iqmp == NULL) {
        mb_flist_rsa_priv_push(tlv->rsa_priv_freelist, rsa_priv_req);
        QATerr(QAT_F_MULTIBUFF_RSA_PRIV_DEC, QAT_R_P_Q_DMP_DMQ_IQMP_NULL);
        OPENSSL_cleanse(to, rsa_len);
        STOP_RDTSC(&rsa_cycles_priv_dec_setup, 1, "[RSA:priv_dec_setup]");
        WARN("Either p %p, q %p, dmp1 %p, dmq1 %p, iqmp %p are NULL\n",
             p, q, dmp1, dmq1, iqmp);
        return sts;
    }

    /* Check whether we have public key info to allow a lenstra
       check. */
    if (e == NULL ||
        e_check == NULL ||
        BN_ucmp(e, e_check) != 0) {
        DEBUG("Disabling Lenstra Check\n");
        rsa_priv_req->disable_lenstra_check = 1;
    } else {
        rsa_priv_req->disable_lenstra_check = 0;
    }

    rsa_priv_req->type = RSA_MULTIBUFF_PRIV_DEC;
    rsa_priv_req->flen = rsa_len;
    rsa_priv_req->from = from;
    rsa_priv_req->to = to;
    rsa_priv_req->rsa = rsa;
    rsa_priv_req->padding = padding;
    rsa_priv_req->job = job;
    rsa_priv_req->e = e;
    rsa_priv_req->n = n;
    rsa_priv_req->p = p;
    rsa_priv_req->q = q;
    rsa_priv_req->dmp1 = dmp1;
    rsa_priv_req->dmq1 = dmq1;
    rsa_priv_req->iqmp = iqmp;
    rsa_priv_req->sts = &sts;

    switch(rsa_bits) {
    case RSA_2K_LENGTH:
        mb_queue_rsa2k_priv_enqueue(tlv->rsa2k_priv_queue, rsa_priv_req);
        break;
    case RSA_3K_LENGTH:
        mb_queue_rsa3k_priv_enqueue(tlv->rsa3k_priv_queue, rsa_priv_req);
        break;
    case RSA_4K_LENGTH:
        mb_queue_rsa4k_priv_enqueue(tlv->rsa4k_priv_queue, rsa_priv_req);
        break;
    }
    STOP_RDTSC(&rsa_cycles_priv_dec_setup, 1, "[RSA:priv_dec_setup]");

    if (!enable_external_polling && (++req_num % MULTIBUFF_MAX_BATCH) == 0) {
        DEBUG("Signal Polling thread, req_num %d\n", req_num);
        if (qat_kill_thread(tlv->polling_thread, SIGUSR1) != 0) {
            WARN("qat_kill_thread error\n");
            /* If we fail the pthread_kill carry on as the timeout
               will catch processing the request in the polling thread */
        }
    }

    DEBUG("Pausing: %p status = %d\n", rsa_priv_req, sts);
    do {
        /* If we get a failure on qat_pause_job then we will
           not flag an error here and quit because we have
           an asynchronous request in flight.
           We don't want to start cleaning up data
           structures that are still being used. If
           qat_pause_job fails we will just yield and
           loop around and try again until the request
           completes and we can continue. */
        if ((job_ret = qat_pause_job(job, ASYNC_STATUS_OK)) == 0)
            pthread_yield();
    } while (QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DEBUG("Finished: %p status = %d\n", rsa_priv_req, sts);

    if (sts < 1 ) {
        WARN("Failure in Private Decrypt\n");
        QATerr(QAT_F_MULTIBUFF_RSA_PRIV_DEC, ERR_R_INTERNAL_ERROR);
        OPENSSL_cleanse(to, rsa_len);
    }
    return sts;

use_sw_method:
    sts = RSA_meth_get_priv_dec(RSA_PKCS1_OpenSSL())(flen, from, to, rsa, padding);
    DEBUG("SW Finished\n");
    return sts;
}

int multibuff_rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to,
                          RSA *rsa, int padding)
{
    int sts = -1;
    ASYNC_JOB *job;
    int rsa_len = 0, rsa_bits = 0;
    rsa_pub_op_data *rsa_pub_req = NULL;
    int padding_result = 0;
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;
    int job_ret = 0;
    mb_thread_data *tlv = NULL;
    static __thread int req_num = 0;

    /* Check Parameters */
    if (rsa == NULL || from == NULL || to == NULL || flen < 0) {
        WARN("RSA key %p, input %p or output %p are NULL or invalid length, \
              flen = %d, rsa_len = %d\n", rsa, from, to, flen, rsa_len);
        QATerr(QAT_F_MULTIBUFF_RSA_PUB_ENC, QAT_R_RSA_FROM_TO_NULL);
        if (to != NULL && rsa != NULL) {
            rsa_len = RSA_size(rsa);
            OPENSSL_cleanse(to, rsa_len);
        }
        return sts;
    }

    rsa_len = RSA_size(rsa);

    /* Check if we are running asynchronously. If not use the SW method */
    if ((job = ASYNC_get_current_job()) == NULL) {
        DEBUG("Running synchronously using sw method\n");
        goto use_sw_method;
    }

    /* Setup asynchronous notifications */
    if (!qat_setup_async_event_notification(0)) {
        DEBUG("Failed to setup async notifications, using sw method\n");
        goto use_sw_method;
    }

    rsa_bits = RSA_bits((const RSA*)rsa);

    /* Check if the request key size is supported */
    if (!multibuff_rsa_range_check(rsa_bits)) {
        DEBUG("Requested key size not supported, use sw method %d\n", rsa_bits);
        goto use_sw_method;
    }

    tlv = mb_check_thread_local();
    if (NULL == tlv) {
        WARN("Could not create thread local variables\n");
        goto use_sw_method;
    }

    while ((rsa_pub_req = mb_flist_rsa_pub_pop(tlv->rsa_pub_freelist)) == NULL) {
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
    }

    DEBUG("QAT SW RSA Started %p\n", rsa_pub_req);
    START_RDTSC(&rsa_cycles_pub_enc_setup);

    /* Buffer up the requests and call the new functions when we have enough
       requests buffered up */

    RSA_get0_key((const RSA*)rsa, &n, &e, &d);

    if (e == NULL ||
        e_check == NULL ||
        BN_ucmp(e, e_check) != 0) {
        mb_flist_rsa_pub_push(tlv->rsa_pub_freelist, rsa_pub_req);
        STOP_RDTSC(&rsa_cycles_pub_enc_setup, 1, "[RSA:pub_enc_setup]");
        DEBUG("Request is using a public exp not equal to 65537\n");
        goto use_sw_method;
    }

    /* padding processing */
    padding_result =
        multibuff_rsa_add_padding_pub_enc(from,
                                          flen,
                                          rsa_pub_req->padded_buf,
                                          rsa_len,
                                          padding);

    if (padding_result <= 0) {
        OPENSSL_cleanse(rsa_pub_req->padded_buf, rsa_len);
        mb_flist_rsa_pub_push(tlv->rsa_pub_freelist, rsa_pub_req);
        /* Error is raised within the padding function. */
        OPENSSL_cleanse(to, rsa_len);
        STOP_RDTSC(&rsa_cycles_pub_enc_setup, 1, "[RSA:pub_enc_setup]");
        WARN("Failed to add padding\n");
        return sts;
    }

    rsa_pub_req->type = RSA_MULTIBUFF_PUB_ENC;
    rsa_pub_req->flen = flen;
    rsa_pub_req->from = rsa_pub_req->padded_buf;
    rsa_pub_req->to = to;
    rsa_pub_req->rsa = rsa;
    rsa_pub_req->job = job;
    rsa_pub_req->padding = padding;
    rsa_pub_req->e = e;
    rsa_pub_req->n = n;
    rsa_pub_req->sts = &sts;

    switch(rsa_bits) {
    case RSA_2K_LENGTH:
        mb_queue_rsa2k_pub_enqueue(tlv->rsa2k_pub_queue, rsa_pub_req);
        break;
    case RSA_3K_LENGTH:
        mb_queue_rsa3k_pub_enqueue(tlv->rsa3k_pub_queue, rsa_pub_req);
        break;
    case RSA_4K_LENGTH:
        mb_queue_rsa4k_pub_enqueue(tlv->rsa4k_pub_queue, rsa_pub_req);
        break;
    }
    STOP_RDTSC(&rsa_cycles_pub_enc_setup, 1, "[RSA:pub_enc_setup]");

    if (!enable_external_polling && (++req_num % MULTIBUFF_MAX_BATCH) == 0) {
        DEBUG("Signal Polling thread, req_num %d\n", req_num);
        if (qat_kill_thread(tlv->polling_thread, SIGUSR1) != 0) {
            WARN("qat_kill_thread error\n");
            /* If we fail the pthread_kill carry on as the timeout
               will catch processing the request in the polling thread */
        }
    }

    DEBUG("Pausing: %p status = %d\n", rsa_pub_req, sts);
    do {
        /* If we get a failure on qat_pause_job then we will
           not flag an error here and quit because we have
           an asynchronous request in flight.
           We don't want to start cleaning up data
           structures that are still being used. If
           qat_pause_job fails we will just yield and
           loop around and try again until the request
           completes and we can continue. */
        if ((job_ret = qat_pause_job(job, ASYNC_STATUS_OK)) == 0)
            pthread_yield();
    } while (QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DEBUG("Finished: %p status = %d\n", rsa_pub_req, sts);

    if (sts > 0) {
        return rsa_len;
    } else {
        WARN("Failure in Public Encrypt\n");
        QATerr(QAT_F_MULTIBUFF_RSA_PUB_ENC, ERR_R_INTERNAL_ERROR);
        OPENSSL_cleanse(to, rsa_len);
        return sts;
    }

use_sw_method:
    sts = RSA_meth_get_pub_enc(RSA_PKCS1_OpenSSL())(flen, from, to, rsa, padding);
    DEBUG("SW Finished\n");
    return sts;
}

int multibuff_rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to,
                          RSA *rsa, int padding)
{
    int sts = -1;
    ASYNC_JOB *job;
    int rsa_len = 0, rsa_bits = 0;
    rsa_pub_op_data *rsa_pub_req = NULL;
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;
    int job_ret = 0;
    mb_thread_data *tlv = NULL;
    static __thread int req_num = 0;

    /* Check Parameters */
    if (rsa == NULL || from == NULL || to == NULL ||
        (flen != (rsa_len = RSA_size(rsa)))) {
        WARN("RSA key %p, input %p or output %p are NULL or invalid length, \
              flen = %d, rsa_len = %d\n", rsa, from, to, flen, rsa_len);
        QATerr(QAT_F_MULTIBUFF_RSA_PUB_DEC, QAT_R_RSA_FROM_TO_NULL);
        if (to != NULL && rsa != NULL) {
            rsa_len = RSA_size(rsa);
            OPENSSL_cleanse(to, rsa_len);
        }
        return sts;
    }

    /* Check if we are running asynchronously. If not use the SW method */
    if ((job = ASYNC_get_current_job()) == NULL) {
        DEBUG("Running synchronously using sw method\n");
        goto use_sw_method;
    }

    /* Setup asynchronous notifications */
    if (!qat_setup_async_event_notification(0)) {
        DEBUG("Failed to setup async notifications, using sw method\n");
        goto use_sw_method;
    }

    rsa_bits = RSA_bits((const RSA*)rsa);

    /* Check if the request key size is supported */
    if (!multibuff_rsa_range_check(rsa_bits)) {
        DEBUG("Requested key size not supported, use sw method %d\n", rsa_bits);
        goto use_sw_method;
    }

    tlv = mb_check_thread_local();
    if (NULL == tlv) {
        WARN("Could not create thread local variables\n");
        goto use_sw_method;
    }

    while ((rsa_pub_req = mb_flist_rsa_pub_pop(tlv->rsa_pub_freelist)) == NULL) {
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
    }

    DEBUG("QAT SW RSA Started %p\n", rsa_pub_req);
    START_RDTSC(&rsa_cycles_pub_dec_setup);

    /* Buffer up the requests and call the new functions when we have enough
       requests buffered up */

    RSA_get0_key((const RSA*)rsa, &n, &e, &d);

    if (e == NULL ||
        e_check == NULL ||
        BN_ucmp(e, e_check) != 0) {
        mb_flist_rsa_pub_push(tlv->rsa_pub_freelist, rsa_pub_req);
        STOP_RDTSC(&rsa_cycles_pub_dec_setup, 1, "[RSA:pub_dec_setup]");
        DEBUG("Request is using a public exp not equal to 65537\n");
        goto use_sw_method;
    }

    rsa_pub_req->type = RSA_MULTIBUFF_PUB_DEC;
    rsa_pub_req->flen = flen;
    rsa_pub_req->from = from;
    rsa_pub_req->to = to;
    rsa_pub_req->rsa = rsa;
    rsa_pub_req->padding = padding;
    rsa_pub_req->job = job;
    rsa_pub_req->e = e;
    rsa_pub_req->n = n;
    rsa_pub_req->sts = &sts;

    switch(rsa_bits) {
    case RSA_2K_LENGTH:
        mb_queue_rsa2k_pub_enqueue(tlv->rsa2k_pub_queue, rsa_pub_req);
        break;
    case RSA_3K_LENGTH:
        mb_queue_rsa3k_pub_enqueue(tlv->rsa3k_pub_queue, rsa_pub_req);
        break;
    case RSA_4K_LENGTH:
        mb_queue_rsa4k_pub_enqueue(tlv->rsa4k_pub_queue, rsa_pub_req);
        break;
    }
    STOP_RDTSC(&rsa_cycles_pub_dec_setup, 1, "[RSA:pub_dec_setup]");

    if (!enable_external_polling && (++req_num % MULTIBUFF_MAX_BATCH) == 0) {
        DEBUG("Signal Polling thread, req_num %d\n", req_num);
        if (qat_kill_thread(tlv->polling_thread, SIGUSR1) != 0) {
            WARN("qat_kill_thread error\n");
            /* If we fail the pthread_kill carry on as the timeout
               will catch processing the request in the polling thread */
        }
    }

    DEBUG("Pausing: %p status = %d\n", rsa_pub_req, sts);
    do {
        /* If we get a failure on qat_pause_job then we will
           not flag an error here and quit because we have
           an asynchronous request in flight.
           We don't want to start cleaning up data
           structures that are still being used. If
           qat_pause_job fails we will just yield and
           loop around and try again until the request
           completes and we can continue. */
        if ((job_ret = qat_pause_job(job, ASYNC_STATUS_OK)) == 0)
            pthread_yield();
    } while (QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DEBUG("Finished: %p status = %d\n", rsa_pub_req, sts);

    if (sts < 1) {
        WARN("Failure in Public Decrypt\n");
        QATerr(QAT_F_MULTIBUFF_RSA_PUB_DEC, ERR_R_INTERNAL_ERROR);
        OPENSSL_cleanse(to, rsa_len);
    }
    return sts;

use_sw_method:
    sts = RSA_meth_get_pub_dec(RSA_PKCS1_OpenSSL())(flen, from, to, rsa, padding);
    DEBUG("SW Finished\n");
    return sts;
}
