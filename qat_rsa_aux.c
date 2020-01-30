/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2020 Intel Corporation.
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
 * @file qat_rsa_aux.c
 *
 * In order to use with OpenSSL 1.0.2, some helper functions for RSA
 * not provided by OpenSSL 1.0.2 are excerpted from OpenSSL 1.1.0.
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#define __USE_GNU

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#include <string.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include "e_qat.h"
#include "qat_rsa_aux.h"

int RSA_bits(const RSA *r)
{
    return (BN_num_bits(r->n));
}

int RSA_size(const RSA *r)
{
    return (BN_num_bytes(r->n));
}

void RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n != NULL)
        *n = r->n;
    if (e != NULL)
        *e = r->e;
    if (d != NULL)
        *d = r->d;
}

void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q)
{
    if (p != NULL)
        *p = r->p;
    if (q != NULL)
        *q = r->q;
}

void RSA_get0_crt_params(const RSA *r,
                         const BIGNUM **dmp1, const BIGNUM **dmq1, const BIGNUM **iqmp)
{
    if (dmp1 != NULL)
        *dmp1 = r->dmp1;
    if (dmq1 != NULL)
        *dmq1 = r->dmq1;
    if (iqmp != NULL)
        *iqmp = r->iqmp;
}

const RSA_METHOD *RSA_PKCS1_OpenSSL(void)
{
    return RSA_PKCS1_SSLeay();
}

RSA_METHOD *RSA_meth_new(const char *name, int flags)
{
    RSA_METHOD *meth = OPENSSL_zalloc(sizeof(RSA_METHOD));

    if (meth != NULL) {
        meth->name = OPENSSL_strdup(name);
        if (meth->name == NULL) {
            OPENSSL_free(meth);
            return NULL;
        }
        meth->flags = flags;
    }

    return meth;
}

void RSA_meth_free(RSA_METHOD *meth)
{
    if (meth != NULL) {
        if (meth->name != NULL)
            OPENSSL_free((void *)meth->name);
        OPENSSL_free(meth);
    }
}

int (*RSA_meth_get_pub_enc(const RSA_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, RSA *rsa, int padding)
{
    return meth->rsa_pub_enc;
}

int RSA_meth_set_pub_enc(RSA_METHOD *meth,
                         int (*pub_enc) (int flen, const unsigned char *from,
                                         unsigned char *to, RSA *rsa,
                                         int padding))
{
    meth->rsa_pub_enc = pub_enc;
    return 1;
}

int (*RSA_meth_get_pub_dec(const RSA_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, RSA *rsa, int padding)
{
    return meth->rsa_pub_dec;
}

int RSA_meth_set_pub_dec(RSA_METHOD *meth,
                         int (*pub_dec) (int flen, const unsigned char *from,
                                         unsigned char *to, RSA *rsa,
                                         int padding))
{
    meth->rsa_pub_dec = pub_dec;
    return 1;
}

int (*RSA_meth_get_priv_enc(const RSA_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, RSA *rsa, int padding)
{
    return meth->rsa_priv_enc;
}

int RSA_meth_set_priv_enc(RSA_METHOD *meth,
                          int (*priv_enc) (int flen, const unsigned char *from,
                                           unsigned char *to, RSA *rsa,
                                           int padding))
{
    meth->rsa_priv_enc = priv_enc;
    return 1;
}

int (*RSA_meth_get_priv_dec(const RSA_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, RSA *rsa, int padding)
{
    return meth->rsa_priv_dec;
}

int RSA_meth_set_priv_dec(RSA_METHOD *meth,
                          int (*priv_dec) (int flen, const unsigned char *from,
                                           unsigned char *to, RSA *rsa,
                                           int padding))
{
    meth->rsa_priv_dec = priv_dec;
    return 1;
}

    /* Can be null */
int (*RSA_meth_get_mod_exp(const RSA_METHOD *meth))
    (BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
    return meth->rsa_mod_exp;
}

int RSA_meth_set_mod_exp(RSA_METHOD *meth,
                         int (*mod_exp) (BIGNUM *r0, const BIGNUM *I, RSA *rsa,
                                         BN_CTX *ctx))
{
    meth->rsa_mod_exp = mod_exp;
    return 1;
}

    /* Can be null */
int (*RSA_meth_get_bn_mod_exp(const RSA_METHOD *meth))
    (BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
     const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    return meth->bn_mod_exp;
}

int RSA_meth_set_bn_mod_exp(RSA_METHOD *meth,
                            int (*bn_mod_exp) (BIGNUM *r,
                                               const BIGNUM *a,
                                               const BIGNUM *p,
                                               const BIGNUM *m,
                                               BN_CTX *ctx,
                                               BN_MONT_CTX *m_ctx))
{
    meth->bn_mod_exp = bn_mod_exp;
    return 1;
}

int RSA_meth_set_init(RSA_METHOD *meth, int (*init) (RSA *rsa))
{
    meth->init = init;
    return 1;
}

int (*RSA_meth_get_init(const RSA_METHOD *meth)) (RSA *rsa)
{
    return meth->init;
}

int RSA_meth_set_finish(RSA_METHOD *meth, int (*finish) (RSA *rsa))
{
    meth->finish = finish;
    return 1;
}

int (*RSA_meth_get_finish(const RSA_METHOD *meth)) (RSA *rsa)
{
    return meth->finish;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
