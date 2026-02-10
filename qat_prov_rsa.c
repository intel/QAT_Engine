/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022-2026 Intel Corporation.
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
 * @file qat_prov_rsa.c
 *
 * This file provides an implementation to qatprovider RSA operations
 *
 *****************************************************************************/
#include<openssl/rsa.h>
#include<openssl/bn.h>
#include "qat_utils.h"
#include "qat_prov_rsa.h"
#include "e_qat.h"

#if defined(ENABLE_QAT_HW_RSA) || defined(ENABLE_QAT_SW_RSA)
#ifdef ENABLE_QAT_FIPS
# include "qat_prov_cmvp.h"
extern int qat_fips_key_zeroize;
#endif

int QAT_RSA_bits(const QAT_RSA *r)
{
    return BN_num_bits(r->n);
}

int QAT_RSA_size(const QAT_RSA *r)
{
    return BN_num_bytes(r->n);
}

int QAT_RSA_up_ref(QAT_RSA *r)
{
    int i = 0;

    /* A refcount less than 2 indicates an unexpected state where the object
     * may not have been properly initialized or referenced. This check
     * ensures that the object is in a valid state before proceeding. */
    if (QAT_CRYPTO_UP_REF(&r->references, &i) <= 0)
        return 0;

    if(i < 2)
    {
        WARN("refcount error");
        return 0;
    }
    return i > 1 ? 1 : 0;
}

void QAT_RSA_free(QAT_RSA *r)
{
#ifdef ENABLE_QAT_FIPS
    qat_fips_key_zeroize = 0;
#endif
    int i;

    if (r == NULL)
        return;
    QAT_CRYPTO_DOWN_REF(&r->references, &i);

    if (i > 0)
        return;
    if(i < 0)
    {
        WARN("refcount error");
        return;
    }

    if (r->meth != NULL && r->meth->finish != NULL)
	r->meth->finish(r);

    CRYPTO_THREAD_lock_free(r->lock);

    BN_clear_free(r->n);
    BN_clear_free(r->e);
    BN_clear_free(r->d);
    BN_clear_free(r->p);
    BN_clear_free(r->q);
    BN_clear_free(r->dmp1);
    BN_clear_free(r->dmq1);
    BN_clear_free(r->iqmp);

    RSA_PSS_PARAMS_free(r->pss);

    BN_BLINDING_free(r->blinding);
    BN_BLINDING_free(r->mt_blinding);
    OPENSSL_free(r);

#ifdef ENABLE_QAT_FIPS
    qat_fips_key_zeroize = 1;
    qat_fips_get_key_zeroize_status();
#endif
}

int QAT_RSA_test_flags(const QAT_RSA *r, int flags)
{
    return r->flags & flags;
}

void QAT_RSA_clear_flags(QAT_RSA *r, int flags)
{
    r->flags &= ~flags;
}

void QAT_RSA_set_flags(QAT_RSA *r, int flags)
{
    r->flags |= flags;
}

const BIGNUM *QAT_RSA_get0_n(const QAT_RSA *r)
{
    return r->n;
}

const BIGNUM *QAT_RSA_get0_e(const QAT_RSA *r)
{
    return r->e;
}

const BIGNUM *QAT_RSA_get0_d(const QAT_RSA *r)
{
    return r->d;
}

int QAT_RSA_set0_factors(QAT_RSA *r, BIGNUM *p, BIGNUM *q)
{
    /* If the fields p and q in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((r->p == NULL && p == NULL)
        || (r->q == NULL && q == NULL))
        return 0;

    if (p != NULL) {
        BN_clear_free(r->p);
        r->p = p;
        BN_set_flags(r->p, BN_FLG_CONSTTIME);
    }
    if (q != NULL) {
        BN_clear_free(r->q);
        r->q = q;
        BN_set_flags(r->q, BN_FLG_CONSTTIME);
    }
    r->dirty_cnt++;

    return 1;
}

int QAT_RSA_set0_crt_params(QAT_RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
    /* If the fields dmp1, dmq1 and iqmp in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((r->dmp1 == NULL && dmp1 == NULL)
        || (r->dmq1 == NULL && dmq1 == NULL)
        || (r->iqmp == NULL && iqmp == NULL))
        return 0;

    if (dmp1 != NULL) {
        BN_clear_free(r->dmp1);
        r->dmp1 = dmp1;
        BN_set_flags(r->dmp1, BN_FLG_CONSTTIME);
    }
    if (dmq1 != NULL) {
        BN_clear_free(r->dmq1);
        r->dmq1 = dmq1;
        BN_set_flags(r->dmq1, BN_FLG_CONSTTIME);
    }
    if (iqmp != NULL) {
        BN_clear_free(r->iqmp);
        r->iqmp = iqmp;
        BN_set_flags(r->iqmp, BN_FLG_CONSTTIME);
    }
    r->dirty_cnt++;

    return 1;
}

int QAT_RSA_set0_key(QAT_RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    /* If the fields n and e in r are NULL, the corresponding input
     * parameters MUST be non-NULL for n and e.  d may be
     * left NULL (in case only the public key is used).
     */
    if ((r->n == NULL && n == NULL)
        || (r->e == NULL && e == NULL))
        return 0;

    if (n != NULL) {
        BN_free(r->n);
        r->n = n;
    }
    if (e != NULL) {
        BN_free(r->e);
        r->e = e;
    }
    if (d != NULL) {
        BN_clear_free(r->d);
        r->d = d;
        BN_set_flags(r->d, BN_FLG_CONSTTIME);
    }
    r->dirty_cnt++;

    return 1;
}
#endif
