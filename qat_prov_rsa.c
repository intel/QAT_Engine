/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022-2023 Intel Corporation.
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

void qat_rsa_multip_info_free_ex(RSA_PRIME_INFO *pinfo)
{
    /* free pp and pinfo only */
    BN_clear_free(pinfo->pp);
    OPENSSL_free(pinfo);
}

void qat_rsa_multip_info_free(RSA_PRIME_INFO *pinfo)
{
    /* free a RSA_PRIME_INFO structure */
    BN_clear_free(pinfo->r);
    BN_clear_free(pinfo->d);
    BN_clear_free(pinfo->t);
    qat_rsa_multip_info_free_ex(pinfo);
}

static int qat_prov_rsa_finish(RSA *rsa)
{
    int i;
    RSA_PRIME_INFO *pinfo;

    for (i = 0; i < sk_RSA_PRIME_INFO_num(rsa->prime_infos); i++) {
        pinfo = sk_RSA_PRIME_INFO_value(rsa->prime_infos, i);
        BN_MONT_CTX_free(pinfo->m);
    }

    BN_MONT_CTX_free(rsa->_method_mod_n);
    BN_MONT_CTX_free(rsa->_method_mod_p);
    BN_MONT_CTX_free(rsa->_method_mod_q);
    return 1;
}

int QAT_RSA_bits(const RSA *r)
{
    return BN_num_bits(r->n);
}

int QAT_RSA_size(const RSA *r)
{
    return BN_num_bytes(r->n);
}

int QAT_RSA_up_ref(RSA *r)
{
    int i;

    if (CRYPTO_UP_REF(&r->references, &i, r->lock) <= 0)
        return 0;

    // REF_PRINT_COUNT("RSA", r);
    if(i < 2)
    {
        WARN("refcount error");
        return 0;
    }
    return i > 1 ? 1 : 0;
}

void QAT_RSA_free(RSA *r)
{
#ifdef ENABLE_QAT_FIPS
    qat_fips_key_zeroize = 0;
#endif
    int i;

    if (r == NULL)
        return;

    CRYPTO_DOWN_REF(&r->references, &i, r->lock);
    // REF_PRINT_COUNT("RSA", r);
    if (i > 0)
        return;
    if(i < 0)
    {
        WARN("refcount error");
        return;
    }

    if (r->meth != NULL)
        qat_prov_rsa_finish(r);

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_RSA, r, &r->ex_data);

    CRYPTO_THREAD_lock_free(r->lock);

    BN_free(r->n);
    BN_free(r->e);
    BN_clear_free(r->d);
    BN_clear_free(r->p);
    BN_clear_free(r->q);
    BN_clear_free(r->dmp1);
    BN_clear_free(r->dmq1);
    BN_clear_free(r->iqmp);

    RSA_PSS_PARAMS_free(r->pss);
    sk_RSA_PRIME_INFO_pop_free(r->prime_infos, qat_rsa_multip_info_free);

    BN_BLINDING_free(r->blinding);
    BN_BLINDING_free(r->mt_blinding);
    OPENSSL_free(r);

#ifdef ENABLE_QAT_FIPS
    qat_fips_key_zeroize = 1;
	qat_fips_get_key_zeroize_status();
#endif
}

int QAT_RSA_test_flags(const RSA *r, int flags)
{
    return r->flags & flags;
}

void QAT_RSA_clear_flags(RSA *r, int flags)
{
    r->flags &= ~flags;
}

void QAT_RSA_set_flags(RSA *r, int flags)
{
    r->flags |= flags;
}

const BIGNUM *QAT_RSA_get0_n(const RSA *r)
{
    return r->n;
}

const BIGNUM *QAT_RSA_get0_e(const RSA *r)
{
    return r->e;
}

const BIGNUM *QAT_RSA_get0_d(const RSA *r)
{
    return r->d;
}

int QAT_RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q)
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

int QAT_RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
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

int QAT_RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
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
