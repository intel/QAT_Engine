#include<openssl/rsa.h>
#include<openssl/bn.h>
#include "qat_utils.h"
#include "qat_prov_rsa.h"

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

static __inline__ int CRYPTO_UP_REF(int *val, int *ret, ossl_unused void *lock)
{
    *ret = __atomic_fetch_add(val, 1, __ATOMIC_RELAXED) + 1;
    return 1;
}

static __inline__ int CRYPTO_DOWN_REF(int *val, int *ret, ossl_unused void *lock)
{
    *ret = __atomic_fetch_sub(val, 1, __ATOMIC_RELAXED) - 1;
    if (*ret == 0)
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
    return 1;
}

static int qat_rsa_finish(RSA *rsa)
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
        qat_rsa_finish(r);

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