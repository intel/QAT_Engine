/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2023 Intel Corporation.
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
 * @file qat_hw_sm2.c
 *
 * This file provides SM2 implementaion for QAT_HW
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#define __USE_GNU
#include "qat_hw_sm2.h"

#ifdef ENABLE_QAT_HW_SM2
typedef struct {
    /* Key and paramgen group */
    EC_GROUP *gen_group;
    /* message digest */
    const EVP_MD *md;
    /* Distinguishing Identifier, ISO/IEC 15946-3 */
    uint8_t *id;
    size_t id_len;
    /* id_set indicates if the 'id' field is set (1) or not (0) */
    int id_set;
} QAT_SM2_PKEY_CTX;

# ifdef QAT_OPENSSL_3
typedef struct evp_signature_st {
    int name_id;
    char *type_name;
    const char *description;
    OSSL_PROVIDER *prov;
    int refcnt;
    void *lock;

    OSSL_FUNC_signature_newctx_fn *newctx;
    OSSL_FUNC_signature_sign_init_fn *sign_init;
    OSSL_FUNC_signature_sign_fn *sign;
    OSSL_FUNC_signature_verify_init_fn *verify_init;
    OSSL_FUNC_signature_verify_fn *verify;
    OSSL_FUNC_signature_verify_recover_init_fn *verify_recover_init;
    OSSL_FUNC_signature_verify_recover_fn *verify_recover;
    OSSL_FUNC_signature_digest_sign_init_fn *digest_sign_init;
    OSSL_FUNC_signature_digest_sign_update_fn *digest_sign_update;
    OSSL_FUNC_signature_digest_sign_final_fn *digest_sign_final;
    OSSL_FUNC_signature_digest_sign_fn *digest_sign;
    OSSL_FUNC_signature_digest_verify_init_fn *digest_verify_init;
    OSSL_FUNC_signature_digest_verify_update_fn *digest_verify_update;
    OSSL_FUNC_signature_digest_verify_final_fn *digest_verify_final;
    OSSL_FUNC_signature_digest_verify_fn *digest_verify;
    OSSL_FUNC_signature_freectx_fn *freectx;
    OSSL_FUNC_signature_dupctx_fn *dupctx;
    OSSL_FUNC_signature_get_ctx_params_fn *get_ctx_params;
    OSSL_FUNC_signature_gettable_ctx_params_fn *gettable_ctx_params;
    OSSL_FUNC_signature_set_ctx_params_fn *set_ctx_params;
    OSSL_FUNC_signature_settable_ctx_params_fn *settable_ctx_params;
    OSSL_FUNC_signature_get_ctx_md_params_fn *get_ctx_md_params;
    OSSL_FUNC_signature_gettable_ctx_md_params_fn *gettable_ctx_md_params;
    OSSL_FUNC_signature_set_ctx_md_params_fn *set_ctx_md_params;
    OSSL_FUNC_signature_settable_ctx_md_params_fn *settable_ctx_md_params;
} QAT_EVP_SIGNATURE /* EVP_SIGNATURE for QAT Provider sm2 */ ;

struct bignum_st {
    BN_ULONG *d;                /* Pointer to an array of 'BN_BITS2' bit
                                 * chunks. */
    int top;                    /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int dmax;                   /* Size of the d array. */
    int neg;                    /* one if the number is negative */
    int flags;
};

static QAT_EVP_SIGNATURE get_def_signature_sm2()
{
    static QAT_EVP_SIGNATURE s_signature;
    static int initilazed = 0;
    if (!initilazed) {
        QAT_EVP_SIGNATURE *signature =
            (QAT_EVP_SIGNATURE *) EVP_SIGNATURE_fetch(NULL, "SM2",
                                                      "provider=default");
        if (signature) {
            s_signature = *signature;
            EVP_SIGNATURE_free((QAT_EVP_SIGNATURE *) signature);
            initilazed = 1;
        } else {
            WARN("EVP_SIGNATURE_fetch from default provider failed");
        }
    }
    return s_signature;
}
# endif

/* Callback to indicate QAT completion of SM2 Sign */
static void qat_sm2SignCallbackFn(void *pCallbackTag, CpaStatus status,
                                  void *pOpData, CpaBoolean signStatus,
                                  CpaFlatBuffer *pR, CpaFlatBuffer *pS)
{
    if (enable_heuristic_polling) {
        QAT_ATOMIC_DEC(num_asym_requests_in_flight);
    }
    qat_crypto_callbackFn(pCallbackTag, status, 0, pOpData, NULL, signStatus);
}

/* Callback to indicate QAT completion of SM2 Verify */
static void qat_sm2VerifyCallbackFn(void *pCallbackTag, CpaStatus status,
                                    void *pOpData, CpaBoolean verifyStatus)
{
    if (enable_heuristic_polling) {
        QAT_ATOMIC_DEC(num_asym_requests_in_flight);
    }
    qat_crypto_callbackFn(pCallbackTag, status, 0, pOpData, NULL, verifyStatus);
}

# ifndef QAT_OPENSSL_PROVIDER
int qat_sm2_init(EVP_PKEY_CTX *ctx)
{
    QAT_SM2_PKEY_CTX *smctx = NULL;

    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_PKEY_CTX) is NULL \n");
        return 0;
    }

    if ((smctx = OPENSSL_zalloc(sizeof(*smctx))) == NULL) {
        WARN("smctx alloc Failure\n");
        QATerr(QAT_F_QAT_SM2_INIT, QAT_R_MALLOC_FAILURE);
        return 0;
    }

    EVP_PKEY_CTX_set_data(ctx, smctx);
    return 1;
}

void qat_sm2_cleanup(EVP_PKEY_CTX *ctx)
{
    QAT_SM2_PKEY_CTX *smctx = NULL;

    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_PKEY_CTX) is NULL \n");
        return;
    }

    smctx = (QAT_SM2_PKEY_CTX *) EVP_PKEY_CTX_get_data(ctx);
    if (smctx == NULL) {
        WARN("smctx is NULL\n");
        return;
    }

    EC_GROUP_free(smctx->gen_group);
    OPENSSL_free(smctx->id);
    OPENSSL_free(smctx);
}

#  ifdef QAT_OPENSSL_3
int qat_sm2_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src)
#  else
int qat_sm2_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
#  endif
{
    QAT_SM2_PKEY_CTX *smdctx, *smsctx;
    if (unlikely(src == NULL)) {
        WARN("src (type EVP_PKEY_CTX) is NULL \n");
        return 0;
    }

    if (unlikely(dst == NULL)) {
        WARN("dst (type EVP_PKEY_CTX) is NULL \n");
        return 0;
    }

    if (!qat_sm2_init(dst))
        return 0;

    if ((smsctx = OPENSSL_zalloc(sizeof(*smsctx))) == NULL) {
        WARN("smsctx alloc Failure\n");
        QATerr(QAT_F_QAT_SM2_COPY, QAT_R_MALLOC_FAILURE);
        return 0;
    }

    if ((smdctx = OPENSSL_zalloc(sizeof(*smdctx))) == NULL) {
        WARN("smdctx alloc Failure\n");
        QATerr(QAT_F_QAT_SM2_COPY, QAT_R_MALLOC_FAILURE);
        return 0;
    }

    smsctx = EVP_PKEY_CTX_get_data(src);
    smdctx = EVP_PKEY_CTX_get_data(dst);

    if (smsctx->gen_group != NULL) {
        smdctx->gen_group = EC_GROUP_dup(smsctx->gen_group);
        if (smdctx->gen_group == NULL) {
            qat_sm2_cleanup(dst);
            return 0;
        }
    }
    if (smsctx->id != NULL) {
        smdctx->id = OPENSSL_malloc(smsctx->id_len);
        if (smdctx->id == NULL) {
            QATerr(QAT_F_QAT_SM2_COPY, QAT_R_MALLOC_FAILURE);
            qat_sm2_cleanup(dst);
            return 0;
        }
        memcpy(smdctx->id, smsctx->id, smsctx->id_len);
    }
    smdctx->id_len = smsctx->id_len;
    smdctx->id_set = smsctx->id_set;
    smdctx->md = smsctx->md;
    return 1;
}

int qat_sm2_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    QAT_SM2_PKEY_CTX *smctx = (QAT_SM2_PKEY_CTX *) EVP_PKEY_CTX_get_data(ctx);
    EC_GROUP *group;
    uint8_t *tmp_id;

    if (unlikely(smctx == NULL)) {
        WARN("smctx cannot be NULL\n");
        QATerr(QAT_F_QAT_SM2_CTRL, QAT_R_CTX_NULL);
        return 0;
    }

    switch (type) {
    case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
        group = EC_GROUP_new_by_curve_name(p1);
        if (group == NULL) {
            WARN("Invalid curve\n");
            QATerr(QAT_F_QAT_SM2_CTRL, QAT_R_INVALID_CURVE);
            return 0;
        }
        EC_GROUP_free(smctx->gen_group);
        smctx->gen_group = group;
        return 1;

    case EVP_PKEY_CTRL_EC_PARAM_ENC:
        if (smctx->gen_group == NULL) {
            WARN("gen group NULL\n");
            QATerr(QAT_F_QAT_SM2_CTRL, QAT_R_NO_PARAMETERS_SET);
            return 0;
        }
        EC_GROUP_set_asn1_flag(smctx->gen_group, p1);
        return 1;

    case EVP_PKEY_CTRL_MD:
        smctx->md = p2;
        return 1;

    case EVP_PKEY_CTRL_GET_MD:
        *(const EVP_MD **)p2 = smctx->md;
        return 1;

    case EVP_PKEY_CTRL_SET1_ID:
        if (p1 > 0) {
            tmp_id = OPENSSL_malloc(p1);
            if (tmp_id == NULL) {
                WARN("Malloc Failure\n");
                QATerr(QAT_F_QAT_SM2_CTRL, QAT_R_MALLOC_FAILURE);
                return 0;
            }
            memcpy(tmp_id, p2, p1);
            OPENSSL_free(smctx->id);
            smctx->id = tmp_id;
        } else {
            /* set null-ID */
            OPENSSL_free(smctx->id);
            smctx->id = NULL;
        }
        smctx->id_len = (size_t)p1;
        smctx->id_set = 1;
        return 1;

    case EVP_PKEY_CTRL_GET1_ID:
        memcpy(p2, smctx->id, smctx->id_len);
        return 1;

    case EVP_PKEY_CTRL_GET1_ID_LEN:
        *(size_t *)p2 = smctx->id_len;
        return 1;
        /* Default behaviour is OK */
    case EVP_PKEY_CTRL_PEER_KEY:
    case EVP_PKEY_CTRL_PKCS7_SIGN:
    case EVP_PKEY_CTRL_CMS_SIGN:
    case EVP_PKEY_CTRL_DIGESTINIT:
        /* nothing to be inited, this is to suppress the error... */
        return 1;

    default:
        return -2;
    }
}

int qat_sm2_compute_z_digest(uint8_t *out,
                             const EVP_MD *digest,
                             const uint8_t *id,
                             const size_t id_len, const EC_KEY *key)
{
    int rc = 0;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    BN_CTX *ctx = NULL;
    EVP_MD_CTX *hash = NULL;
    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *xG = NULL;
    BIGNUM *yG = NULL;
    BIGNUM *xA = NULL;
    BIGNUM *yA = NULL;
    int p_bytes = 0;
    uint8_t *buf = NULL;
    uint16_t entl = 0;
    uint8_t e_byte = 0;

    hash = EVP_MD_CTX_new();
    ctx = BN_CTX_new();
    if (hash == NULL || ctx == NULL) {
        QATerr(QAT_F_QAT_SM2_COMPUTE_Z_DIGEST, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    xG = BN_CTX_get(ctx);
    yG = BN_CTX_get(ctx);
    xA = BN_CTX_get(ctx);
    yA = BN_CTX_get(ctx);

    if (yA == NULL) {
        QATerr(QAT_F_QAT_SM2_COMPUTE_Z_DIGEST, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!EVP_DigestInit(hash, digest)) {
        QATerr(QAT_F_QAT_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }

    /* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */

    if (id_len >= (UINT16_MAX / 8)) {
        /* too large */
        QATerr(QAT_F_QAT_SM2_COMPUTE_Z_DIGEST, QAT_R_SM2_ID_TOO_LARGE);
        goto done;
    }

    entl = (uint16_t)(8 * id_len);

    e_byte = entl >> 8;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        QATerr(QAT_F_QAT_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }
    e_byte = entl & 0xFF;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        QATerr(QAT_F_QAT_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }

    if (id_len > 0 && !EVP_DigestUpdate(hash, id, id_len)) {
        QATerr(QAT_F_QAT_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }

    if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {
        QATerr(QAT_F_QAT_SM2_COMPUTE_Z_DIGEST, ERR_R_EC_LIB);
        goto done;
    }

    p_bytes = BN_num_bytes(p);
    buf = OPENSSL_zalloc(p_bytes);
    if (buf == NULL) {
        QATerr(QAT_F_QAT_SM2_COMPUTE_Z_DIGEST, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (BN_bn2binpad(a, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || BN_bn2binpad(b, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || !EC_POINT_get_affine_coordinates(group,
                                            EC_GROUP_get0_generator(group),
                                            xG, yG, ctx)
        || BN_bn2binpad(xG, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || BN_bn2binpad(yG, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || !EC_POINT_get_affine_coordinates(group,
                                            EC_KEY_get0_public_key(key),
                                            xA, yA, ctx)
        || BN_bn2binpad(xA, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || BN_bn2binpad(yA, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || !EVP_DigestFinal(hash, out, NULL)) {
        QATerr(QAT_F_QAT_SM2_COMPUTE_Z_DIGEST, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    rc = 1;

 done:
    OPENSSL_free(buf);
    BN_CTX_free(ctx);
    EVP_MD_CTX_free(hash);
    return rc;
}

#  ifdef QAT_OPENSSL_3
static BIGNUM *sm2_compute_msg_hash(const EVP_MD *digest,
                                    const EC_KEY *key,
                                    const uint8_t *id,
                                    const size_t id_len,
                                    const uint8_t *msg, size_t msg_len)
{
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    const int md_size = EVP_MD_size(digest);
    uint8_t *z = NULL;
    BIGNUM *e = NULL;

    if (md_size < 0) {
        QATerr(QAT_F_SM2_COMPUTE_MSG_HASH, QAT_R_SM2_INVALID_DIGEST);
        goto done;
    }

    z = OPENSSL_zalloc(md_size);
    if (hash == NULL || z == NULL) {
        QATerr(QAT_F_SM2_COMPUTE_MSG_HASH, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!qat_sm2_compute_z_digest(z, digest, id, id_len, key)) {
        /* SM2err already called */
        goto done;
    }

    if (!EVP_DigestInit(hash, digest)
        || !EVP_DigestUpdate(hash, z, md_size)
        || !EVP_DigestUpdate(hash, msg, msg_len)
        /* reuse z buffer to hold H(Z || M) */
        || !EVP_DigestFinal(hash, z, NULL)) {
        QATerr(QAT_F_SM2_COMPUTE_MSG_HASH, ERR_R_EVP_LIB);
        goto done;
    }

    e = BN_bin2bn(z, md_size, NULL);
    if (e == NULL)
        QATerr(QAT_F_SM2_COMPUTE_MSG_HASH, ERR_R_INTERNAL_ERROR);

 done:
    OPENSSL_free(z);
    EVP_MD_CTX_free(hash);
    return e;
}
#  endif

int qat_sm2_digest_custom(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    uint8_t z[EVP_MAX_MD_SIZE];
    QAT_SM2_PKEY_CTX *smctx = (QAT_SM2_PKEY_CTX *) EVP_PKEY_CTX_get_data(ctx);
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    const EC_KEY *eckey = EVP_PKEY_get0_EC_KEY(pkey);

    const EVP_MD *md = EVP_MD_CTX_md(mctx);
    int mdlen = EVP_MD_size(md);

    if (!smctx->id_set) {
        /*
         * Actually, there is no standard doc which illustrate how to set sm2-id
         * correctly, only GM/T 0009-2012 gives a fuzzy definition that sm2-id
         * would be "1234567812345678", and there is no way to get sm2-id from
         * certificate. In tls handshake, client/server would get a long
         * certificate chain from peer, we can't find any effective way to
         * recognize or set sm2-id for each cert, so we choose to set a default
         * sm2 id for each sm2 sign process.
         */
        smctx->id_set = 1;
        smctx->id =
            (uint8_t *)OPENSSL_memdup(SM2_DEFAULT_USERID,
                                      SM2_DEFAULT_USERID_LEN);
        smctx->id_len = SM2_DEFAULT_USERID_LEN;
    }

    if (mdlen < 0) {
        QATerr(QAT_F_QAT_SM2_DIGEST_CUSTOM, QAT_R_SM2_INVALID_DIGEST);
        return 0;
    }

    /* get hashed prefix 'z' of tbs message */
    if (!qat_sm2_compute_z_digest(z, md, smctx->id, smctx->id_len, eckey))
        return 0;

    return EVP_DigestUpdate(mctx, z, (size_t)mdlen);
}
# endif

# ifdef QAT_OPENSSL_PROVIDER
int qat_sm2_sign(QAT_PROV_SM2_CTX *smctx,
                 unsigned char *sig, size_t *siglen,
                 size_t sigsize, const unsigned char *tbs, size_t tbslen)
# else
int qat_sm2_sign(EVP_PKEY_CTX *ctx,
                 unsigned char *sig, size_t *siglen,
                 const unsigned char *tbs, size_t tbslen)
# endif
{
    int ret = 0, i, sigleni, job_ret = 0, fallback = 0;
    ECDSA_SIG *s = NULL;
    size_t buflen = 0;
    const EC_GROUP *group;
    const BIGNUM *priv_key, *order;
    const EC_POINT *pub_key = NULL;
    BIGNUM *sig_r = NULL, *sig_s = NULL;
    CpaFlatBuffer *pResultR = NULL;
    CpaFlatBuffer *pResultS = NULL;
    int inst_num = QAT_INVALID_INSTANCE;
    BIGNUM *k = NULL, *e = NULL;
    CpaCyEcsm2SignOpData *opData = NULL;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean bSM2SignStatus = 0;
    int sig_sz;
    op_done_t op_done;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
    thread_local_variables_t *tlv = NULL;
    BN_CTX *bctx = NULL;

# if defined(QAT_OPENSSL_3) && !defined(QAT_OPENSSL_PROVIDER)
    unsigned char *dgst = NULL;
    BIGNUM *bg = NULL;
    EVP_MD *md = NULL;
    int dlen = 0;
    QAT_PROV_SM2_CTX *sw_ctx;
# endif

# if defined(QAT_OPENSSL_3) || defined(QAT_OPENSSL_PROVIDER)
    QAT_EVP_SIGNATURE sw_sm2_signature;
# else
    int (*psign)(EVP_PKEY_CTX *ctx,
                 unsigned char *sig, size_t *siglen,
                 const unsigned char *tbs, size_t tbslen) = NULL;
# endif

# ifdef QAT_OPENSSL_PROVIDER
    const EC_KEY *eckey = smctx->ec;
# else
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    const EC_KEY *eckey = EVP_PKEY_get0_EC_KEY(pkey);
# endif

    DEBUG("Entering \n");
    if (unlikely(eckey == NULL) || unlikely(siglen == NULL)) {
        WARN("Invalid Input params\n");
        QATerr(QAT_F_QAT_SM2_SIGN, QAT_R_INPUT_PARAM_INVALID);
        return ret;
    }

    sig_sz = ECDSA_size(eckey);

    if (sig_sz <= 0)
        return ret;

    /* To know how much memory is needed to store the sig */
    if (sig == NULL) {
        *siglen = (size_t)sig_sz;
        return 1;
    }

    if (*siglen < (size_t)sig_sz) {
        WARN("Invalid Input param\n");
        QATerr(QAT_F_QAT_SM2_SIGN, QAT_R_INPUT_PARAM_INVALID);
        return ret;
    }

    group = EC_KEY_get0_group(eckey);
    priv_key = EC_KEY_get0_private_key(eckey);
    pub_key = EC_KEY_get0_public_key(eckey);
    order = EC_GROUP_get0_order(group);

    if (group == NULL || priv_key == NULL || pub_key == NULL) {
        WARN("Either group, priv_key or pub_key are NULL\n");
        QATerr(QAT_F_QAT_SM2_SIGN, QAT_R_GROUP_PRIV_KEY_PUB_KEY_NULL);
        return ret;
    }
# ifndef QAT_OPENSSL_PROVIDER
    QAT_SM2_PKEY_CTX *smctx = (QAT_SM2_PKEY_CTX *) EVP_PKEY_CTX_get_data(ctx);
    if (!smctx->id_set) {
        smctx->id_set = 1;
        smctx->id =
            (uint8_t *)OPENSSL_memdup(SM2_DEFAULT_USERID,
                                      SM2_DEFAULT_USERID_LEN);
        smctx->id_len = SM2_DEFAULT_USERID_LEN;
    }
# endif

    DEBUG("QAT HW SM2 Sign Started \n");

    if ((bctx = BN_CTX_new()) == NULL) {
        WARN("Failure to allocate ctx\n");
        QATerr(QAT_F_QAT_SM2_SIGN, QAT_R_CTX_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(bctx);
    k = BN_CTX_get(bctx);
    e = BN_CTX_get(bctx);

    if (e == NULL) {
        WARN("Failure to allocate  k, e or order\n");
        QATerr(QAT_F_QAT_SM2_SIGN, QAT_R_K_E_ORDER_MALLOC_FAILURE);
        goto err;
    }

    i = BN_num_bits(order);

    /*
     * Need to truncate digest if it is too long: first truncate whole bytes.
     */
    if (8 * tbslen > i)
        tbslen = (i + 7) / 8;

    if (!BN_bin2bn(tbs, tbslen, e)) {
        WARN("Failure to convert dgst to e\n");
        QATerr(QAT_F_QAT_SM2_SIGN, ERR_R_BN_LIB);
        goto err;
    }

    /* If still too long truncate remaining bits with a shift */
    if ((8 * tbslen > i) && !BN_rshift(e, e, 8 - (i & 0x7))) {
        WARN("Failure to truncate e\n");
        QATerr(QAT_F_QAT_SM2_SIGN, ERR_R_BN_LIB);
        goto err;
    }

    do
        if (!BN_rand_range(k, order)) {
            WARN("Failure to get random number k\n");
            QATerr(QAT_F_QAT_SM2_SIGN, QAT_R_K_RAND_GENERATE_FAILURE);
            goto err;
        }
    while (BN_is_zero(k)) ;

    /* SM2 BabaSSL implementaion uses ECDSA hence following
     * the same */
    if ((s = ECDSA_SIG_new()) == NULL) {
        WARN("Failure to allocate SM2_SIG\n");
        QATerr(QAT_F_QAT_SM2_SIGN, QAT_R_SM2_SIG_MALLOC_FAILURE);
        goto err;
    }
    sig_r = BN_new();
    sig_s = BN_new();

    if (ECDSA_SIG_set0(s, sig_r, sig_s) == 0) {
        WARN("Failure to allocate r and s values to assign to the ECDSA_SIG\n");
        QATerr(QAT_F_QAT_SM2_SIGN, QAT_R_SM2_SIG_SET_R_S_FAILURE);
        goto err;
    }

    opData = (CpaCyEcsm2SignOpData *)
        OPENSSL_zalloc(sizeof(CpaCyEcsm2SignOpData));
    if (opData == NULL) {
        WARN("Failed to allocate memory for opData\n");
        QATerr(QAT_F_QAT_SM2_SIGN, QAT_R_OPDATA_MALLOC_FAILURE);
        goto err;
    }

    /*  may be made dynamic */
    buflen = QAT_GFP_SM2_SIZE_IN_BITS;

    /* Only this field type for the operation is supported */
    opData->fieldType = CPA_CY_EC_FIELD_TYPE_PRIME;

    /*
     * k - scalar multiplier (k > 0 and k < n)
     * e - digest of the message
     * d - private key (d > 0 and d < n)
     */
    if ((qat_BN_to_FB(&(opData->k), k) != 1) ||
        (qat_BN_to_FB(&(opData->e), e) != 1) ||
        (qat_BN_to_FB(&(opData->d), (BIGNUM *)priv_key) != 1)) {
        WARN("Failure to convert e, tbs and priv_key to flatbuffer\n");
        QATerr(QAT_F_QAT_SM2_SIGN, QAT_R_PRIV_KEY_K_E_D_CONVERT_TO_FB_FAILURE);
        goto err;
    }

    pResultR = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (!pResultR) {
        WARN("Failed to allocate memory for pResultR\n");
        QATerr(QAT_F_QAT_SM2_SIGN, QAT_R_PRESULTR_MALLOC_FAILURE);
        goto err;
    }

    pResultR->pData =
        (Cpa8U *) qaeMemAllocNUMA(buflen, NUMA_ANY_NODE, QAT_BYTE_ALIGNMENT);
    if (!pResultR->pData) {
        WARN("Failed to allocate memory for pResultR data\n");
        QATerr(QAT_F_QAT_SM2_SIGN, QAT_R_PRESULTR_PDATA_MALLOC_FAILURE);
        goto err;
    }
    pResultR->dataLenInBytes = (Cpa32U) buflen;

    pResultS = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (!pResultS) {
        WARN("Failed to allocate memory for pResultS\n");
        QATerr(QAT_F_QAT_SM2_SIGN, QAT_R_PRESULTS_MALLOC_FAILURE);
        goto err;
    }

    pResultS->pData =
        (Cpa8U *) qaeMemAllocNUMA(buflen, NUMA_ANY_NODE, QAT_BYTE_ALIGNMENT);
    if (!pResultS->pData) {
        WARN("Failed to allocate memory for pResultS data\n");
        QATerr(QAT_F_QAT_SM2_SIGN, QAT_R_PRESULTS_PDATA_MALLOC_FAILURE);
        goto err;
    }
    pResultS->dataLenInBytes = (Cpa32U) buflen;

    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
        WARN("could not create local variables\n");
        QATerr(QAT_F_QAT_SM2_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(op_done.job) == 0) {
            WARN("Failed to setup async event notification\n");
            QATerr(QAT_F_QAT_SM2_SIGN, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            goto err;
        }
    }
    CRYPTO_QAT_LOG("KX - %s\n", __func__);

    do {
        if ((inst_num = get_next_inst_num(INSTANCE_TYPE_CRYPTO_ASYM))
            == QAT_INVALID_INSTANCE) {
            WARN("Failure to get another instance\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG
                    ("Failed to get an instance - fallback to SW - %s\n",
                     __func__);
                fallback = 1;
            } else {
                QATerr(QAT_F_QAT_SM2_SIGN, ERR_R_INTERNAL_ERROR);
            }
            if (op_done.job != NULL) {
                qat_clear_async_event_notification(op_done.job);
            }
            qat_cleanup_op_done(&op_done);
            goto err;
        }

        CRYPTO_QAT_LOG("AU - %s\n", __func__);
        DUMP_SM2_SIGN(qat_instance_handles[inst_num], opData, pResultR,
                      pResultS);
        status = cpaCyEcsm2Sign(qat_instance_handles[inst_num],
                                qat_sm2SignCallbackFn,
                                &op_done,
                                opData, &bSM2SignStatus, pResultR, pResultS);
        if (status == CPA_STATUS_RETRY) {
            if (op_done.job == NULL) {
                usleep(ulPollInterval +
                       (qatPerformOpRetries %
                        QAT_RETRY_BACKOFF_MODULO_DIVISOR));
                qatPerformOpRetries++;
                if (iMsgRetry != QAT_INFINITE_MAX_NUM_RETRIES) {
                    if (qatPerformOpRetries >= iMsgRetry) {
                        WARN("No. of retries exceeded max retry : %d\n",
                             iMsgRetry);
                        break;
                    }
                }
            } else {
                if ((qat_wake_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0) ||
                    (qat_pause_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0)) {
                    WARN("qat_wake_job or qat_pause_job failed\n");
                    break;
                }
            }
        }
    }
    while (status == CPA_STATUS_RETRY);

    if (status != CPA_STATUS_SUCCESS) {
        WARN("Failed to submit request to qat - status = %d\n", status);
        if (qat_get_sw_fallback_enabled() &&
            (status == CPA_STATUS_RESTARTING || status == CPA_STATUS_FAIL)) {
            CRYPTO_QAT_LOG
                ("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                 inst_num,
                 qat_instance_details[inst_num].qat_instance_info.
                 physInstId.packageId, __func__);
            fallback = 1;
        } else {
            QATerr(QAT_F_QAT_SM2_SIGN, ERR_R_INTERNAL_ERROR);
        }
        if (op_done.job != NULL) {
            qat_clear_async_event_notification(op_done.job);
        }
        qat_cleanup_op_done(&op_done);
        goto err;
    }

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (sem_post(&hw_polling_thread_sem) != 0) {
                WARN("hw sem_post failed!, hw_polling_thread_sem address: %p.\n", &hw_polling_thread_sem);
                QATerr(QAT_F_QAT_SM2_SIGN, ERR_R_INTERNAL_ERROR);
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                goto err;
            }
        }
    }

    if (qat_get_sw_fallback_enabled()) {
        CRYPTO_QAT_LOG("Submit success qat inst_num %d device_id %d - %s\n",
                       inst_num,
                       qat_instance_details[inst_num].
                       qat_instance_info.physInstId.packageId, __func__);
    }

    if (enable_heuristic_polling) {
        QAT_ATOMIC_INC(num_asym_requests_in_flight);
    }

    do {
        if (op_done.job != NULL) {
            /* If we get a failure on qat_pause_job then we will
               not flag an error here and quit because we have
               an asynchronous request in flight.
               We don't want to start cleaning up data
               structures that are still being used. If
               qat_pause_job fails we will just yield and
               loop around and try again until the request
               completes and we can continue. */
            if ((job_ret = qat_pause_job(op_done.job, ASYNC_STATUS_OK)) == 0)
                sched_yield();
        } else {
            sched_yield();
        }
    }
    while (!op_done.flag || QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DUMP_SM2_SIGN_OUTPUT(bSM2SignStatus, pResultR, pResultS);
    QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);

    if (op_done.verifyResult != CPA_TRUE) {
        WARN("Verification of result failed\n");
        if (qat_get_sw_fallback_enabled() && op_done.status == CPA_STATUS_FAIL) {
            CRYPTO_QAT_LOG
                ("Verification of result failed for qat inst_num %d device_id %d - fallback to SW - %s\n",
                 inst_num,
                 qat_instance_details[inst_num].qat_instance_info.
                 physInstId.packageId, __func__);
            fallback = 1;
        } else {
            QATerr(QAT_F_QAT_SM2_SIGN, ERR_R_INTERNAL_ERROR);
        }
        qat_cleanup_op_done(&op_done);
        goto err;
    }

    qat_cleanup_op_done(&op_done);

    /* Convert the flatbuffer results back to a BN */
    BN_bin2bn(pResultR->pData, pResultR->dataLenInBytes, sig_r);
    BN_bin2bn(pResultS->pData, pResultS->dataLenInBytes, sig_s);
    sigleni = i2d_ECDSA_SIG(s, &sig);
    if (sigleni < 0) {
        QATerr(QAT_F_QAT_SM2_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *siglen = (unsigned int)sigleni;
    ret = 1;
    DEBUG("Sign operation successful\n");

 err:
    if (!ret) {
        if (s != NULL) {
            ECDSA_SIG_free(s);
            s = NULL;
        }
        if (siglen != NULL)
            *siglen = 0;
    }

    if (pResultR) {
        QAT_CHK_QMFREE_FLATBUFF(*pResultR);
        OPENSSL_free(pResultR);
    }
    if (pResultS) {
        QAT_CHK_QMFREE_FLATBUFF(*pResultS);
        OPENSSL_free(pResultS);
    }

    if (opData) {
        QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(opData->k);
        QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(opData->d);
        QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(opData->e);
        OPENSSL_free(opData);
    }

    if (bctx) {
        BN_CTX_end(bctx);
        BN_CTX_free(bctx);
    }

    if (fallback) {
        WARN("- Fallback to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);

# ifdef QAT_OPENSSL_PROVIDER
        /* When using OpenSSL 3 provider API */
        sw_sm2_signature = get_def_signature_sm2();
        if (sw_sm2_signature.digest_sign) {
            return sw_sm2_signature.digest_sign((void *)smctx, sig, siglen,
                                                sigsize, tbs, tbslen);
        } else {
            if (sw_sm2_signature.digest_sign_update == NULL ||
                sw_sm2_signature.digest_sign_final == NULL) {
                WARN("ECDSA  digest_sign_update is NULL or digest_sign_final is NULL\n");
                QATerr(QAT_F_QAT_SM2_SIGN, QAT_R_SM2_SIGN_NULL);
                return 0;
            }
            if (sw_sm2_signature.
                digest_sign_update((void *)smctx, tbs, tbslen) <= 0) {
                return 0;
            }
            return sw_sm2_signature.digest_sign_final((void *)smctx, sig,
                                                      siglen, sigsize);
        }
# else
#  ifdef QAT_OPENSSL_3          // to be deleted
        /* When using OpenSSL 3 legacy engine API */
        sw_ctx = OPENSSL_malloc(sizeof(QAT_PROV_SM2_CTX));
        sw_ctx->mdsize = 0;
        sw_ctx->ec = (EC_KEY *)eckey;
        md = (EVP_MD *)EVP_sm3();
        bg = sm2_compute_msg_hash(md, eckey, smctx->id, smctx->id_len, tbs,
                                  tbslen);
        dgst = OPENSSL_zalloc(SM3_DIGEST_LENGTH);
        dlen = BN_bn2bin(bg, dgst);

        sw_sm2_signature = get_def_signature_sm2();
        if (sw_sm2_signature.sign) {
            ret =
                sw_sm2_signature.sign(sw_ctx, sig, siglen, (size_t)sig_sz, dgst,
                                      dlen);
        } else {
            WARN("Failed to obtain sm2 sign func from default provider.\n");
            ret = 0;
        }
        OPENSSL_free(dgst);
        BN_free(bg);
        OPENSSL_free(sw_ctx);

        return ret;
#  else
        /* When using OpenSSL 1.1.1 */
        EVP_PKEY_meth_get_sign((EVP_PKEY_METHOD *)sw_sm2_pmeth, NULL, &psign);
        ret = (*psign) (ctx, sig, siglen, tbs, tbslen);
        DEBUG("SW Finished, ret: %d\n", ret);
        return ret;
#  endif
# endif
    }
    DEBUG("- FinishedP: %d\n", ret);
    return ret;
}

# ifdef QAT_OPENSSL_PROVIDER
int qat_sm2_verify(QAT_PROV_SM2_CTX *smctx,
                   const unsigned char *sig, size_t siglen,
                   const unsigned char *tbs, size_t tbslen)
# else
int qat_sm2_verify(EVP_PKEY_CTX *ctx,
                   const unsigned char *sig, size_t siglen,
                   const unsigned char *tbs, size_t tbslen)
# endif
{
    int ret = 0, i, job_ret = 0, fallback = 0;
    ECDSA_SIG *s;
    const EC_GROUP *group;
    BN_CTX *bctx = NULL;
    const BIGNUM *priv_key, *order;
    const EC_POINT *pub_key = NULL;
    const BIGNUM *sig_r = NULL, *sig_s = NULL;
    int inst_num = QAT_INVALID_INSTANCE;
    BIGNUM *xp = NULL, *yp = NULL;
    CpaCyEcsm2VerifyOpData *opData = NULL;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean bSM2VerifyStatus = 0;
    op_done_t op_done;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
    thread_local_variables_t *tlv = NULL;
    unsigned char *dgst = NULL;
    const unsigned char *p = sig;
    BIGNUM *e = NULL;
    int dlen = 0;

# if defined(QAT_OPENSSL_3) && !defined(QAT_OPENSSL_PROVIDER)
    unsigned char *msdgst = NULL;
    BIGNUM *bg = NULL;
    EVP_MD *md = NULL;
    int mdlen = 0;
    QAT_PROV_SM2_CTX *sw_ctx;
# endif

# if defined(QAT_OPENSSL_3) || defined(QAT_OPENSSL_PROVIDER)
    QAT_EVP_SIGNATURE sw_sm2_signature;
# else
    int (*pverify)(EVP_PKEY_CTX *ctx,
                   const unsigned char *sig, size_t siglen,
                   const unsigned char *tbs, size_t tbslen) = NULL;
# endif

# ifdef QAT_OPENSSL_PROVIDER
    const EC_KEY *eckey = smctx->ec;
# else
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    const EC_KEY *eckey = EVP_PKEY_get0_EC_KEY(pkey);
# endif

    DEBUG("Entering \n");
    if (unlikely(eckey == NULL) || unlikely(siglen == 0) ||
        unlikely(tbs == NULL) || unlikely(tbslen == 0)) {
        WARN("Invalid Input params\n");
        QATerr(QAT_F_QAT_SM2_VERIFY, QAT_R_INPUT_PARAM_INVALID);
        return ret;
    }

    group = EC_KEY_get0_group(eckey);
    priv_key = EC_KEY_get0_private_key(eckey);
    pub_key = EC_KEY_get0_public_key(eckey);

    if (group == NULL || priv_key == NULL || pub_key == NULL) {
        WARN("Either group, priv_key or pub_key are NULL\n");
        QATerr(QAT_F_QAT_SM2_VERIFY, QAT_R_GROUP_PRIV_KEY_PUB_KEY_NULL);
        return ret;
    }

# ifndef QAT_OPENSSL_PROVIDER
    QAT_SM2_PKEY_CTX *smctx = (QAT_SM2_PKEY_CTX *) EVP_PKEY_CTX_get_data(ctx);
    if (!smctx->id_set) {
        smctx->id_set = 1;
        smctx->id =
            (uint8_t *)OPENSSL_memdup(SM2_DEFAULT_USERID,
                                      SM2_DEFAULT_USERID_LEN);
        smctx->id_len = SM2_DEFAULT_USERID_LEN;
    }
# endif

    DEBUG("QAT HW SM2 Verify Started \n");

    if ((s = ECDSA_SIG_new()) == NULL) {
        WARN("Failure to allocate ECDSA_SIG_SM2\n");
        QATerr(QAT_F_QAT_SM2_VERIFY, QAT_R_SM2_SIG_MALLOC_FAILURE);
        return ret;
    }

    sig_r = BN_new();
    sig_s = BN_new();

    if (ECDSA_SIG_set0(s, (BIGNUM *)sig_r, (BIGNUM *)sig_s) == 0) {
        WARN("Failure to allocate r and s values to assign to the ECDSA_SIG\n");
        QATerr(QAT_F_QAT_SM2_VERIFY, QAT_R_SM2_SIG_SET_R_S_FAILURE);
        goto err;
    }

    if (d2i_ECDSA_SIG(&s, &p, siglen) == NULL) {
        WARN("Failure to get ECDSA_SIG_SM2\n");
        return ret;
    }

    dlen = i2d_ECDSA_SIG(s, &dgst);
    if (dlen != siglen || memcmp(sig, dgst, dlen) != 0) {
        WARN("Invalid Encoding dlen =%d \nsig = %s \ndgst = %s\n", dlen, sig,
             dgst);
        return ret;
    }

    if ((bctx = BN_CTX_new()) == NULL) {
        WARN("Failure to allocate ctx\n");
        QATerr(QAT_F_QAT_SM2_VERIFY, QAT_R_CTX_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(bctx);
    e = BN_CTX_get(bctx);
    xp = BN_CTX_get(bctx);
    yp = BN_CTX_get(bctx);

    if (xp == NULL || yp == NULL || e == NULL) {
        WARN("Failed to allocate xp or yp or e\n");
        QATerr(QAT_F_QAT_SM2_VERIFY, QAT_R_X_Y_E_MALLOC_FAILURE);
        goto err;
    }

    if ((order = EC_GROUP_get0_order(group)) == NULL) {
        WARN("Failure to get order from group\n");
        QATerr(QAT_F_QAT_SM2_VERIFY, QAT_R_GET_ORDER_FAILURE);
    }

    ECDSA_SIG_get0(s, &sig_r, &sig_s);
    if (BN_is_zero(sig_r) ||
        BN_is_negative(sig_r) ||
        BN_ucmp(sig_r, order) >= 0 ||
        BN_is_zero(sig_s) ||
        BN_is_negative(sig_s) || BN_ucmp(sig_s, order) >= 0) {
        WARN("ECDSA_SIG sig is invalid\n");
        QATerr(QAT_F_QAT_SM2_VERIFY, ERR_R_INTERNAL_ERROR);
        ret = 0;
        goto err;
    }

    i = BN_num_bits(order);

    /*
     * Need to truncate digest if it is too long: first truncate whole bytes.
     */
    if (8 * tbslen > i)
        tbslen = (i + 7) / 8;

    if (!BN_bin2bn(tbs, tbslen, e)) {
        WARN("Failure to convert dgst to e\n");
        QATerr(QAT_F_QAT_SM2_VERIFY, ERR_R_BN_LIB);
        goto err;
    }

    /* If still too long truncate remaining bits with a shift */
    if ((8 * tbslen > i) && !BN_rshift(e, e, 8 - (i & 0x7))) {
        WARN("Failure to truncate e\n");
        QATerr(QAT_F_QAT_SM2_VERIFY, ERR_R_BN_LIB);
        goto err;
    }

    opData = (CpaCyEcsm2VerifyOpData *)
        OPENSSL_zalloc(sizeof(CpaCyEcsm2VerifyOpData));
    if (opData == NULL) {
        WARN("Failed to allocate memory for opData\n");
        QATerr(QAT_F_QAT_SM2_VERIFY, QAT_R_OPDATA_MALLOC_FAILURE);
        goto err;
    }

    opData->fieldType = CPA_CY_EC_FIELD_TYPE_PRIME;

    if (!EC_POINT_get_affine_coordinates(group, pub_key, xp, yp, bctx)) {
        WARN("Failure to get the affine coordinates\n");
        QATerr(QAT_F_QAT_SM2_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if ((qat_BN_to_FB(&(opData->r), (BIGNUM *)sig_r) != 1) ||
        (qat_BN_to_FB(&(opData->s), (BIGNUM *)sig_s) != 1) ||
        (qat_BN_to_FB(&(opData->e), e) != 1) ||
        (qat_BN_to_FB(&(opData->xP), xp) != 1) ||
        (qat_BN_to_FB(&(opData->yP), yp) != 1)) {
        WARN("Failed to convert sig_r, sig_s, xp or yp to a flatbuffer\n");
        QATerr(QAT_F_QAT_SM2_VERIFY,
               QAT_R_CURVE_COORDINATE_PARAMS_CONVERT_TO_FB_FAILURE);
        goto err;
    }

    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
        WARN("could not create local variables\n");
        QATerr(QAT_F_QAT_SM2_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(op_done.job) == 0) {
            WARN("Failed to setup async event notification\n");
            QATerr(QAT_F_QAT_SM2_VERIFY, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            goto err;
        }
    }
    CRYPTO_QAT_LOG("KX - %s\n", __func__);

    do {
        if ((inst_num = get_next_inst_num(INSTANCE_TYPE_CRYPTO_ASYM))
            == QAT_INVALID_INSTANCE) {
            WARN("Failure to get another instance\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG
                    ("Failed to get an instance - fallback to SW - %s\n",
                     __func__);
                fallback = 1;
            } else {
                QATerr(QAT_F_QAT_SM2_VERIFY, ERR_R_INTERNAL_ERROR);
            }
            if (op_done.job != NULL) {
                qat_clear_async_event_notification(op_done.job);
            }
            qat_cleanup_op_done(&op_done);
            goto err;
        }

        CRYPTO_QAT_LOG("AU - %s\n", __func__);
        DUMP_SM2_VERIFY(qat_instance_handles[inst_num], opData);
        status = cpaCyEcsm2Verify(qat_instance_handles[inst_num],
                                  qat_sm2VerifyCallbackFn,
                                  &op_done, opData, &bSM2VerifyStatus);
        if (status == CPA_STATUS_RETRY) {
            if (op_done.job == NULL) {
                usleep(ulPollInterval +
                       (qatPerformOpRetries %
                        QAT_RETRY_BACKOFF_MODULO_DIVISOR));
                qatPerformOpRetries++;
                if (iMsgRetry != QAT_INFINITE_MAX_NUM_RETRIES) {
                    if (qatPerformOpRetries >= iMsgRetry) {
                        WARN("No. of retries exceeded max retry : %d\n",
                             iMsgRetry);
                        break;
                    }
                }
            } else {
                if ((qat_wake_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0) ||
                    (qat_pause_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0)) {
                    WARN("qat_wake_job or qat_pause_job failed\n");
                    break;
                }
            }
        }
    }
    while (status == CPA_STATUS_RETRY);

    if (status != CPA_STATUS_SUCCESS) {
        WARN("Failed to submit request to qat - status = %d\n", status);
        if (qat_get_sw_fallback_enabled() &&
            (status == CPA_STATUS_RESTARTING || status == CPA_STATUS_FAIL)) {
            CRYPTO_QAT_LOG
                ("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                 inst_num,
                 qat_instance_details[inst_num].qat_instance_info.
                 physInstId.packageId, __func__);
            fallback = 1;
        } else {
            QATerr(QAT_F_QAT_SM2_VERIFY, ERR_R_INTERNAL_ERROR);
        }
        if (op_done.job != NULL) {
            qat_clear_async_event_notification(op_done.job);
        }
        qat_cleanup_op_done(&op_done);
        goto err;
    }

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (sem_post(&hw_polling_thread_sem) != 0) {
                WARN("hw sem_post failed!, hw_polling_thread_sem address: %p.\n", &hw_polling_thread_sem);
                QATerr(QAT_F_QAT_SM2_VERIFY, ERR_R_INTERNAL_ERROR);
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                goto err;
            }
        }
    }

    if (qat_get_sw_fallback_enabled()) {
        CRYPTO_QAT_LOG("Submit success qat inst_num %d device_id %d - %s\n",
                       inst_num,
                       qat_instance_details[inst_num].
                       qat_instance_info.physInstId.packageId, __func__);
    }

    if (enable_heuristic_polling) {
        QAT_ATOMIC_INC(num_asym_requests_in_flight);
    }

    do {
        if (op_done.job != NULL) {
            /* If we get a failure on qat_pause_job then we will
               not flag an error here and quit because we have
               an asynchronous request in flight.
               We don't want to start cleaning up data
               structures that are still being used. If
               qat_pause_job fails we will just yield and
               loop around and try again until the request
               completes and we can continue. */
            if ((job_ret = qat_pause_job(op_done.job, ASYNC_STATUS_OK)) == 0)
                sched_yield();
        } else {
            sched_yield();
        }
    }
    while (!op_done.flag || QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));
    DEBUG("Verify Status %d\n", bSM2VerifyStatus);
    QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);

    if (op_done.verifyResult != CPA_TRUE) {
        WARN("Verification of result failed\n");
        if (qat_get_sw_fallback_enabled() && op_done.status == CPA_STATUS_FAIL) {
            CRYPTO_QAT_LOG
                ("Verification of result failed for qat inst_num %d device_id %d - fallback to SW - %s\n",
                 inst_num,
                 qat_instance_details[inst_num].qat_instance_info.
                 physInstId.packageId, __func__);
            fallback = 1;
        } else {
            QATerr(QAT_F_QAT_SM2_VERIFY, ERR_R_INTERNAL_ERROR);
        }
        qat_cleanup_op_done(&op_done);
        goto err;
    } else
        DEBUG("Verification Status Success\n");

    qat_cleanup_op_done(&op_done);
    ret = 1;

 err:
    if (!ret) {
        ECDSA_SIG_free(s);
        s = NULL;
        siglen = 0;
    }

    if (opData) {
        QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(opData->r);
        QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(opData->s);
        QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(opData->e);
        QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(opData->xP);
        QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(opData->yP);
        OPENSSL_free(opData);
    }

    if (bctx) {
        BN_CTX_end(bctx);
        BN_CTX_free(bctx);
    }

    if (fallback) {
        WARN("- Fallback to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);

# ifdef QAT_OPENSSL_PROVIDER
        /* When using OpenSSL 3 provider API */
        sw_sm2_signature = get_def_signature_sm2();
        if (sw_sm2_signature.digest_verify) {
            return sw_sm2_signature.digest_verify((void *)smctx, sig, siglen,
                                                  tbs, tbslen);
        } else {
            if (sw_sm2_signature.digest_verify_update == NULL ||
                sw_sm2_signature.digest_verify_final == NULL) {
                WARN("ECDSA  digest_verify_update is NULL or digest_verify_final is NULL\n");
                QATerr(QAT_F_QAT_SM2_VERIFY, QAT_R_SM2_VERIFY_NULL);
                return -1;
            }
            if (sw_sm2_signature.
                digest_verify_update((void *)smctx, tbs, tbslen) <= 0) {
                return -1;
            }
            return sw_sm2_signature.digest_verify_final((void *)smctx, sig,
                                                        siglen);
        }
# else
#  ifdef QAT_OPENSSL_3
        /* When using OpenSSL 3 legacy engine API */
        sw_ctx = OPENSSL_malloc(sizeof(QAT_PROV_SM2_CTX));
        sw_ctx->mdsize = 0;
        sw_ctx->ec = (EC_KEY *)eckey;
        md = (EVP_MD *)EVP_sm3();
        bg = sm2_compute_msg_hash(md, eckey, smctx->id, smctx->id_len, tbs,
                                  tbslen);
        msdgst = OPENSSL_zalloc(SM3_DIGEST_LENGTH);
        mdlen = BN_bn2bin(bg, msdgst);

        sw_sm2_signature = get_def_signature_sm2();
        if (sw_sm2_signature.verify) {
            ret = sw_sm2_signature.verify(sw_ctx, sig, siglen, msdgst, mdlen);
        } else {
            WARN("Failed to obtain sm2 verify func from default provider.\n");
            ret = 0;
        }
        OPENSSL_free(msdgst);
        BN_free(bg);
        OPENSSL_free(sw_ctx);

        return ret;
#  else
        /* When using OpenSSL 1.1.1 */
        EVP_PKEY_meth_get_verify((EVP_PKEY_METHOD *)sw_sm2_pmeth,
                                 NULL, &pverify);
        ret = (*pverify) (ctx, sig, siglen, tbs, tbslen);
        DEBUG("SW Finished, ret: %d\n", ret);
        return ret;
#  endif
# endif
    }
    DEBUG("- Finished\n");
    return ret;
}
#endif
