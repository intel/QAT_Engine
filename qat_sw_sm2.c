/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2021-2024 Intel Corporation.
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
 * @file qat_sw_sm2.c
 *
 * This file provides multibuffer support for SM2 ECDSA
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#define __USE_GNU


#include "qat_sw_sm2.h"
#if defined(ENABLE_QAT_SW_SM2)
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

#if defined(QAT_OPENSSL_3) && defined(ENABLE_QAT_SW_SM2)
typedef struct evp_signature_st {
    int name_id;
    char *type_name;
    const char *description;
    OSSL_PROVIDER *prov;
    int refcnt;
# if OPENSSL_VERSION_NUMBER < 0x30200000
    void *lock;
# endif

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
} QAT_EVP_SIGNATURE /* EVP_SIGNATURE for QAT Provider sm2 */;

struct bignum_st {
    BN_ULONG *d;                /* Pointer to an array of 'BN_BITS2' bit
                                 * chunks. */
    int top;                    /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int dmax;                   /* Size of the d array. */
    int neg;                    /* one if the number is negative */
    int flags;
};

static QAT_EVP_SIGNATURE get_default_signature_sm2()
{
    static QAT_EVP_SIGNATURE s_signature;
    static int initilazed = 0;
    if (!initilazed) {
        QAT_EVP_SIGNATURE *signature = (QAT_EVP_SIGNATURE *)EVP_SIGNATURE_fetch(NULL, "SM2", "provider=default");
        if (signature) {
            s_signature = *signature;
            EVP_SIGNATURE_free((QAT_EVP_SIGNATURE *)signature);
            initilazed = 1;
        } else {
            WARN("EVP_SIGNATURE_fetch from default provider failed");
        }
    }
    return s_signature;
}
#endif

void process_ecdsa_sm2_sign_reqs(mb_thread_data *tlv)
{
    ecdsa_sm2_sign_op_data *ecdsa_sm2_sign_req_array[MULTIBUFF_BATCH] = {0};
    unsigned char *sign_r[MULTIBUFF_BATCH] = {0};
    unsigned char *sign_s[MULTIBUFF_BATCH] = {0};;
    const unsigned char *digest[MULTIBUFF_BATCH] = {0};
    const BIGNUM *eph_key[MULTIBUFF_BATCH] = {0};
    const BIGNUM *priv_key[MULTIBUFF_BATCH] = {0};
    const int8u* id[MULTIBUFF_BATCH] = {0};
    const BIGNUM *ecdsa_sm2_sign_x[MULTIBUFF_BATCH] = {0};
    const BIGNUM *ecdsa_sm2_sign_y[MULTIBUFF_BATCH] = {0};
    const BIGNUM *ecdsa_sm2_sign_z[MULTIBUFF_BATCH] = {0};
    int id_len[MULTIBUFF_BATCH] = {0};
    int digest_len[MULTIBUFF_BATCH] = {0};
    unsigned int sts = 0;
    int local_request_no = 0;
    int req_num = 0;

    START_RDTSC(&ecdsa_cycles_sign_execute);

    /* Build Arrays of pointers for call */
    DEBUG("Dequeue ECDSA SM2 sign reqs.\n");
    while ((ecdsa_sm2_sign_req_array[req_num] =
                mb_queue_ecdsa_sm2_sign_dequeue(tlv->ecdsa_sm2_sign_queue)) != NULL) {
        sign_r[req_num] = ecdsa_sm2_sign_req_array[req_num]->sign_r;
        sign_s[req_num] = ecdsa_sm2_sign_req_array[req_num]->sign_s;
        digest[req_num] = ecdsa_sm2_sign_req_array[req_num]->digest;
        eph_key[req_num] = ecdsa_sm2_sign_req_array[req_num]->eph_key;
        priv_key[req_num] = ecdsa_sm2_sign_req_array[req_num]->priv_key;
        id[req_num] = ecdsa_sm2_sign_req_array[req_num]->id;
        ecdsa_sm2_sign_x[req_num] = (const BIGNUM* const)ecdsa_sm2_sign_req_array[req_num]->x;
        ecdsa_sm2_sign_y[req_num] = (const BIGNUM* const)ecdsa_sm2_sign_req_array[req_num]->y;
        ecdsa_sm2_sign_z[req_num] = (const BIGNUM* const)ecdsa_sm2_sign_req_array[req_num]->z;
        id_len[req_num] = (const int)ecdsa_sm2_sign_req_array[req_num]->id_len;
        digest_len[req_num] = (const int)ecdsa_sm2_sign_req_array[req_num]->dig_len;

        req_num++;
        if (req_num == MULTIBUFF_MIN_BATCH)
            break;
    }
    local_request_no = req_num;

    DEBUG("Submitting %d ECDSA SM2 sign requests\n", local_request_no);
    sts = mbx_sm2_ecdsa_sign_ssl_mb8(sign_r,
                                     sign_s,
                                     id,
                                     id_len,
                                     digest,
                                     digest_len,
                                     eph_key,
                                     priv_key,
                                     ecdsa_sm2_sign_x,
                                     ecdsa_sm2_sign_y,
                                     ecdsa_sm2_sign_z,
                                     NULL);


    for (req_num = 0; req_num < local_request_no; req_num++) {
        if (ecdsa_sm2_sign_req_array[req_num]->sts != NULL) {
            if (MBX_GET_STS(sts, req_num) == MBX_STATUS_OK) {
                DEBUG("Multibuffer ECDSA SM2 Sign request[%d] success\n", req_num);
                *ecdsa_sm2_sign_req_array[req_num]->sts = 1;
            } else {
                WARN("Multibuffer ECDSA SM2 Sign request[%d] failure - sts %d\n",
                      req_num, MBX_GET_STS(sts, req_num));
                *ecdsa_sm2_sign_req_array[req_num]->sts = 0;
            }
        }

        if (ecdsa_sm2_sign_req_array[req_num]->job) {
            qat_wake_job(ecdsa_sm2_sign_req_array[req_num]->job,
                         ASYNC_STATUS_OK);
        }
        OPENSSL_cleanse(ecdsa_sm2_sign_req_array[req_num],
                        sizeof(ecdsa_sm2_sign_op_data));
        mb_flist_ecdsa_sm2_sign_push(tlv->ecdsa_sm2_sign_freelist,
                                 ecdsa_sm2_sign_req_array[req_num]);
    }

# ifdef QAT_SW_HEURISTIC_TIMEOUT
        mb_ecdsa_sm2_sign_req_rates.req_this_period += local_request_no;
# endif

    STOP_RDTSC(&ecdsa_cycles_sign_execute, 1, "[ECDSA:sign_execute]");
    DEBUG("Processed Final Request\n");
}

void process_ecdsa_sm2_verify_reqs(mb_thread_data *tlv)
{
    ecdsa_sm2_verify_op_data *ecdsa_sm2_verify_req_array[MULTIBUFF_BATCH] = {0};
    const int8u* id[MULTIBUFF_BATCH] = {0};
    const int8u* digest[MULTIBUFF_BATCH] = {0};
    const BIGNUM *ecdsa_sm2_verify_x[MULTIBUFF_BATCH] = {0};
    const BIGNUM *ecdsa_sm2_verify_y[MULTIBUFF_BATCH] = {0};
    const BIGNUM *ecdsa_sm2_verify_z[MULTIBUFF_BATCH] = {0};
    int id_len[MULTIBUFF_BATCH] = {0};
    int digest_len[MULTIBUFF_BATCH] = {0};
    const ECDSA_SIG *sig[MULTIBUFF_BATCH] = {0};
    unsigned int sts = 0;
    int local_request_no = 0;
    int req_num = 0;

    START_RDTSC(&ecdsa_cycles_verify_execute);

    /* Build Arrays of pointers for call */
    while ((ecdsa_sm2_verify_req_array[req_num] =
                mb_queue_ecdsa_sm2_verify_dequeue(tlv->ecdsa_sm2_verify_queue)) != NULL) {
        sig[req_num] = ecdsa_sm2_verify_req_array[req_num]->s;
        digest[req_num] = (int8u*)ecdsa_sm2_verify_req_array[req_num]->digest;
        id[req_num] = (int8u*)ecdsa_sm2_verify_req_array[req_num]->id;
        ecdsa_sm2_verify_x[req_num] = (const BIGNUM* const)ecdsa_sm2_verify_req_array[req_num]->x;
        ecdsa_sm2_verify_y[req_num] = (const BIGNUM* const)ecdsa_sm2_verify_req_array[req_num]->y;
        ecdsa_sm2_verify_z[req_num] = (const BIGNUM* const)ecdsa_sm2_verify_req_array[req_num]->z;
        id_len[req_num] = (const int)ecdsa_sm2_verify_req_array[req_num]->id_len;
        digest_len[req_num] = (const int)ecdsa_sm2_verify_req_array[req_num]->dig_len;

        req_num++;
        if (req_num == MULTIBUFF_MIN_BATCH)
            break;
    }
    local_request_no = req_num;

    DEBUG("Submitting %d ECDSA_SM2 verify requests\n", local_request_no);
    sts = mbx_sm2_ecdsa_verify_ssl_mb8(sig,
                                       id,
                                       id_len,
                                       digest,
                                       digest_len,
                                       ecdsa_sm2_verify_x,
                                       ecdsa_sm2_verify_y,
                                       ecdsa_sm2_verify_z,
                                       NULL);

    for (req_num = 0; req_num < local_request_no; req_num++) {
        if (ecdsa_sm2_verify_req_array[req_num]->sts != NULL) {
            if (MBX_GET_STS(sts, req_num) == MBX_STATUS_OK) {
                DEBUG("Multibuffer ECDSA_SM2 Verify request[%d] success\n", req_num);
                *ecdsa_sm2_verify_req_array[req_num]->sts = 1;
            } else {
                WARN("Multibuffer ECDSA_SM2 Verify request[%d] failure - sts %d\n",
                      req_num, MBX_GET_STS(sts, req_num));
                *ecdsa_sm2_verify_req_array[req_num]->sts = 0;
            }
        }

        if (ecdsa_sm2_verify_req_array[req_num]->job) {
            qat_wake_job(ecdsa_sm2_verify_req_array[req_num]->job,
                         ASYNC_STATUS_OK);
        }
        OPENSSL_cleanse(ecdsa_sm2_verify_req_array[req_num],
                        sizeof(ecdsa_sm2_verify_op_data));
        mb_flist_ecdsa_sm2_verify_push(tlv->ecdsa_sm2_verify_freelist,
                                 ecdsa_sm2_verify_req_array[req_num]);
    }

# ifdef QAT_SW_HEURISTIC_TIMEOUT
        mb_ecdsa_sm2_verify_req_rates.req_this_period += local_request_no;
# endif

    STOP_RDTSC(&ecdsa_cycles_verify_execute, 1, "[ECDSA:verify_execute]");
    DEBUG("Processed Final Request\n");
}

/* OpenSSL Softare implementation for synchronous requests,
 * Since OpenSSL doesn't support single shot operation
 * and it has to be digest and then sign, Whereas crypto_mb only
 * supports single shot operation for performance reasons.
 * Had to use this code here from OpenSSL as OpenSSL throws error
 * (ONLY_ONESHOT_SUPPORTED) when doing EVP_DigestUpdate() from
 * digest_custom if digestsign is registered from engine */
int qat_sm2_compute_z_digest(uint8_t *out,
                              const EVP_MD *digest,
                              const uint8_t *id,
                              const size_t id_len,
                              const EC_KEY *key)
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
    ctx = BN_CTX_secure_new();
    BN_CTX_start(ctx);
    if (hash == NULL || ctx == NULL) {
        QATerr(QAT_F_QAT_SM2_COMPUTE_Z_DIGEST, QAT_R_MALLOC_FAILURE);
        WARN("Hash internal error\n");
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
        QATerr(QAT_F_QAT_SM2_COMPUTE_Z_DIGEST, QAT_R_MALLOC_FAILURE);
        WARN("Hash internal error\n");
        goto done;
    }

    if (!EVP_DigestInit(hash, digest)) {
        QATerr(QAT_F_QAT_SM2_COMPUTE_Z_DIGEST, QAT_R_EVP_LIB);
        WARN("Hash internal error\n");
        goto done;
    }

    /* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */

    if (id_len >= (UINT16_MAX / 8)) {
        /* too large */
        QATerr(QAT_F_QAT_SM2_COMPUTE_Z_DIGEST, QAT_R_ID_TOO_LARGE);
        WARN("id_len too large\n");
        goto done;
    }

    entl = (uint16_t)(8 * id_len);

    e_byte = entl >> 8;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        QATerr(QAT_F_QAT_SM2_COMPUTE_Z_DIGEST, QAT_R_EVP_LIB);
        WARN("EVP Digest Failure\n");
        goto done;
    }
    e_byte = entl & 0xFF;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        QATerr(QAT_F_QAT_SM2_COMPUTE_Z_DIGEST, QAT_R_EVP_LIB);
        WARN("EVP Digest Failure\n");
        goto done;
    }

    if (id_len > 0 && !EVP_DigestUpdate(hash, id, id_len)) {
        QATerr(QAT_F_QAT_SM2_COMPUTE_Z_DIGEST, QAT_R_EVP_LIB);
        WARN("EVP Digest Failure\n");
        goto done;
    }

    if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {
        QATerr(QAT_F_QAT_SM2_COMPUTE_Z_DIGEST, QAT_R_EC_LIB);
        WARN("EC Group get curve failed\n");
        goto done;
    }


    p_bytes = BN_num_bytes(p);
    buf = OPENSSL_zalloc(p_bytes);
    if (buf == NULL) {
        WARN("Malloc Failure\n");
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
        QATerr(QAT_F_QAT_SM2_COMPUTE_Z_DIGEST, QAT_R_INTERNAL_ERROR);
        WARN("EVP Digest Operation failure\n");
        goto done;
    }

    rc = 1;
 done:
    OPENSSL_free(buf);
    BN_CTX_free(ctx);
    EVP_MD_CTX_free(hash);
    return rc;
}

# ifndef QAT_OPENSSL_PROVIDER
int mb_sm2_init(EVP_PKEY_CTX *ctx)
{
    QAT_SM2_PKEY_CTX *smctx = NULL;

    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_PKEY_CTX) is NULL \n");
        return 0;
    }

    if ((smctx = OPENSSL_zalloc(sizeof(*smctx))) == NULL) {
        WARN("smctx alloc Failure\n");
        QATerr(QAT_F_MB_SM2_INIT, QAT_R_MALLOC_FAILURE);
        return 0;
    }

    EVP_PKEY_CTX_set_data(ctx, smctx);
    return 1;
}

void mb_sm2_cleanup(EVP_PKEY_CTX *ctx)
{
    QAT_SM2_PKEY_CTX *smctx = NULL;

    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_PKEY_CTX) is NULL \n");
        return;
    }

    smctx = (QAT_SM2_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);
    if (smctx == NULL) {
        WARN("smctx is NULL\n");
        return;
    }

    EC_GROUP_free(smctx->gen_group);
    OPENSSL_free(smctx->id);
    OPENSSL_free(smctx);
}

int mb_sm2_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    QAT_SM2_PKEY_CTX *smctx = (QAT_SM2_PKEY_CTX *)EVP_PKEY_CTX_get_data(ctx);
    EC_GROUP *group;
    uint8_t *tmp_id;

    if (unlikely(smctx == NULL)) {
        WARN("smctx cannot be NULL\n");
        QATerr(QAT_F_MB_SM2_CTRL, QAT_R_CTX_NULL);
        return 0;
    }

    switch (type) {
    case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
        group = EC_GROUP_new_by_curve_name(p1);
        if (group == NULL) {
            WARN("Invalid curve\n");
            QATerr(QAT_F_MB_SM2_CTRL, QAT_R_INVALID_CURVE);
            return 0;
        }
        EC_GROUP_free(smctx->gen_group);
        smctx->gen_group = group;
        return 1;

    case EVP_PKEY_CTRL_EC_PARAM_ENC:
        if (smctx->gen_group == NULL) {
            WARN("gen group NULL\n");
            QATerr(QAT_F_MB_SM2_CTRL, QAT_R_NO_PARAMETERS_SET);
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
                QATerr(QAT_F_MB_SM2_CTRL, QAT_R_MALLOC_FAILURE);
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
        WARN("md_size is less than zero\n");
        goto done;
    }

    z = OPENSSL_zalloc(md_size);
    if (hash == NULL || z == NULL) {
        WARN("Hash internal error\n");
        goto done;
    }

    if (!qat_sm2_compute_z_digest(z, digest, id, id_len, key)) {
        /* QATerr already called */
        goto done;
    }

    if (!EVP_DigestInit(hash, digest)
            || !EVP_DigestUpdate(hash, z, md_size)
            || !EVP_DigestUpdate(hash, msg, msg_len)
               /* reuse z buffer to hold H(Z || M) */
            || !EVP_DigestFinal(hash, z, NULL)) {
        WARN("Hash internal error\n");
        goto done;
    }

    e = BN_bin2bn(z, md_size, NULL);
    if (e == NULL) {
        WARN("Hash internal error\n");
    }

 done:
    OPENSSL_free(z);
    EVP_MD_CTX_free(hash);
    return e;
}

int mb_digest_custom(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{

    /* Do nothing as this is taken care in use_sw_method within
     * corresponding digestsign and digestverify function */
    return 1;
}
# endif

# ifdef QAT_OPENSSL_PROVIDER
int mb_ecdsa_sm2_sign(QAT_PROV_SM2_CTX *smctx,
                             unsigned char *sig, size_t *siglen,
                             size_t sigsize, const unsigned char *tbs,
                             size_t tbslen)
# else
int mb_ecdsa_sm2_sign(EVP_MD_CTX *mctx,
                             unsigned char *sig, size_t *siglen,
                             const unsigned char *tbs,
                             size_t tbslen)
# endif
{
    int ret = 0, len = 0, job_ret = 0, sts = 0;
    BN_CTX *ctx = NULL;
    ECDSA_SIG *s;
    ASYNC_JOB *job;
    size_t buflen;
    static __thread int req_num = 0;
    const EC_GROUP *group;
    BIGNUM *k = NULL;
    const BIGNUM *priv_key, *order;
    const EC_POINT *pub_key = NULL;
    BIGNUM *ecdsa_sig_r = NULL, *ecdsa_sig_s = NULL;
    ecdsa_sm2_sign_op_data *ecdsa_sm2_sign_req = NULL;
    mb_thread_data *tlv = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL;
    int sig_sz;

/* Only used for OpenSSL 3 legacy engine API */
#if defined(QAT_OPENSSL_3) && !defined(QAT_OPENSSL_PROVIDER)
    QAT_PROV_SM2_CTX *sw_ctx;
#endif

#ifndef QAT_OPENSSL_PROVIDER
    unsigned char *dgst = NULL;
    BIGNUM *e = NULL;
    EVP_MD *md = NULL;
    int dlen = 0;
#endif

#ifdef QAT_OPENSSL_3
    QAT_EVP_SIGNATURE sw_sm2_signature;
#else
    int (*psign) (EVP_PKEY_CTX *ctx,
                  unsigned char *sig, size_t *siglen,
                  const unsigned char *tbs,
                  size_t tbslen) = NULL;
#endif

# ifdef QAT_OPENSSL_PROVIDER
    const EC_KEY *eckey = smctx->ec;
# else
    EVP_PKEY_CTX *pctx = EVP_MD_CTX_pkey_ctx(mctx);
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(pctx);
    const EC_KEY *eckey = EVP_PKEY_get0_EC_KEY(pkey);
# endif

    DEBUG("Entering \n");
    if (unlikely(eckey == NULL) || unlikely(siglen == NULL)) {
        WARN("Invalid Input params\n");
        QATerr(QAT_F_MB_ECDSA_SM2_SIGN, QAT_R_INPUT_PARAM_INVALID);
        return ret;
    }
    sig_sz = ECDSA_size(eckey);

    /* To know how much memory is needed to store the sig */
    if (sig == NULL) {
        *siglen = (size_t)sig_sz;
        return 1;
    }

    if (*siglen < (size_t)sig_sz) {
        WARN("Invalid Input param\n");
        QATerr(QAT_F_MB_ECDSA_SM2_SIGN, QAT_R_INPUT_PARAM_INVALID);
        return ret;
    }

    group = EC_KEY_get0_group(eckey);
    priv_key = EC_KEY_get0_private_key(eckey);
    pub_key = EC_KEY_get0_public_key(eckey);

    if (group == NULL || priv_key == NULL || pub_key == NULL) {
        WARN("Either group, priv_key or pub_key are NULL\n");
        QATerr(QAT_F_MB_ECDSA_SM2_SIGN, QAT_R_GROUP_PRIV_KEY_PUB_KEY_NULL);
        return ret;
    }

# ifndef QAT_OPENSSL_PROVIDER
    QAT_SM2_PKEY_CTX *smctx = (QAT_SM2_PKEY_CTX *)EVP_PKEY_CTX_get_data(pctx);
    if (!smctx->id_set) {
        smctx->id_set = 1;
        smctx->id = (uint8_t*)OPENSSL_memdup(SM2_DEFAULT_USERID, SM2_DEFAULT_USERID_LEN);
        smctx->id_len = SM2_DEFAULT_USERID_LEN;
    }
# endif

# if defined(QAT_OPENSSL_3) && !defined(QAT_OPENSSL_PROVIDER)
    if (qat_openssl3_sm2_fallback == 1) {
        DEBUG("- Switched to software mode\n");
        goto use_sw_method;
    }
# endif

    /* QAT SW initialization fail, switching to OpenSSL. */
    if (fallback_to_openssl)
        goto use_sw_method;

    /* Check if we are running asynchronously */
    if ((job = ASYNC_get_current_job()) == NULL) {
        DEBUG("Running synchronously using sw method\n");
        goto use_sw_method;
    }

    /* Setup asynchronous notifications */
    if (!qat_setup_async_event_notification(job)) {
        DEBUG("Failed to setup async notifications, using sw method\n");
        goto use_sw_method;
    }

    tlv = mb_check_thread_local();
    if (NULL == tlv) {
        WARN("Could not create thread local variables\n");
        goto use_sw_method;
    }

    while ((ecdsa_sm2_sign_req =
            mb_flist_ecdsa_sm2_sign_pop(tlv->ecdsa_sm2_sign_freelist)) == NULL) {
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
    }

    DEBUG("QAT SW ECDSA SM2 Sign Started %p\n", ecdsa_sm2_sign_req);
    START_RDTSC(&ecdsa_cycles_sign_setup);

    /* Buffer up the requests and call the new functions when we have enough
     * requests buffered up */

    if ((s = ECDSA_SIG_new()) == NULL) {
        mb_flist_ecdsa_sm2_sign_push(tlv->ecdsa_sm2_sign_freelist, ecdsa_sm2_sign_req);
        WARN("Failure to allocate ECDSA_SIG\n");
        QATerr(QAT_F_MB_ECDSA_SM2_SIGN, QAT_R_ECDSA_SIG_MALLOC_FAILURE);
        return ret;
    }

    ecdsa_sig_r = BN_new();
    ecdsa_sig_s = BN_new();

    /* NULL checking of ecdsa_sig_r & ecdsa_sig_s done in ECDSA_SIG_set0() */
    if (ECDSA_SIG_set0(s, ecdsa_sig_r, ecdsa_sig_s) == 0) {
        mb_flist_ecdsa_sm2_sign_push(tlv->ecdsa_sm2_sign_freelist, ecdsa_sm2_sign_req);
        WARN("Failure to allocate r and s values to assign to the ECDSA_SIG\n");
        QATerr(QAT_F_MB_ECDSA_SM2_SIGN, QAT_R_ECDSA_SIG_SET_R_S_FAILURE);
        goto err;
    }

    if ((ctx = BN_CTX_new()) == NULL) {
        mb_flist_ecdsa_sm2_sign_push(tlv->ecdsa_sm2_sign_freelist, ecdsa_sm2_sign_req);
        WARN("Failure to allocate ctx\n");
        QATerr(QAT_F_MB_ECDSA_SM2_SIGN, QAT_R_CTX_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    z = BN_CTX_get(ctx);

    if (k == NULL || x == NULL || y == NULL || z == NULL) {
        mb_flist_ecdsa_sm2_sign_push(tlv->ecdsa_sm2_sign_freelist, ecdsa_sm2_sign_req);
        WARN("Failed to allocate k or x or y or z\n");
        QATerr(QAT_F_MB_ECDSA_SM2_SIGN, QAT_R_X_Y_Z_MALLOC_FAILURE);
        goto err;
    }


    if ((order = EC_GROUP_get0_order(group)) ==  NULL) {
        mb_flist_ecdsa_sm2_sign_push(tlv->ecdsa_sm2_sign_freelist, ecdsa_sm2_sign_req);
        WARN("Failure to get order from group\n");
        QATerr(QAT_F_MB_ECDSA_SM2_SIGN, QAT_R_GET_ORDER_FAILURE);
        goto err;
    }

    len = BN_num_bits(order);
    buflen = (len + 7) / 8;

    /* Get random k */
    do {
        if (!BN_priv_rand_range(k, order)) {
            mb_flist_ecdsa_sm2_sign_push(tlv->ecdsa_sm2_sign_freelist, ecdsa_sm2_sign_req);
            WARN("Failure in BN_priv_rand_range\n");
            QATerr(QAT_F_MB_ECDSA_SM2_SIGN, QAT_R_RAND_GENERATE_FAILURE);
            goto err;
        }
    } while (BN_is_zero(k));

    if (!EC_POINT_get_Jprojective_coordinates_GFp(group, pub_key, x, y, z,ctx)) {
        mb_flist_ecdsa_sm2_sign_push(tlv->ecdsa_sm2_sign_freelist, ecdsa_sm2_sign_req);
        WARN("Failure to get the Jacobian coordinates for public Key\n");
        QATerr(QAT_F_MB_ECDSA_SM2_SIGN, QAT_R_INTERNAL_ERROR);
        goto err;
    }

    ecdsa_sm2_sign_req->sign_r = sig;
    ecdsa_sm2_sign_req->sign_s = sig + buflen;
    ecdsa_sm2_sign_req->eph_key = k;
    ecdsa_sm2_sign_req->priv_key = priv_key;
    ecdsa_sm2_sign_req->job = job;
    ecdsa_sm2_sign_req->sts = &sts;
    ecdsa_sm2_sign_req->x = x;
    ecdsa_sm2_sign_req->y = y;
    ecdsa_sm2_sign_req->z = z;
    ecdsa_sm2_sign_req->id = smctx->id;
    ecdsa_sm2_sign_req->id_len = smctx->id_len;
    ecdsa_sm2_sign_req->digest = tbs;
    ecdsa_sm2_sign_req->dig_len = tbslen;

    mb_queue_ecdsa_sm2_sign_enqueue(tlv->ecdsa_sm2_sign_queue, ecdsa_sm2_sign_req);
    STOP_RDTSC(&ecdsa_cycles_sign_setup, 1, "[ECDSA:sign_setup]");

    if (!enable_external_polling && (++req_num % MULTIBUFF_MAX_BATCH) == 0) {
        DEBUG("Signal Polling thread, req_num %d\n", req_num);
        if (sem_post(&tlv->mb_polling_thread_sem) != 0) {
            WARN("hw sem_post failed!, mb_polling_thread_sem address: %p.\n",
                  &tlv->mb_polling_thread_sem);
            /* If we fail the pthread_kill carry on as the timeout
             * will catch processing the request in the polling thread */
        }
    }

    DEBUG("Pausing: %p status = %d\n", ecdsa_sm2_sign_req, sts);
    do {
        /* If we get a failure on qat_pause_job then we will
         * not flag an error here and quit because we have
         * an asynchronous request in flight.
         * We don't want to start cleaning up data
         * structures that are still being used. If
         * qat_pause_job fails we will just yield and
         * loop around and try again until the request
         * completes and we can continue. */
        if ((job_ret = qat_pause_job(job, ASYNC_STATUS_OK)) == 0)
            sched_yield();
    } while (QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DEBUG("Finished: %p status = %d\n", ecdsa_sm2_sign_req, sts);

    if (sts) {
        /* Convert the buffers to BN */
        BN_bin2bn(sig, buflen, ecdsa_sig_r);
        BN_bin2bn(sig + buflen, buflen, ecdsa_sig_s);

        *siglen = i2d_ECDSA_SIG(s, &sig);

        DEBUG("siglen %zu, tbslen %zu\n", *siglen, tbslen);
        ECDSA_SIG_free(s);
        ret = 1;
    } else {
        WARN("Failure in ECDSA Sign\n");
        QATerr(QAT_F_MB_ECDSA_SM2_SIGN, QAT_R_ECDSA_SIGN_FAILURE);
        goto err;
    }

err:
    if (!ret) {
        ECDSA_SIG_free(s);
        if (siglen != NULL)
            *siglen = 0;
    }

    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;

use_sw_method:
#ifdef QAT_OPENSSL_PROVIDER
    /* When using OpenSSL 3 provider API */
    sw_sm2_signature = get_default_signature_sm2();
    if (sw_sm2_signature.digest_sign) {
        return sw_sm2_signature.digest_sign((void*)smctx, sig, siglen, sigsize, tbs, tbslen);
    } else {
        if (sw_sm2_signature.digest_sign_update == NULL ||
                sw_sm2_signature.digest_sign_final == NULL) {
            WARN("ECDSA  digest_sign_update is NULL or digest_sign_final is NULL\n");
            QATerr(QAT_F_MB_ECDSA_SM2_SIGN, QAT_R_ECDSA_SIGN_NULL);
            return 0;
        }
        if (sw_sm2_signature.digest_sign_update((void*)smctx, tbs, tbslen) <= 0) {
            return 0;
        }
        return sw_sm2_signature.digest_sign_final((void*)smctx, sig, siglen, sigsize);
    }
#else
# ifdef QAT_OPENSSL_3
    /* When using OpenSSL 3 legacy engine API */
    sw_sm2_signature = get_default_signature_sm2();

    sw_ctx = OPENSSL_malloc(sizeof(QAT_PROV_SM2_CTX));
    sw_ctx->mdsize = 0;
    sw_ctx->ec = (EC_KEY *)eckey;

    md = (EVP_MD *)EVP_sm3();
    e = sm2_compute_msg_hash(md, eckey, smctx->id, smctx->id_len, tbs, tbslen);
    dgst = OPENSSL_zalloc(SM3_DIGEST_LENGTH);
    dlen = BN_bn2bin(e, dgst);

    if (sw_sm2_signature.sign) {
        sts = sw_sm2_signature.sign(sw_ctx, sig, siglen, ECDSA_size(eckey), dgst, dlen);
    } else {
        WARN("Failed to obtain sm2 sign func from default provider.\n");
        sts = 0;
    }

    OPENSSL_free(dgst);
    BN_free(e);
    OPENSSL_free(sw_ctx);
    return sts;
# else
    /* When using OpenSSL 1.1.1 */
    EVP_PKEY_meth_get_sign((EVP_PKEY_METHOD *)sw_sm2_pmeth, NULL, &psign);
    md = (EVP_MD *)EVP_sm3();
    e = sm2_compute_msg_hash(md, eckey, smctx->id, smctx->id_len, tbs, tbslen);
    dgst = OPENSSL_zalloc(SM3_DIGEST_LENGTH);
    dlen = BN_bn2bin(e, dgst);

    sts = (*psign)(pctx, sig, siglen, dgst, dlen);
    OPENSSL_free(dgst);
    BN_free(e);
    DEBUG("SW Finished\n");
    return sts;
# endif
#endif
}

# ifdef QAT_OPENSSL_PROVIDER
int mb_ecdsa_sm2_verify(QAT_PROV_SM2_CTX *smctx,
                               const unsigned char *sig, size_t siglen,
                               const unsigned char *tbs,
                               size_t tbslen)
# else
int mb_ecdsa_sm2_verify(EVP_MD_CTX *mctx,
                               const unsigned char *sig, size_t siglen,
                               const unsigned char *tbs,
                               size_t tbslen)
# endif
{
    int ret = 0, sts =0, job_ret = 0;
    const EC_GROUP *group = NULL;
    const BIGNUM *order = NULL;
    const EC_POINT *pub_key = NULL;
    ASYNC_JOB *job;
    ecdsa_sm2_verify_op_data *ecdsa_sm2_verify_req = NULL;
    mb_thread_data *tlv = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL;
    static __thread int req_num = 0;
    ECDSA_SIG *s = NULL;
    BN_CTX *ctx = NULL;
    const unsigned char *p = sig;
    unsigned char *der = NULL;
    int derlen = -1;

/* Only used for OpenSSL 3 legacy engine API */
#if defined(QAT_OPENSSL_3) && !defined(QAT_OPENSSL_PROVIDER)
    QAT_PROV_SM2_CTX *sw_ctx;
#endif

#ifndef QAT_OPENSSL_PROVIDER
    unsigned char *dgst = NULL;
    BIGNUM *e = NULL;
    EVP_MD *md = NULL;
    int dlen = 0;
#endif

#ifdef QAT_OPENSSL_3
    QAT_EVP_SIGNATURE sw_sm2_signature;
#else
    int (*pverify) (EVP_PKEY_CTX *pctx,
                    const unsigned char *sig, size_t siglen,
                    const unsigned char *dgst, size_t tbslen) = NULL;
#endif

# ifdef QAT_OPENSSL_PROVIDER
    const EC_KEY *eckey = smctx->ec;
# else
    EVP_PKEY_CTX *pctx = EVP_MD_CTX_pkey_ctx(mctx);
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(pctx);
    const EC_KEY *eckey = EVP_PKEY_get0_EC_KEY(pkey);
# endif

    if (unlikely(eckey == NULL)) {
        WARN("Invalid Input param\n");
        QATerr(QAT_F_MB_ECDSA_SM2_VERIFY, QAT_R_INPUT_PARAM_INVALID);
        return ret;
    }

    group = EC_KEY_get0_group(eckey);
    pub_key = EC_KEY_get0_public_key(eckey);

    if (group == NULL || pub_key == NULL) {
        WARN("Either group or pub_key are NULL\n");
        QATerr(QAT_F_MB_ECDSA_SM2_VERIFY, QAT_R_GROUP_PRIV_KEY_PUB_KEY_NULL);
        return ret;
    }

# ifndef QAT_OPENSSL_PROVIDER
    QAT_SM2_PKEY_CTX *smctx = (QAT_SM2_PKEY_CTX *)EVP_PKEY_CTX_get_data(pctx);
    if (!smctx->id_set) {
        smctx->id_set = 1;
        smctx->id = (uint8_t*)OPENSSL_memdup(SM2_DEFAULT_USERID, SM2_DEFAULT_USERID_LEN);
        smctx->id_len = SM2_DEFAULT_USERID_LEN;
    }
# endif

# if defined(QAT_OPENSSL_3) && !defined(QAT_OPENSSL_PROVIDER)
    if (qat_openssl3_sm2_fallback == 1) {
        DEBUG("- Switched to software mode\n");
        goto use_sw_method;
    }
# endif

    /* QAT SW initialization fail, switching to OpenSSL. */
    if (fallback_to_openssl)
        goto use_sw_method;

    /* Check if we are running asynchronously */
    if ((job = ASYNC_get_current_job()) == NULL) {
        DEBUG("Running synchronously using sw method\n");
        goto use_sw_method;
    }

    /* Setup asynchronous notifications */
    if (!qat_setup_async_event_notification(job)) {
        DEBUG("Failed to setup async notifications, using sw method\n");
        goto use_sw_method;
    }

    tlv = mb_check_thread_local();
    if (NULL == tlv) {
        WARN("Could not create thread local variables\n");
        goto use_sw_method;
    }

    while ((ecdsa_sm2_verify_req =
            mb_flist_ecdsa_sm2_verify_pop(tlv->ecdsa_sm2_verify_freelist)) == NULL) {
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
    }

    DEBUG("QAT SW ECDSA SM2 Verify Started %p\n", ecdsa_sm2_verify_req);
    START_RDTSC(&ecdsa_cycles_verify_setup);

    /* Buffer up the requests and call the new functions when we have enough
     * requests buffered up */

    if ((s = ECDSA_SIG_new()) == NULL) {
        mb_flist_ecdsa_sm2_verify_push(tlv->ecdsa_sm2_verify_freelist, ecdsa_sm2_verify_req);
        WARN("Failure to allocate ECDSA_SIG_SM2\n");
        QATerr(QAT_F_MB_ECDSA_SM2_VERIFY, QAT_R_ECDSA_SIG_MALLOC_FAILURE);
        return ret;
    }

    if (d2i_ECDSA_SIG(&s, &p, siglen) == NULL) {
        WARN("Failure to get ECDSA_SIG_SM2\n");
        return ret;
    }

    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = i2d_ECDSA_SIG(s, &der);
    if (derlen != siglen || memcmp(sig, der, derlen) != 0) {
        WARN("Failure to get ECDSA_SIG_SM2\n");
        return ret;
    }

    if ((ctx = BN_CTX_new()) == NULL) {
        mb_flist_ecdsa_sm2_verify_push(tlv->ecdsa_sm2_verify_freelist, ecdsa_sm2_verify_req);
        WARN("Failure to allocate ctx\n");
        QATerr(QAT_F_MB_ECDSA_SM2_VERIFY, QAT_R_CTX_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    z = BN_CTX_get(ctx);

    if (x == NULL || y == NULL || z == NULL) {
        mb_flist_ecdsa_sm2_verify_push(tlv->ecdsa_sm2_verify_freelist, ecdsa_sm2_verify_req);
        WARN("Failed to allocate x or y or z\n");
        QATerr(QAT_F_MB_ECDSA_SM2_VERIFY, QAT_R_X_Y_Z_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_POINT_get_Jprojective_coordinates_GFp(group, pub_key, x, y, z, ctx)) {
        mb_flist_ecdsa_sm2_verify_push(tlv->ecdsa_sm2_verify_freelist, ecdsa_sm2_verify_req);
        WARN("Failure to get the Jacobian coordinates for public Key\n");
        QATerr(QAT_F_MB_ECDSA_SM2_VERIFY, QAT_R_INTERNAL_ERROR);
        goto err;
    }

    if ((order = EC_GROUP_get0_order(group)) ==  NULL) {
        mb_flist_ecdsa_sm2_verify_push(tlv->ecdsa_sm2_verify_freelist, ecdsa_sm2_verify_req);
        WARN("Failure to get order from group\n");
        QATerr(QAT_F_MB_ECDSA_SM2_VERIFY, QAT_R_GET_ORDER_FAILURE);
        goto err;
    }

    ecdsa_sm2_verify_req->s = s;
    ecdsa_sm2_verify_req->x = x;
    ecdsa_sm2_verify_req->y = y;
    ecdsa_sm2_verify_req->z = z;
    ecdsa_sm2_verify_req->job = job;
    ecdsa_sm2_verify_req->sts = &sts;
    ecdsa_sm2_verify_req->id = smctx->id;
    ecdsa_sm2_verify_req->id_len = smctx->id_len;
    ecdsa_sm2_verify_req->digest = tbs;
    ecdsa_sm2_verify_req->dig_len = tbslen;

    mb_queue_ecdsa_sm2_verify_enqueue(tlv->ecdsa_sm2_verify_queue, ecdsa_sm2_verify_req);

    STOP_RDTSC(&ecdsa_cycles_verify_setup, 1, "[ECDSA:verify_setup]");

    if (!enable_external_polling && (++req_num % MULTIBUFF_MAX_BATCH) == 0) {
        DEBUG("Signal Polling thread, req_num %d\n", req_num);
        if (sem_post(&tlv->mb_polling_thread_sem) != 0) {
            WARN("hw sem_post failed!, mb_polling_thread_sem address: %p.\n",
                  &tlv->mb_polling_thread_sem);
            /* If we fail the pthread_kill carry on as the timeout
             * will catch processing the request in the polling thread */
        }
    }

    DEBUG("Pausing: %p status = %d\n", ecdsa_sm2_verify_req, sts);
    do {
        /* If we get a failure on qat_pause_job then we will
         * not flag an error here and quit because we have
         * an asynchronous request in flight.
         * We don't want to start cleaning up data
         * structures that are still being used. If
         * qat_pause_job fails we will just yield and
         * loop around and try again until the request
         * completes and we can continue. */
        if ((job_ret = qat_pause_job(job, ASYNC_STATUS_OK)) == 0)
            sched_yield();
    } while (QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DEBUG("Finished: %p status = %d\n", ecdsa_sm2_verify_req, sts);

    if (sts) {
        ret = 1;
        ECDSA_SIG_free(s);
        OPENSSL_free(der);
    } else {
        WARN("Failure in ECDSA_SM2 Verify\n");
        QATerr(QAT_F_MB_ECDSA_SM2_VERIFY, QAT_R_ECDSA_VERIFY_FAILURE);
        goto err;
    }

err:
    if (!ret) {
        ECDSA_SIG_free(s);
        OPENSSL_free(der);
    }

    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;

use_sw_method:
#ifdef QAT_OPENSSL_PROVIDER
    /* When using OpenSSL 3 provider API */
    sw_sm2_signature = get_default_signature_sm2();
    if (sw_sm2_signature.digest_verify) {
        return sw_sm2_signature.digest_verify((void*)smctx, sig, siglen, tbs, tbslen);
    } else {
        if (sw_sm2_signature.digest_verify_update == NULL ||
                sw_sm2_signature.digest_verify_final == NULL) {
            WARN("ECDSA  digest_verify_update is NULL or digest_verify_final is NULL\n");
            QATerr(QAT_F_MB_ECDSA_SM2_VERIFY, QAT_R_ECDSA_VERIFY_NULL);
            return -1;
        }
        if (sw_sm2_signature.digest_verify_update((void*)smctx, tbs, tbslen) <= 0) {
            return -1;
        }
        return sw_sm2_signature.digest_verify_final((void*)smctx, sig, siglen);
    }
#else
# ifdef QAT_OPENSSL_3
    /* When using OpenSSL 3 legacy engine API */

    sw_sm2_signature = get_default_signature_sm2();

    sw_ctx = OPENSSL_malloc(sizeof(QAT_PROV_SM2_CTX));
    sw_ctx->mdsize = 0;
    sw_ctx->ec = (EC_KEY *)eckey;

    md = (EVP_MD *)EVP_sm3();
    e = sm2_compute_msg_hash(md, eckey, smctx->id, smctx->id_len, tbs, tbslen);
    dgst = OPENSSL_zalloc(SM3_DIGEST_LENGTH);
    dlen = BN_bn2bin(e, dgst);

    if (sw_sm2_signature.sign) {
        sts = sw_sm2_signature.verify(sw_ctx, sig, siglen, dgst, dlen);
    } else {
        WARN("Failed to obtain sm2 verify func from default provider.\n");
        sts = 0;
    }
    OPENSSL_free(dgst);
    BN_free(e);
    OPENSSL_free(sw_ctx);
    return sts;
# else
    /* When using OpenSSL 1.1.1 */
    EVP_PKEY_meth_get_verify((EVP_PKEY_METHOD *)sw_sm2_pmeth,
                              NULL, &pverify);
    md = (EVP_MD *)EVP_sm3();
    e = sm2_compute_msg_hash(md, eckey, smctx->id,
                             smctx->id_len, tbs, tbslen);
    dgst = OPENSSL_zalloc(SM3_DIGEST_LENGTH);
    dlen = BN_bn2bin(e, dgst);
    sts = (*pverify)(pctx, sig, siglen, dgst, dlen);
    OPENSSL_free(dgst);
    BN_free(e);
    DEBUG("SW Finished, ret: %d\n", sts);
    return sts;
# endif
#endif /* QAT_OPENSSL_PROVIDER */
}
#endif /*ENABLE_QAT_SW_SM2*/
