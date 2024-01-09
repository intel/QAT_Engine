/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2023-2024 Intel Corporation.
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
 * @file qat_self_test_kats.c
 *
 * This file provides an implementation to perform qat self test
 *
 *****************************************************************************/

#include "qat_fips.h"
#ifndef FIPS_MODULE
# define FIPS_MODULE 1
#endif

#ifdef ENABLE_QAT_FIPS

extern int qat_fips_kat_test;

int add_params(OSSL_PARAM_BLD *bld, const ST_KAT_PARAM *params, BN_CTX *ctx)
{
    int ret = 0;
    const ST_KAT_PARAM *p;
    BIGNUM *bn = NULL;

    if (params == NULL) {
        WARN("params are NULL,...so quitting..\n");
        return 1;
    }

    for (p = params; p->data != NULL; ++p) {
        switch (p->type) {
        case OSSL_PARAM_UNSIGNED_INTEGER:
            bn = BN_CTX_get(ctx);

            if (bn == NULL || (BN_bin2bn(p->data, p->data_len, bn) == NULL)
                || !OSSL_PARAM_BLD_push_BN(bld, p->name, bn))
                goto err;
            break;
        case OSSL_PARAM_UTF8_STRING:
            if (!OSSL_PARAM_BLD_push_utf8_string(bld, p->name, p->data,
                                                 p->data_len))
                goto err;
            break;
        case OSSL_PARAM_OCTET_STRING:
            if (!OSSL_PARAM_BLD_push_octet_string(bld, p->name, p->data,
                                                  p->data_len))
                goto err;
            break;
        case OSSL_PARAM_INTEGER:
            if (!OSSL_PARAM_BLD_push_int(bld, p->name, *(int *)p->data))
                goto err;
            break;
        default:
            break;
        }
    }
    ret = 1;
 err:
    return ret;
}

/*
 * Helper function to setup a EVP_CipherInit
 * Used to hide the complexity of Authenticated ciphers.
 */
static int cipher_init(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                       const ST_KAT_CIPHER *t, int enc)
{
    unsigned char *in_tag = NULL;
    int pad = 0, tmp;

    /* Flag required for Key wrapping */
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (t->tag == NULL) {
        /* Use a normal cipher init */
        return EVP_CipherInit_ex(ctx, cipher, NULL, t->key, t->iv, enc)
            && EVP_CIPHER_CTX_set_padding(ctx, pad);
    }

    /* The authenticated cipher init */
    if (!enc)
        in_tag = (unsigned char *)t->tag;

    return EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, enc)
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, t->iv_len, NULL)
        && (in_tag == NULL
            || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, t->tag_len,
                                   in_tag))
        && EVP_CipherInit_ex(ctx, NULL, NULL, t->key, t->iv, enc)
        && EVP_CIPHER_CTX_set_padding(ctx, pad)
        && EVP_CipherUpdate(ctx, NULL, &tmp, t->aad, t->aad_len);
}

int RSA_components_update(RSA *rsa, size_t size)
{
    int ret = 1;
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    BIGNUM *d = NULL;
    BIGNUM *p = NULL;
    BIGNUM *q = NULL;
    BIGNUM *dmp1 = NULL;
    BIGNUM *dmq1 = NULL;
    BIGNUM *iqmp = NULL;

    if (size > 1024 && size <= 2048) {
        /* bignumber format needed for RSA structure */
        if (((n = BN_bin2bn(rsa_n, sizeof(rsa_n), NULL)) == NULL) ||
            ((e = BN_bin2bn(rsa_e, sizeof(rsa_e), NULL)) == NULL) ||
            ((d = BN_bin2bn(rsa_d, sizeof(rsa_d), NULL)) == NULL) ||
            ((p = BN_bin2bn(rsa_p, sizeof(rsa_p), NULL)) == NULL) ||
            ((q = BN_bin2bn(rsa_q, sizeof(rsa_q), NULL)) == NULL) ||
            ((dmp1 = BN_bin2bn(rsa_dp, sizeof(rsa_dp), NULL)) == NULL) ||
            ((dmq1 = BN_bin2bn(rsa_dq, sizeof(rsa_dq), NULL)) == NULL) ||
            ((iqmp = BN_bin2bn(rsa_qInv, sizeof(rsa_qInv), NULL)) == NULL)) {
            WARN("# FAIL RSA - Failed setting parameters\n");
            ret = 0;
            if (n)
                BN_free(n);
            if (e)
                BN_free(e);
            if (d)
                BN_free(d);
            if (p)
                BN_free(p);
            if (q)
                BN_free(q);
            if (dmp1)
                BN_free(dmp1);
            if (dmq1)
                BN_free(dmq1);
            if (iqmp)
                BN_free(iqmp);
        }
    }

    RSA_set0_key(rsa, n, e, d);
    RSA_set0_factors(rsa, p, q);
    RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp);

    return ret;
}

static int QAT_self_test_sign(const ST_KAT_SIGN *t,
                              TEST_PARAMS *args, OSSL_LIB_CTX *libctx)
{
    qat_fips_kat_test = 1;
    int ret = 0;
    OSSL_PARAM *params = NULL, *params_sig = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    EVP_PKEY_CTX *sctx = NULL, *kctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_SELF_TEST *st = args->st;
    unsigned char sig[256];
    const char *typ = OSSL_SELF_TEST_TYPE_KAT_SIGNATURE;
    BN_CTX *bnctx = NULL;
    size_t siglen = sizeof(sig);
    static const unsigned char dgst[] = {
        0x7f, 0x83, 0xb1, 0x65, 0x7f, 0xf1, 0xfc, 0x53, 0xb9, 0x2d, 0xc1, 0x81,
        0x48, 0xa1, 0xd6, 0x5d, 0xfc, 0x2d, 0x4b, 0x1f, 0xa3, 0xd6, 0x77, 0x28,
        0x4a, 0xdd, 0xd2, 0x00, 0x12, 0x6d, 0x90, 0x69
    };

    if (t->sig_expected == NULL)
        typ = OSSL_SELF_TEST_TYPE_PCT_SIGNATURE;

    OSSL_SELF_TEST_onbegin(st, typ, t->desc);

    bnctx = BN_CTX_new_ex(libctx);
    if (bnctx == NULL) {
        WARN("Error in memory creation for BN_CTX\n");
        ret = 0;
        goto err;
    }

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) {
        WARN("Error in memory creation for OSSL_PARAM_BLD\n");
        ret = 0;
        goto err;
    }

    if (!add_params(bld, t->key, bnctx)) {
        WARN("Error in add_params API\n");
        ret = 0;
        goto err;
    }
    params = OSSL_PARAM_BLD_to_param(bld);

    /* Create a EVP_PKEY_CTX to load the DSA key into */
    kctx = EVP_PKEY_CTX_new_from_name(libctx, t->algorithm, "");
    if (kctx == NULL || params == NULL) {
        WARN("Error in kctx creation..\n");
        ret = 0;
        goto err;
    }

    if (EVP_PKEY_fromdata_init(kctx) <= 0
        || EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        WARN("Error in EVP_PKEY_fromdata_init || EVP_PKEY_fromdata \n");
        ret = 0;
        goto err;
    }

    /* Create a EVP_PKEY_CTX to use for the signing operation */
    sctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL);

    /*calling QAT provider qat_signature_rsa_sign_init()
     * using EVP_PKEY_sign_init*/
    if (sctx == NULL || EVP_PKEY_sign_init(sctx) <= 0) {
        WARN("Error in EVP_PKEY_CTX_new_from_pkey\n");
        ret = 0;
        goto err;
    }

    /* set signature parameters */
    if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_SIGNATURE_PARAM_DIGEST,
                                         t->mdalgorithm,
                                         strlen(t->mdalgorithm) + 1)) {
        WARN("Error in OSSL_PARAM_BLD_push_utf8_string\n");
        goto err;
    }

    params_sig = OSSL_PARAM_BLD_to_param(bld);

    if (EVP_PKEY_CTX_set_params(sctx, params_sig) <= 0) {
        WARN("Error in EVP_PKEY_CTX_set_params..\n");
        ret = 0;
        goto err;
    }

    if (!strcmp(t->desc, OSSL_SELF_TEST_DESC_SIGN_RSA)) {
        QAT_EVP_PKEY_CTX *tctx = (QAT_EVP_PKEY_CTX *) sctx;
        QAT_PROV_RSA_CTX *vprsactx = (QAT_PROV_RSA_CTX *) tctx->op.sig.algctx;
        if (!RSA_components_update((RSA *)vprsactx->rsa, siglen * 8)) {
            WARN("Error: Failed to update RSA components!!..\n");
        }
    }

    if (EVP_PKEY_sign(sctx, sig, &siglen, dgst, sizeof(dgst)) <= 0)
        WARN("Error: Failed at EVP_PKEY_sign API!!..\n");

    if (EVP_PKEY_verify_init(sctx) <= 0)
        WARN("Error: Failed at EVP_PKEY_verify_init API!!..\n");

    if (EVP_PKEY_CTX_set_params(sctx, params_sig) <= 0) {
        WARN("Error: Failed at EVP_PKEY_CTX_set_params API!!..\n");
        ret = 0;
        goto err;
    }
    /*
     * Used by RSA, for other key types where the signature changes, we
     * can only use the verify.
     */
    DUMPL("Expected Sign", t->sig_expected, t->sig_expected_len);
    DUMPL("Actual Sign", sig, siglen);
    if (t->sig_expected != NULL
        && (siglen != t->sig_expected_len
            || memcmp(sig, t->sig_expected, t->sig_expected_len) != 0)) {
        WARN("Error: Failed at expected sig..\n");
        ret = 0;
        goto err;
    }

    OSSL_SELF_TEST_oncorrupt_byte(st, sig);
    if (EVP_PKEY_verify(sctx, sig, siglen, dgst, sizeof(dgst)) <= 0) {
        WARN("Error: Failed at EVP_PKEY_verify..\n");
        ret = 0;
        goto err;
    }

    ret = 1;

 err:
    BN_CTX_free(bnctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(sctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_free(params_sig);
    OSSL_PARAM_BLD_free(bld);
    OSSL_SELF_TEST_onend(st, ret);
    qat_fips_kat_test = 0;
    return ret;

}

# if !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_EC)
static int QAT_self_test_ka(const ST_KAT_KAS *t,
                            TEST_PARAMS *args, OSSL_LIB_CTX *libctx)
{
    int ret = 0;
    EVP_PKEY_CTX *kactx = NULL, *dctx = NULL;
    EVP_PKEY *pkey = NULL, *peerkey = NULL;
    OSSL_PARAM *params = NULL;
    OSSL_PARAM *params_peer = NULL;
    unsigned char secret[256];
    size_t secret_len = sizeof(secret);
    OSSL_PARAM_BLD *bld = NULL;
    BN_CTX *bnctx = NULL;
    OSSL_SELF_TEST *st = args->st;

    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_KAT_KA, t->desc);

    bnctx = BN_CTX_new_ex(libctx);
    if (bnctx == NULL)
        goto err;

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL)
        goto err;

    if (!add_params(bld, t->key_group, bnctx)
        || !add_params(bld, t->key_host_data, bnctx))
        goto err;
    params = OSSL_PARAM_BLD_to_param(bld);

    if (!add_params(bld, t->key_group, bnctx)
        || !add_params(bld, t->key_peer_data, bnctx))
        goto err;

    params_peer = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL || params_peer == NULL)
        goto err;

    /* Create a EVP_PKEY_CTX to load the DH keys into */
    kactx = EVP_PKEY_CTX_new_from_name(libctx, t->algorithm, "");
    if (kactx == NULL)
        goto err;
    if (EVP_PKEY_fromdata_init(kactx) <= 0
        || EVP_PKEY_fromdata(kactx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0)
        goto err;
    if (EVP_PKEY_fromdata_init(kactx) <= 0
        || EVP_PKEY_fromdata(kactx, &peerkey, EVP_PKEY_KEYPAIR,
                             params_peer) <= 0)
        goto err;

    /* Create a EVP_PKEY_CTX to perform key derivation */
    dctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL);
    if (dctx == NULL)
        goto err;

    if (EVP_PKEY_derive_init(dctx) <= 0
        || EVP_PKEY_derive_set_peer(dctx, peerkey) <= 0
        || EVP_PKEY_derive(dctx, secret, &secret_len) <= 0)
        goto err;

    OSSL_SELF_TEST_oncorrupt_byte(st, secret);

    DUMPL("Expected Secret Key", t->expected, t->expected_len);
    DUMPL("Actual Secret Key", secret, secret_len);

    if (secret_len != t->expected_len
        || memcmp(secret, t->expected, t->expected_len) != 0)
        goto err;
    ret = 1;
 err:
    BN_CTX_free(bnctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peerkey);
    EVP_PKEY_CTX_free(kactx);
    EVP_PKEY_CTX_free(dctx);
    OSSL_PARAM_free(params_peer);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    OSSL_SELF_TEST_onend(st, ret);
    return ret;
}
# endif                         /* !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_EC) */

static int QAT_self_test_kdf(const ST_KAT_KDF *t, TEST_PARAMS *args,
                             OSSL_LIB_CTX *libctx)
{
    int ret = 0;
    unsigned char out[128], *prf_out[128];
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *ctx = NULL;
    BN_CTX *bnctx = NULL;
    OSSL_PARAM *params = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_SELF_TEST *st = args->st;

    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_KAT_KDF, t->desc);

    if (!strcmp(t->desc, "TLS13_KDF_EXTRACT_256")
        || !strcmp(t->desc, "TLS13_KDF_EXPAND_256")
        || !strcmp(t->desc, "TLS13_KDF_EXTRACT_384")
        || !strcmp(t->desc, "TLS13_KDF_EXPAND_384")) {
        bld = OSSL_PARAM_BLD_new();
        if (bld == NULL) {
            printf("Error in memory creation for OSSL_PARAM_BLD\n");
            ret = 0;
            goto err;
        }

        kdf = EVP_KDF_fetch(libctx, t->algorithm, "");
        if (kdf == NULL) {
            printf("Error in kdf fetch..\n");
            ret = 0;
            goto err;
        }
        ctx = EVP_KDF_CTX_new(kdf);
        if (ctx == NULL) {
            printf("Error in kctx creation..\n");
            ret = 0;
            goto err;
        }

        bnctx = BN_CTX_new_ex(libctx);
        if (bnctx == NULL) {
            printf("Error in memory creation for BN_CTX\n");
            ret = 0;
            goto err;
        }

        if (!add_params(bld, t->params, bnctx)) {
            printf("Error in add_params API\n");
            ret = 0;
            goto err;
        }

        params = OSSL_PARAM_BLD_to_param(bld);
        if (params == NULL)
            goto err;

        if (t->expected_len > sizeof(out))
            goto err;

        if (EVP_KDF_derive(ctx, out, t->expected_len, params) <= 0)
            goto err;
    }

    if (!strcmp(t->desc, "TLS12_PRF_256") || !strcmp(t->desc, "TLS12_PRF_384")) {
        *prf_out = out;
        if (QAT_TlsPrf_Ops(args, *prf_out, t->expected_len, t->desc) <= 0) {
            WARN("Error in QAT_TlsPrf_Ops API\n");
            goto err;
        }
    }

    OSSL_SELF_TEST_oncorrupt_byte(st, out);

    if (!strcmp(t->desc, "TLS12_PRF_256") || !strcmp(t->desc, "TLS12_PRF_384")) {
        if (memcmp(*prf_out, t->expected, t->expected_len) != 0)
            goto err;
    }

    if (!strcmp(t->desc, "TLS13_KDF_EXTRACT_256")
        || !strcmp(t->desc, "TLS13_KDF_EXPAND_256")
        || !strcmp(t->desc, "TLS13_KDF_EXTRACT_384")
        || !strcmp(t->desc, "TLS13_KDF_EXPAND_384")) {
        DUMPL("Expected Secret Key", t->expected, t->expected_len);
        DUMPL("Actual Secret Key", out, t->expected_len);

        if (memcmp(out, t->expected, t->expected_len) != 0)
            goto err;
    }

    ret = 1;

 err:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(ctx);
    BN_CTX_free(bnctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    OSSL_SELF_TEST_onend(st, ret);
    return ret;
}

/* Test a single KAT for encrypt/decrypt */
static int QAT_self_test_cipher(const ST_KAT_CIPHER *t, TEST_PARAMS *args,
                                OSSL_LIB_CTX *libctx)
{
    int ret = 0, encrypt = 1, len = 0, ct_len = 0, pt_len = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    unsigned char ct_buf[256] = { 0 };
    unsigned char pt_buf[256] = { 0 };
    OSSL_SELF_TEST *st = args->st;

    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_KAT_CIPHER, t->base.desc);

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto err;
    cipher = EVP_CIPHER_fetch(libctx, t->base.algorithm, NULL);
    if (cipher == NULL)
        goto err;

    /* Encrypt plain text message */
    if ((t->mode & CIPHER_MODE_ENCRYPT) != 0) {
        if (!cipher_init(ctx, cipher, t, encrypt)
            || !EVP_CipherUpdate(ctx, ct_buf, &len, t->base.pt, t->base.pt_len)
            || !EVP_CipherFinal_ex(ctx, ct_buf + len, &ct_len))
            goto err;

        OSSL_SELF_TEST_oncorrupt_byte(st, ct_buf);
        ct_len += len;
        if (ct_len != (int)t->base.expected_len
            || memcmp(t->base.expected, ct_buf, ct_len) != 0)
            goto err;

        if (t->tag != NULL) {
            unsigned char tag[16] = { 0 };

            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, t->tag_len,
                                     tag)
                || memcmp(tag, t->tag, t->tag_len) != 0)
                goto err;
        }
    }

    /* Decrypt cipher text */
    if ((t->mode & CIPHER_MODE_DECRYPT) != 0) {
        if (!(cipher_init(ctx, cipher, t, !encrypt)
              && EVP_CipherUpdate(ctx, pt_buf, &len,
                                  t->base.expected, t->base.expected_len)
              && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, t->tag_len,
                                     (void *)t->tag)
              && EVP_CipherFinal_ex(ctx, pt_buf + len, &pt_len)))
            goto err;
        OSSL_SELF_TEST_oncorrupt_byte(st, pt_buf);
        pt_len += len;
        if (pt_len != (int)t->base.pt_len
            || memcmp(pt_buf, t->base.pt, pt_len) != 0)
            goto err;
    }

    ret = 1;
 err:
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    OSSL_SELF_TEST_onend(st, ret);
    return ret;
}

static int QAT_self_test_digest(const ST_KAT_DIGEST *t, TEST_PARAMS *args,
                                OSSL_LIB_CTX *libctx)
{
    int ok = 0;
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int out_len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_ONESHOT);
    EVP_MD *md = EVP_MD_fetch(libctx, t->algorithm, NULL);
    OSSL_SELF_TEST *st = args->st;

    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_KAT_DIGEST, t->desc);

    if (ctx == NULL || md == NULL || !EVP_DigestInit_ex(ctx, md, NULL)
        || !EVP_DigestUpdate(ctx, t->pt, t->pt_len)
        || !EVP_DigestFinal(ctx, out, &out_len))
        goto err;

    /* Optional corruption */
    OSSL_SELF_TEST_oncorrupt_byte(st, out);

    DUMPL("Expected output", t->expected, t->expected_len);
    DUMPL("Actual output", out, out_len);

    if (out_len != t->expected_len || memcmp(out, t->expected, out_len) != 0)
        goto err;
    ok = 1;
 err:
    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);
    OSSL_SELF_TEST_onend(st, ok);
    return ok;
}

static int qat_self_test_kdfs(TEST_PARAMS *args, OSSL_LIB_CTX *libctx)
{
    int i, ret = 1, count = 0;

    if (args->enable_async) {
        qat_async_kdf_result = (QAT_SELF_TEST_RESULT *)
            calloc(1, sizeof(QAT_SELF_TEST_RESULT));
    } else {
        qat_kdf_result = (QAT_SELF_TEST_RESULT *)
            calloc(1, sizeof(QAT_SELF_TEST_RESULT));
    }

    for (i = 0; i < (int)OSSL_NELEM(st_kat_kdf_tests); ++i) {
        if ((qat_hw_hkdf_offload == 0
             && !strcmp(st_kat_kdf_tests[i].desc, "TLS13_KDF_EXTRACT_256"))
            || (qat_hw_hkdf_offload == 0
                && !strcmp(st_kat_kdf_tests[i].desc, "TLS13_KDF_EXPAND_256"))
            || (qat_hw_hkdf_offload == 0
                && !strcmp(st_kat_kdf_tests[i].desc, "TLS13_KDF_EXTRACT_384"))
            || (qat_hw_hkdf_offload == 0
                && !strcmp(st_kat_kdf_tests[i].desc, "TLS13_KDF_EXPAND_384"))
            || (qat_hw_prf_offload == 0
                && !strcmp(st_kat_kdf_tests[i].desc, "TLS12_PRF_256"))
            || (qat_hw_prf_offload == 0
                && !strcmp(st_kat_kdf_tests[i].desc, "TLS12_PRF_384")))
            continue;

        if (!QAT_self_test_kdf(&st_kat_kdf_tests[i], args, libctx)) {
            ret = 0;
            count++;
        }

        if (args->enable_async) {
            qat_async_kdf_result->desc[i] = st_kat_kdf_tests[i].desc;
            qat_async_kdf_result->type[i] = OSSL_SELF_TEST_TYPE_KAT_KDF;
            qat_async_kdf_result->result[i] = ret;
        } else {
            qat_kdf_result->desc[i] = st_kat_kdf_tests[i].desc;
            qat_kdf_result->type[i] = OSSL_SELF_TEST_TYPE_KAT_KDF;
            qat_kdf_result->result[i] = ret;
        }
        ret = 1;
    }

    return (count ? 0 : 1);
}

static int qat_self_test_digests(TEST_PARAMS *args, OSSL_LIB_CTX *libctx)
{
    int i, ret = 1;

    if (args->enable_async) {
        qat_async_digest_result =
            (QAT_SELF_TEST_RESULT *) calloc(1, sizeof(QAT_SELF_TEST_RESULT));
    } else {
        qat_digest_result = (QAT_SELF_TEST_RESULT *)
            calloc(1, sizeof(QAT_SELF_TEST_RESULT));
    }

    for (i = 0; i < (int)OSSL_NELEM(st_kat_digest_tests); ++i) {
        if (qat_hw_sha_offload == 0
            && !strcmp(st_kat_digest_tests[i].desc, "SHA3"))
            continue;
        if (qat_sw_sha_offload == 0
            && !strcmp(st_kat_digest_tests[i].desc, "SHA256"))
            continue;
        if (qat_sw_sha_offload == 0
            && !strcmp(st_kat_digest_tests[i].desc, "SHA512"))
            continue;

        if (!QAT_self_test_digest(&st_kat_digest_tests[i], args, libctx))
            ret = 0;

        if (args->enable_async) {
            qat_async_digest_result->desc[i] = st_kat_digest_tests[i].desc;
            qat_async_digest_result->type[i] = OSSL_SELF_TEST_TYPE_KAT_DIGEST;
            qat_async_digest_result->result[i] = ret;
        } else {
            qat_digest_result->desc[i] = st_kat_digest_tests[i].desc;
            qat_digest_result->type[i] = OSSL_SELF_TEST_TYPE_KAT_DIGEST;
            qat_digest_result->result[i] = ret;
        }
    }

    return ret;
}

static int qat_self_test_ciphers(TEST_PARAMS *args, OSSL_LIB_CTX *libctx)
{
    int i, ret = 1, count = 0;

    if (args->enable_async) {
        qat_async_cipher_result = (QAT_SELF_TEST_RESULT *)
            calloc(1, sizeof(QAT_SELF_TEST_RESULT));
    } else {
        qat_cipher_result = (QAT_SELF_TEST_RESULT *)
            calloc(1, sizeof(QAT_SELF_TEST_RESULT));
    }

    for (i = 0; i < (int)OSSL_NELEM(st_kat_cipher_tests); ++i) {
        /* To skip self test when particular algorithm support is disabled */
        if (qat_hw_offload) {
            if ((qat_hw_gcm_offload == 0
                 && !strcmp(st_kat_cipher_tests[i].base.desc, "AES_GCM")))
                continue;
        } else {
            if ((qat_sw_gcm_offload == 0
                 && !strcmp(st_kat_cipher_tests[i].base.desc, "AES_GCM")))
                continue;
        }
        if (!QAT_self_test_cipher(&st_kat_cipher_tests[i], args, libctx)) {
            ret = 0;
            count++;
        }

        if (args->enable_async) {
            qat_async_cipher_result->desc[i] = st_kat_cipher_tests[i].base.desc;
            qat_async_cipher_result->type[i] = OSSL_SELF_TEST_TYPE_KAT_CIPHER;
            qat_async_cipher_result->result[i] = ret;
        } else {
            qat_cipher_result->desc[i] = st_kat_cipher_tests[i].base.desc;
            qat_cipher_result->type[i] = OSSL_SELF_TEST_TYPE_KAT_CIPHER;
            qat_cipher_result->result[i] = ret;
        }
        ret = 1;
    }
    return (count ? 0 : 1);
}

static int qat_self_test_kas(TEST_PARAMS *args, OSSL_LIB_CTX *libctx)
{
    int ret = 1, count = 0;

    if (args->enable_async) {
        qat_async_kas_result = (QAT_SELF_TEST_RESULT *)
            calloc(1, sizeof(QAT_SELF_TEST_RESULT));
    } else {
        qat_kas_result = (QAT_SELF_TEST_RESULT *)
            calloc(1, sizeof(QAT_SELF_TEST_RESULT));
    }
# if !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_EC)
    int i;

    for (i = 0; i < (int)OSSL_NELEM(st_kat_kas_tests); ++i) {
        /* To skip self test when particular algorithm support is disabled */
        if (qat_hw_offload) {
            if ((qat_hw_dh_offload == 0
                 && !strcmp(st_kat_kas_tests[i].desc, "DH"))
                || (qat_hw_ecdh_offload == 0
                    && !strcmp(st_kat_kas_tests[i].desc, "ECDHP256"))
                || (qat_hw_ecdh_offload == 0
                    && !strcmp(st_kat_kas_tests[i].desc, "ECDHP384"))
                || (qat_hw_ecx_offload == 0
                    && !strcmp(st_kat_kas_tests[i].desc, "ECX25519"))
                || (qat_hw_ecx_448_offload == 0
                    && !strcmp(st_kat_kas_tests[i].desc, "ECX448")))
                continue;
        } else {
            if ((qat_hw_dh_offload == 0
                 && !strcmp(st_kat_kas_tests[i].desc, "DH"))
                || (qat_sw_ecdh_offload == 0
                    && !strcmp(st_kat_kas_tests[i].desc, "ECDHP256"))
                || (qat_sw_ecdh_offload == 0
                    && !strcmp(st_kat_kas_tests[i].desc, "ECDHP384"))
                || (qat_sw_ecx_offload == 0
                    && !strcmp(st_kat_kas_tests[i].desc, "ECX25519"))
                || (qat_hw_ecx_448_offload == 0
                    && !strcmp(st_kat_kas_tests[i].desc, "ECX448")))
                continue;
        }

        if (!QAT_self_test_ka(&st_kat_kas_tests[i], args, libctx)) {
            ret = 0;
            count++;
        }

        if (args->enable_async) {
            qat_async_kas_result->desc[i] = st_kat_kas_tests[i].desc;
            qat_async_kas_result->type[i] = OSSL_SELF_TEST_TYPE_KAT_KA;
            qat_async_kas_result->result[i] = ret;
        } else {
            qat_kas_result->desc[i] = st_kat_kas_tests[i].desc;
            qat_kas_result->type[i] = OSSL_SELF_TEST_TYPE_KAT_KA;
            qat_kas_result->result[i] = ret;
        }
        ret = 1;
    }
# endif

    return (count ? 0 : 1);
}

static int qat_self_test_signatures(TEST_PARAMS *args, OSSL_LIB_CTX *libctx)
{
    int i, ret = 1, count = 0;

    if (args->enable_async) {
        qat_async_signature_result = (QAT_SELF_TEST_RESULT *)
            calloc(1, sizeof(QAT_SELF_TEST_RESULT));
    } else {
        qat_signature_result = (QAT_SELF_TEST_RESULT *)
            calloc(1, sizeof(QAT_SELF_TEST_RESULT));
    }

    /* Since expected sig value is different for QAT_HW QAT_SW
     * So that, Using different test vectors */
    if (qat_hw_offload) {       /* Self test for QAT_HW signature algorithms */
        for (i = 0; i < (int)OSSL_NELEM(st_kat_sign_tests); ++i) {
            /* To skip self test when particular algorithm support is disabled */
            if ((qat_hw_dsa_offload == 0
                 && !strcmp(st_kat_sign_tests[i].desc, "DSA"))
                || (qat_hw_rsa_offload == 0
                    && !strcmp(st_kat_sign_tests[i].desc, "RSA"))
                || (qat_hw_ecdsa_offload == 0
                    && !strcmp(st_kat_sign_tests[i].desc, "ECDSAP256"))
                || (qat_hw_ecdsa_offload == 0
                    && !strcmp(st_kat_sign_tests[i].desc, "ECDSAP384")))
                continue;

            if (!QAT_self_test_sign(&st_kat_sign_tests[i], args, libctx)) {
                ret = 0;
                count++;
            }

            if (args->enable_async) {
                qat_async_signature_result->desc[i] = st_kat_sign_tests[i].desc;
                qat_async_signature_result->type[i] =
                    OSSL_SELF_TEST_TYPE_KAT_SIGNATURE;
                qat_async_signature_result->result[i] = ret;
            } else {
                qat_signature_result->desc[i] = st_kat_sign_tests[i].desc;
                qat_signature_result->type[i] =
                    OSSL_SELF_TEST_TYPE_KAT_SIGNATURE;
                qat_signature_result->result[i] = ret;
            }
            ret = 1;
        }
    } else {                    /* Self test for QAT_SW signature algorithms */
        for (i = 0; i < (int)OSSL_NELEM(st_kat_sw_sign_tests); ++i) {
            /* To skip self test when particular algorithm support is disabled */
            if ((qat_hw_dsa_offload == 0
                 && !strcmp(st_kat_sign_tests[i].desc, "DSA"))
                || (qat_sw_rsa_offload == 0
                    && !strcmp(st_kat_sign_tests[i].desc, "RSA"))
                || (qat_sw_ecdsa_offload == 0
                    && !strcmp(st_kat_sign_tests[i].desc, "ECDSAP256"))
                || (qat_sw_ecdsa_offload == 0
                    && !strcmp(st_kat_sign_tests[i].desc, "ECDSAP384")))
                continue;

            if (!QAT_self_test_sign(&st_kat_sw_sign_tests[i], args, libctx)) {
                ret = 0;
                count++;
            }

            if (args->enable_async) {
                qat_async_signature_result->desc[i] =
                    st_kat_sw_sign_tests[i].desc;
                qat_async_signature_result->type[i] =
                    OSSL_SELF_TEST_TYPE_KAT_SIGNATURE;
                qat_async_signature_result->result[i] = ret;
            } else {
                qat_signature_result->desc[i] = st_kat_sw_sign_tests[i].desc;
                qat_signature_result->type[i] =
                    OSSL_SELF_TEST_TYPE_KAT_SIGNATURE;
                qat_signature_result->result[i] = ret;
            }
            ret = 1;
        }
    }
    return (count ? 0 : 1);
}

/*
 * Run the algorithm KAT's.
 * Return 1 is successful, otherwise return 0.
 * Here we will call or add required tests.
 * This runs all the tests regardless of if any fail.
 */
int QAT_SELF_TEST_kats(void *args)
{
    int ret = 1;
    TEST_PARAMS *temp_args = (TEST_PARAMS *) args;

    if (!qat_self_test_signatures(temp_args, temp_args->provctx))
        ret = 0;
    if (!qat_self_test_kas(temp_args, temp_args->provctx))
        ret = 0;
    if (!qat_self_test_ciphers(temp_args, temp_args->provctx))
        ret = 0;
    if (!qat_self_test_kdfs(temp_args, temp_args->provctx))
        ret = 0;
    if (!qat_self_test_digests(temp_args, temp_args->provctx))
        ret = 0;

    return ret;
}
#endif
