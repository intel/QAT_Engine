/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2023-2025 Intel Corporation.
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
 * @file qat_prov_cmvp.c
 *
 * This file contains the qatprovider FIPs CMVP features implementation
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#ifdef QAT_HW
# define NID_dh2048 1126
# define NID_dh3072 1127
# define NID_dh4096 1128
# define NID_dh8192 1130
# define MAX_DH_SIZE 1024
#endif

#include "qat_prov_cmvp.h"

#ifdef ENABLE_QAT_FIPS
extern int qat_fips_key_zeroize;

int qat_fips_service_indicator = 0;

int qat_provider_info(void)
{
    INFO("Module Info\n");
    INFO("\tName: %s\n", QAT_FIPS_PROVIDER_NAME);
    INFO("\tID: %s\n", QAT_FIPS_PROVIDER_ID);
    INFO("\tVersion: %s\n", QAT_FIPS_PROVIDER_VERSION);
# ifdef QAT_HW
    INFO("\tQAT_HW Driver version: %s\n", QAT_HW_DRIVER_version);
# endif
# ifdef QAT_SW
    INFO("\tIPSec-mb version: %s\n", QAT_FIPS_IPSec_mb_QAT_SW_VERSION);
    INFO("\tIPP-crypto version: %s\n\n", QAT_FIPS_IPP_crypto_QAT_SW_VERSION);
# endif
    return 0;
}

# ifdef QAT_HW
/*
 * DSA FIPS range Supported in QAT {L,N} = {2048, 224}, {2048, 256}, {3072, 256}
 */
int dsa_fips_range[3][2] = {
    {2048, 224},
    {2048, 256},
    {3072, 256}
};

/*
 * DSA FIPS range check is performed so that if the sizes of P and Q are not in
 * the range supported by QAT engine then fall back to software
 */

int dsa_fips_range_check(int plen, int qlen)
{
    int i, j, range = 0;

    for (i = 0, j = 0; i < 3; i++) {
        if ((plen == dsa_fips_range[i][j])
            && (qlen == dsa_fips_range[i][j + 1])) {
            range = 1;
            break;
        }
    }
    return range;
}
# endif

char *qat_fips_ec_non_approved_curve(int nid)
{
    switch (nid) {
    case NID_X9_62_prime192v1:
        return "Prime-Curve P-192";
    case NID_sect163r2:
        return "Binary-Curve B-163";
    case NID_sect163k1:
        return "Binary-Curve K-163";
# ifdef QAT_SW
    case NID_secp224r1:
        return "Prime-Curve P-224";
    case NID_secp521r1:
        return "Prime-Curve P-521";
    case NID_sect233k1:
        return "Binary-Curve K-233";
    case NID_sect283k1:
        return "Binary-Curve K-283";
    case NID_sect409k1:
        return "Binary-Curve K-409";
    case NID_sect571k1:
        return "Binary-Curve K-571";
    case NID_sect233r1:
        return "Binary-Curve B-233";
    case NID_sect283r1:
        return "Binary-Curve B-283";
    case NID_sect409r1:
        return "Binary-Curve B-409";
    case NID_sect571r1:
        return "Binary-Curve B-571";
# endif
    default:
        INFO("Unsupported EC Curve\n");
        return NULL;
    }
}

int qat_fips_ec_check_approved_curve(const EC_KEY *eckey)
{
    const EC_GROUP *group;
    int curve_name;
    group = EC_KEY_get0_group(eckey);
    curve_name = EC_GROUP_get_curve_name(group);

    switch (curve_name) {
    case NID_X9_62_prime256v1:
    case NID_secp384r1:
# ifdef QAT_HW
    case NID_secp224r1:
    case NID_secp521r1:
    case NID_sect233k1:
    case NID_sect283k1:
    case NID_sect409k1:
    case NID_sect571k1:
    case NID_sect233r1:
    case NID_sect283r1:
    case NID_sect409r1:
    case NID_sect571r1:
# endif
        return 1;
    default:
        if (qat_fips_ec_non_approved_curve(curve_name) != NULL) {
            INFO("%s is FIPS non approved curve\n",
                 qat_fips_ec_non_approved_curve(curve_name));
        }
        return 0;
    }
}

# ifdef QAT_HW
static unsigned int get_dh_nid(int size)
{
    switch (size) {
    case 2048:
        return NID_dh2048;
    case 3072:
        return NID_dh3072;
    case 4096:
        return NID_dh4096;
    case 8192:
        return NID_dh8192;
    default:
        return 0;
    }
}

int qat_fips_dh_safe_group(const DH *dh)
{
    int nid, plen;
    const BIGNUM *p = NULL;

    p = DH_get0_p(dh);
    plen = BN_num_bits(p);
    nid = get_dh_nid(plen);

    switch (nid) {
    case NID_ffdhe2048:
    case NID_ffdhe3072:
    case NID_ffdhe4096:
    case NID_ffdhe8192:
        return plen;
    default:
        INFO("%d is FIPS non approved size\n", plen);
        return 0;
    }
}
# endif

int qat_fips_ec_key_private_check(const EC_KEY *eckey)
{
    if (eckey == NULL || eckey->group == NULL || eckey->priv_key == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (BN_cmp(eckey->priv_key, BN_value_one()) < 0
        || BN_cmp(eckey->priv_key, eckey->group->order) >= 0) {
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_PRIVATE_KEY);
        return 0;
    }
    return 1;
}

int qat_fips_ec_key_pairwise_check(const EC_KEY *eckey, BN_CTX *ctx)
{
    int ret = 0;
    EC_POINT *point = NULL;

    if (eckey == NULL
        || eckey->group == NULL
        || eckey->pub_key == NULL || eckey->priv_key == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    point = EC_POINT_new(eckey->group);
    if (point == NULL)
        goto err;

    if (!EC_POINT_mul(eckey->group, point, eckey->priv_key, NULL, NULL, ctx)) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }
    if (EC_POINT_cmp(eckey->group, point, eckey->pub_key, ctx) != 0) {
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_PRIVATE_KEY);
        goto err;
    }
    ret = 1;
 err:
    EC_POINT_free(point);
    return ret;
}

int qat_fips_ec_key_public_range_check(BN_CTX *ctx, const EC_KEY *key)
{
    int ret = 0;
    BIGNUM *x, *y;

    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    if (y == NULL)
        goto err;

    if (!EC_POINT_get_affine_coordinates(key->group, key->pub_key, x, y, ctx))
        goto err;

    if (EC_GROUP_get_field_type(key->group) == NID_X9_62_prime_field) {
        if (BN_is_negative(x)
            || BN_cmp(x, key->group->field) >= 0 || BN_is_negative(y)
            || BN_cmp(y, key->group->field) >= 0) {
            goto err;
        }
    } else {
        int m = EC_GROUP_get_degree(key->group);
        if (BN_num_bits(x) > m || BN_num_bits(y) > m) {
            goto err;
        }
    }
    ret = 1;
 err:
    BN_CTX_end(ctx);
    return ret;
}

int qat_fips_ec_key_public_check_quick(const EC_KEY *eckey, BN_CTX *ctx)
{
    if (eckey == NULL || eckey->group == NULL || eckey->pub_key == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /* Test Q != infinity */
    if (EC_POINT_is_at_infinity(eckey->group, eckey->pub_key)) {
        ERR_raise(ERR_LIB_EC, EC_R_POINT_AT_INFINITY);
        return 0;
    }

    /* Test if the public key is in range */
    if (!qat_fips_ec_key_public_range_check(ctx, eckey)) {
        ERR_raise(ERR_LIB_EC, EC_R_COORDINATES_OUT_OF_RANGE);
        return 0;
    }

    /* Test is the pub_key on the elliptic curve */
    if (EC_POINT_is_on_curve(eckey->group, eckey->pub_key, ctx) <= 0) {
        ERR_raise(ERR_LIB_EC, EC_R_POINT_IS_NOT_ON_CURVE);
        return 0;
    }
    return 1;
}

int qat_fips_ec_key_public_check(const EC_KEY *eckey, BN_CTX *ctx)
{
    int ret = 0;
    EC_POINT *point = NULL;
    const BIGNUM *order = NULL;

    if (!qat_fips_ec_key_public_check_quick(eckey, ctx))
        return 0;

    point = EC_POINT_new(eckey->group);
    if (point == NULL)
        return 0;

    order = eckey->group->order;
    if (BN_is_zero(order)) {
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_GROUP_ORDER);
        goto err;
    }
    /* Test pub_key * order is the point at infinity. */
    if (!EC_POINT_mul(eckey->group, point, NULL, eckey->pub_key, order, ctx)) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }
    if (!EC_POINT_is_at_infinity(eckey->group, point)) {
        ERR_raise(ERR_LIB_EC, EC_R_WRONG_ORDER);
        goto err;
    }
    ret = 1;
 err:
    EC_POINT_free(point);
    return ret;
}

int qat_fips_ec_key_simple_check_key(const EC_KEY *eckey)
{
    int ok = 0;
    BN_CTX *ctx = NULL;

    if (eckey == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if ((ctx = BN_CTX_new_ex(eckey->libctx)) == NULL)
        return 0;

    if (!qat_fips_ec_key_public_check(eckey, ctx))
        goto err;

    if (eckey->priv_key != NULL) {
        if (!qat_fips_ec_key_private_check(eckey)
            || !qat_fips_ec_key_pairwise_check(eckey, ctx))
            goto err;
    }
    ok = 1;
 err:
    BN_CTX_free(ctx);
    return ok;
}

int qat_fips_get_key_zeroize_status(void)
{
    if (qat_fips_key_zeroize == 1)
        DEBUG("zeroization done successfully!!..\n");
    else
        INFO("zeroization failure!!..\n");
    return qat_fips_key_zeroize;
}

int qat_fips_get_approved_status(void)
{
    if (qat_fips_service_indicator) {
        DEBUG("Running FIPS approved service.\n");
        return 1;
    } else {
        INFO("Requested service is not a FIPS approved service.\n");
        return 0;
    }
}
#endif
