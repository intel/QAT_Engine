/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022 Intel Corporation.
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
 * @file qat_prov_ec.h
 *
 * This file provides an interface to qatprovider ECDSA & ECDH operations
 *
 *****************************************************************************/
#ifndef QAT_PROV_EC_H
# define QAT_PROV_EC_H

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <openssl/core.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/proverr.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/types.h>
#include <openssl/trace.h>
#include <openssl/obj_mac.h>
#include <openssl/configuration.h>
#include <openssl/kdf.h>

# define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))

# define OSSL_MAX_NAME_SIZE           50 /* Algorithm name */
# define OSSL_MAX_PROPQUERY_SIZE     256 /* Property query strings */
# define OSSL_MAX_ALGORITHM_ID_SIZE  256 /* AlgorithmIdentifier DER */

typedef struct wpacket_sub WPACKET_SUB;
struct wpacket_sub {
    /* The parent WPACKET_SUB if we have one or NULL otherwise */
    WPACKET_SUB *parent;

    /*
     * Offset into the buffer where the length of this WPACKET goes. We use an
     * offset in case the buffer grows and gets reallocated.
     */
    size_t packet_len;

    /* Number of bytes in the packet_len or 0 if we don't write the length */
    size_t lenbytes;

    /* Number of bytes written to the buf prior to this packet starting */
    size_t pwritten;

    /* Flags for this sub-packet */
    unsigned int flags;
};

typedef struct wpacket_st WPACKET;
struct wpacket_st {
    /* The buffer where we store the output data */
    BUF_MEM *buf;

    /* Fixed sized buffer which can be used as an alternative to buf */
    unsigned char *staticbuf;

    /*
     * Offset into the buffer where we are currently writing. We use an offset
     * in case the buffer grows and gets reallocated.
     */
    size_t curr;

    /* Number of bytes written so far */
    size_t written;

    /* Maximum number of bytes we will allow to be written to this WPACKET */
    size_t maxsize;

    /* Our sub-packets (always at least one if not finished) */
    WPACKET_SUB *subs;

    /* Writing from the end first? */
    unsigned int endfirst : 1;
};

/* Types and functions to manipulate pre-computed values.*/
typedef struct nistp224_pre_comp_st NISTP224_PRE_COMP;
typedef struct nistp256_pre_comp_st NISTP256_PRE_COMP;
typedef struct nistp521_pre_comp_st NISTP521_PRE_COMP;
typedef struct nistz256_pre_comp_st NISTZ256_PRE_COMP;
typedef struct ec_pre_comp_st EC_PRE_COMP;

struct ec_key_method_st {
    const char *name;
    int32_t flags;
    int (*init)(EC_KEY *key);
    void (*finish)(EC_KEY *key);
    int (*copy)(EC_KEY *dest, const EC_KEY *src);
    int (*set_group)(EC_KEY *key, const EC_GROUP *grp);
    int (*set_private)(EC_KEY *key, const BIGNUM *priv_key);
    int (*set_public)(EC_KEY *key, const EC_POINT *pub_key);
    int (*keygen)(EC_KEY *key);
    int (*compute_key)(unsigned char **pout, size_t *poutlen,
                       const EC_POINT *pub_key, const EC_KEY *ecdh);
    int (*sign)(int type, const unsigned char *dgst, int dlen, unsigned char
                *sig, unsigned int *siglen, const BIGNUM *kinv,
                const BIGNUM *r, EC_KEY *eckey);
    int (*sign_setup)(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                      BIGNUM **rp);
    ECDSA_SIG *(*sign_sig)(const unsigned char *dgst, int dgst_len,
                           const BIGNUM *in_kinv, const BIGNUM *in_r,
                           EC_KEY *eckey);

    int (*verify)(int type, const unsigned char *dgst, int dgst_len,
                  const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);
    int (*verify_sig)(const unsigned char *dgst, int dgst_len,
                      const ECDSA_SIG *sig, EC_KEY *eckey);
};
typedef struct ec_key_method_st EC_KEY_METHOD;

struct ec_method_st {
    /* Various method flags */
    int flags;
    /* used by EC_METHOD_get_field_type: */
    int field_type;             /* a NID */
    /*
     * used by EC_GROUP_new, EC_GROUP_free, EC_GROUP_clear_free,
     * EC_GROUP_copy:
     */
    int (*group_init) (EC_GROUP *);
    void (*group_finish) (EC_GROUP *);
    void (*group_clear_finish) (EC_GROUP *);
    int (*group_copy) (EC_GROUP *, const EC_GROUP *);
    /* used by EC_GROUP_set_curve, EC_GROUP_get_curve: */
    int (*group_set_curve) (EC_GROUP *, const BIGNUM *p, const BIGNUM *a,
                            const BIGNUM *b, BN_CTX *);
    int (*group_get_curve) (const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b,
                            BN_CTX *);
    /* used by EC_GROUP_get_degree: */
    int (*group_get_degree) (const EC_GROUP *);
    int (*group_order_bits) (const EC_GROUP *);
    /* used by EC_GROUP_check: */
    int (*group_check_discriminant) (const EC_GROUP *, BN_CTX *);
    /*
     * used by EC_POINT_new, EC_POINT_free, EC_POINT_clear_free,
     * EC_POINT_copy:
     */
    int (*point_init) (EC_POINT *);
    void (*point_finish) (EC_POINT *);
    void (*point_clear_finish) (EC_POINT *);
    int (*point_copy) (EC_POINT *, const EC_POINT *);
    /*-
     * used by EC_POINT_set_to_infinity,
     * EC_POINT_set_Jprojective_coordinates_GFp,
     * EC_POINT_get_Jprojective_coordinates_GFp,
     * EC_POINT_set_affine_coordinates,
     * EC_POINT_get_affine_coordinates,
     * EC_POINT_set_compressed_coordinates:
     */
    int (*point_set_to_infinity) (const EC_GROUP *, EC_POINT *);
    int (*point_set_affine_coordinates) (const EC_GROUP *, EC_POINT *,
                                         const BIGNUM *x, const BIGNUM *y,
                                         BN_CTX *);
    int (*point_get_affine_coordinates) (const EC_GROUP *, const EC_POINT *,
                                         BIGNUM *x, BIGNUM *y, BN_CTX *);
    int (*point_set_compressed_coordinates) (const EC_GROUP *, EC_POINT *,
                                             const BIGNUM *x, int y_bit,
                                             BN_CTX *);
    /* used by EC_POINT_point2oct, EC_POINT_oct2point: */
    size_t (*point2oct) (const EC_GROUP *, const EC_POINT *,
                         point_conversion_form_t form, unsigned char *buf,
                         size_t len, BN_CTX *);
    int (*oct2point) (const EC_GROUP *, EC_POINT *, const unsigned char *buf,
                      size_t len, BN_CTX *);
    /* used by EC_POINT_add, EC_POINT_dbl, ECP_POINT_invert: */
    int (*add) (const EC_GROUP *, EC_POINT *r, const EC_POINT *a,
                const EC_POINT *b, BN_CTX *);
    int (*dbl) (const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
    int (*invert) (const EC_GROUP *, EC_POINT *, BN_CTX *);
    /*
     * used by EC_POINT_is_at_infinity, EC_POINT_is_on_curve, EC_POINT_cmp:
     */
    int (*is_at_infinity) (const EC_GROUP *, const EC_POINT *);
    int (*is_on_curve) (const EC_GROUP *, const EC_POINT *, BN_CTX *);
    int (*point_cmp) (const EC_GROUP *, const EC_POINT *a, const EC_POINT *b,
                      BN_CTX *);
    /* used by EC_POINT_make_affine, EC_POINTs_make_affine: */
    int (*make_affine) (const EC_GROUP *, EC_POINT *, BN_CTX *);
    int (*points_make_affine) (const EC_GROUP *, size_t num, EC_POINT *[],
                               BN_CTX *);
    /*
     * used by EC_POINTs_mul, EC_POINT_mul, EC_POINT_precompute_mult,
     * EC_POINT_have_precompute_mult (default implementations are used if the
     * 'mul' pointer is 0):
     */
    /*-
     * mul() calculates the value
     *
     *   r := generator * scalar
     *        + points[0] * scalars[0]
     *        + ...
     *        + points[num-1] * scalars[num-1].
     *
     * For a fixed point multiplication (scalar != NULL, num == 0)
     * or a variable point multiplication (scalar == NULL, num == 1),
     * mul() must use a constant time algorithm: in both cases callers
     * should provide an input scalar (either scalar or scalars[0])
     * in the range [0, ec_group_order); for robustness, implementers
     * should handle the case when the scalar has not been reduced, but
     * may treat it as an unusual input, without any constant-timeness
     * guarantee.
     */
    int (*mul) (const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
                size_t num, const EC_POINT *points[], const BIGNUM *scalars[],
                BN_CTX *);
    int (*precompute_mult) (EC_GROUP *group, BN_CTX *);
    int (*have_precompute_mult) (const EC_GROUP *group);
    /* internal functions */
    /*
     * 'field_mul', 'field_sqr', and 'field_div' can be used by 'add' and
     * 'dbl' so that the same implementations of point operations can be used
     * with different optimized implementations of expensive field
     * operations:
     */
    int (*field_mul) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                      const BIGNUM *b, BN_CTX *);
    int (*field_sqr) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
    int (*field_div) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                      const BIGNUM *b, BN_CTX *);
    /*-
     * 'field_inv' computes the multiplicative inverse of a in the field,
     * storing the result in r.
     *
     * If 'a' is zero (or equivalent), you'll get an EC_R_CANNOT_INVERT error.
     */
    int (*field_inv) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
    /* e.g. to Montgomery */
    int (*field_encode) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                         BN_CTX *);
    /* e.g. from Montgomery */
    int (*field_decode) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                         BN_CTX *);
    int (*field_set_to_one) (const EC_GROUP *, BIGNUM *r, BN_CTX *);
    /* private key operations */
    size_t (*priv2oct)(const EC_KEY *eckey, unsigned char *buf, size_t len);
    int (*oct2priv)(EC_KEY *eckey, const unsigned char *buf, size_t len);
    int (*set_private)(EC_KEY *eckey, const BIGNUM *priv_key);
    int (*keygen)(EC_KEY *eckey);
    int (*keycheck)(const EC_KEY *eckey);
    int (*keygenpub)(EC_KEY *eckey);
    int (*keycopy)(EC_KEY *dst, const EC_KEY *src);
    void (*keyfinish)(EC_KEY *eckey);
    /* custom ECDH operation */
    int (*ecdh_compute_key)(unsigned char **pout, size_t *poutlen,
                            const EC_POINT *pub_key, const EC_KEY *ecdh);
    /* custom ECDSA */
    int (*ecdsa_sign_setup)(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinvp,
                            BIGNUM **rp);
    ECDSA_SIG *(*ecdsa_sign_sig)(const unsigned char *dgst, int dgstlen,
                                 const BIGNUM *kinv, const BIGNUM *r,
                                 EC_KEY *eckey);
    int (*ecdsa_verify_sig)(const unsigned char *dgst, int dgstlen,
                            const ECDSA_SIG *sig, EC_KEY *eckey);
    /* Inverse modulo order */
    int (*field_inverse_mod_ord)(const EC_GROUP *, BIGNUM *r,
                                 const BIGNUM *x, BN_CTX *);
    int (*blind_coordinates)(const EC_GROUP *group, EC_POINT *p, BN_CTX *ctx);
    int (*ladder_pre)(const EC_GROUP *group,
                      EC_POINT *r, EC_POINT *s,
                      EC_POINT *p, BN_CTX *ctx);
    int (*ladder_step)(const EC_GROUP *group,
                       EC_POINT *r, EC_POINT *s,
                       EC_POINT *p, BN_CTX *ctx);
    int (*ladder_post)(const EC_GROUP *group,
                       EC_POINT *r, EC_POINT *s,
                       EC_POINT *p, BN_CTX *ctx);
};
typedef struct ec_method_st EC_METHOD;

struct ec_group_st {
    const EC_METHOD *meth;
    EC_POINT *generator;        /* optional */
    BIGNUM *order, *cofactor;
    int curve_name;             /* optional NID for named curve */
    int asn1_flag;              /* flag to control the asn1 encoding */
    int decoded_from_explicit_params; /* set if decoded from explicit
                                       * curve parameters encoding */
    point_conversion_form_t asn1_form;
    unsigned char *seed;        /* optional seed for parameters (appears in
                                 * ASN1) */
    size_t seed_len;
    /*
     * The following members are handled by the method functions, even if
     * they appear generic
     */
    /*
     * Field specification. For curves over GF(p), this is the modulus; for
     * curves over GF(2^m), this is the irreducible polynomial defining the
     * field.
     */
    BIGNUM *field;
    /*
     * Field specification for curves over GF(2^m). The irreducible f(t) is
     * then of the form: t^poly[0] + t^poly[1] + ... + t^poly[k] where m =
     * poly[0] > poly[1] > ... > poly[k] = 0. The array is terminated with
     * poly[k+1]=-1. All elliptic curve irreducibles have at most 5 non-zero
     * terms.
     */
    int poly[6];
    /*
     * Curve coefficients. (Here the assumption is that BIGNUMs can be used
     * or abused for all kinds of fields, not just GF(p).) For characteristic
     * > 3, the curve is defined by a Weierstrass equation of the form y^2 =
     * x^3 + a*x + b. For characteristic 2, the curve is defined by an
     * equation of the form y^2 + x*y = x^3 + a*x^2 + b.
     */
    BIGNUM *a, *b;
    /* enable optimized point arithmetics for special case */
    int a_is_minus3;
    /* method-specific (e.g., Montgomery structure) */
    void *field_data1;
    /* method-specific */
    void *field_data2;
    /* method-specific */
    int (*field_mod_func) (BIGNUM *, const BIGNUM *, const BIGNUM *,
                           BN_CTX *);
    /* data for ECDSA inverse */
    BN_MONT_CTX *mont_data;

    /*
     * Precomputed values for speed. The PCT_xxx names match the
     * pre_comp.xxx union names; see the SETPRECOMP and HAVEPRECOMP
     * macros, below.
     */
    enum {
        PCT_none,
        PCT_nistp224, PCT_nistp256, PCT_nistp521, PCT_nistz256,
        PCT_ec
    } pre_comp_type;
    union {
        NISTP224_PRE_COMP *nistp224;
        NISTP256_PRE_COMP *nistp256;
        NISTP521_PRE_COMP *nistp521;
        NISTZ256_PRE_COMP *nistz256;
        EC_PRE_COMP *ec;
    } pre_comp;

    OSSL_LIB_CTX *libctx;
    char *propq;
};
typedef struct ec_group_st EC_GROUP;

struct ec_key_st {
    const EC_KEY_METHOD *meth;
    ENGINE *engine;
    int version;
    EC_GROUP *group;
    EC_POINT *pub_key;
    BIGNUM *priv_key;
    unsigned int enc_flag;
    point_conversion_form_t conv_form;
    int references; /*CRYPTO_REF_COUNT references;*/
    int flags;
#ifndef FIPS_MODULE
    CRYPTO_EX_DATA ex_data;
#endif
    CRYPTO_RWLOCK *lock;
    OSSL_LIB_CTX *libctx;
    char *propq;

    /* Provider data */
    size_t dirty_cnt; /* If any key material changes, increment this */
};
typedef struct ec_key_st EC_KEY;

typedef struct rsa_prime_info_st {
    BIGNUM *r;
    BIGNUM *d;
    BIGNUM *t;
    /* save product of primes prior to this one */
    BIGNUM *pp;
    BN_MONT_CTX *m;
} EC_PRIME_INFO;

typedef struct {
    OSSL_LIB_CTX *libctx;
    char *propq;
    EC_KEY *ec;
    char mdname[OSSL_MAX_NAME_SIZE];

    /*
     * Flag to determine if the hash function can be changed (1) or not (0)
     * Because it's dangerous to change during a DigestSign or DigestVerify
     * operation, this flag is cleared by their Init function, and set again
     * by their Final function.
     */
    unsigned int flag_allow_md : 1;

    /* The Algorithm Identifier of the combined signature algorithm */
    unsigned char aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE];
    unsigned char *aid;
    size_t  aid_len;
    size_t mdsize;
    int operation;

    EVP_MD *md;
    EVP_MD_CTX *mdctx;
    /*
     * Internally used to cache the results of calling the EC group
     * sign_setup() methods which are then passed to the sign operation.
     * This is used by CAVS failure tests to terminate a loop if the signature
     * is not valid.
     * This could of also been done with a simple flag.
     */
    BIGNUM *kinv;
    BIGNUM *r;
#if !defined(OPENSSL_NO_ACVP_TESTS)
    /*
     * This indicates that KAT (CAVS) test is running. Externally an app will
     * override the random callback such that the generated private key and k
     * are known.
     * Normal operation will loop to choose a new k if the signature is not
     * valid - but for this mode of operation it forces a failure instead.
     */
    unsigned int kattest;
#endif
} QAT_PROV_ECDSA_CTX;

int QAT_EC_KEY_up_ref(EC_KEY *r);
void QAT_EC_KEY_free(EC_KEY *r);

/* With security check enabled it can return -1 to indicate disallowed md */
int qat_digest_ecdsa_get_approved_nid_with_sha1(OSSL_LIB_CTX *ctx,
                                     const EVP_MD *md, int sha1_allowed);
int qat_digest_ecdsa_md_to_nid(const EVP_MD *md, const OSSL_ITEM *it,
                                                          size_t it_len);
int qat_digest_ecdsa_get_approved_nid(const EVP_MD *md);
int qat_ec_check_key(OSSL_LIB_CTX *ctx, const EC_KEY *ec, int protect);
int qat_securitycheck_enabled(OSSL_LIB_CTX *libctx);

OSSL_LIB_CTX *qat_ec_key_get_libctx(const EC_KEY *key);
#endif  /* QAT_PROV_EC_H */
