/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2021 Intel Corporation.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/async.h>
#include <openssl/objects.h>
#include <openssl/ec.h>
#include <openssl/engine.h>

#include "tests.h"
#include "../qat_utils.h"

static const char rnd_seed[] =
    "string to make the random number generator think it has entropy";


static int get_nid(int type)
{
    switch (type) {
    case P_CURVE_192:
        return NID_X9_62_prime192v1;
    case P_CURVE_224:
        return NID_secp224r1;
    case P_CURVE_256:
        return NID_X9_62_prime256v1;
    case P_CURVE_384:
        return NID_secp384r1;
    case P_CURVE_521:
        return NID_secp521r1;
    case K_CURVE_163:
        return NID_sect163k1;
    case K_CURVE_233:
        return NID_sect233k1;
    case K_CURVE_283:
        return NID_sect283k1;
    case K_CURVE_409:
        return NID_sect409k1;
    case K_CURVE_571:
        return NID_sect571k1;
    case B_CURVE_163:
        return NID_sect163r2;
    case B_CURVE_233:
        return NID_sect233r1;
    case B_CURVE_283:
        return NID_sect283r1;
    case B_CURVE_409:
        return NID_sect409r1;
    case B_CURVE_571:
        return NID_sect571r1;
    case 0:
        return 0;
    }
    return -1;
}

/******************************************************************************
 * function:
 *       test_ecdsa (int count,
 *                   int size,
 *                   engine *e,
 *                   int print_output,
 *                   int verify,
 *                   int nid,
 *                   const char *curveName)
 *
 * @param count [IN] - number of iterations
 * @param size [IN] - the length of input message
 * @param e [IN] - OpenSSL engine pointer
 * @param print_output [IN] - print hex output flag
 * @param verify [IN] - verify flag
 * @param nid [IN] - nid to be used
 * @param curveName [IN] - curve name to be used
 *
 * description:
 *       specify a test case
 *
******************************************************************************/
static int test_ecdsa(int count, int size, ENGINE * e, int print_output,
                      int verify, int nid, const char *curveName)
{
    EC_KEY *eckey = NULL, *wrong_eckey = NULL;
    EC_GROUP *group;
    unsigned char digest[size], wrong_digest[size];
    unsigned char *signature = NULL;
    unsigned int sig_len = 0, degree = 0;
    BIGNUM *kinv = NULL, *rp = NULL;
    ECDSA_SIG *sig = NULL;
    BIO *out = NULL;
    int ret = 0, i;
    char buf[256];

    out = BIO_new(BIO_s_file());
    if (out == NULL) {
        WARN("# FAIL: Unable to create BIO\n");
        exit(1);
    }
    BIO_set_fp(out, stdout, BIO_NOCLOSE);

    /* fill digest values with some random data */
    if ((RAND_bytes(digest, size) <= 0) ||
        (RAND_bytes(wrong_digest, size) <= 0)) {
        WARN("# FAIL: unable to get random data\n");
        ret = -1;
        goto builtin_err;
    }

    /* create new ecdsa key (== EC_KEY) */
    if ((eckey = EC_KEY_new()) == NULL) {
        WARN("# FAIL: Failed to new up key\n");
        ret = -1;
        goto builtin_err;
    }

    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL) {
        WARN("# FAIL: Failed to new up group\n");
        ret = -1;
        goto builtin_err;
    }
    if (EC_KEY_set_group(eckey, group) == 0) {
        WARN("# FAIL: Failed to set group\n");
        ret = -1;
        goto builtin_err;
    }
    EC_GROUP_free(group);
    degree = EC_GROUP_get_degree(EC_KEY_get0_group(eckey));
    if (degree < 160) {
        /* drop the curve */
        EC_KEY_free(eckey);
        eckey = NULL;
        WARN("# FAIL: As the degree is less than 160, Drop the curve from processing\n");
        ret = -1;
        goto builtin_err;
    }
    if(print_output)
        printf("%s\n", OBJ_nid2sn(nid));

    if (!EC_KEY_generate_key(eckey)) {
        WARN("# FAIL: Failed to generate key\n");
        ret = -1;
        goto builtin_err;
    }

    /* create second key */
    if ((wrong_eckey = EC_KEY_new()) == NULL) {
        WARN("# FAIL: Failed to new up key\n");
        ret = -1;
        goto builtin_err;
    }
    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL) {
        WARN("# FAIL: Failed to new up group\n");
        ret = -1;
        goto builtin_err;
    }
    if (EC_KEY_set_group(wrong_eckey, group) == 0) {
        WARN("# FAIL: Failed to set group\n");
        ret = -1;
        goto builtin_err;
    }
    EC_GROUP_free(group);
    if (!EC_KEY_generate_key(wrong_eckey)) {
        WARN("# FAIL: Failed to create wrong_eckey\n");
        ret = -1;
        goto builtin_err;
    }

    /* check key */
    if (!EC_KEY_check_key(eckey)) {
        WARN("# FAIL: EC_KEY_check_key failed\n");
        ret = -1;
        goto builtin_err;
    }

    /* create signature */
    sig_len = ECDSA_size(eckey);
    if ((signature = OPENSSL_malloc(sig_len)) == NULL) {
        WARN("# FAIL: failed to malloc signature\n");
        ret = -1;
        goto builtin_err;
    }

    for (i = 0; i < count; ++i) {
        if (!ECDSA_sign(0, digest, size, signature, &sig_len, eckey)) {
            WARN("# FAIL: Failed to Sign\n");
            ret = -1;
            goto builtin_err;
        }
        if (print_output) {
            BIO_puts(out,"ECDSA_sign signature: ");
            for (i = 0; i < sig_len; i++) {
                sprintf(buf, "%02X ", signature[i]);
                BIO_puts(out, buf);
            }
            BIO_puts(out, "\n");
        }

        /* Verify Signature */
        if (ECDSA_verify(0, digest, size, signature, sig_len, eckey) != 1) {
            WARN("# FAIL: Failed to verify\n");
            ret = -1;
            goto builtin_err;
        }

        /* Sign setup - sign_sig and Verify */
        sig = ECDSA_do_sign_ex(digest, size, kinv, rp, eckey);
        if (sig == NULL) {
            WARN("# FAIL: Failed to Sign\n");
            ret = -1;
            goto builtin_err;
        }

        if (ECDSA_do_verify(digest, size, sig, eckey) != 1) {
            WARN("# FAIL: Failed to verify\n");
            ret = -1;
            goto builtin_err;
        }
    }

    /* Verify Signature with a wrong digest*/
    if (ECDSA_verify(0, wrong_digest, size, signature, sig_len, eckey) == 1) {
        WARN("# FAIL: Verified with wrong digest\n");
        ret = -1;
        goto builtin_err;
    }

builtin_err:
    if (eckey)
        EC_KEY_free(eckey);
    if (wrong_eckey)
        EC_KEY_free(wrong_eckey);
    if (signature)
        OPENSSL_free(signature);
    BIO_free(out);

    if (0 == ret)
        INFO("# PASS ECDSA Sign/Verify for nid %s\n",curveName);
    else
        INFO("# FAIL ECDSA Sign/Verify for nid %s\n",curveName);
    return ret;
}


/******************************************************************************
* function:
*       tests_run_ecdsa (void *args)
*
* @param args [IN] - the test parameters
*
* description:
*   specify a test case
*
******************************************************************************/
static int run_ecdsa(void *args)
{
    int i = 0;
    int ret = 1;

    TEST_PARAMS *temp_args = (TEST_PARAMS *)args;
    int count = *(temp_args->count);
    int size = temp_args->size;
    /*
     * If temp_args->explicit_engine is not set then set the
     * engine to NULL to allow fallback to software if
     * that engine under test does not support this operation.
     * This relies on the engine we are testing being
     * set as the default engine.
     */
    ENGINE *e = temp_args->explicit_engine ? temp_args->e : NULL;
    int print_output = temp_args->print_output;
    int verify = temp_args->verify;
    int curve = temp_args->curve;

    RAND_seed(rnd_seed, sizeof(rnd_seed));

    if (!curve) {
        for (i = 1; i < CURVE_TYPE_MAX; i++) {
            if (test_ecdsa(count, size, e, print_output, verify, get_nid(i),
                           ecdh_curve_name(i)) < 0)
                ret = 0;
        }
    } else if (test_ecdsa(count, size, e, print_output, verify, get_nid(curve),
                       ecdh_curve_name(curve)) < 0)
            ret = 0;
    return ret;
}


/******************************************************************************
* function:
*       tests_run_ecdsa(TEST_PARAMS *args)
*
* @param args [IN] - the test parameters
*
* description:
*   specify a test case
*
******************************************************************************/
void tests_run_ecdsa(TEST_PARAMS *args)
{
    args->additional_args = NULL;

    if (!args->enable_async)
        run_ecdsa(args);
    else
        start_async_job(args, run_ecdsa);
}
