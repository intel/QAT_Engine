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
#include <openssl/err.h>
#include <openssl/async.h>
#include <openssl/objects.h>
#include <openssl/ec.h>
#include <openssl/engine.h>

#include "tests.h"
#include "../qat_utils.h"

#define ECDH_NEGATIVE_TESTCOUNT 2 /* Should be incremented when new negative tests added */


/******************************************************************************
* function:
*       get_nid (int type)
*
* @param type [IN] - type of the curve
*
* description:
*       get the object identifier for a particular curve
*
******************************************************************************/

int get_nid(int type)
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

static const int KDF1_SHA1_len = 20;
static void *KDF1_SHA1(const void *in, size_t inlen, void *out, size_t *outlen)
{
    if (*outlen < SHA_DIGEST_LENGTH)
        return NULL;
    else
        *outlen = SHA_DIGEST_LENGTH;
    return SHA1(in, inlen, out);
}

/******************************************************************************
* function:
*       test_ecdh_curve (ENGINE *e,
*                        int nid,
*                        const char *text,
*                        BN_CTX *ctx,
*                        int count,
*                        int print_output,
*                        int verify,
*                        BIO *out,
*                        int kdf)
*
* @param e [IN] - engine idetifier
* @param nid [IN] - curve object identifier
* @param text [IN] - curve names
* @param ctx [IN] - BN context
* @param count [IN] - number of iterations
* @param print_output [IN] - print hex output flag
* @param verify [IN] - verify flag
* @param out [IN] - for printf debug messages
* @param kdf [IN] - to enable or disable KDF
* @param ecdh_negative_testcount  [IN] - number of negative test iterations
*
* description:
*       perform ECDH compute key
*
******************************************************************************/

static int test_ecdh_curve(ENGINE * e,
                           int nid,
                           const char *text,
                           BN_CTX *ctx,
                           int count,
                           int print_output,
                           int verify,
                           BIO *out,
                           int kdf,
                           int ecdh_negative_testcount)
{
    EC_KEY *a = NULL;
    EC_KEY *b = NULL;
    BIGNUM *x_a = NULL, *y_a = NULL,
    *x_b = NULL, *y_b = NULL;
    char buf[12];
    unsigned char *abuf = NULL, *bbuf = NULL;
    int i, aout = 0, bout, ret = 0;
    size_t alen = 0, blen = 0;
    const EC_GROUP *group;

    a = EC_KEY_new_by_curve_name(nid);
    b = EC_KEY_new_by_curve_name(nid);
    if (a == NULL || b == NULL) {
        WARN("# FAIL ECDH - Initial mallocs failed\n");
        ret = -1;
        goto err;
    }

    group = EC_KEY_get0_group(a);

    if ((x_a=BN_new()) == NULL) {
        WARN("# FAIL ECDH - Initial mallocs failed\n");
        ret = -1;
        goto err;
    }
    if ((y_a=BN_new()) == NULL) {
        WARN("# FAIL ECDH - Initial mallocs failed\n");
        ret = -1;
        goto err;
    }
    if ((x_b=BN_new()) == NULL) {
        WARN("# FAIL ECDH - Initial mallocs failed\n");
        ret = -1;
        goto err;
    }
    if ((y_b=BN_new()) == NULL) {
        WARN("# FAIL ECDH - Initial mallocs failed\n");
        ret = -1;
        goto err;
    }

    if (print_output) {
        BIO_puts(out,"\nTesting key generation with ");
        BIO_puts(out,text);
        BIO_puts(out,"\n");
    }

    if (EC_KEY_generate_key(a) <= 0) {
        WARN("# FAIL ECDH - EC_KEY_generate_key failed\n");
        ret = -1;
        goto err;
    }

#if OPENSSL_VERSION_NUMBER > 0x10101000L
    if (!EC_POINT_get_affine_coordinates(
        group, EC_KEY_get0_public_key(a), x_a, y_a, ctx)) {
        WARN("# FAIL ECDH - EC_POINT_get_affine_coordinates failed\n");
        ret = -1;
        goto err;
    }

#else
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
        NID_X9_62_prime_field) {
        if (!EC_POINT_get_affine_coordinates_GFp(
            group, EC_KEY_get0_public_key(a), x_a, y_a, ctx)) {
            WARN("# FAIL ECDH - EC_POINT_get_affine_coordinates_GFp failed\n");
            ret = -1;
            goto err;
        }
    }
    else {
        if (!EC_POINT_get_affine_coordinates_GF2m(
            group, EC_KEY_get0_public_key(a), x_a, y_a, ctx)) {
            WARN("# FAIL ECDH - EC_POINT_get_affine_coordinates_GF2m failed\n");
            ret = -1;
            goto err;
        }
    }
#endif

    if (EC_KEY_generate_key(b) <= 0) {
        WARN("# FAIL ECDH - EC_KEY_generate_key failed\n");
        ret = -1;
        goto err;
    }

#if OPENSSL_VERSION_NUMBER > 0x10101000L
    if (!EC_POINT_get_affine_coordinates(
        group, EC_KEY_get0_public_key(b), x_b, y_b, ctx)) {
        WARN("# FAIL ECDH - EC_POINT_get_affine_coordinates failed\n");
        ret = -1;
        goto err;
    }

#else
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
        NID_X9_62_prime_field) {
        if (!EC_POINT_get_affine_coordinates_GFp(
            group, EC_KEY_get0_public_key(b), x_b, y_b, ctx)) {
            WARN("# FAIL ECDH - EC_POINT_get_affine_coordinates_GFp failed\n");
            ret = -1;
            goto err;
        }
    }
    else if (!EC_POINT_get_affine_coordinates_GF2m(
             group, EC_KEY_get0_public_key(b), x_b, y_b, ctx)) {
            WARN("# FAIL ECDH - EC_POINT_get_affine_coordinates_GF2m failed\n");
            ret = -1;
            goto err;
     }
#endif

    alen = KDF1_SHA1_len;
    abuf = (unsigned char *)OPENSSL_malloc(alen);

    for (i = 0; i < count; i++) {
        if(ecdh_negative_testcount > 0) {
           /*
            * Negative Scenario1: Change the public key of 'b' with public key
            * of 'a'
            */
           if (ecdh_negative_testcount == 1) {
              aout = ECDH_compute_key(abuf, alen, EC_KEY_get0_public_key(a), a,
                                     (kdf) ? KDF1_SHA1 : NULL);
              if (print_output)
                  BIO_puts(out,
                          "Negative tests 1 :Changed the public key of 'b' with public key of 'a'\n");
              if (aout <= 0) {
                  WARN("# FAIL ECDH - ECDH_compute_key failed \n");
                  ret = -1;
                  goto err;
              }
           } else {
              /* Negative Scenario2 : Invalid Length */
              alen = 10; /* Invalid Length */
              if (print_output)
                  BIO_puts(out,"Negative tests 2: Invalid Length \n");
              aout = ECDH_compute_key(abuf, alen, EC_KEY_get0_public_key(b), a,
                                     (kdf) ? KDF1_SHA1 : NULL);
              if (aout <= 0) {
                  WARN("# FAIL ECDH - ECDH_compute_key failed \n");
                  ret = -1;
                  goto err;
              }
           }
        } else {
             /* Positive scenario */
             if (print_output)
                 BIO_puts(out,"Positive test \n");
             aout = ECDH_compute_key(abuf, alen, EC_KEY_get0_public_key(b), a,
                                    (kdf) ? KDF1_SHA1 : NULL);
             if (aout <= 0) {
                 WARN("# FAIL ECDH - ECDH_compute_key failed \n");
                 ret = -1;
                 goto err;
            }
        }

        if (print_output) {
            BIO_puts(out,"  key1 =");
            for (i = 0; i < aout; i++) {
                sprintf(buf,"%02X",abuf[i]);
                BIO_puts(out,buf);
            }
            BIO_puts(out,"\n");
        }
    }

    if (verify) {
        blen = KDF1_SHA1_len;
        bbuf = (unsigned char *)OPENSSL_malloc(blen);
        bout = ECDH_compute_key(bbuf, blen, EC_KEY_get0_public_key(a), b,
                                (kdf) ? KDF1_SHA1 : NULL);
        if (bout <= 0) {
            WARN("# FAIL ECDH - ECDH_compute_key failed \n");
            ret = -1;
            goto err;
        }

        if (print_output) {
            BIO_puts(out,"  key2 =");
            for (i = 0; i < bout; i++) {
                sprintf(buf,"%02X",bbuf[i]);
                BIO_puts(out,buf);
            }
            BIO_puts(out,"\n");
        }

        if ((aout < 4) || (bout != aout) || (memcmp(abuf,bbuf,aout) != 0)) {
            if (print_output) {
                BIO_printf(out, " failed\n\n");
                BIO_printf(out, "key a:\n");
                BIO_printf(out, "private key: ");
                BN_print(out, EC_KEY_get0_private_key(a));
                BIO_printf(out, "\n");
                BIO_printf(out, "public key (x,y): ");
                BN_print(out, x_a);
                BIO_printf(out, ",");
                BN_print(out, y_a);
                BIO_printf(out, "\nkey b:\n");
                BIO_printf(out, "private key: ");
                BN_print(out, EC_KEY_get0_private_key(b));
                BIO_printf(out, "\n");
                BIO_printf(out, "public key (x,y): ");
                BN_print(out, x_b);
                BIO_printf(out, ",");
                BN_print(out, y_b);
                BIO_printf(out, "\n");
                BIO_printf(out, "generated key a: ");
                for (i=0; i<bout; i++) {
                    sprintf(buf, "%02X", bbuf[i]);
                    BIO_puts(out, buf);
                }
                BIO_printf(out, "\n");
                BIO_printf(out, "generated key b: ");
                for (i=0; i<aout; i++) {
                    sprintf(buf, "%02X", abuf[i]);
                    BIO_puts(out,buf);
                }
                BIO_printf(out, "\n");
            }
            if (!ecdh_negative_testcount)
                INFO("# FAIL verify for ECDH.\n");
            else {
                INFO("# PASS verify for ECDH.\n");
                BIO_printf(out,
                           "Negative scenario %d: verify failed as expected ",
                           ecdh_negative_testcount );
            }
            BIO_puts(out,text);
            BIO_puts(out,"\n");
            ret = -1;
        }
    }
    if (!ret) {
        if (!ecdh_negative_testcount )
            INFO("# PASS verify for ECDH.\n");
        else {
            INFO("# FAIL verify for ECDH.\n");
            BIO_printf(out,"Negative scenario %d: verify Passed unexpectedly ",
                       ecdh_negative_testcount );
        }
        BIO_puts(out,text);
        BIO_puts(out,"\n");
    }

err:
    ERR_print_errors_fp(stderr);
    if (abuf != NULL) OPENSSL_free(abuf);
    if (bbuf != NULL) OPENSSL_free(bbuf);
    if (x_a) BN_free(x_a);
    if (y_a) BN_free(y_a);
    if (x_b) BN_free(x_b);
    if (y_b) BN_free(y_b);
    if (b) EC_KEY_free(b);
    if (a) EC_KEY_free(a);

    return ret;
}


/******************************************************************************
* function:
*       run_ecdh (void *args)
*
* @param args [IN] - the test parameters
*
* description:
*   specify a test case
*
******************************************************************************/
static int run_ecdh(void *args)
{
    BN_CTX *ctx = NULL;
    int i = 0, j = 0;
    BIO *out = NULL;
    int ret = 1;

    TEST_PARAMS *temp_args = (TEST_PARAMS *)args;
    int count = *(temp_args->count);
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
    int kdf = temp_args->kdf;
    int enable_negative = temp_args->enable_negative;
    int ecdh_negative_testcount = 0;
    out = BIO_new(BIO_s_file());
    if (out == NULL) {
        WARN("# FAIL: Unable to create BIO\n");
        exit(1);
    }
    BIO_set_fp(out, stdout, BIO_NOCLOSE);

    if ((ctx = BN_CTX_new()) == NULL) {
        WARN("# FAIL ECDH - Initial malloc failed \n");
        ret = 0;
        goto err;
    }

    if(enable_negative > 0)
       ecdh_negative_testcount = ECDH_NEGATIVE_TESTCOUNT;

    if (curve) {
            for (i = 0; i <= ecdh_negative_testcount; i++) {
                  if (test_ecdh_curve(e, get_nid(curve), ecdh_curve_name(curve),
                          ctx, count, print_output, verify, out, kdf, i) < 0) {
                          ret = 0;
                     }
            }
     }
     else {
          for (i = 0; i <= ecdh_negative_testcount; i++) {
               for (j = 1; j < CURVE_TYPE_MAX; j++) {
                    if (test_ecdh_curve(e, get_nid(j), ecdh_curve_name(j), ctx,
                           count, print_output, verify, out, kdf, i) < 0) {
                    ret = 0;
                    }
               }
         }
     }
err:
    ERR_print_errors_fp(stderr);
    if (ctx) BN_CTX_free(ctx);
    BIO_free(out);

    return ret;
}


/******************************************************************************
* function:
*       tests_run_ecdh (TEST_PARAMS *args)
*
* @param args [IN] - the test parameters
*
* description:
*   specify a test case
*
******************************************************************************/
void tests_run_ecdh(TEST_PARAMS *args)
{
    args->additional_args = NULL;

    if (!args->enable_async)
        run_ecdh(args);
    else
        start_async_job(args, run_ecdh);
}
