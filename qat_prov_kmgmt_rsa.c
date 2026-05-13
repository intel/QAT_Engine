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
 * @file qat_prov_kmgmt_rsa.c
 *
 * This file contains RSA key management implementation from default provider.
 *
 *****************************************************************************/

#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include "qat_provider.h"
#include "qat_prov_rsa.h"
#include "qat_prov_kmgmt_rsa_utils.h"
#include "qat_utils.h"
#include "qat_prov_cmvp.h"

#if defined(ENABLE_QAT_HW_RSA) || defined(ENABLE_QAT_SW_RSA)

#define RSA_MIN_MODULUS_BITS    512
#define RSA_DEFAULT_MD "SHA256"
#define QAT_RSA_POSSIBLE_SELECTIONS                                        \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)

#define qat_rsa_gen_basic                                                  \
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),                     \
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, NULL),                   \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0)

#define qat_rsa_gen_pss                                                    \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST, NULL, 0),           \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST_PROPS, NULL, 0),     \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MASKGENFUNC, NULL, 0),      \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MGF1_DIGEST, NULL, 0),      \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, NULL)

/**
 * @brief Allocates and initializes a new RSA key object for RSA key management.
 *
 * This function creates a new RSA key object using the provided provider context,
 * initializes its fields, and sets the key type flags for a standard RSA key.
 * It returns a pointer to the new RSA key object, or NULL on failure.
 *
 * @param provctx  Pointer to the provider context.
 *
 * @return Pointer to the newly allocated RSA key object, or NULL on failure.
 */
static void *qat_keymgmt_rsa_newdata(void *provctx)
{
    DEBUG("%s\n", __func__);
    OSSL_LIB_CTX *libctx = prov_libctx_of(provctx);
    RSA *rsa;

    if (!qat_prov_is_running())
        return NULL;

    rsa = qat_rsa_new_with_ctx(libctx);
    if (rsa != NULL) {
        RSA_clear_flags(rsa, RSA_FLAG_TYPE_MASK);
        RSA_set_flags(rsa, RSA_FLAG_TYPE_RSA);
    }
    return rsa;
}

/**
 * @brief Allocates and initializes a new RSA key object for RSA-PSS key management.
 *
 * This function creates a new RSA key object using the provided provider context,
 * initializes its fields, and sets the key type flags for an RSA-PSS key.
 * It returns a pointer to the new RSA key object, or NULL on failure.
 *
 * @param provctx  Pointer to the provider context.
 *
 * @return Pointer to the newly allocated RSA key object, or NULL on failure.
 */
static void *qat_keymgmt_rsapss_newdata(void *provctx)
{
    OSSL_LIB_CTX *libctx = prov_libctx_of(provctx);
    RSA *rsa;

    if (!qat_prov_is_running())
	return NULL;

    rsa = qat_rsa_new_with_ctx(libctx);
    if (rsa != NULL) {
        RSA_clear_flags(rsa, RSA_FLAG_TYPE_MASK);
        RSA_set_flags(rsa, RSA_FLAG_TYPE_RSASSAPSS);
    }
    return rsa;
}

/**
 * @brief Frees and cleans up a RSA key object.
 *
 * This function releases all resources associated with a RSA key object,
 * including any allocated memory and internal key components. It should be
 * called when the key data is no longer needed to prevent memory leaks.
 *
 * @param keydata  Pointer to the RSA key object to free.
 */
static void qat_keymgmt_rsa_freedata(void *keydata)
{
    DEBUG("%s\n", __func__);
    QAT_RSA_free(keydata);
}

/**
 * @brief Checks if the RSA key object contains the requested key components.
 *
 * This function verifies the presence of required key components in the given QAT_RSA
 * structure based on the specified selection mask. It checks for the existence of
 * modulus (n), public exponent (e), and private exponent (d) as needed for keypair,
 * public key, and private key selections. Returns 1 if all requested components are present,
 * 0 otherwise.
 *
 * @param keydata    Pointer to the RSA key object to check.
 * @param selection  Bitmask specifying which key components to check for.
 *
 * @return 1 if all requested components are present, 0 otherwise.
 */
static int qat_keymgmt_rsa_has(const void *keydata, int selection)
{
    DEBUG("%s\n", __func__);
    const RSA *rsa = keydata;
    int ok = 1;

    if (rsa == NULL || !qat_prov_is_running())
        return 0;
    if ((selection & QAT_RSA_POSSIBLE_SELECTIONS) == 0)
        return 1; /* the selection is not missing */

    /* OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS are always available even if empty */
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        ok = ok && (RSA_get0_n(rsa) != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && (RSA_get0_e(rsa) != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && (RSA_get0_d(rsa) != NULL);
    return ok;
}

/**
 * @brief Imports RSA key components and parameters from an OSSL_PARAM array into a RSA key object.
 *
 * This function populates the given RSA key object with key components and parameters
 * provided in the OSSL_PARAM array, according to the specified selection mask. It handles
 * both standard and PSS-specific parameters, and can import public and private key data.
 * The function ensures that the imported parameters are consistent with the key type and
 * applies any necessary defaults for PSS keys.
 *
 * @param keydata    Pointer to the RSA key object to populate.
 * @param selection  Bitmask specifying which key components and parameters to import.
 * @param params     Array of OSSL_PARAM containing the key data and parameters.
 *
 * @return 1 on success, 0 on failure.
 */
static int qat_keymgmt_rsa_import(void *keydata, int selection,
	                          const OSSL_PARAM params[])
{
    DEBUG("%s\n", __func__);
    RSA *rsa = keydata;
    int rsa_type;
    int ok = 1;
    int pss_defaults_set = 0;

    if (!qat_prov_is_running() || rsa == NULL)
        return 0;

    if ((selection & QAT_RSA_POSSIBLE_SELECTIONS) == 0)
        return 0;

    rsa_type = RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK);

    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
        ok = ok && qat_pss_params_fromdata(qat_rsa_get0_pss_params_30(rsa),
                                           &pss_defaults_set,
                                           params, rsa_type,
                                           qat_rsa_get0_libctx(rsa));
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int include_private =
            selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;

        ok = ok && import_rsa_private_key(rsa, params, include_private);
    }
    DEBUG("rsa_import complete\n");
    return ok;
}

/**
 * @brief Retrieves the list of importable parameter types for QAT RSA key management.
 *
 * This function returns an array of OSSL_PARAM descriptors that specify which key
 * components and parameters can be imported for the given selection mask. It is used
 * by OpenSSL to determine which parameters are supported for import operations.
 *
 * @param selection  Bitmask specifying which key components and parameters are being imported.
 *
 * @return Pointer to an array of OSSL_PARAM descriptors, or NULL if none are available.
 */
static const OSSL_PARAM *qat_keymgmt_rsa_import_types(int selection)
{
    DEBUG("%s\n", __func__);
    return qat_rsa_imexport_types(selection);
}

/**
 * @brief Sets RSA key generation parameters from an OSSL_PARAM array.
 *
 * This function parses and applies key generation parameters from the provided OSSL_PARAM array
 * to the QAT_RSA_GEN_CTX context. It handles modulus size, number of primes, public exponent,
 * and (for RSA-PSS keys) PSS-specific parameters. The function validates parameter values and
 * ensures minimum security requirements are met.
 *
 * @param genctx  Pointer to the QAT_RSA_GEN_CTX context to configure.
 * @param params  Array of OSSL_PARAM containing the generation parameters.
 *
 * @return 1 on success, 0 on failure.
 */
static int qat_keymgmt_rsa_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    DEBUG("%s\n", __func__);
    QAT_RSA_GEN_CTX *gctx = genctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS)) != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &gctx->nbits))
            return 0;
        if (gctx->nbits < RSA_MIN_MODULUS_BITS) {
            QATerr(ERR_LIB_PROV, QAT_R_PROV_KEY_SIZE_TOO_SMALL);
            return 0;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_PRIMES)) != NULL
        && !OSSL_PARAM_get_size_t(p, &gctx->primes))
        return 0;
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E)) != NULL
        && !OSSL_PARAM_get_BN(p, &gctx->pub_exp))
        return 0;
    /* Only attempt to get PSS parameters when generating an RSA-PSS key */
    if (gctx->rsa_type == RSA_FLAG_TYPE_RSASSAPSS
        && !qat_pss_params_fromdata(&gctx->pss_params, &gctx->pss_defaults_set,
				    params, gctx->rsa_type, gctx->libctx))
        return 0;
    return 1;
}

/**
 * @brief Initializes a QAT_RSA_GEN_CTX structure for RSA or RSA-PSS key generation.
 *
 * This function allocates and sets up a QAT_RSA_GEN_CTX context for RSA key generation,
 * including setting the library context, default modulus size, number of primes, public exponent,
 * and RSA key type (standard or PSS). It also parses and applies any additional key generation
 * parameters provided in the OSSL_PARAM array.
 *
 * @param provctx    Pointer to the provider context.
 * @param selection  Bitmask specifying which key components to generate.
 * @param rsa_type   Integer indicating the RSA key type (e.g., RSA_FLAG_TYPE_RSA or RSA_FLAG_TYPE_RSASSAPSS).
 * @param params     Array of OSSL_PARAM containing key generation parameters.
 *
 * @return Pointer to the newly allocated QAT_RSA_GEN_CTX structure, or NULL on failure.
 */
static void *qat_gen_init(void *provctx, int selection, int rsa_type,
                          const OSSL_PARAM params[])
{
    DEBUG("%s\n", __func__);
    OSSL_LIB_CTX *libctx = prov_libctx_of(provctx);
    QAT_RSA_GEN_CTX *gctx = NULL;

    if (!qat_prov_is_running())
        return NULL;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return NULL;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->libctx = libctx;
        if ((gctx->pub_exp = BN_new()) == NULL
            || !BN_set_word(gctx->pub_exp, RSA_F4)) {
            goto err;
        }
        gctx->nbits = 2048;
        gctx->primes = RSA_DEFAULT_PRIME_NUM;
        gctx->rsa_type = rsa_type;
    } else {
        goto err;
    }
    if (!qat_keymgmt_rsa_gen_set_params(gctx, params))
        goto err;
    return gctx;
err:
    if (gctx != NULL)
        BN_free(gctx->pub_exp);
    OPENSSL_free(gctx);
    return NULL;
}

static void *qat_keymgmt_rsa_gen_init(void *provctx, int selection,
                                      const OSSL_PARAM params[])
{
    return qat_gen_init(provctx, selection, RSA_FLAG_TYPE_RSA, params);
}

static void *qat_keymgmt_rsapss_gen_init(void *provctx, int selection,
	                                 const OSSL_PARAM params[])
{
    return qat_gen_init(provctx, selection, RSA_FLAG_TYPE_RSASSAPSS, params);
}

static const OSSL_PARAM *qat_keymgmt_rsa_gen_settable_params(ossl_unused void *genctx,
                                                             ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] = {
        qat_rsa_gen_basic,
        OSSL_PARAM_END
    };
    return settable;
}

static const OSSL_PARAM *qat_keymgmt_rsapss_gen_settable_params(ossl_unused void *genctx,
                                                                ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] = {
        qat_rsa_gen_basic,
        qat_rsa_gen_pss,
        OSSL_PARAM_END
    };
    return settable;
}

/**
 * @brief Generates a new RSA or RSA-PSS key using the specified generation context.
 *
 * This function creates a new RSA key according to the parameters set in the QAT_RSA_GEN_CTX
 * context, including modulus size, public exponent, number of primes, and (for PSS keys) PSS parameters.
 * It performs all necessary checks for key type and parameter restrictions, generates the key using
 * software routines, and copies any PSS parameters to the resulting key structure.
 *
 * @param genctx    Pointer to the QAT_RSA_GEN_CTX context containing generation parameters.
 * @param osslcb    Optional OpenSSL callback for progress reporting (may be NULL).
 * @param cbarg     Optional argument for the callback (may be NULL).
 *
 * @return Pointer to the newly generated RSA key, or NULL on failure.
 */
static void *qat_keymgmt_rsa_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    DEBUG("%s\n", __func__);
    QAT_RSA_GEN_CTX *gctx = genctx;
    RSA *rsa = NULL, *rsa_tmp = NULL;
    BN_GENCB *gencb = NULL;

    if (!qat_prov_is_running() || gctx == NULL)
        return NULL;

    switch (gctx->rsa_type) {
    case RSA_FLAG_TYPE_RSA:
        /* For plain RSA keys, PSS parameters must not be set */
        if (!qat_rsa_pss_params_30_is_unrestricted(&gctx->pss_params))
            goto err;
        break;
    case RSA_FLAG_TYPE_RSASSAPSS:
        /*
         * For plain RSA-PSS keys, PSS parameters may be set but don't have
         * to, so not check.
         */
        break;
    default:
        /* Unsupported RSA key sub-type... */
        return NULL;
    }
    if ((rsa_tmp = qat_rsa_new_with_ctx(gctx->libctx)) == NULL)
        return NULL;

    gctx->cb = osslcb;
    gctx->cbarg = cbarg;
    gencb = BN_GENCB_new();
    if (gencb != NULL)
        BN_GENCB_set(gencb, qat_rsa_gencb, genctx);

    if (!RSA_generate_swkey(rsa_tmp, (int)gctx->nbits, gctx->pub_exp, gencb))
	    goto err;

    if (!qat_rsa_pss_params_30_copy(qat_rsa_get0_pss_params_30(rsa_tmp),
                                    &gctx->pss_params))
        goto err;

    RSA_clear_flags(rsa_tmp, RSA_FLAG_TYPE_MASK);
    RSA_set_flags(rsa_tmp, gctx->rsa_type);

    rsa = rsa_tmp;
    rsa_tmp = NULL;
 err:
    BN_GENCB_free(gencb);
    QAT_RSA_free(rsa_tmp);
    return rsa;
}

/**
 * @brief Frees and cleans up a QAT_RSA_GEN_CTX key generation context.
 *
 * This function releases all resources associated with a QAT_RSA_GEN_CTX structure,
 * including the public exponent BIGNUM and any allocated memory. It should be called
 * when the key generation context is no longer needed to prevent memory leaks.
 *
 * @param genctx  Pointer to the QAT_RSA_GEN_CTX structure to free.
 */
static void qat_keymgmt_rsa_gen_cleanup(void *genctx)
{
    QAT_RSA_GEN_CTX *gctx = genctx;

    if (gctx == NULL)
        return;

    BN_clear_free(gctx->pub_exp);
    OPENSSL_free(gctx);
}

/**
 * @brief Loads a RSA key object from a reference pointer.
 *
 * This function retrieves a RSA key object from a reference pointer, validating
 * the reference size and ensuring the key type matches the expected RSA type (standard or PSS).
 * If the reference is valid, the function detaches the object from the reference pointer
 * and returns it; otherwise, it returns NULL.
 *
 * @param reference     Pointer to the reference containing the RSA key object address.
 * @param reference_sz  Size of the reference (should match sizeof(RSA *)).
 * @param rsa_type      Expected RSA key type (e.g., RSA_FLAG_TYPE_RSA or RSA_FLAG_TYPE_RSASSAPSS).
 *
 * @return Pointer to the loaded RSA key object, or NULL on failure.
 */
static void *common_load(const void *reference, size_t reference_sz,
	                 int rsa_type)
{
    RSA *rsa = NULL;

    if (qat_prov_is_running() && reference_sz == sizeof(rsa)) {
	/* The contents of the reference is the address to our object */
        rsa = *(RSA **)reference;

        if (RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK) != rsa_type)
            return NULL;

        /* We grabbed, so we detach it */
        *(RSA **)reference = NULL;
        return rsa;
    }
    return NULL;
}

static void *qat_keymgmt_rsa_load(const void *reference, size_t reference_sz)
{
    return common_load(reference, reference_sz, RSA_FLAG_TYPE_RSA);
}

static void *qat_keymgmt_rsapss_load(const void *reference, size_t reference_sz)
{
    return common_load(reference, reference_sz, RSA_FLAG_TYPE_RSASSAPSS);
}

/**
 * @brief Retrieves key parameters from a RSA key object and populates an OSSL_PARAM array.
 *
 * This function fills the provided OSSL_PARAM array with key parameters from the given QAT_RSA
 * structure, such as modulus size, security bits, maximum size, and default or mandatory digest.
 * For RSA-PSS keys, it also exports PSS parameters if present. The function ensures that only
 * valid and available parameters are set in the output array.
 *
 * @param key      Pointer to the RSA key object.
 * @param params   Array of OSSL_PARAM to be populated with key parameters.
 *
 * @return 1 on success, 0 on failure.
 */
static int qat_keymgmt_rsa_get_params(void *key, OSSL_PARAM params[])
{
    DEBUG("%s\n", __func__);
    RSA *rsa = key;
    const QAT_RSA_PSS_PARAMS_30 *pss_params = qat_rsa_get0_pss_params_30(rsa);
    int rsa_type = RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK);
    OSSL_PARAM *p;
    int empty = RSA_get0_n(rsa) == NULL;
    int ret = 0;

    DEBUG("n is empty: %d\n", empty);
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL) {
	if (empty || !OSSL_PARAM_set_int(p, RSA_bits(rsa)))
            return 0;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && (empty || !OSSL_PARAM_set_int(p, RSA_security_bits(rsa))))
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && (empty || !OSSL_PARAM_set_int(p, RSA_size(rsa))))
        return 0;
    /*
     * For restricted RSA-PSS keys, we ignore the default digest request.
     * With RSA-OAEP keys, this may need to be amended.
     */

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST)) != NULL
        && (rsa_type != RSA_FLAG_TYPE_RSASSAPSS
		|| qat_rsa_pss_params_30_is_unrestricted(pss_params))) {
        if (!OSSL_PARAM_set_utf8_string(p, RSA_DEFAULT_MD))
            return 0;
    }
    /*
     * For non-RSA-PSS keys, we ignore the mandatory digest request.
     * With RSA-OAEP keys, this may need to be amended.
     */
    if ((p = OSSL_PARAM_locate(params,
                               OSSL_PKEY_PARAM_MANDATORY_DIGEST)) != NULL
        && rsa_type == RSA_FLAG_TYPE_RSASSAPSS
        && !qat_rsa_pss_params_30_is_unrestricted(pss_params)) {
        const char *mdname =
            qat_rsa_oaeppss_nid2name(qat_rsa_pss_params_30_hashalg(pss_params));
        if (mdname == NULL || !OSSL_PARAM_set_utf8_string(p, mdname))
            return 0;
    }
    DEBUG("%s completed.\n", __func__);
    ret = (rsa_type != RSA_FLAG_TYPE_RSASSAPSS
		                || qat_rsa_pss_params_30_todata(pss_params, NULL, params))
	            && qat_rsa_todata(rsa, NULL, params, 1);

    return ret;
}

static const OSSL_PARAM rsa_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
    RSA_KEY_TYPES()
    OSSL_PARAM_END
};
static const OSSL_PARAM *qat_keymgmt_rsa_gettable_params(void *provctx)
{
    return rsa_params;
}

/**
 * @brief Exports RSA key components and parameters from a RSA key object.
 *
 * This function serializes the key components and parameters of the given RSA key object
 * into an OSSL_PARAM array using an OSSL_PARAM_BLD builder, according to the specified
 * selection mask. It handles both standard and PSS-specific parameters, and can export
 * public and private key data. The resulting parameters are passed to the provided callback.
 *
 * @param keydata        Pointer to the RSA key object to export.
 * @param selection      Bitmask specifying which key components and parameters to export.
 * @param param_callback Callback function to receive the exported parameters.
 * @param cbarg          Argument to pass to the callback function.
 *
 * @return 1 on success, 0 on failure.
 */
static int qat_keymgmt_rsa_export(void *keydata, int selection,
	                          OSSL_CALLBACK *param_callback,
	                          void *cbarg)
{
    DEBUG("%s\n", __func__);
    RSA *rsa = keydata;
    const QAT_RSA_PSS_PARAMS_30 *pss_params = qat_rsa_get0_pss_params_30(rsa);
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    int ok = 1;

    if (!qat_prov_is_running() || rsa == NULL)
        return 0;

    if ((selection & QAT_RSA_POSSIBLE_SELECTIONS) == 0)
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
        ok = ok && (qat_rsa_pss_params_30_is_unrestricted(pss_params)
                    || qat_rsa_pss_params_30_todata(pss_params, tmpl, NULL));
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int include_private =
            selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;

        ok = ok && qat_rsa_todata(rsa, tmpl, NULL, include_private);
    }

    if (!ok || (params = OSSL_PARAM_BLD_to_param(tmpl)) == NULL) {
        ok = 0;
        goto err;
    }

    ok = param_callback(params, cbarg);
    OSSL_PARAM_free(params);
err:
    OSSL_PARAM_BLD_free(tmpl);
    return ok;
}

/**
 * @brief Retrieves the list of exportable parameter types for QAT RSA key management.
 *
 * This function returns an array of OSSL_PARAM descriptors that specify which key
 * components and parameters can be exported for the given selection mask. It is used
 * by OpenSSL to determine which parameters are supported for export operations.
 *
 * @param selection  Bitmask specifying which key components and parameters are being exported.
 *
 * @return Pointer to an array of OSSL_PARAM descriptors, or NULL if none are available.
 */
static const OSSL_PARAM *qat_keymgmt_rsa_export_types(int selection)
{
    return qat_rsa_imexport_types(selection);
}

/**
 * @brief Compares two RSA key objects for equality based on the selection mask.
 *
 * This function checks whether the two provided RSA key objects match according to
 * the specified selection mask. It compares the public exponent, modulus, and private exponent
 * as required by the selection. The function returns 1 if all selected components match,
 * and 0 otherwise.
 *
 * @param keydata1   Pointer to the first RSA key object.
 * @param keydata2   Pointer to the second RSA key object.
 * @param selection  Bitmask specifying which key components to compare.
 *
 * @return 1 if all selected components match, 0 otherwise.
 */
static int qat_keymgmt_rsa_match(const void *keydata1, const void *keydata2,
	                         int selection)
{
    DEBUG("%s\n", __func__);
    const RSA *rsa1 = keydata1;
    const RSA *rsa2 = keydata2;

    int ok = 1;

    if (!qat_prov_is_running())
        return 0;

    /* There is always an |e| */
    ok = ok && BN_cmp(RSA_get0_e(rsa1), RSA_get0_e(rsa2)) == 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int key_checked = 0;
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
            const BIGNUM *pa = RSA_get0_n(rsa1);
            const BIGNUM *pb = RSA_get0_n(rsa2);
            if (pa != NULL && pb != NULL) {
                ok = ok && BN_cmp(pa, pb) == 0;
                key_checked = 1;
            }
        }
        if (!key_checked
            && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
            const BIGNUM *pa = RSA_get0_d(rsa1);
            const BIGNUM *pb = RSA_get0_d(rsa2);
            if (pa != NULL && pb != NULL) {
                ok = ok && BN_cmp(pa, pb) == 0;
	            key_checked = 1;
            }
        }
        ok = ok && key_checked;
    }
    return ok;
}

const OSSL_DISPATCH qat_rsa_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))qat_keymgmt_rsa_newdata},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))qat_keymgmt_rsa_freedata},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))qat_keymgmt_rsa_has},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))qat_keymgmt_rsa_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))qat_keymgmt_rsa_import_types},
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))qat_keymgmt_rsa_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
       (void (*)(void))qat_keymgmt_rsa_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
       (void (*)(void))qat_keymgmt_rsa_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))qat_keymgmt_rsa_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))qat_keymgmt_rsa_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))qat_keymgmt_rsa_load },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))qat_keymgmt_rsa_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))qat_keymgmt_rsa_gettable_params },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))qat_keymgmt_rsa_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))qat_keymgmt_rsa_export_types },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))qat_keymgmt_rsa_match },
    {0, NULL}
};

const OSSL_DISPATCH qat_rsapss_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))qat_keymgmt_rsapss_newdata},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))qat_keymgmt_rsa_freedata},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))qat_keymgmt_rsa_has},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))qat_keymgmt_rsa_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))qat_keymgmt_rsa_import_types},
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))qat_keymgmt_rsapss_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
       (void (*)(void))qat_keymgmt_rsa_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
       (void (*)(void))qat_keymgmt_rsapss_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))qat_keymgmt_rsa_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))qat_keymgmt_rsa_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))qat_keymgmt_rsapss_load },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))qat_keymgmt_rsa_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))qat_keymgmt_rsa_gettable_params },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))qat_keymgmt_rsa_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))qat_keymgmt_rsa_export_types },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))qat_keymgmt_rsa_match },
    {0, NULL}
};
#endif
