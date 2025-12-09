#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/proverr.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "e_qat.h"
#include "qat_provider.h"
#include "qat_prov_rsa.h"
#include "qat_utils.h"

#ifdef ENABLE_QAT_FIPS
# include "qat_prov_cmvp.h"
#endif

#ifdef QAT_HW
#include "qat_hw_rsa.h"
#endif

#ifdef QAT_SW
#include "qat_sw_rsa.h"
#endif

# define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))
#define rsa_pss_restricted(prsactx) (prsactx->min_saltlen != -1)
#define SSL_SIG_LENGTH  36
#define RSA_DEFAULT_DIGEST_NAME OSSL_DIGEST_NAME_SHA1

#define ASN1_SEQUENCE 0x30
#define ASN1_OCTET_STRING_ 0x04
#define ASN1_NULL 0x05
#define ASN1_OID 0x06

#define NID_mdc2              95

#define ENCODE_DIGESTINFO_SHA(name, n, sz)                                     \
static const unsigned char digestinfo_##name##_der[] = {                       \
    ASN1_SEQUENCE, 0x11 + sz,                                                  \
      ASN1_SEQUENCE, 0x0d,                                                     \
        ASN1_OID, 0x09, 2 * 40 + 16, 0x86, 0x48, 1, 101, 3, 4, 2, n,           \
        ASN1_NULL, 0x00,                                                       \
      ASN1_OCTET_STRING_, sz                                                   \
};

#define RSA_KEY_SIZE 8
#define RSA_PSS_SALTLEN_AUTO_DIGEST_MAX  -4
#define OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX "auto-digestmax"

#if defined(ENABLE_QAT_HW_RSA) || defined(ENABLE_QAT_SW_RSA)

struct evp_signature_st {
    int name_id;
    char *type_name;
    const char *description;
    OSSL_PROVIDER *prov;
    QAT_CRYPTO_REF_COUNT references;
#if OPENSSL_VERSION_NUMBER < 0x30200000
    CRYPTO_RWLOCK *lock;
#endif
    OSSL_FUNC_signature_newctx_fn *newctx;
    OSSL_FUNC_signature_sign_init_fn *sign_init;
    OSSL_FUNC_signature_sign_fn *sign;
#if OPENSSL_VERSION_NUMBER >= 0x30400000
    OSSL_FUNC_signature_sign_message_init_fn *sign_message_init;
    OSSL_FUNC_signature_sign_message_update_fn *sign_message_update;
    OSSL_FUNC_signature_sign_message_final_fn *sign_message_final;
#endif
    OSSL_FUNC_signature_verify_init_fn *verify_init;
    OSSL_FUNC_signature_verify_fn *verify;
#if OPENSSL_VERSION_NUMBER >= 0x30400000
    OSSL_FUNC_signature_verify_message_init_fn *verify_message_init;
    OSSL_FUNC_signature_verify_message_update_fn *verify_message_update;
    OSSL_FUNC_signature_verify_message_final_fn *verify_message_final;
#endif
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
} /* EVP_SIGNATURE */;

static EVP_SIGNATURE get_default_rsa_signature()
{
    static EVP_SIGNATURE s_signature;
    static int initilazed = 0;
    if (!initilazed) {
        EVP_SIGNATURE *signature = (EVP_SIGNATURE *)EVP_SIGNATURE_fetch(NULL, "RSA",
									"provider=default");
        if (signature) {
            s_signature = *signature;
            EVP_SIGNATURE_free((EVP_SIGNATURE *)signature);
            initilazed = 1;
        } else {
            WARN("EVP_SIGNATURE_fetch from default provider failed");
        }
    }
    return s_signature;
}

ENCODE_DIGESTINFO_SHA(sha256, 0x01, SHA256_DIGEST_LENGTH)
ENCODE_DIGESTINFO_SHA(sha384, 0x02, SHA384_DIGEST_LENGTH)
ENCODE_DIGESTINFO_SHA(sha512, 0x03, SHA512_DIGEST_LENGTH)
ENCODE_DIGESTINFO_SHA(sha224, 0x04, SHA224_DIGEST_LENGTH)
ENCODE_DIGESTINFO_SHA(sha512_224, 0x05, SHA224_DIGEST_LENGTH)
ENCODE_DIGESTINFO_SHA(sha512_256, 0x06, SHA256_DIGEST_LENGTH)
ENCODE_DIGESTINFO_SHA(sha3_224, 0x07, SHA224_DIGEST_LENGTH)
ENCODE_DIGESTINFO_SHA(sha3_256, 0x08, SHA256_DIGEST_LENGTH)
ENCODE_DIGESTINFO_SHA(sha3_384, 0x09, SHA384_DIGEST_LENGTH)
ENCODE_DIGESTINFO_SHA(sha3_512, 0x0a, SHA512_DIGEST_LENGTH)

static const unsigned char digestinfo_sha1_der[] = {
    ASN1_SEQUENCE, 0x0d + SHA_DIGEST_LENGTH,
    ASN1_SEQUENCE, 0x09,
    ASN1_OID, 0x05, 1 * 40 + 3, 14, 3, 2, 26,
    ASN1_NULL, 0x00,
    ASN1_OCTET_STRING_, SHA_DIGEST_LENGTH
};

#define MD_CASE(name)                                                          \
    case NID_##name:                                                           \
        *len = sizeof(digestinfo_##name##_der);                                \
        return digestinfo_##name##_der;

#define MD_NID_CASE(name, sz)                                                  \
    case NID_##name:                                                           \
        return sz;

const unsigned char *qat_rsa_digestinfo_encoding(int md_nid, size_t *len)
{
    switch (md_nid) {
    MD_CASE(sha1)
    MD_CASE(sha224)
    MD_CASE(sha256)
    MD_CASE(sha384)
    MD_CASE(sha512)
    MD_CASE(sha512_224)
    MD_CASE(sha512_256)
    MD_CASE(sha3_224)
    MD_CASE(sha3_256)
    MD_CASE(sha3_384)
    MD_CASE(sha3_512)
    default:
        return NULL;
    }
}

static const unsigned char zeroes[] = { 0, 0, 0, 0, 0, 0, 0, 0 };

static const OSSL_ITEM oaeppss_name_nid_map[] = {
    { NID_sha1,         OSSL_DIGEST_NAME_SHA1         },
    { NID_sha224,       OSSL_DIGEST_NAME_SHA2_224     },
    { NID_sha256,       OSSL_DIGEST_NAME_SHA2_256     },
    { NID_sha384,       OSSL_DIGEST_NAME_SHA2_384     },
    { NID_sha512,       OSSL_DIGEST_NAME_SHA2_512     },
    { NID_sha512_224,   OSSL_DIGEST_NAME_SHA2_512_224 },
    { NID_sha512_256,   OSSL_DIGEST_NAME_SHA2_512_256 },
};

static OSSL_ITEM padding_item[] = {
    { RSA_PKCS1_PADDING,        OSSL_PKEY_RSA_PAD_MODE_PKCSV15 },
    { RSA_NO_PADDING,           OSSL_PKEY_RSA_PAD_MODE_NONE },
    { RSA_X931_PADDING,         OSSL_PKEY_RSA_PAD_MODE_X931 },
    { RSA_PKCS1_PSS_PADDING,    OSSL_PKEY_RSA_PAD_MODE_PSS },
    { 0,                        NULL     }
};

const QAT_RSA_PSS_PARAMS_30 default_RSASSA_PSS_params = {
    NID_sha1,                    /* default hashAlgorithm */
    {
        NID_mgf1,                /* default maskGenAlgorithm */
        NID_sha1                 /* default MGF1 hash */
    },
    20,                          /* default saltLength */
    1                            /* default trailerField (0xBC) */
};

static const OSSL_PARAM settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM settable_ctx_params_no_digest[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
    OSSL_PARAM_END
};

static int qat_rsa_private_encrypt(int flen, const unsigned char *from,
                                   unsigned char *to, QAT_RSA *rsa,
				   int padding)
{
    int ret = 0;
#ifdef ENABLE_QAT_HW_RSA
    if (qat_hw_rsa_offload)
        ret = qat_rsa_priv_enc(flen, from, to, rsa, padding);
#endif

#ifdef ENABLE_QAT_SW_RSA
    if (qat_sw_rsa_offload)
        ret = multibuff_rsa_priv_enc(flen, from, to, rsa, padding);
#endif
    return ret;
}

static int qat_rsa_public_decrypt(int flen, const unsigned char *from,
		                  unsigned char *to, QAT_RSA *rsa,
		                  int padding)
{
    int ret = 0;
#ifdef ENABLE_QAT_HW_RSA
    if (qat_hw_rsa_offload)
        ret = qat_rsa_pub_dec(flen, from, to, rsa, padding);
#endif

#ifdef ENABLE_QAT_SW_RSA
    if (qat_sw_rsa_offload)
        ret = multibuff_rsa_pub_dec(flen, from, to, rsa, padding);
#endif
    return ret;
}

static size_t rsa_get_md_size(const QAT_PROV_RSA_CTX *prsactx)
{
    if (prsactx->md != NULL)
        return EVP_MD_size(prsactx->md);
    return 0;
}

static int setup_tbuf(QAT_PROV_RSA_CTX *ctx)
{
    if (ctx->tbuf != NULL)
        return 1;
    if ((ctx->tbuf = OPENSSL_malloc(QAT_RSA_size(ctx->rsa))) == NULL) {
        QATerr(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

static void clean_tbuf(QAT_PROV_RSA_CTX *ctx)
{
    if (ctx->tbuf != NULL)
        OPENSSL_cleanse(ctx->tbuf, QAT_RSA_size(ctx->rsa));
}

static void free_tbuf(QAT_PROV_RSA_CTX *ctx)
{
    clean_tbuf(ctx);
    OPENSSL_free(ctx->tbuf);
    ctx->tbuf = NULL;
}

static int encode_pkcs1(unsigned char **out, size_t *out_len, int type,
                        const unsigned char *m, size_t m_len)
{
    size_t di_prefix_len, dig_info_len;
    const unsigned char *di_prefix;
    unsigned char *dig_info;

    if (type == NID_undef) {
        QATerr(ERR_LIB_RSA, RSA_R_UNKNOWN_ALGORITHM_TYPE);
        return 0;
    }
    di_prefix = qat_rsa_digestinfo_encoding(type, &di_prefix_len);
    if (di_prefix == NULL) {
        QATerr(ERR_LIB_RSA,
                  RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD);
        return 0;
    }
    dig_info_len = di_prefix_len + m_len;
    dig_info = OPENSSL_malloc(dig_info_len);
    if (dig_info == NULL) {
        QATerr(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    memcpy(dig_info, di_prefix, di_prefix_len);
    memcpy(dig_info + di_prefix_len, m, m_len);

    *out = dig_info;
    *out_len = dig_info_len;
    return 1;
}

#ifdef ENABLE_QAT_FIPS
/**
 * @brief Checks if the given RSA key size is FIPS approved.
 *
 * This function checks if the key size (in bytes) is within the FIPS approved range.
 * It sets the qat_fips_service_indicator as needed.
 *
 * @param rsasize   RSA modulus size in bytes.
 * @param is_sign   1 if used for signing, 0 if used for verification.
 *
 * @return 1 if key size is FIPS approved, 0 otherwise.
 */
static int qat_fips_check_rsa_key_size(size_t rsasize, int is_sign)
{
    int key_size = rsasize * RSA_KEY_SIZE;
    qat_fips_service_indicator = 0;

    if (is_sign) {
        if (key_size < FIPS_RSA_SIGN_MIN_SIZE || key_size > FIPS_RSA_MAX_SIZE) {
            WARN("%d is FIPS non approved size\n", key_size);
            return 0;
        }
        qat_fips_service_indicator = 1;
    } else {
        if (key_size != FIPS_RSA_VER_MIN_SIZE) {
            if (key_size < FIPS_RSA_SIGN_MIN_SIZE || key_size > FIPS_RSA_MAX_SIZE) {
                WARN("%d is FIPS non approved size\n", key_size);
                return 0;
            }
            qat_fips_service_indicator = 1;
        } else {
            INFO("Given Key size %d is Allowed. But, FIPS non-approved size\n", FIPS_RSA_VER_MIN_SIZE);
        }
    }
    return 1;
}
#endif

/**
 * @brief Adds PKCS#1 PSS padding with MGF1 to a message hash for RSA signature.
 *
 * This function applies PKCS#1 PSS (Probabilistic Signature Scheme) padding using MGF1
 * to the provided message hash, preparing it for RSA signature generation. It supports
 * custom hash algorithms for both the main digest and the MGF1 mask generation function,
 * and allows for variable salt lengths as required by the PSS scheme.
 *
 * @param rsa      Pointer to the QAT_RSA key structure.
 * @param EM       Output buffer for the encoded message (should be at least RSA_size(rsa) bytes).
 * @param mHash    Input message hash to be padded.
 * @param Hash     Digest method for the main hash.
 * @param mgf1Hash Digest method for the MGF1 mask generation function (if NULL, Hash is used).
 * @param sLenOut  Pointer to the salt length (input/output).
 *
 * @return 1 on success, 0 on failure.
 */
int QAT_RSA_padding_add_PKCS1_PSS_mgf1(QAT_RSA *rsa, unsigned char *EM,
                                       const unsigned char *mHash,
                                       const EVP_MD *Hash,
		                       const EVP_MD *mgf1Hash,
                                       int *sLenOut)
{
    int i;
    int ret = 0;
    int hLen, maskedDBLen, MSBits, emLen;
    int sLen = *sLenOut;
    unsigned char *H, *salt = NULL, *p;
    EVP_MD_CTX *ctx = NULL;

    if (mgf1Hash == NULL)
        mgf1Hash = Hash;

    hLen = EVP_MD_get_size(Hash);
    if (hLen < 0)
        goto err;
    /*-
     * Negative sLen has special meanings:
     *      -1      sLen == hLen
     *      -2      salt length is maximized
     *      -3      same as above (on signing)
     *      -N      reserved
     */
    if (sLen == RSA_PSS_SALTLEN_DIGEST) {
        sLen = hLen;
    } else if (sLen == RSA_PSS_SALTLEN_MAX_SIGN) {
        sLen = RSA_PSS_SALTLEN_MAX;
    } else if (sLen < RSA_PSS_SALTLEN_MAX) {
        QATerr(ERR_LIB_RSA, RSA_R_SLEN_CHECK_FAILED);
        goto err;
    }

    MSBits = (BN_num_bits(rsa->n) - 1) & 0x7;
    emLen = QAT_RSA_size(rsa);
    if (MSBits == 0) {
        *EM++ = 0;
        emLen--;
    }
    if (emLen < hLen + 2) {
        QATerr(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        goto err;
    }
    if (sLen == RSA_PSS_SALTLEN_MAX) {
        sLen = emLen - hLen - 2;
    } else if (sLen > emLen - hLen - 2) {
        QATerr(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        goto err;
    }
    if (sLen > 0) {
        salt = OPENSSL_malloc(sLen);
        if (salt == NULL) {
            QATerr(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (RAND_bytes_ex(rsa->libctx, salt, sLen, 0) <= 0)
            goto err;
    }
    maskedDBLen = emLen - hLen - 1;
    H = EM + maskedDBLen;
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        goto err;
    if (!EVP_DigestInit_ex(ctx, Hash, NULL)
        || !EVP_DigestUpdate(ctx, zeroes, sizeof(zeroes))
        || !EVP_DigestUpdate(ctx, mHash, hLen))
        goto err;
    if (sLen && !EVP_DigestUpdate(ctx, salt, sLen))
        goto err;
    if (!EVP_DigestFinal_ex(ctx, H, NULL))
        goto err;

    /* Generate dbMask in place then perform XOR on it */
    if (QAT_PKCS1_MGF1(EM, maskedDBLen, H, hLen, mgf1Hash))
        goto err;

    p = EM;

    /*
     * Initial PS XORs with all zeroes which is a NOP so just update pointer.
     * Note from a test above this value is guaranteed to be non-negative.
     */
    p += emLen - sLen - hLen - 2;
    *p++ ^= 0x1;
    if (sLen > 0) {
        for (i = 0; i < sLen; i++)
            *p++ ^= salt[i];
    }
    if (MSBits)
        EM[0] &= 0xFF >> (8 - MSBits);

    /* H is already in place so just set final 0xbc */

    EM[emLen - 1] = 0xbc;

    ret = 1;
    *sLenOut = sLen;

 err:
    EVP_MD_CTX_free(ctx);
    OPENSSL_clear_free(salt, (size_t)sLen); /* salt != NULL implies sLen > 0 */

    return ret;

}

/**
 * @brief Signs a message digest using RSA and PKCS#1 v1.5 padding.
 *
 * This function creates an RSA signature for the given message digest using the specified
 * digest type and the provided QAT_RSA key. It encodes the digest using the appropriate
 * ASN.1 DigestInfo structure (unless the digest type is NID_md5_sha1), applies PKCS#1 v1.5
 * padding, and performs the RSA private key operation.
 *
 * @param prsactx  Pointer to the provider RSA context.
 * @param type     NID of the digest algorithm used (e.g., NID_sha256).
 * @param m        Pointer to the message digest to sign.
 * @param m_len    Length of the message digest.
 * @param sigret   Output buffer for the resulting signature.
 * @param siglen   Pointer to an unsigned int to receive the signature length.
 * @param rsa      Pointer to the QAT_RSA key structure.
 *
 * @return 1 on success, 0 on failure.
 */
int QAT_RSA_sign(void *prsactx, int type, const unsigned char *m, unsigned int m_len,
                 unsigned char *sigret, size_t *sigLen, size_t sigsize, unsigned int *siglen,
	         QAT_RSA *rsa)
{
    int encrypt_len, ret = 0;
    size_t encoded_len = 0;
    unsigned char *tmps = NULL;
    const unsigned char *encoded = NULL;

    /* Compute the encoded digest. */
    if (type == NID_md5_sha1) {
        /*
         * NID_md5_sha1 corresponds to the MD5/SHA1 combination in TLS 1.1 and
         * earlier. It has no DigestInfo wrapper but otherwise is
         * RSASSA-PKCS1-v1_5.
         */
        if (m_len != SSL_SIG_LENGTH) {
            QATerr(ERR_LIB_RSA, RSA_R_INVALID_MESSAGE_LENGTH);
            return 0;
        }
        encoded_len = SSL_SIG_LENGTH;
        encoded = m;
    } else {
        if (!encode_pkcs1(&tmps, &encoded_len, type, m, m_len))
            goto err;
        encoded = tmps;
    }

    if (encoded_len + RSA_PKCS1_PADDING_SIZE > (size_t)QAT_RSA_size(rsa)) {
        QATerr(ERR_LIB_RSA, RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY);
        goto err;
    }

    if (qat_hw_rsa_offload || qat_sw_rsa_offload) {
        encrypt_len = qat_rsa_private_encrypt((int)encoded_len, encoded, sigret,
					      rsa, RSA_PKCS1_PADDING);
    } else {
        typedef int (*fun_ptr)(void *prsactx, unsigned char *sigret,
			       size_t *sigLen, size_t sigsize,
			       const unsigned char *m,
			       size_t m_len);
	fun_ptr fun = get_default_rsa_signature().sign;
	if (!fun)
	    goto err;
	return fun(prsactx, sigret, sigLen, sigsize, m, m_len);
    }

    if (encrypt_len <= 0)
        goto err;

    *siglen = encrypt_len;
    ret = 1;

err:
    OPENSSL_clear_free(tmps, encoded_len);
    return ret;
}

static int rsa_sign_directly(QAT_PROV_RSA_CTX *prsactx, unsigned char *sig,
			     size_t *siglen, size_t sigsize,
			     const unsigned char *tbs, size_t tbslen)
{
    size_t rsasize = QAT_RSA_size(prsactx->rsa);
    size_t mdsize = rsa_get_md_size(prsactx);
    int ret = 0;

    if (!qat_prov_is_running())
        return 0;

    if (sig == NULL) {
        *siglen = rsasize;
        return 1;
    }

    if (sigsize < rsasize) {
        WARN("signature size is %zu, should be at least %zu", sigsize, rsasize);
        QATerr(ERR_LIB_PROV, PROV_R_INVALID_SIGNATURE_SIZE);
	return 0;
    }

    if (mdsize != 0) {
        if (tbslen != mdsize) {
            QATerr(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH);
	    return 0;
	}

	switch (prsactx->pad_mode) {
        case RSA_X931_PADDING:
	    if ((size_t)QAT_RSA_size(prsactx->rsa) < tbslen + 1) {
	        WARN("RSA key size = %d, expected minimum = %zu",
		      QAT_RSA_size(prsactx->rsa), tbslen + 1);
	        QATerr(ERR_LIB_PROV, QAT_R_PROV_KEY_SIZE_TOO_SMALL);
		return 0;
	    }
	    if (!setup_tbuf(prsactx)) {
		QATerr(ERR_LIB_PROV, QAT_R_PROV_INVALID_CTX_LIB);
		return 0;
	    }
	    memcpy(prsactx->tbuf, tbs, tbslen);
	    prsactx->tbuf[tbslen] = RSA_X931_hash_id(prsactx->mdnid);
	    if (qat_hw_rsa_offload || qat_sw_rsa_offload) {
		ret = qat_rsa_private_encrypt(tbslen + 1, prsactx->tbuf,
	                      		      sig, prsactx->rsa,
					      RSA_X931_PADDING);
	    } else {
	        typedef int (*fun_ptr)(void *prsactx, unsigned char *sig,
				       size_t *siglen, size_t sigsize,
				       const unsigned char *tbs,
				       size_t tbslen);
	        fun_ptr fun = get_default_rsa_signature().sign;
		if (!fun)
		    return 0;
		return fun(prsactx, sig, siglen, sigsize, tbs, tbslen);
	    }
	    clean_tbuf(prsactx);
	    break;

	case RSA_PKCS1_PADDING:
	{
	    unsigned int sltmp = 0;
   	    ret = QAT_RSA_sign(prsactx, prsactx->mdnid, tbs, tbslen, sig,
			       siglen, sigsize, &sltmp,
	 		       prsactx->rsa);
	    if (ret <= 0) {
		QATerr(ERR_LIB_PROV, ERR_R_RSA_LIB);
		return 0;
	    }
	    ret = sltmp;
	}
	break;

	case RSA_PKCS1_PSS_PADDING:
	{
	    int saltlen = -1;

	    if (rsa_pss_restricted(prsactx)) {
	        switch (prsactx->saltlen) {
	        case RSA_PSS_SALTLEN_DIGEST:
	            if (prsactx->min_saltlen > EVP_MD_get_size(prsactx->md)) {
                        WARN("minimum salt length set to %d, but the digest only gives %d",
                             prsactx->min_saltlen, EVP_MD_get_size(prsactx->md));
                        QATerr(ERR_LIB_PROV, PROV_R_PSS_SALTLEN_TOO_SMALL);
   		        return 0;
		    }
		/* FALLTHRU */
	        default:
		    if ((prsactx->saltlen >= 0)
		        && (prsactx->saltlen < prsactx->min_saltlen)) {
		        WARN("minimum salt length set to %d, but the actual salt length is only set to %d",
			     prsactx->min_saltlen, prsactx->saltlen);
                        QATerr(ERR_LIB_PROV, PROV_R_PSS_SALTLEN_TOO_SMALL);
		        return 0;
		    }
		    break;
	        }
	    }

	    if (!setup_tbuf(prsactx))
		return 0;
	    saltlen = prsactx->saltlen;

	    if (!QAT_RSA_padding_add_PKCS1_PSS_mgf1(prsactx->rsa,
						    prsactx->tbuf, tbs,
						    prsactx->md,
						    prsactx->mgf1_md,
						    &saltlen)) {
		QATerr(ERR_LIB_PROV, ERR_R_RSA_LIB);
		return 0;
	    }
	    if (qat_hw_rsa_offload || qat_sw_rsa_offload) {
	        ret = qat_rsa_private_encrypt(RSA_size(prsactx->rsa), prsactx->tbuf,
			                      sig, prsactx->rsa, RSA_NO_PADDING);
	    }
	    else {
	        typedef int (*fun_ptr)(void *prsactx, unsigned char *sig,
				       size_t *siglen, size_t sigsize,
				       const unsigned char *tbs,
				       size_t tbslen);
		fun_ptr fun = get_default_rsa_signature().sign;
		if (!fun)
		    return 0;
		return fun(prsactx, sig, siglen, sigsize, tbs, tbslen);
	    }
	    clean_tbuf(prsactx);
	}
	break;

	default:
	    WARN("Only X.931, PKCS#1 v1.5 or PSS padding allowed");
	    QATerr(ERR_LIB_PROV, PROV_R_INVALID_PADDING_MODE);
	    return 0;
        }
    } else {
        if (qat_hw_rsa_offload || qat_sw_rsa_offload) {
	    ret = qat_rsa_private_encrypt(tbslen, tbs, sig, prsactx->rsa,
	 			          prsactx->pad_mode);
	} else {
	    typedef int (*fun_ptr)(void *prsactx, unsigned char *sig,
	  		           size_t *siglen, size_t sigsize,
				   const unsigned char *tbs,
				   size_t tbslen);
	    fun_ptr fun = get_default_rsa_signature().sign;
	    if (!fun)
	        return 0;
	    return fun(prsactx, sig, siglen, sigsize, tbs, tbslen);
	}
    }

    if (ret <= 0) {
	QATerr(ERR_LIB_PROV, ERR_R_RSA_LIB);
	return 0;
    }

    *siglen = ret;
    return 1;
}

/**
 * @brief Updates the message digest for RSA sign or verify operations.
 *
 * This function feeds additional data into the message digest context associated
 * with the QAT_PROV_RSA_CTX during a multi-part (streaming) RSA sign or verify operation.
 * It ensures that updates are allowed in the current context state and disables
 * one-shot mode if called.
 *
 * @param vprsactx  Pointer to the QAT_PROV_RSA_CTX context.
 * @param data      Pointer to the input data to update the digest with.
 * @param datalen   Length of the input data.
 *
 * @return 1 on success, 0 on failure.
 */
static int rsa_signverify_message_update(void *vprsactx,
                                         const unsigned char *data,
                                         size_t datalen)
{
    QAT_PROV_RSA_CTX *prsactx = (QAT_PROV_RSA_CTX *)vprsactx;

    if (prsactx == NULL || prsactx->mdctx == NULL)
	return 0;

    if (!prsactx->flag_allow_update) {
	QATerr(ERR_LIB_PROV, QAT_R_PROV_UPDATE_CALL_OUT_OF_ORDER);
	return 0;
    }
    prsactx->flag_allow_oneshot = 0;

    return EVP_DigestUpdate(prsactx->mdctx, data, datalen);
}

/**
 * @brief Finalizes a multi-part RSA sign operation and produces the signature.
 *
 * This function completes a streaming (multi-part) RSA sign operation by finalizing
 * the message digest, performing any necessary padding, and generating the final
 * RSA signature. It ensures the context is in a valid state for finalization and
 * disables further updates or one-shot calls after completion.
 *
 * @param vprsactx  Pointer to the QAT_PROV_RSA_CTX context.
 * @param sig       Output buffer for the resulting signature (may be NULL to query size).
 * @param siglen    Pointer to a size_t to receive the signature length.
 * @param sigsize   Size of the output buffer.
 *
 * @return 1 on success, 0 on failure.
 */
static int rsa_sign_message_final(void *vprsactx, unsigned char *sig,
			          size_t *siglen, size_t sigsize)
{
    DEBUG("%s\n", __func__);
    QAT_PROV_RSA_CTX *prsactx = (QAT_PROV_RSA_CTX *)vprsactx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (!qat_prov_is_running() || prsactx == NULL)
    	return 0;

    if (prsactx->mdctx == NULL)
	return 0;

    if (!prsactx->flag_allow_final) {
	QATerr(ERR_LIB_PROV, QAT_R_PROV_FINAL_CALL_OUT_OF_ORDER);
	return 0;
    }

    if (sig != NULL) {
	if (!EVP_DigestFinal_ex(prsactx->mdctx, digest, &dlen))
   	    return 0;

	prsactx->flag_allow_update = 0;
	prsactx->flag_allow_oneshot = 0;
	prsactx->flag_allow_final = 0;
    }

    return rsa_sign_directly(prsactx, sig, siglen, sigsize, digest, dlen);
}

QAT_RSA_PSS_PARAMS_30 *qat_rsa_get0_pss_params_30(QAT_RSA *r)
{
    return &r->pss_params;
}

int qat_rsa_pss_params_30_is_unrestricted(const QAT_RSA_PSS_PARAMS_30 *rsa_pss_params)
{
    static QAT_RSA_PSS_PARAMS_30 pss_params_cmp = { 0, };

    return rsa_pss_params == NULL
        || memcmp(rsa_pss_params, &pss_params_cmp,
                  sizeof(*rsa_pss_params)) == 0;
}

int qat_rsa_pss_params_30_hashalg(const QAT_RSA_PSS_PARAMS_30 *rsa_pss_params)
{
    if (rsa_pss_params == NULL)
        return default_RSASSA_PSS_params.hash_algorithm_nid;
    return rsa_pss_params->hash_algorithm_nid;
}

int qat_rsa_pss_params_30_maskgenhashalg(const QAT_RSA_PSS_PARAMS_30 *rsa_pss_params)
{
    if (rsa_pss_params == NULL)
        return default_RSASSA_PSS_params.hash_algorithm_nid;
    return rsa_pss_params->mask_gen.hash_algorithm_nid;
}

int qat_rsa_pss_params_30_saltlen(const QAT_RSA_PSS_PARAMS_30 *rsa_pss_params)
{
    if (rsa_pss_params == NULL)
        return default_RSASSA_PSS_params.salt_len;
    return rsa_pss_params->salt_len;
}

const char *nid2name(int meth, const OSSL_ITEM *items, size_t items_n)
{
    size_t i;

    for (i = 0; i < items_n; i++)
        if (meth == (int)items[i].id)
            return items[i].ptr;
    return NULL;
}

const char *qat_rsa_oaeppss_nid2name(int md)
{
    return nid2name(md, oaeppss_name_nid_map, OSSL_NELEM(oaeppss_name_nid_map));
}

static int qat_rsa_check_padding(const QAT_PROV_RSA_CTX *prsactx,
                                 const char *mdname,
				 const char *mgf1_mdname,
                                 int mdnid)
{
    switch(prsactx->pad_mode) {
    case RSA_NO_PADDING:
        QATerr(ERR_LIB_PROV, PROV_R_INVALID_PADDING_MODE);
        return 0;

    case RSA_X931_PADDING:
        if (RSA_X931_hash_id(mdnid) == -1) {
            QATerr(ERR_LIB_PROV, PROV_R_INVALID_X931_DIGEST);
            return 0;
        }
        break;

    case RSA_PKCS1_PSS_PADDING:
        if (rsa_pss_restricted(prsactx)) {
            if ((mdname != NULL && !EVP_MD_is_a(prsactx->md, mdname))
                || (mgf1_mdname != NULL
                    && !EVP_MD_is_a(prsactx->mgf1_md, mgf1_mdname))) {
                QATerr(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED);
                return 0;
            }
	}
        break;
    default:
        break;
    }

    return 1;
}

int qat_digest_md_to_nid(const EVP_MD *md, const OSSL_ITEM *it, size_t it_len)
{
    size_t i;

    if (md == NULL)
        return NID_undef;

    for (i = 0; i < it_len; i++)
        if (EVP_MD_is_a(md, it[i].ptr))
            return (int)it[i].id;
    return NID_undef;
}

int qat_digest_get_approved_nid(const EVP_MD *md)
{
    static const OSSL_ITEM name_to_nid[] = {
        { NID_sha1,      OSSL_DIGEST_NAME_SHA1      },
        { NID_sha224,    OSSL_DIGEST_NAME_SHA2_224  },
        { NID_sha256,    OSSL_DIGEST_NAME_SHA2_256  },
        { NID_sha384,    OSSL_DIGEST_NAME_SHA2_384  },
        { NID_sha512,    OSSL_DIGEST_NAME_SHA2_512  },
        { NID_sha512_224, OSSL_DIGEST_NAME_SHA2_512_224 },
        { NID_sha512_256, OSSL_DIGEST_NAME_SHA2_512_256 },
        { NID_sha3_224,  OSSL_DIGEST_NAME_SHA3_224  },
        { NID_sha3_256,  OSSL_DIGEST_NAME_SHA3_256  },
        { NID_sha3_384,  OSSL_DIGEST_NAME_SHA3_384  },
        { NID_sha3_512,  OSSL_DIGEST_NAME_SHA3_512  },
        { NID_md5_sha1,  OSSL_DIGEST_NAME_MD5_SHA1  },
    };

    return qat_digest_md_to_nid(md, name_to_nid, OSSL_NELEM(name_to_nid));
}

int qat_digest_rsa_sign_get_md_nid(OSSL_LIB_CTX *ctx, const EVP_MD *md,
                                   int sha1_allowed)
{
    return qat_digest_get_approved_nid(md);
}

/**
 * @brief Sets up the MGF1 digest method for RSA-PSS operations in the QAT provider context.
 *
 * This function fetches and assigns the specified MGF1 digest algorithm to the QAT_PROV_RSA_CTX
 * structure. It validates the digest, checks compatibility with the current padding mode,
 * and updates the context with the digest name and NID. If a previous MGF1 digest is set,
 * it is freed before assignment.
 *
 * @param ctx      Pointer to the QAT_PROV_RSA_CTX context.
 * @param mdname   Name of the MGF1 digest algorithm to fetch.
 * @param mdprops  Optional property query string for digest selection (may be NULL).
 *
 * @return 1 on success, 0 on failure.
 */
static int qat_rsa_setup_mgf1_md(QAT_PROV_RSA_CTX *ctx, const char *mdname,
                                 const char *mdprops)
{
    size_t len;
    EVP_MD *md = NULL;
    int mdnid;

    if (mdprops == NULL)
        mdprops = ctx->propq;

    if ((md = EVP_MD_fetch(ctx->libctx, mdname, mdprops)) == NULL) {
        WARN("%s could not be fetched", mdname);
        QATerr(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
        return 0;
    }
    /* The default for mgf1 is SHA1 - so allow SHA1 */
    if ((mdnid = qat_digest_rsa_sign_get_md_nid(ctx->libctx, md, 1)) <= 0
        || !qat_rsa_check_padding(ctx, NULL, mdname, mdnid)) {
        if (mdnid <= 0) {
            WARN("digest=%s", mdname);
            QATerr(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED);
	}
	EVP_MD_free(md);
        return 0;
    }
    len = OPENSSL_strlcpy(ctx->mgf1_mdname, mdname, sizeof(ctx->mgf1_mdname));
    if (len >= sizeof(ctx->mgf1_mdname)) {
        WARN("%s exceeds name buffer length", mdname);
        QATerr(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
        EVP_MD_free(md);
        return 0;
    }

    EVP_MD_free(ctx->mgf1_md);
    ctx->mgf1_md = md;
    ctx->mgf1_mdnid = mdnid;
    ctx->mgf1_md_set = 1;
    return 1;
}

/**
 * @brief Sets up the main digest method for RSA operations in the QAT provider context.
 *
 * This function fetches and assigns the specified digest algorithm to the QAT_PROV_RSA_CTX
 * structure. It validates the digest, checks compatibility with the current padding mode,
 * and updates the context with the digest name and NID. If the MGF1 digest is not set,
 * it also assigns the main digest as the MGF1 digest. The function manages memory for
 * previous digest assignments and ensures the context is updated consistently.
 *
 * @param ctx      Pointer to the QAT_PROV_RSA_CTX context.
 * @param mdname   Name of the digest algorithm to fetch.
 * @param mdprops  Optional property query string for digest selection (may be NULL).
 *
 * @return 1 on success, 0 on failure.
 */
static int qat_rsa_setup_md(QAT_PROV_RSA_CTX *ctx, const char *mdname,
                            const char *mdprops)
{
    if (mdprops == NULL)
        mdprops = ctx->propq;

    if (mdname != NULL) {
        EVP_MD *md = EVP_MD_fetch(ctx->libctx, mdname, mdprops);
        int sha1_allowed = (ctx->operation != EVP_PKEY_OP_SIGN);
        int md_nid = qat_digest_rsa_sign_get_md_nid(ctx->libctx, md,
                                                    sha1_allowed);
        size_t mdname_len = strlen(mdname);

        if (md == NULL
            || md_nid <= 0
            || !qat_rsa_check_padding(ctx, mdname, NULL, md_nid)
            || mdname_len >= sizeof(ctx->mdname)) {
            if (md == NULL) {
                WARN("%s could not be fetched", mdname);
                QATerr(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
	    }
	    if (mdname_len >= sizeof(ctx->mdname)) {
                WARN("%s exceeds name buffer length", mdname);
                QATerr(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
	    }
	    EVP_MD_free(md);
            return 0;
        }

        if (!ctx->mgf1_md_set) {
            if (!EVP_MD_up_ref(md)) {
                EVP_MD_free(md);
                return 0;
            }
            EVP_MD_free(ctx->mgf1_md);
            ctx->mgf1_md = md;
            ctx->mgf1_mdnid = md_nid;
            OPENSSL_strlcpy(ctx->mgf1_mdname, mdname, sizeof(ctx->mgf1_mdname));
        }

        EVP_MD_CTX_free(ctx->mdctx);
        EVP_MD_free(ctx->md);

        ctx->mdctx = NULL;
        ctx->md = md;
        ctx->mdnid = md_nid;
        OPENSSL_strlcpy(ctx->mdname, mdname, sizeof(ctx->mdname));
    }

    return 1;
}

static int qat_rsa_check_parameters(QAT_PROV_RSA_CTX *prsactx, int min_saltlen)
{
    if (prsactx->pad_mode == RSA_PKCS1_PSS_PADDING) {
        int max_saltlen;

        /* See if minimum salt length exceeds maximum possible */
        max_saltlen = QAT_RSA_size(prsactx->rsa) - EVP_MD_size(prsactx->md);
        if ((QAT_RSA_bits(prsactx->rsa) & 0x7) == 1)
            max_saltlen--;
        if (min_saltlen < 0 || min_saltlen > max_saltlen) {
            QATerr(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
            return 0;
        }
        prsactx->min_saltlen = min_saltlen;
    }
    return 1;
}

/**
 * @brief Generates a mask using the PKCS#1 MGF1 (Mask Generation Function 1) algorithm.
 *
 * This function implements the MGF1 algorithm as specified in PKCS#1, which is used
 * in OAEP and PSS padding schemes for RSA. It generates a mask of the requested length
 * by repeatedly hashing the seed concatenated with a 4-byte counter, using the specified
 * digest algorithm.
 *
 * @param mask     Output buffer for the generated mask.
 * @param len      Desired length of the mask in bytes.
 * @param seed     Input seed for the mask generation.
 * @param seedlen  Length of the input seed.
 * @param dgst     Digest algorithm to use for hashing (e.g., EVP_sha256()).
 *
 * @return 0 on success, -1 on failure.
 */
int QAT_PKCS1_MGF1(unsigned char *mask, long len, const unsigned char *seed,
		   long seedlen, const EVP_MD *dgst)
{
    long i, outlen = 0;
    unsigned char cnt[4];
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    unsigned char md[EVP_MAX_MD_SIZE];
    int mdlen;
    int rv = -1;

    if (c == NULL)
        goto err;
    mdlen = EVP_MD_get_size(dgst);
    if (mdlen < 0)
        goto err;
    /* step 4 */
    for (i = 0; outlen < len; i++) {
        /* step 4a: D = I2BS(counter, 4) */
        cnt[0] = (unsigned char)((i >> 24) & 255);
        cnt[1] = (unsigned char)((i >> 16) & 255);
        cnt[2] = (unsigned char)((i >> 8)) & 255;
        cnt[3] = (unsigned char)(i & 255);
        /* step 4b: T =T || hash(mgfSeed || D) */
        if (!EVP_DigestInit_ex(c, dgst, NULL)
            || !EVP_DigestUpdate(c, seed, seedlen)
            || !EVP_DigestUpdate(c, cnt, 4))
            goto err;
        if (outlen + mdlen <= len) {
            if (!EVP_DigestFinal_ex(c, mask + outlen, NULL))
                goto err;
            outlen += mdlen;
        } else {
            if (!EVP_DigestFinal_ex(c, md, NULL))
                goto err;
            memcpy(mask + outlen, md, len - outlen);
            outlen = len;
        }
    }
    rv = 0;
 err:
    OPENSSL_cleanse(md, sizeof(md));
    EVP_MD_CTX_free(c);
    return rv;
}

/**
 * @brief Verifies an RSA-PSS signature using PKCS#1 PSS padding with MGF1.
 *
 * This function checks that the provided encoded message (EM) is a valid PKCS#1 PSS
 * encoding of the given message hash (mHash), using the specified hash and MGF1
 * algorithms and salt length. It supports automatic and explicit salt length handling,
 * and performs all necessary decoding and comparison steps as described in PKCS#1.
 *
 * @param rsa      Pointer to the QAT_RSA key structure.
 * @param mHash    Input message hash to verify.
 * @param Hash     Digest method for the main hash.
 * @param mgf1Hash Digest method for the MGF1 mask generation function (if NULL, Hash is used).
 * @param EM       Encoded message (signature to verify).
 * @param sLenout  Pointer to the salt length (input/output).
 *
 * @return 1 on successful verification, 0 on failure.
 */
int QAT_RSA_verify_PKCS1_PSS_mgf1(QAT_RSA *rsa, const unsigned char *mHash,
                                  const EVP_MD *Hash, const EVP_MD *mgf1Hash,
                                  const unsigned char *EM, int *sLenout)
{
    int i;
    int ret = 0;
    int hLen, maskedDBLen, MSBits, emLen;
    const unsigned char *H;
    int sLen = *sLenout;
    unsigned char *DB = NULL;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char H_[EVP_MAX_MD_SIZE];

    if (ctx == NULL)
        goto err;

    if (mgf1Hash == NULL)
        mgf1Hash = Hash;

    hLen = EVP_MD_get_size(Hash);
    if (hLen < 0)
        goto err;
    /*-
     * Negative sLen has special meanings:
     *      -1      sLen == hLen
     *      -2      salt length is autorecovered from signature
     *      -3      salt length is maximized
     *      -N      reserved
     */
    if (sLen == RSA_PSS_SALTLEN_DIGEST) {
        sLen = hLen;
    } else if (sLen < RSA_PSS_SALTLEN_MAX) {
        QATerr(ERR_LIB_RSA, RSA_R_SLEN_CHECK_FAILED);
        goto err;
    }

    MSBits = (BN_num_bits(rsa->n) - 1) & 0x7;
    emLen = QAT_RSA_size(rsa);
    if (EM[0] & (0xFF << MSBits)) {
        QATerr(ERR_LIB_RSA, RSA_R_FIRST_OCTET_INVALID);
        goto err;
    }
    if (MSBits == 0) {
        EM++;
        emLen--;
    }
    if (emLen < hLen + 2) {
        QATerr(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE);
        goto err;
    }
    if (sLen == RSA_PSS_SALTLEN_MAX) {
        sLen = emLen - hLen - 2;
    } else if (sLen > emLen - hLen - 2) { /* sLen can be small negative */
        QATerr(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE);
        goto err;
    }
    if (EM[emLen - 1] != 0xbc) {
        QATerr(ERR_LIB_RSA, RSA_R_LAST_OCTET_INVALID);
        goto err;
    }
    maskedDBLen = emLen - hLen - 1;
    H = EM + maskedDBLen;
    DB = OPENSSL_malloc(maskedDBLen);
    if (DB == NULL) {
        QATerr(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (QAT_PKCS1_MGF1(DB, maskedDBLen, H, hLen, mgf1Hash) < 0)
        goto err;
    for (i = 0; i < maskedDBLen; i++)
        DB[i] ^= EM[i];
    if (MSBits)
        DB[0] &= 0xFF >> (8 - MSBits);
    for (i = 0; DB[i] == 0 && i < (maskedDBLen - 1); i++) ;
    if (DB[i++] != 0x1) {
        QATerr(ERR_LIB_RSA, RSA_R_SLEN_RECOVERY_FAILED);
        goto err;
    }
    if (sLen != RSA_PSS_SALTLEN_AUTO && (maskedDBLen - i) != sLen) {
        WARN("expected: %d retrieved: %d", sLen, maskedDBLen - i);
        QATerr(ERR_LIB_RSA, RSA_R_SLEN_CHECK_FAILED);
        goto err;
    }
    if (!EVP_DigestInit_ex(ctx, Hash, NULL)
        || !EVP_DigestUpdate(ctx, zeroes, sizeof(zeroes))
        || !EVP_DigestUpdate(ctx, mHash, hLen))
        goto err;
    if (maskedDBLen - i) {
        if (!EVP_DigestUpdate(ctx, DB + i, maskedDBLen - i))
            goto err;
    }
    if (!EVP_DigestFinal_ex(ctx, H_, NULL))
        goto err;
    if (memcmp(H_, H, hLen)) {
        QATerr(ERR_LIB_RSA, RSA_R_BAD_SIGNATURE);
        ret = 0;
    } else {
        ret = 1;
    }
    *sLenout = sLen;

 err:
    OPENSSL_free(DB);
    EVP_MD_CTX_free(ctx);

    return ret;

}

static int digest_sz_from_nid(int nid)
{
    switch (nid) {
    MD_NID_CASE(sha1, SHA_DIGEST_LENGTH)
    MD_NID_CASE(sha224, SHA224_DIGEST_LENGTH)
    MD_NID_CASE(sha256, SHA256_DIGEST_LENGTH)
    MD_NID_CASE(sha384, SHA384_DIGEST_LENGTH)
    MD_NID_CASE(sha512, SHA512_DIGEST_LENGTH)
    MD_NID_CASE(sha512_224, SHA224_DIGEST_LENGTH)
    MD_NID_CASE(sha512_256, SHA256_DIGEST_LENGTH)
    MD_NID_CASE(sha3_224, SHA224_DIGEST_LENGTH)
    MD_NID_CASE(sha3_256, SHA256_DIGEST_LENGTH)
    MD_NID_CASE(sha3_384, SHA384_DIGEST_LENGTH)
    MD_NID_CASE(sha3_512, SHA512_DIGEST_LENGTH)
    default:
        return 0;
    }
}

/**
 * @brief Verifies an RSA signature using PKCS#1 v1.5 padding.
 *
 * This function verifies an RSA signature by decrypting the signature using the public key,
 * reconstructing the expected encoded digest, and comparing it to the decrypted value.
 * It supports special cases for MD5/SHA1 (TLS 1.1 and earlier) and MDC2 digests, as well as
 * generic digest types. If the signature is valid, the function can optionally recover the
 * original digest value.
 *
 * @param prsactx   Pointer to the provider RSA context.
 * @param type      NID of the digest algorithm used (e.g., NID_sha256).
 * @param m         Pointer to the message digest to verify against.
 * @param m_len     Length of the message digest.
 * @param rm        Output buffer for the recovered digest (may be NULL if not needed).
 * @param prm_len   Pointer to a size_t to receive the length of the recovered digest (may be NULL).
 * @param sigbuf    Input buffer containing the signature to verify.
 * @param siglen    Length of the signature buffer.
 * @param rsa       Pointer to the QAT_RSA key structure.
 *
 * @return 1 on successful verification, 0 on failure.
 */
int QAT_RSA_verify(void *prsactx, int type, const unsigned char *m,
		   unsigned int m_len, unsigned char *rm,
		   size_t *prm_len,
                   const unsigned char *sigbuf,
		   size_t siglen, QAT_RSA *rsa)
{
    DEBUG("%s\n", __func__);
    int len, ret = 0;
    size_t decrypt_len, encoded_len = 0;
    unsigned char *decrypt_buf = NULL, *encoded = NULL;

    if (siglen != (size_t)QAT_RSA_size(rsa)) {
        QATerr(ERR_LIB_RSA, RSA_R_WRONG_SIGNATURE_LENGTH);
        return 0;
    }

    /* Recover the encoded digest. */
    decrypt_buf = OPENSSL_malloc(siglen);
    if (decrypt_buf == NULL) {
        QATerr(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (qat_hw_rsa_offload || qat_sw_rsa_offload) {
	len = qat_rsa_public_decrypt((int)siglen, sigbuf, decrypt_buf, rsa,
                                     RSA_PKCS1_PADDING);
    }
    else {
        typedef int (*fun_ptr)(void *prsactx, const unsigned char *sigbuf,
			       size_t siglen, const unsigned char *m,
			       size_t m_len);
        fun_ptr fun = get_default_rsa_signature().verify;
        if (!fun)
	    return 0;
        return fun(prsactx, sigbuf, siglen, m, m_len);
    }
    if (len <= 0)
        goto err;
    decrypt_len = len;

    if (type == NID_md5_sha1) {
        /*
         * NID_md5_sha1 corresponds to the MD5/SHA1 combination in TLS 1.1 and
         * earlier. It has no DigestInfo wrapper but otherwise is
         * RSASSA-PKCS1-v1_5.
         */
        if (decrypt_len != SSL_SIG_LENGTH) {
            QATerr(ERR_LIB_RSA, RSA_R_BAD_SIGNATURE);
            goto err;
        }

        if (rm != NULL) {
            memcpy(rm, decrypt_buf, SSL_SIG_LENGTH);
            *prm_len = SSL_SIG_LENGTH;
        } else {
            if (m_len != SSL_SIG_LENGTH) {
                QATerr(ERR_LIB_RSA, RSA_R_INVALID_MESSAGE_LENGTH);
                goto err;
            }

            if (memcmp(decrypt_buf, m, SSL_SIG_LENGTH) != 0) {
                QATerr(ERR_LIB_RSA, RSA_R_BAD_SIGNATURE);
                goto err;
            }
        }
    } else if (type == NID_mdc2 && decrypt_len == 2 + 16
               && decrypt_buf[0] == 0x04 && decrypt_buf[1] == 0x10) {
        /*
         * Oddball MDC2 case: signature can be OCTET STRING. check for correct
         * tag and length octets.
         */
        if (rm != NULL) {
            memcpy(rm, decrypt_buf + 2, 16);
            *prm_len = 16;
        } else {
            if (m_len != 16) {
                QATerr(ERR_LIB_RSA, RSA_R_INVALID_MESSAGE_LENGTH);
                goto err;
            }

            if (memcmp(m, decrypt_buf + 2, 16) != 0) {
                QATerr(ERR_LIB_RSA, RSA_R_BAD_SIGNATURE);
                goto err;
            }
        }
    } else
    {
        /*
         * If recovering the digest, extract a digest-sized output from the end
         * of |decrypt_buf| for |encode_pkcs1|, then compare the decryption
         * output as in a standard verification.
         */
        if (rm != NULL) {
            len = digest_sz_from_nid(type);

            if (len <= 0)
                goto err;
            m_len = (unsigned int)len;
            if (m_len > decrypt_len) {
                QATerr(ERR_LIB_RSA, RSA_R_INVALID_DIGEST_LENGTH);
                goto err;
            }
            m = decrypt_buf + decrypt_len - m_len;
        }

        /* Construct the encoded digest and ensure it matches. */
        if (!encode_pkcs1(&encoded, &encoded_len, type, m, m_len))
            goto err;

        if (encoded_len != decrypt_len
                || memcmp(encoded, decrypt_buf, encoded_len) != 0) {
            QATerr(ERR_LIB_RSA, RSA_R_BAD_SIGNATURE);
            goto err;
        }

        /* Output the recovered digest. */
        if (rm != NULL) {
            memcpy(rm, m, m_len);
            *prm_len = m_len;
        }
    }

    ret = 1;

err:
    OPENSSL_clear_free(encoded, encoded_len);
    OPENSSL_clear_free(decrypt_buf, siglen);
    return ret;
}

static int ossl_param_is_empty(const OSSL_PARAM params[])
{
    return params == NULL || params->key == NULL;
}

/**
 * @brief Sets context parameters for the QAT RSA signature operation.
 *
 * This function updates the QAT_PROV_RSA_CTX context with new settings provided in the
 * OSSL_PARAM array, such as digest algorithm, padding mode, PSS salt length, and MGF1
 * digest. It validates the parameters, applies restrictions based on the current context
 * and key type, and ensures the context is consistent for subsequent sign or verify
 * operations.
 *
 * @param vprsactx  Pointer to the QAT_PROV_RSA_CTX context.
 * @param params    Array of OSSL_PARAM containing the parameters to set.
 *
 * @return 1 on success, 0 on failure.
 */
static int qat_signature_rsa_set_ctx_params(void *vprsactx,
					    const OSSL_PARAM params[])
{
    DEBUG("%s\n", __func__);
    QAT_PROV_RSA_CTX *prsactx = (QAT_PROV_RSA_CTX *)vprsactx;
    const OSSL_PARAM *p;
    int pad_mode;
    int saltlen;
    char mdname[50] = "", *pmdname = NULL;
    char mdprops[256] = "", *pmdprops = NULL;
    char mgf1mdname[50] = "", *pmgf1mdname = NULL;
    char mgf1mdprops[256] = "", *pmgf1mdprops = NULL;

    if (prsactx == NULL)
        return 0;

    if (ossl_param_is_empty(params))
        return 1;

    pad_mode = prsactx->pad_mode;
    saltlen = prsactx->saltlen;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    /* Not allowed during certain operations */
    if (p != NULL && !prsactx->flag_allow_md)
        return 0;
    if (p != NULL) {
        const OSSL_PARAM *propsp =
            OSSL_PARAM_locate_const(params,
                                    OSSL_SIGNATURE_PARAM_PROPERTIES);

        pmdname = mdname;
        if (!OSSL_PARAM_get_utf8_string(p, &pmdname, sizeof(mdname)))
            return 0;

        if (propsp != NULL) {
            pmdprops = mdprops;
            if (!OSSL_PARAM_get_utf8_string(propsp,
                                            &pmdprops, sizeof(mdprops)))
                return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p != NULL) {
        const char *err_extra_text = NULL;

        switch (p->data_type) {
        case OSSL_PARAM_INTEGER: /* Support for legacy pad mode number */
            if (!OSSL_PARAM_get_int(p, &pad_mode))
                return 0;
            break;
        case OSSL_PARAM_UTF8_STRING:
            {
                int i;

                if (p->data == NULL)
                    return 0;

                for (i = 0; padding_item[i].id != 0; i++) {
                    if (strcmp(p->data, padding_item[i].ptr) == 0) {
                        pad_mode = padding_item[i].id;
                        break;
                    }
                }
            }
            break;
        default:
            return 0;
        }

        switch (pad_mode) {
        case RSA_PKCS1_OAEP_PADDING:
            /*
             * OAEP padding is for asymmetric cipher only so is not compatible
             * with signature use.
             */
            err_extra_text = "OAEP padding not allowed for signing / verifying";
            goto bad_pad;
        case RSA_PKCS1_PSS_PADDING:
#if OPENSSL_VERSION_NUMBER >= 0x30400000
	   if ((prsactx->operation
                 & (EVP_PKEY_OP_SIGN | EVP_PKEY_OP_SIGNMSG
		    | EVP_PKEY_OP_VERIFY | EVP_PKEY_OP_VERIFYMSG)) == 0) {
              err_extra_text =
	           "PSS padding only allowed for sign and verify operations";
    	      goto bad_pad;
	   }
#else
	    if ((prsactx->operation
		& (EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY)) == 0) {
                err_extra_text =
		    "PSS padding only allowed for sign and verify operations";
	        goto bad_pad;
	    }
#endif
 	    break;
        case RSA_PKCS1_PADDING:
            err_extra_text = "PKCS#1 padding not allowed with RSA-PSS";
            goto cont;
        case RSA_NO_PADDING:
            err_extra_text = "No padding not allowed with RSA-PSS";
            goto cont;
        case RSA_X931_PADDING:
            err_extra_text = "X.931 padding not allowed with RSA-PSS";
        cont:
            if (QAT_RSA_test_flags(prsactx->rsa,
                               RSA_FLAG_TYPE_MASK) == RSA_FLAG_TYPE_RSA)
                break;
            /* FALLTHRU */
        default:
        bad_pad:
            if (err_extra_text == NULL) {
                QATerr(ERR_LIB_PROV,
                          PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
	    } else {
                WARN("%s", err_extra_text);
                QATerr(ERR_LIB_PROV,
                           PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
            }
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if (p != NULL) {
        if (pad_mode != RSA_PKCS1_PSS_PADDING) {
            WARN("PSS saltlen can only be specified if PSS padding has been specified first");
            QATerr(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
            return 0;
        }

        switch (p->data_type) {
        case OSSL_PARAM_INTEGER: /* Support for legacy pad mode number */
            if (!OSSL_PARAM_get_int(p, &saltlen))
                return 0;
            break;
        case OSSL_PARAM_UTF8_STRING:
            if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST) == 0)
                saltlen = RSA_PSS_SALTLEN_DIGEST;
            else if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_MAX) == 0)
                saltlen = RSA_PSS_SALTLEN_MAX;
            else if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO) == 0)
                saltlen = RSA_PSS_SALTLEN_AUTO;
            else
                saltlen = atoi(p->data);
            break;
        default:
            return 0;
        }

        /*
         * RSA_PSS_SALTLEN_MAX seems curiously named in this check.
         * Contrary to what it's name suggests, it's the currently
         * lowest saltlen number possible.
         */
        if (saltlen < RSA_PSS_SALTLEN_MAX) {
            QATerr(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
            return 0;
        }

        if (rsa_pss_restricted(prsactx)) {
            switch (saltlen) {
            case RSA_PSS_SALTLEN_AUTO:
	    case RSA_PSS_SALTLEN_AUTO_DIGEST_MAX:
		if (prsactx->operation == EVP_PKEY_OP_VERIFY) {
                    WARN("Cannot use autodetected salt length");
                    QATerr(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
                    return 0;
                }
#if OPENSSL_VERSION_NUMBER >= 0x30400000
               if (prsactx->operation == EVP_PKEY_OP_VERIFYMSG) {
                    WARN("Cannot use autodetected salt length");
                    QATerr(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
                    return 0;
                }
#endif
		break;
            case RSA_PSS_SALTLEN_DIGEST:
                if (prsactx->min_saltlen > EVP_MD_size(prsactx->md)) {
                    WARN("minimum salt length set to %d, but the digest only gives %d",
                         prsactx->min_saltlen, EVP_MD_get_size(prsactx->md));
                    QATerr(ERR_LIB_PROV, PROV_R_PSS_SALTLEN_TOO_SMALL);
                    return 0;
                }
                break;
            default:
                if ((saltlen >= 0) && (saltlen < prsactx->min_saltlen)) {
                    WARN("minimum salt length set to %d, but the actual salt length is only set to %d",
                         prsactx->min_saltlen, prsactx->saltlen);
                    QATerr(ERR_LIB_PROV, PROV_R_PSS_SALTLEN_TOO_SMALL);
                    return 0;
                }
            }
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
    if (p != NULL) {
        const OSSL_PARAM *propsp =
            OSSL_PARAM_locate_const(params,
                                    OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES);

        pmgf1mdname = mgf1mdname;
        if (!OSSL_PARAM_get_utf8_string(p, &pmgf1mdname, sizeof(mgf1mdname)))
            return 0;

        if (propsp != NULL) {
            pmgf1mdprops = mgf1mdprops;
            if (!OSSL_PARAM_get_utf8_string(propsp,
                                            &pmgf1mdprops, sizeof(mgf1mdprops)))
                return 0;
        }

        if (pad_mode != RSA_PKCS1_PSS_PADDING) {
            QATerr(ERR_LIB_PROV, PROV_R_INVALID_MGF1_MD);
            return  0;
        }
    }

    prsactx->saltlen = saltlen;
    prsactx->pad_mode = pad_mode;

    if (prsactx->md == NULL && pmdname == NULL
        && pad_mode == RSA_PKCS1_PSS_PADDING)
        pmdname = RSA_DEFAULT_DIGEST_NAME;

    if (pmgf1mdname != NULL
        && !qat_rsa_setup_mgf1_md(prsactx, pmgf1mdname, pmgf1mdprops))
        return 0;

    if (pmdname != NULL) {
        if (!qat_rsa_setup_md(prsactx, pmdname, pmdprops))
            return 0;
    } else {
        if (!qat_rsa_check_padding(prsactx, NULL, NULL, prsactx->mdnid))
            return 0;
    }

    return 1;
}

/**
 * @brief Allocates and initializes a new QAT RSA signature context.
 *
 * This function creates a new QAT_PROV_RSA_CTX structure for RSA signature operations,
 * initializes its fields, and copies the provided property query string if present.
 * It sets default values for salt length and minimum salt length, and associates
 * the context with the appropriate OpenSSL library context.
 *
 * @param provctx  Pointer to the provider context.
 * @param propq    Optional property query string (may be NULL).
 *
 * @return Pointer to the newly allocated QAT_PROV_RSA_CTX, or NULL on failure.
 */
static void *qat_signature_rsa_newctx(void *provctx, const char *propq)
{
    DEBUG("%s\n", __func__);
    QAT_PROV_RSA_CTX *prsactx = NULL;
    char *propq_copy = NULL;

    if ((prsactx = OPENSSL_zalloc(sizeof(QAT_PROV_RSA_CTX))) == NULL
        || (propq != NULL && (propq_copy = OPENSSL_strdup(propq)) == NULL)) {
        OPENSSL_free(prsactx);
        QATerr(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    prsactx->libctx = prov_libctx_of(provctx);
    prsactx->flag_allow_md = 1;
    prsactx->propq = propq_copy;
    prsactx->saltlen = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
    prsactx->min_saltlen = -1;

    return prsactx;
}

/**
 * @brief Frees and cleans up a QAT RSA signature context.
 *
 * This function releases all resources associated with a QAT_PROV_RSA_CTX structure,
 * including digest contexts, digest algorithms, property query strings, temporary buffers,
 * and the associated RSA key. It securely clears sensitive memory before freeing.
 *
 * @param vprsactx  Pointer to the QAT_PROV_RSA_CTX context to free.
 */
static void qat_signature_rsa_freectx(void *vprsactx)
{
    DEBUG("%s\n", __func__);
    QAT_PROV_RSA_CTX *prsactx = (QAT_PROV_RSA_CTX *)vprsactx;

    if (prsactx == NULL)
        return;

    EVP_MD_CTX_free(prsactx->mdctx);
    EVP_MD_free(prsactx->md);
    EVP_MD_free(prsactx->mgf1_md);
    OPENSSL_free(prsactx->propq);
    free_tbuf(prsactx);
    QAT_RSA_free((RSA*)prsactx->rsa);

    OPENSSL_clear_free(prsactx, sizeof(*prsactx));

    return;
}

/**
 * @brief Recovers the original message from an RSA signature using the QAT provider context.
 *
 * This function attempts to recover the original message or digest from the provided RSA signature,
 * according to the current padding mode and digest settings in the QAT_PROV_RSA_CTX context.
 * It supports PKCS#1 v1.5 and X9.31 padding modes, and handles output buffer sizing and validation.
 *
 * @param vprsactx  Pointer to the QAT_PROV_RSA_CTX context.
 * @param rout      Output buffer for the recovered message (may be NULL to query size).
 * @param routlen   Pointer to a size_t to receive the length of the recovered message.
 * @param routsize  Size of the output buffer.
 * @param sig       Input buffer containing the signature.
 * @param siglen    Length of the signature buffer.
 *
 * @return 1 on success, 0 on failure.
 */
static int qat_signature_rsa_verify_recover(void *vprsactx,
                                            unsigned char *rout,
                                            size_t *routlen,
                                            size_t routsize,
                                            const unsigned char *sig,
                                            size_t siglen)
{
    DEBUG("%s\n", __func__);
    QAT_PROV_RSA_CTX *prsactx = (QAT_PROV_RSA_CTX *)vprsactx;
    int ret;

    if (!qat_prov_is_running())
        return 0;

    if (rout == NULL) {
        *routlen = QAT_RSA_size(prsactx->rsa);
        return 1;
    }

    if (prsactx->md != NULL) {
        switch (prsactx->pad_mode) {
        case RSA_X931_PADDING:
            if (!setup_tbuf(prsactx))
                return 0;
            if (qat_hw_rsa_offload || qat_sw_rsa_offload) {
	        ret = qat_rsa_public_decrypt(siglen, sig, prsactx->tbuf,
					     prsactx->rsa,
                                             RSA_X931_PADDING);
	    } else {
	        typedef int (*fun_ptr)(void *prsactx, const unsigned char *sig,
				       size_t siglen, const unsigned char *tbs,
				       size_t tbslen);
	        fun_ptr fun = get_default_rsa_signature().verify;
	        if (!fun)
		    return 0;
	        return fun(prsactx, sig, siglen, NULL, 0);
	    }
            if (ret < 1) {
                QATerr(ERR_LIB_PROV, ERR_R_RSA_LIB);
                return 0;
            }
            ret--;
            if (prsactx->tbuf[ret] != RSA_X931_hash_id(prsactx->mdnid)) {
                QATerr(ERR_LIB_PROV, PROV_R_ALGORITHM_MISMATCH);
                return 0;
            }
            if (ret != EVP_MD_size(prsactx->md)) {
                WARN("Should be %d, but got %d", EVP_MD_size(prsactx->md), ret);
                QATerr(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH);
                return 0;
            }

            *routlen = ret;
            if (rout != prsactx->tbuf) {
                if (routsize < (size_t)ret) {
                    WARN("buffer size is %zu, should be %d", routsize, ret);
                    QATerr(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
                    return 0;
                }
                memcpy(rout, prsactx->tbuf, ret);
            }
            break;

        case RSA_PKCS1_PADDING:
            {
                size_t sltmp;
                ret = QAT_RSA_verify(prsactx, prsactx->mdnid, NULL, 0, rout, &sltmp,
                                     sig, siglen, prsactx->rsa);
                if (ret <= 0) {
                    QATerr(ERR_LIB_PROV, ERR_R_RSA_LIB);
                    return 0;
                }
                ret = sltmp;
            }
            break;

        default:
            WARN("Only X.931 or PKCS#1 v1.5 padding allowed");
            QATerr(ERR_LIB_PROV, PROV_R_INVALID_PADDING_MODE);
            return 0;
        }
    } else {
        if (qat_hw_rsa_offload || qat_sw_rsa_offload) {
            ret = qat_rsa_public_decrypt(siglen, sig, rout, prsactx->rsa,
                                         prsactx->pad_mode);
	} else {
	    typedef int (*fun_ptr)(void *prsactx, const unsigned char *sig,
			           size_t siglen, const unsigned char *tbs,
				   size_t tbslen);
	    fun_ptr fun = get_default_rsa_signature().verify;
	    if (!fun)
	       return 0;
	    return fun(prsactx, sig, siglen, NULL, 0);
	}

	if (ret < 0) {
            QATerr(ERR_LIB_PROV, ERR_R_RSA_LIB);
            return 0;
        }
    }
    *routlen = ret;
    return 1;
}

static int rsa_verify_directly(QAT_PROV_RSA_CTX *prsactx,
			       const unsigned char *sig, size_t siglen,
			       const unsigned char *tbs, size_t tbslen)
{
    size_t rslen = 0;
    int ret = 0;

    if (!qat_prov_is_running())
        goto end;
    if (prsactx->md != NULL) {
	switch (prsactx->pad_mode) {
	case RSA_PKCS1_PADDING:
 	    if (!QAT_RSA_verify(prsactx, prsactx->mdnid, tbs, tbslen, NULL, NULL,
				sig, siglen, prsactx->rsa)) {
                QATerr(ERR_LIB_PROV, ERR_R_RSA_LIB);
	        goto end;
	    }
	    ret = 1;
	    goto end;
	case RSA_X931_PADDING:
	    if (!setup_tbuf(prsactx))
		return 0;
	    if (qat_signature_rsa_verify_recover(prsactx, prsactx->tbuf, &rslen, 0,
	 			                 sig, siglen) <= 0)
		goto end;
	    break;
	case RSA_PKCS1_PSS_PADDING:
	{
	    int ret = 0;
	    int saltlen = -1;
	    size_t mdsize;

	    mdsize = rsa_get_md_size(prsactx);
	    if (tbslen != mdsize) {
		WARN("Should be %zu, but got %zu", mdsize, tbslen);
		QATerr(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH);
  	        goto end;
	    }

	    if (!setup_tbuf(prsactx))
	        goto end;
            if (qat_hw_rsa_offload || qat_sw_rsa_offload) {
                ret = qat_rsa_public_decrypt(siglen, sig, prsactx->tbuf,
				             prsactx->rsa, RSA_NO_PADDING);
	    } else {
	        typedef int (*fun_ptr)(void *prsactx, const unsigned char *sig,
			               size_t siglen, const unsigned char *tbs,
				       size_t tbslen);
	        fun_ptr fun = get_default_rsa_signature().verify;
	        if (!fun)
	           return 0;
	        return fun(prsactx, sig, siglen, tbs, tbslen);
	    }

	    if (ret <= 0) {
		QATerr(ERR_LIB_PROV, ERR_R_RSA_LIB);
		goto end;
	    }
	    saltlen = prsactx->saltlen;
	    ret = QAT_RSA_verify_PKCS1_PSS_mgf1(prsactx->rsa, tbs,
					        prsactx->md, prsactx->mgf1_md,
						prsactx->tbuf, &saltlen);
	    if (ret <= 0) {
		QATerr(ERR_LIB_PROV, ERR_R_RSA_LIB);
		goto end;
	    }
	    return 1;
	}
	default:
	    WARN("Only X.931, PKCS#1 v1.5 or PSS padding allowed");
	    QATerr(ERR_LIB_PROV, PROV_R_INVALID_PADDING_MODE);
	    goto end;
	}
    } else {
	int verify_ret = 0;

	if (!setup_tbuf(prsactx))
	    goto end;
	if (qat_hw_rsa_offload || qat_sw_rsa_offload) {
	    verify_ret = qat_rsa_public_decrypt(siglen, sig, prsactx->tbuf,
						prsactx->rsa,
				                prsactx->pad_mode);
	    if (verify_ret <= 0) {
		QATerr(ERR_LIB_PROV, ERR_R_RSA_LIB);
		goto end;
	    }
	} else {
	    typedef int (*fun_ptr)(void *prsactx, const unsigned char *sig,
				   size_t siglen, const unsigned char *tbs,
				   size_t tbslen);
	    fun_ptr fun = get_default_rsa_signature().verify;
	    if (!fun)
		return 0;
	    return fun(prsactx, sig, siglen, tbs, tbslen);
	}
	rslen = (size_t)verify_ret;
    }

    if ((rslen != tbslen) || memcmp(tbs, prsactx->tbuf, rslen))
        goto end;
    ret = 1;
end:
    return ret;
}

#if OPENSSL_VERSION_NUMBER >= 0x30400000
static int rsa_verify_set_sig(void *vprsactx, const unsigned char *sig,
			      size_t siglen)
{
    QAT_PROV_RSA_CTX *prsactx = (QAT_PROV_RSA_CTX *)vprsactx;
    const OSSL_PARAM *p;
    OSSL_PARAM params[2];

    params[0] =
	OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE,
					  (unsigned char *)sig, siglen);
    params[1] = OSSL_PARAM_construct_end();

    if (prsactx->operation == EVP_PKEY_OP_VERIFYMSG) {
        p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_SIGNATURE);
        if (p != NULL) {
            OPENSSL_free(prsactx->sig);
            prsactx->sig = NULL;
            prsactx->siglen = 0;
            if (!OSSL_PARAM_get_octet_string(p, (void **)&prsactx->sig,
                                             0, &prsactx->siglen)) {
                return 0;
            }
        }
    }
    return 1;
}

/**
 * @brief Finalizes a multi-part RSA verify operation and checks the signature.
 *
 * This function completes a streaming (multi-part) RSA verify operation by finalizing
 * the message digest, performing any necessary padding checks, and verifying the provided
 * signature against the computed digest. It ensures the context is in a valid state for
 * finalization and disables further updates or one-shot calls after completion.
 *
 * @param vprsactx  Pointer to the QAT_PROV_RSA_CTX context.
 *
 * @return 1 on successful verification, 0 on failure.
 */
static int rsa_verify_message_final(void *vprsactx)
{
    DEBUG("%s\n", __func__);
    QAT_PROV_RSA_CTX *prsactx = (QAT_PROV_RSA_CTX *)vprsactx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (!qat_prov_is_running() || prsactx == NULL)
	return 0;
    if (prsactx->mdctx == NULL)
	return 0;
    if (!prsactx->flag_allow_final) {
	QATerr(ERR_LIB_PROV, QAT_R_PROV_FINAL_CALL_OUT_OF_ORDER);
	return 0;
    }

    if (!EVP_DigestFinal_ex(prsactx->mdctx, digest, &dlen))
	return 0;

    prsactx->flag_allow_update = 0;
    prsactx->flag_allow_final = 0;
    prsactx->flag_allow_oneshot = 0;

    return rsa_verify_directly(prsactx, prsactx->sig, prsactx->siglen,
   			       digest, dlen);
}
#endif

/**
 * @brief Initializes the QAT RSA sign/verify context for a signature operation.
 *
 * This function sets up the QAT_PROV_RSA_CTX structure for a sign or verify operation,
 * associates it with the given RSA key, sets the operation type, and initializes
 * padding mode and salt length according to the key type and any PSS restrictions.
 * It also applies any context parameters provided and prepares the context for
 * subsequent signing or verification steps.
 *
 * @param prsactx   Pointer to the QAT_PROV_RSA_CTX context to initialize.
 * @param vrsa      Pointer to the QAT_RSA key structure (may be NULL if already set).
 * @param params    Optional OSSL_PARAM array of context parameters.
 * @param operation Operation type (e.g., EVP_PKEY_OP_SIGN, EVP_PKEY_OP_VERIFY).
 *
 * @return 1 on success, 0 on failure.
 */
static int qat_rsa_signverify_init(QAT_PROV_RSA_CTX *prsactx, void *vrsa,
                                   const OSSL_PARAM params[], int operation)
{
    DEBUG("%s\n", __func__);

    if (!qat_prov_is_running())
        return 0;

    if (prsactx == NULL || vrsa == NULL)
        return 0;

    if (vrsa != NULL) {
        if (!QAT_RSA_up_ref(vrsa))
	        return 0;
	    QAT_RSA_free(prsactx->rsa);
	    prsactx->rsa = vrsa;
    }
    prsactx->operation = operation;
    prsactx->flag_allow_update = 1;
    prsactx->flag_allow_final = 1;
    prsactx->flag_allow_oneshot = 1;

    /* Maximum for sign, auto for verify */
    prsactx->saltlen = RSA_PSS_SALTLEN_AUTO;
    prsactx->min_saltlen = -1;

    switch (QAT_RSA_test_flags(prsactx->rsa, RSA_FLAG_TYPE_MASK)) {
    case RSA_FLAG_TYPE_RSA:
        prsactx->pad_mode = RSA_PKCS1_PADDING;
        break;
    case RSA_FLAG_TYPE_RSASSAPSS:
        prsactx->pad_mode = RSA_PKCS1_PSS_PADDING;

        {
            const QAT_RSA_PSS_PARAMS_30 *pss =
                qat_rsa_get0_pss_params_30(prsactx->rsa);

            if (!qat_rsa_pss_params_30_is_unrestricted(pss)) {
                int md_nid = qat_rsa_pss_params_30_hashalg(pss);
                int mgf1md_nid = qat_rsa_pss_params_30_maskgenhashalg(pss);
                int min_saltlen = qat_rsa_pss_params_30_saltlen(pss);
                const char *mdname, *mgf1mdname;
                size_t len;

                mdname = qat_rsa_oaeppss_nid2name(md_nid);
                mgf1mdname = qat_rsa_oaeppss_nid2name(mgf1md_nid);

                if (mdname == NULL) {
                    WARN("PSS restrictions lack hash algorithm");
                    QATerr(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
                    return 0;
                }
                if (mgf1mdname == NULL) {
                    WARN("PSS restrictions lack MGF1 hash algorithm");
                    QATerr(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
                    return 0;
                }

                len = OPENSSL_strlcpy(prsactx->mdname, mdname,
                                      sizeof(prsactx->mdname));
                if (len >= sizeof(prsactx->mdname)) {
                    WARN("hash algorithm name too long");
                    QATerr(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
                    return 0;
                }
                len = OPENSSL_strlcpy(prsactx->mgf1_mdname, mgf1mdname,
                                      sizeof(prsactx->mgf1_mdname));
                if (len >= sizeof(prsactx->mgf1_mdname)) {
                    WARN("MGF1 hash algorithm name too long");
                    QATerr(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
                    return 0;
                }
                prsactx->saltlen = min_saltlen;

                /* call rsa_setup_mgf1_md before rsa_setup_md to avoid duplication */
                return qat_rsa_setup_mgf1_md(prsactx, mgf1mdname, prsactx->propq)
                    && qat_rsa_setup_md(prsactx, mdname, prsactx->propq)
                    && qat_rsa_check_parameters(prsactx, min_saltlen);
            }
        }

        break;
    default:
        QATerr(ERR_LIB_RSA, PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return 0;
    }

    if (!qat_signature_rsa_set_ctx_params(prsactx, params))
        return 0;

    return 1;
}

static int qat_signature_rsa_sign_init(void *vprsactx, void *vrsa,
				       const OSSL_PARAM params[])
{
    DEBUG("qat_rsa_sign_init.\n");

    if (!qat_prov_is_running())
        return 0;
    return qat_rsa_signverify_init(vprsactx, vrsa, params, EVP_PKEY_OP_SIGN);
}

/**
 * @brief Signs a message using the QAT RSA signature context.
 *
 * This function generates an RSA signature for the provided message or digest using the
 * QAT_PROV_RSA_CTX context. It supports both one-shot and streaming (multi-part) signing
 * operations, applies the appropriate padding mode, and handles FIPS checks if enabled.
 * The function writes the signature to the output buffer and sets the signature length.
 *
 * @param vprsactx  Pointer to the QAT_PROV_RSA_CTX context.
 * @param sig       Output buffer for the resulting signature.
 * @param siglen    Pointer to a size_t to receive the signature length.
 * @param sigsize   Size of the output buffer.
 * @param tbs       Input data to be signed (message or digest).
 * @param tbslen    Length of the input data.
 *
 * @return 1 on success, 0 on failure.
 */
static int qat_signature_rsa_sign(void *vprsactx, unsigned char *sig,
                                  size_t *siglen, size_t sigsize,
                                  const unsigned char *tbs, size_t tbslen)
{
    DEBUG("%s\n", __func__);
    QAT_PROV_RSA_CTX *prsactx = (QAT_PROV_RSA_CTX *)vprsactx;

#ifdef ENABLE_QAT_FIPS
    size_t rsasize = QAT_RSA_size(prsactx->rsa);
    if (!qat_fips_check_rsa_key_size(rsasize, 1))
	return 0;
#endif

    if (!qat_prov_is_running())
        return 0;

    if (!prsactx->flag_allow_oneshot) {
        QATerr(ERR_LIB_PROV, QAT_R_PROV_ONESHOT_CALL_OUT_OF_ORDER);
	return 0;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30400000
    if (prsactx->operation == EVP_PKEY_OP_SIGNMSG) {
        if (sig == NULL)
            return rsa_sign_message_final(prsactx, sig, siglen, sigsize);

        return rsa_signverify_message_update(prsactx, tbs, tbslen)
		  && rsa_sign_message_final(prsactx, sig, siglen, sigsize);
    }
#endif
    return rsa_sign_directly(prsactx, sig, siglen, sigsize, tbs, tbslen);
}

static int qat_signature_rsa_verify_recover_init(void *vprsactx, void *vrsa,
                                                 const OSSL_PARAM params[])
{
    DEBUG("qat_rsa_verify_recover_init.\n");

    if (!qat_prov_is_running())
        return 0;
    return qat_rsa_signverify_init(vprsactx, vrsa, params,
                               EVP_PKEY_OP_VERIFYRECOVER);
}

static int qat_signature_rsa_verify_init(void *vprsactx, void *vrsa,
                                         const OSSL_PARAM params[])
{
    DEBUG("qat_rsa_verify_init.\n");
    if (!qat_prov_is_running())
        return 0;
    return qat_rsa_signverify_init(vprsactx, vrsa, params, EVP_PKEY_OP_VERIFY);

}

/**
 * @brief Verifies an RSA signature using the QAT RSA signature context.
 *
 * This function checks the validity of the provided signature against the given message or digest,
 * using the QAT_PROV_RSA_CTX context. It supports both one-shot and streaming (multi-part) verify
 * operations, applies the appropriate padding mode, and handles FIPS checks if enabled. The function
 * returns 1 if the signature is valid, 0 otherwise.
 *
 * @param vprsactx  Pointer to the QAT_PROV_RSA_CTX context.
 * @param sig       Input buffer containing the signature to verify.
 * @param siglen    Length of the signature buffer.
 * @param tbs       Input data to verify against (message or digest).
 * @param tbslen    Length of the input data.
 *
 * @return 1 on successful verification, 0 on failure.
 */
static int qat_signature_rsa_verify(void *vprsactx, const unsigned char *sig,
                                    size_t siglen, const unsigned char *tbs,
                                    size_t tbslen)
{
    DEBUG("%s\n", __func__);
    QAT_PROV_RSA_CTX *prsactx = (QAT_PROV_RSA_CTX *)vprsactx;

#ifdef ENABLE_QAT_FIPS
    size_t rsasize = QAT_RSA_size(prsactx->rsa);
    if (!qat_fips_check_rsa_key_size(rsasize, 0))
	return 0;
#endif

    if (!prsactx->flag_allow_oneshot) {
        QATerr(ERR_LIB_PROV, QAT_R_PROV_ONESHOT_CALL_OUT_OF_ORDER);
        return 0;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30400000
    if (prsactx->operation == EVP_PKEY_OP_VERIFYMSG) {
        return rsa_verify_set_sig(prsactx, sig, siglen)
	     && rsa_signverify_message_update(prsactx, tbs, tbslen)
             && rsa_verify_message_final(prsactx);

    }
#endif
    return rsa_verify_directly(prsactx, sig, siglen, tbs, tbslen);
}

static const OSSL_PARAM *qat_signature_rsa_settable_ctx_params(void *vprsactx,
                                                               ossl_unused void *provctx)
{
    QAT_PROV_RSA_CTX *prsactx = (QAT_PROV_RSA_CTX *)vprsactx;
    if (prsactx != NULL && !prsactx->flag_allow_md)
        return settable_ctx_params_no_digest;
    return settable_ctx_params;
}

/**
 * @brief Initializes the QAT RSA signature context for digest sign or verify operations.
 *
 * This function prepares the QAT_PROV_RSA_CTX context for a digest sign or verify operation,
 * associates it with the given RSA key, sets the operation type, and initializes the digest
 * method if specified. It also applies any context parameters provided and allocates the
 * message digest context for subsequent streaming or one-shot operations.
 *
 * @param vprsactx   Pointer to the QAT_PROV_RSA_CTX context.
 * @param mdname     Name of the digest algorithm to use (may be NULL).
 * @param vrsa       Pointer to the QAT_RSA key structure.
 * @param params     Optional OSSL_PARAM array of context parameters.
 * @param operation  Operation type (e.g., EVP_PKEY_OP_SIGN, EVP_PKEY_OP_VERIFY).
 *
 * @return 1 on success, 0 on failure.
 */
static int qat_signature_rsa_digest_signverify_init(void *vprsactx,
						    const char *mdname,
                                                    void *vrsa,
						    const OSSL_PARAM params[],
                                                    int operation)
{
    DEBUG("%s\n", __func__);
    QAT_PROV_RSA_CTX *prsactx = (QAT_PROV_RSA_CTX *)vprsactx;

    if (!qat_prov_is_running())
        return 0;

    if (!qat_rsa_signverify_init(prsactx, vrsa, params, operation))
        return 0;

    if (mdname != NULL
        /* was rsa_setup_md already called in rsa_signverify_init()? */
        && (mdname[0] == '\0' || OPENSSL_strcasecmp(prsactx->mdname, mdname) != 0)
        && !qat_rsa_setup_md(prsactx, mdname, prsactx->propq))
        return 0;

    prsactx->flag_allow_md = 0;

    if (prsactx->mdctx == NULL) {
        prsactx->mdctx = EVP_MD_CTX_new();
        if (prsactx->mdctx == NULL)
            goto error;
    }

    if (!EVP_DigestInit_ex2(prsactx->mdctx, prsactx->md, params))
        goto error;

    return 1;
    DEBUG("%s\n", __func__);

 error:
    EVP_MD_CTX_free(prsactx->mdctx);
    prsactx->mdctx = NULL;
    return 0;
}

static int qat_signature_rsa_digest_sign_init(void *vprsactx, const char *mdname,
                                              void *vrsa, const OSSL_PARAM params[])
{
    DEBUG("%s\n", __func__);
    if (!qat_prov_is_running())
        return 0;
#if OPENSSL_VERSION_NUMBER < 0x30400000
    return qat_signature_rsa_digest_signverify_init(vprsactx, mdname, vrsa,
                                                    params, EVP_PKEY_OP_SIGN);
#else
    return qat_signature_rsa_digest_signverify_init(vprsactx, mdname, vrsa,
                                                    params, EVP_PKEY_OP_SIGNMSG);
#endif
}

static int qat_signature_rsa_digest_sign_update(void *vprsactx,
                                                const unsigned char *data,
                                                size_t datalen)
{
    DEBUG("%s\n", __func__);
    QAT_PROV_RSA_CTX *prsactx = (QAT_PROV_RSA_CTX *)vprsactx;

    return rsa_signverify_message_update(prsactx, data, datalen);
}

static int qat_signature_rsa_digest_verify_update(void *vprsactx,
                                        const unsigned char *data,
                                        size_t datalen)
{
    DEBUG("%s\n", __func__);
    QAT_PROV_RSA_CTX *prsactx = (QAT_PROV_RSA_CTX *)vprsactx;

    if (prsactx == NULL)
        return 0;

    return rsa_signverify_message_update(prsactx, data, datalen);
}

static int qat_signature_rsa_digest_sign_final(void *vprsactx, unsigned char *sig,
                                               size_t *siglen, size_t sigsize)
{
    DEBUG("%s\n", __func__);
    QAT_PROV_RSA_CTX *prsactx = (QAT_PROV_RSA_CTX *)vprsactx;
    int ret = 0;

    if (!qat_prov_is_running() || prsactx == NULL)
        return 0;

    if (rsa_sign_message_final(prsactx, sig, siglen, sigsize))
	ret = 1;
    /*
     * If sig is NULL then we're just finding out the sig size. Other fields
     * are ignored. Defer to rsa_sign.
     */
    prsactx->flag_allow_md = 1;

    return ret;
}

static int qat_signature_rsa_digest_verify_init(void *vprsactx, const char *mdname,
                                                void *vrsa, const OSSL_PARAM params[])
{
    DEBUG("%s\n", __func__);
    if (!qat_prov_is_running())
        return 0;
#if OPENSSL_VERSION_NUMBER < 0x30400000
    return qat_signature_rsa_digest_signverify_init(vprsactx, mdname, vrsa,
                                                    params, EVP_PKEY_OP_VERIFY);
#else
    return qat_signature_rsa_digest_signverify_init(vprsactx, mdname, vrsa,
                                                    params, EVP_PKEY_OP_VERIFYMSG);
#endif
}

/**
 * @brief Finalizes a multi-part RSA digest verify operation and checks the signature.
 *
 * This function completes a streaming (multi-part) RSA digest verify operation by finalizing
 * the message digest, performing any necessary padding checks, and verifying the provided
 * signature against the computed digest. It supports both one-shot and streaming usage,
 * and handles OpenSSL version differences for signature verification.
 *
 * @param vprsactx  Pointer to the QAT_PROV_RSA_CTX context.
 * @param sig       Input buffer containing the signature to verify.
 * @param siglen    Length of the signature buffer.
 *
 * @return 1 on successful verification, 0 on failure.
 */
int qat_signature_rsa_digest_verify_final(void *vprsactx, const unsigned char *sig,
                                          size_t siglen)
{
    QAT_PROV_RSA_CTX *prsactx = (QAT_PROV_RSA_CTX *)vprsactx;

    if (!qat_prov_is_running())
        return 0;

    if (prsactx == NULL)
        return 0;

    prsactx->flag_allow_md = 1;

#if OPENSSL_VERSION_NUMBER >= 0x30400000
    int ret = 0;
    ret = rsa_verify_set_sig(prsactx, sig, siglen);
    if (ret)
        ret = rsa_verify_message_final(vprsactx);
    return ret;
#else
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (prsactx->mdctx == NULL)
        return 0;
    if (!EVP_DigestFinal_ex(prsactx->mdctx, digest, &dlen))
        return 0;

    return rsa_verify_directly(prsactx, sig, siglen,
   			       digest, dlen);
#endif
}

/**
 * @brief Duplicates a QAT RSA signature context.
 *
 * This function creates a deep copy of the given QAT_PROV_RSA_CTX context, including
 * all associated resources such as the RSA key, digest algorithms, digest contexts,
 * property query string, and temporary buffers. Reference counts are incremented for
 * shared resources. The duplicated context can be used independently of the original.
 *
 * @param vprsactx  Pointer to the QAT_PROV_RSA_CTX context to duplicate.
 *
 * @return Pointer to the newly allocated duplicate context, or NULL on failure.
 */
static void *qat_signature_rsa_dupctx(void *vprsactx)
{
    DEBUG("%s\n", __func__);
    QAT_PROV_RSA_CTX *srcctx = (QAT_PROV_RSA_CTX *)vprsactx;
    QAT_PROV_RSA_CTX *dstctx;

    if (!qat_prov_is_running())
        return NULL;

    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL) {
        QATerr(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    *dstctx = *srcctx;
    dstctx->rsa = NULL;
    dstctx->md = NULL;
    dstctx->mdctx = NULL;
    dstctx->tbuf = NULL;
    dstctx->propq = NULL;

    if (srcctx->rsa != NULL && !QAT_RSA_up_ref(srcctx->rsa))
        goto err;
    dstctx->rsa = srcctx->rsa;

    if (srcctx->md != NULL && !EVP_MD_up_ref(srcctx->md))
        goto err;
    dstctx->md = srcctx->md;

    if (srcctx->mgf1_md != NULL && !EVP_MD_up_ref(srcctx->mgf1_md))
        goto err;
    dstctx->mgf1_md = srcctx->mgf1_md;

    if (srcctx->mdctx != NULL) {
        dstctx->mdctx = EVP_MD_CTX_new();
        if (dstctx->mdctx == NULL
                || !EVP_MD_CTX_copy_ex(dstctx->mdctx, srcctx->mdctx))
            goto err;
    }

    if (srcctx->propq != NULL) {
        dstctx->propq = OPENSSL_strdup(srcctx->propq);
        if (dstctx->propq == NULL)
            goto err;
    }

    return dstctx;
 err:
    qat_signature_rsa_freectx(dstctx);
    return NULL;
}

/**
 * @brief Retrieves context parameters for the QAT RSA signature context.
 *
 * This function populates the provided OSSL_PARAM array with the current settings
 * from the QAT_PROV_RSA_CTX context, such as padding mode, digest algorithm name,
 * MGF1 digest name, and PSS salt length. It is used by OpenSSL to query the state
 * of the RSA signature context.
 *
 * @param vprsactx  Pointer to the QAT_PROV_RSA_CTX context.
 * @param params    Array of OSSL_PARAM to be populated with context parameters.
 *
 * @return 1 on success, 0 on failure.
 */
static int qat_signature_rsa_get_ctx_params(void *vprsactx, OSSL_PARAM *params)
{
    typedef int (*rsa_get_ctx_params_fn)(void *rvprsact, OSSL_PARAM *params);
    rsa_get_ctx_params_fn get_ctx_params_func = get_default_rsa_signature().get_ctx_params;
    if (!get_ctx_params_func)
        return 0;
    return get_ctx_params_func(vprsactx, params);
}

/**
 * @brief Retrieves the set of gettable message digest context parameters for QAT RSA signature.
 *
 * This function returns the list of OSSL_PARAM descriptors that can be queried from the
 * message digest context associated with the QAT_PROV_RSA_CTX. It is used by OpenSSL to
 * determine which digest-related parameters are available for retrieval.
 *
 * @param vprsactx  Pointer to the QAT_PROV_RSA_CTX context.
 *
 * @return Pointer to an array of OSSL_PARAM descriptors, or NULL if unavailable.
 */
static const OSSL_PARAM *qat_signature_rsa_gettable_ctx_md_params(void *vprsactx)
{
    QAT_PROV_RSA_CTX *prsactx = (QAT_PROV_RSA_CTX *)vprsactx;

    if (prsactx->md == NULL)
        return 0;

    return EVP_MD_gettable_ctx_params(prsactx->md);
}

/**
 * @brief Sets message digest context parameters for the QAT RSA signature context.
 *
 * This function updates the message digest context (EVP_MD_CTX) associated with the
 * QAT_PROV_RSA_CTX using the provided OSSL_PARAM array. It is used by OpenSSL to
 * configure digest-specific parameters (such as control parameters for the digest)
 * before performing signature operations.
 *
 * @param vprsactx  Pointer to the QAT_PROV_RSA_CTX context.
 * @param params    Array of OSSL_PARAM containing the digest parameters to set.
 *
 * @return 1 on success, 0 on failure.
 */
static int qat_signature_rsa_set_ctx_md_params(void *vprsactx,
					       const OSSL_PARAM params[])
{
   QAT_PROV_RSA_CTX *prsactx = (QAT_PROV_RSA_CTX *)vprsactx;
   if (prsactx->mdctx == NULL)
       return 0;
   return EVP_MD_CTX_set_params(prsactx->mdctx, params);
}

/**
 * @brief Retrieves the set of settable message digest context parameters for QAT RSA signature.
 *
 * This function returns the list of OSSL_PARAM descriptors that can be set on the
 * message digest context associated with the QAT_PROV_RSA_CTX. It is used by OpenSSL to
 * determine which digest-related parameters are available for configuration before
 * performing signature operations.
 *
 * @param vprsactx  Pointer to the QAT_PROV_RSA_CTX context.
 *
 * @return Pointer to an array of OSSL_PARAM descriptors, or NULL if unavailable.
 */
static const OSSL_PARAM *qat_signature_rsa_settable_ctx_md_params(void *vprsactx)
{
   QAT_PROV_RSA_CTX *prsactx = (QAT_PROV_RSA_CTX *)vprsactx;
   if (prsactx->md == NULL)
       return 0;

   return EVP_MD_settable_ctx_params(prsactx->md);
}

static const OSSL_PARAM *qat_signature_rsa_gettable_ctx_params(ossl_unused void *vprsactx,
                                                               ossl_unused void *provctx)
{
    return known_gettable_ctx_params;
}

/**
 * @brief Retrieves message digest context parameters for the QAT RSA signature context.
 *
 * This function populates the provided OSSL_PARAM array with the current settings
 * from the message digest context (EVP_MD_CTX) associated with the QAT_PROV_RSA_CTX.
 * It is used by OpenSSL to query digest-specific parameters, such as digest size or
 * control parameters, from the signature context.
 *
 * @param vprsactx  Pointer to the QAT_PROV_RSA_CTX context.
 * @param params    Array of OSSL_PARAM to be populated with digest context parameters.
 *
 * @return 1 on success, 0 on failure.
 */
static int qat_signature_rsa_get_ctx_md_params(void *vprsactx, OSSL_PARAM *params)
{
    QAT_PROV_RSA_CTX *prsactx = (QAT_PROV_RSA_CTX *)vprsactx;

    if (prsactx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_get_params(prsactx->mdctx, params);
}

const OSSL_DISPATCH qat_rsa_signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))qat_signature_rsa_newctx},
    {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))qat_signature_rsa_sign_init},
    {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))qat_signature_rsa_sign},
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))qat_signature_rsa_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))qat_signature_rsa_verify },
    { OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT,
        (void (*)(void))qat_signature_rsa_verify_recover_init },
    { OSSL_FUNC_SIGNATURE_VERIFY_RECOVER,
        (void (*)(void))qat_signature_rsa_verify_recover },
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))qat_signature_rsa_freectx},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))qat_signature_rsa_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        (void (*)(void))qat_signature_rsa_settable_ctx_params},
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))qat_signature_rsa_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))qat_signature_rsa_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))qat_signature_rsa_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))qat_signature_rsa_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))qat_signature_rsa_digest_verify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))qat_signature_rsa_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))qat_signature_rsa_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))qat_signature_rsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))qat_signature_rsa_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
      (void (*)(void))qat_signature_rsa_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
      (void (*)(void))qat_signature_rsa_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
      (void (*)(void))qat_signature_rsa_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
      (void (*)(void))qat_signature_rsa_settable_ctx_md_params },
    {0, NULL}
};

#endif
