#include <assert.h>
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
/* For TLS1_VERSION etc */
#include <openssl/prov_ssl.h>
#include <openssl/params.h>
#include "qat_provider.h"

/* If neither ec or dh is available then we have no TLS-GROUP capabilities */
#if !defined(OPENSSL_NO_EC) || !defined(OPENSSL_NO_DH)

# define OSSL_TLS_GROUP_ID_sect163k1        0x0001
# define OSSL_TLS_GROUP_ID_sect163r1        0x0002
# define OSSL_TLS_GROUP_ID_sect163r2        0x0003
# define OSSL_TLS_GROUP_ID_sect193r1        0x0004
# define OSSL_TLS_GROUP_ID_sect193r2        0x0005
# define OSSL_TLS_GROUP_ID_sect233k1        0x0006
# define OSSL_TLS_GROUP_ID_sect233r1        0x0007
# define OSSL_TLS_GROUP_ID_sect239k1        0x0008
# define OSSL_TLS_GROUP_ID_sect283k1        0x0009
# define OSSL_TLS_GROUP_ID_sect283r1        0x000A
# define OSSL_TLS_GROUP_ID_sect409k1        0x000B
# define OSSL_TLS_GROUP_ID_sect409r1        0x000C
# define OSSL_TLS_GROUP_ID_sect571k1        0x000D
# define OSSL_TLS_GROUP_ID_sect571r1        0x000E
# define OSSL_TLS_GROUP_ID_secp160k1        0x000F
# define OSSL_TLS_GROUP_ID_secp160r1        0x0010
# define OSSL_TLS_GROUP_ID_secp160r2        0x0011
# define OSSL_TLS_GROUP_ID_secp192k1        0x0012
# define OSSL_TLS_GROUP_ID_secp192r1        0x0013
# define OSSL_TLS_GROUP_ID_secp224k1        0x0014
# define OSSL_TLS_GROUP_ID_secp224r1        0x0015
# define OSSL_TLS_GROUP_ID_secp256k1        0x0016
# define OSSL_TLS_GROUP_ID_secp256r1        0x0017
# define OSSL_TLS_GROUP_ID_secp384r1        0x0018
# define OSSL_TLS_GROUP_ID_secp521r1        0x0019
# define OSSL_TLS_GROUP_ID_brainpoolP256r1  0x001A
# define OSSL_TLS_GROUP_ID_brainpoolP384r1  0x001B
# define OSSL_TLS_GROUP_ID_brainpoolP512r1  0x001C
# define OSSL_TLS_GROUP_ID_x25519           0x001D
# define OSSL_TLS_GROUP_ID_x448             0x001E
# define OSSL_TLS_GROUP_ID_ffdhe2048        0x0100
# define OSSL_TLS_GROUP_ID_ffdhe3072        0x0101
# define OSSL_TLS_GROUP_ID_ffdhe4096        0x0102
# define OSSL_TLS_GROUP_ID_ffdhe6144        0x0103
# define OSSL_TLS_GROUP_ID_ffdhe8192        0x0104
# define OSSL_TLS_GROUP_ID_sm2              0x0029
/* Pure ML-KEM group IDs (IANA draft-ietf-tls-mlkem) */
# define OSSL_TLS_GROUP_ID_MLKEM512         0x0200
# define OSSL_TLS_GROUP_ID_MLKEM768         0x0201
# define OSSL_TLS_GROUP_ID_MLKEM1024        0x0202
/* Hybrid ML-KEM composite group IDs (IANA draft-ietf-tls-hybrid-design) */
# define OSSL_TLS_GROUP_ID_SecP256r1MLKEM768  0x11EB
# define OSSL_TLS_GROUP_ID_X25519MLKEM768     0x11EC
# define OSSL_TLS_GROUP_ID_SecP384r1MLKEM1024 0x11ED

# if !defined(NTLS1_1_VERSION)
/* NTLS version.
   OpenSSL3 doesn't support yet, define to pass the compile.
 */
#  define NTLS1_1_VERSION                   0x0101
# endif

typedef struct tls_group_constants_st {
    unsigned int group_id;   /* Group ID */
    unsigned int secbits;    /* Bits of security */
    int mintls;              /* Minimum TLS version, -1 unsupported */
    int maxtls;              /* Maximum TLS version (or 0 for undefined) */
    int mindtls;             /* Minimum DTLS version, -1 unsupported */
    int maxdtls;             /* Maximum DTLS version (or 0 for undefined) */
} TLS_GROUP_CONSTANTS;

static const TLS_GROUP_CONSTANTS group_list[36] = {
    { OSSL_TLS_GROUP_ID_sect163k1, 80, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect163r1, 80, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect163r2, 80, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect193r1, 80, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect193r2, 80, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect233k1, 112, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect233r1, 112, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect239k1, 112, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect283k1, 128, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect283r1, 128, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect409k1, 192, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect409r1, 192, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect571k1, 256, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect571r1, 256, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_secp160k1, 80, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_secp160r1, 80, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_secp160r2, 80, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_secp192k1, 80, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_secp192r1, 80, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_secp224k1, 112, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_secp224r1, 112, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_secp256k1, 128, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_secp256r1, 128, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { OSSL_TLS_GROUP_ID_secp384r1, 192, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { OSSL_TLS_GROUP_ID_secp521r1, 256, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { OSSL_TLS_GROUP_ID_brainpoolP256r1, 128, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_brainpoolP384r1, 192, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_brainpoolP512r1, 256, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_x25519, 128, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { OSSL_TLS_GROUP_ID_x448, 224, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    /* Security bit values as given by BN_security_bits() */
    { OSSL_TLS_GROUP_ID_ffdhe2048, 112, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_ffdhe3072, 128, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_ffdhe4096, 128, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_ffdhe6144, 128, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_ffdhe8192, 192, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_sm2, 128, NTLS1_1_VERSION, 0, -1, -1 },
};

#define TLS_GROUP_ENTRY(tlsname, realname, algorithm, idx) \
    { \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, \
                               tlsname, \
                               sizeof(tlsname)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, \
                               realname, \
                               sizeof(realname)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, \
                               algorithm, \
                               sizeof(algorithm)), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID, \
                        (unsigned int *)&group_list[idx].group_id), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, \
                        (unsigned int *)&group_list[idx].secbits), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, \
                        (unsigned int *)&group_list[idx].mintls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, \
                        (unsigned int *)&group_list[idx].maxtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, \
                        (unsigned int *)&group_list[idx].mindtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, \
                        (unsigned int *)&group_list[idx].maxdtls), \
        OSSL_PARAM_END \
    }

static const OSSL_PARAM param_group_list[][10] = {
    TLS_GROUP_ENTRY("secp256r1", "prime256v1", "EC", 22),
    TLS_GROUP_ENTRY("P-256", "prime256v1", "EC", 22), /* Alias of above */
    TLS_GROUP_ENTRY("secp384r1", "secp384r1", "EC", 23),
    TLS_GROUP_ENTRY("P-384", "secp384r1", "EC", 23), /* Alias of above */
    TLS_GROUP_ENTRY("secp521r1", "secp521r1", "EC", 24),
    TLS_GROUP_ENTRY("P-521", "secp521r1", "EC", 24), /* Alias of above */

    TLS_GROUP_ENTRY("x25519", "X25519", "X25519", 28),
    TLS_GROUP_ENTRY("x448", "X448", "X448", 29),

    /* Security bit values for FFDHE groups are as per RFC 7919 */
    TLS_GROUP_ENTRY("ffdhe2048", "ffdhe2048", "DH", 30),
    TLS_GROUP_ENTRY("ffdhe3072", "ffdhe3072", "DH", 31),
    TLS_GROUP_ENTRY("ffdhe4096", "ffdhe4096", "DH", 32),
    TLS_GROUP_ENTRY("ffdhe6144", "ffdhe6144", "DH", 33),
    TLS_GROUP_ENTRY("ffdhe8192", "ffdhe8192", "DH", 34),

    TLS_GROUP_ENTRY("curveSM2", "SM2", "SM2", 35),
};
#endif /* !defined(OPENSSL_NO_EC) || !defined(OPENSSL_NO_DH) */

#ifdef ENABLE_QAT_SW_ML_KEM
/* ML-KEM TLS group entries (TLS 1.3 key encapsulation, RFC draft-ietf-tls-mlkem) */
static const TLS_GROUP_CONSTANTS ml_kem_group_list[3] = {
    { OSSL_TLS_GROUP_ID_MLKEM512,  128, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_MLKEM768,  192, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_MLKEM1024, 256, TLS1_3_VERSION, 0, -1, -1 },
};

static const unsigned int ml_kem_is_kem = 1;

# define ML_KEM_TLS_GROUP_ENTRY(tlsname, algorithm, idx)                     \
    {                                                                         \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME,               \
                               tlsname, sizeof(tlsname)),                     \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,      \
                               algorithm, sizeof(algorithm)),                 \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG,                \
                               algorithm, sizeof(algorithm)),                 \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID,                        \
                        (unsigned int *)&ml_kem_group_list[idx].group_id),   \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,             \
                        (unsigned int *)&ml_kem_group_list[idx].secbits),    \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS,                    \
                        (unsigned int *)&ml_kem_group_list[idx].mintls),     \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS,                    \
                        (unsigned int *)&ml_kem_group_list[idx].maxtls),     \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS,                   \
                        (unsigned int *)&ml_kem_group_list[idx].mindtls),    \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS,                   \
                        (unsigned int *)&ml_kem_group_list[idx].maxdtls),    \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_IS_KEM,                    \
                        (unsigned int *)&ml_kem_is_kem),                     \
        OSSL_PARAM_END                                                        \
    }

static const OSSL_PARAM ml_kem_param_group_list[][11] = {
    ML_KEM_TLS_GROUP_ENTRY("MLKEM512",  "ML-KEM-512",  0),
    ML_KEM_TLS_GROUP_ENTRY("MLKEM768",  "ML-KEM-768",  1),
    ML_KEM_TLS_GROUP_ENTRY("MLKEM1024", "ML-KEM-1024", 2),
};

/* Hybrid composite ML-KEM groups (classical KEX + ML-KEM).
 * These are registered by the default provider but require a TLS-GROUP
 * capability entry from qatprovider so that OpenSSL's ssl_load_groups()
 * resolves the composite algorithm name against qatprovider's ML-KEM keymgmt. */
static const TLS_GROUP_CONSTANTS hybrid_ml_kem_group_list[3] = {
    { OSSL_TLS_GROUP_ID_SecP256r1MLKEM768,  192, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_X25519MLKEM768,     192, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_SecP384r1MLKEM1024, 256, TLS1_3_VERSION, 0, -1, -1 },
};

# define HYBRID_ML_KEM_TLS_GROUP_ENTRY(tlsname, algorithm, idx)              \
    {                                                                          \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME,                \
                               tlsname, sizeof(tlsname)),                      \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,       \
                               algorithm, sizeof(algorithm)),                  \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG,                 \
                               algorithm, sizeof(algorithm)),                  \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID,                         \
                        (unsigned int *)&hybrid_ml_kem_group_list[idx].group_id), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,              \
                        (unsigned int *)&hybrid_ml_kem_group_list[idx].secbits), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS,                     \
                        (unsigned int *)&hybrid_ml_kem_group_list[idx].mintls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS,                     \
                        (unsigned int *)&hybrid_ml_kem_group_list[idx].maxtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS,                    \
                        (unsigned int *)&hybrid_ml_kem_group_list[idx].mindtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS,                    \
                        (unsigned int *)&hybrid_ml_kem_group_list[idx].maxdtls), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_IS_KEM,                     \
                        (unsigned int *)&ml_kem_is_kem),                       \
        OSSL_PARAM_END                                                         \
    }

static const OSSL_PARAM hybrid_ml_kem_param_group_list[][11] = {
    HYBRID_ML_KEM_TLS_GROUP_ENTRY("SecP256r1MLKEM768",  "SecP256r1MLKEM768",  0),
    HYBRID_ML_KEM_TLS_GROUP_ENTRY("X25519MLKEM768",     "X25519MLKEM768",     1),
    HYBRID_ML_KEM_TLS_GROUP_ENTRY("SecP384r1MLKEM1024", "SecP384r1MLKEM1024", 2),
};
#endif /* ENABLE_QAT_SW_ML_KEM */

static int tls_group_capability(OSSL_CALLBACK *cb, void *arg)
{
#if !defined(OPENSSL_NO_EC) || !defined(OPENSSL_NO_DH)
    size_t i;

    for (i = 0; i < OSSL_NELEM(param_group_list); i++)
        if (!cb(param_group_list[i], arg))
            return 0;
#endif

#ifdef ENABLE_QAT_SW_ML_KEM
    {
        size_t i;
        for (i = 0; i < OSSL_NELEM(ml_kem_param_group_list); i++)
            if (!cb(ml_kem_param_group_list[i], arg))
                return 0;
        for (i = 0; i < OSSL_NELEM(hybrid_ml_kem_param_group_list); i++)
            if (!cb(hybrid_ml_kem_param_group_list[i], arg))
                return 0;
    }
#endif

    return 1;
}

/* TLS-SIGALG capability: required so that SSL_CTX_new populates its provider
 * sigalg list with ML-DSA entries pointing to qatprovider's KEYMGMT.
 * Without this, OpenSSL's ssl_load_sigalgs() queries EVP_KEYMGMT_fetch("ML-DSA-*")
 * which returns qatprovider (higher priority), but the capability was only
 * advertised by the default provider -> keymgmt owner mismatch -> ML-DSA never
 * added to ctx->sigalg_list -> SSL_CTX_use_certificate fails with
 * SSL_R_UNKNOWN_CERTIFICATE_TYPE for PQC certs. */
#ifdef ENABLE_QAT_SW_ML_DSA

typedef struct tls_sigalg_constants_st {
    unsigned int code_point;
    unsigned int sec_bits;
    int min_tls;
    int max_tls;
    int min_dtls;
    int max_dtls;
} QAT_TLS_SIGALG_CONSTANTS;

static const QAT_TLS_SIGALG_CONSTANTS qat_sigalg_constants_list[3] = {
    { 0x0904, 128, TLS1_3_VERSION, 0, -1, -1 }, /* ML-DSA-44 */
    { 0x0905, 192, TLS1_3_VERSION, 0, -1, -1 }, /* ML-DSA-65 */
    { 0x0906, 256, TLS1_3_VERSION, 0, -1, -1 }, /* ML-DSA-87 */
};

# define QAT_TLS_SIGALG_ENTRY(tlsname, algorithm, oid, idx)              \
    {                                                                     \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME,     \
            tlsname, sizeof(tlsname)),                                    \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_NAME,          \
            algorithm, sizeof(algorithm)),                                \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_OID,           \
            oid, sizeof(oid)),                                            \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT,           \
            (unsigned int *)&qat_sigalg_constants_list[idx].code_point), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS,        \
            (unsigned int *)&qat_sigalg_constants_list[idx].sec_bits),   \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS,               \
            (unsigned int *)&qat_sigalg_constants_list[idx].min_tls),    \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS,               \
            (unsigned int *)&qat_sigalg_constants_list[idx].max_tls),    \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_DTLS,              \
            (unsigned int *)&qat_sigalg_constants_list[idx].min_dtls),   \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_DTLS,              \
            (unsigned int *)&qat_sigalg_constants_list[idx].max_dtls),   \
        OSSL_PARAM_END                                                    \
    }

static const OSSL_PARAM qat_param_sigalg_list[][10] = {
    QAT_TLS_SIGALG_ENTRY("mldsa44", "ML-DSA-44", "2.16.840.1.101.3.4.3.17", 0),
    QAT_TLS_SIGALG_ENTRY("mldsa65", "ML-DSA-65", "2.16.840.1.101.3.4.3.18", 1),
    QAT_TLS_SIGALG_ENTRY("mldsa87", "ML-DSA-87", "2.16.840.1.101.3.4.3.19", 2),
};

static int tls_sigalg_capability(OSSL_CALLBACK *cb, void *arg)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(qat_param_sigalg_list); i++)
        if (!cb(qat_param_sigalg_list[i], arg))
            return 0;
    return 1;
}

#endif /* ENABLE_QAT_SW_ML_DSA */

int qat_prov_get_capabilities(void *provctx, const char *capability,
                               OSSL_CALLBACK *cb, void *arg)
{
    if (strcasecmp(capability, "TLS-GROUP") == 0)
        return tls_group_capability(cb, arg);

#ifdef ENABLE_QAT_SW_ML_DSA
    if (strcasecmp(capability, "TLS-SIGALG") == 0)
        return tls_sigalg_capability(cb, arg);
#endif

    /* We don't support this capability */
    return 0;
}
