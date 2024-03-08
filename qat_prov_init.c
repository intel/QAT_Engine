/* macros defined to allow use of the cpu get and set affinity functions */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#ifndef __USE_GNU
# define __USE_GNU
#endif

#ifdef ENABLE_QAT_FIPS
# include <sys/ipc.h>
# include <sys/shm.h>
# include <sys/types.h>
#endif

#include <openssl/core_names.h>
#include <openssl/params.h>
#include "qat_provider.h"
#include "e_qat.h"
#include "qat_evp.h"
#include "qat_fork.h"
#include "qat_utils.h"
#include "qat_prov_bio.h"

#ifdef QAT_SW
# include "qat_sw_polling.h"
# include "crypto_mb/cpu_features.h"
#endif

#ifdef ENABLE_QAT_SW_GCM
# include "qat_sw_gcm.h"
#endif

#if defined(ENABLE_QAT_FIPS) && defined(ENABLE_QAT_SW_SHA2)
# include "qat_sw_sha2.h"
#endif

#include "qat_fips.h"
#include "qat_prov_cmvp.h"

OSSL_PROVIDER *prov = NULL;
#ifdef ENABLE_QAT_FIPS
# define SM_KEY 0x00102F

void *sm_ptr;
int sm_id;
#endif

/* By default, qat provider always in a happy state */
int qat_prov_is_running(void)
{
    return 1;
}

OSSL_LIB_CTX *prov_libctx_of(QAT_PROV_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->libctx;
}

void qat_prov_ctx_set_core_bio_method(QAT_PROV_CTX *ctx, QAT_BIO_METHOD *corebiometh)
{
    if (ctx != NULL)
        ctx->corebiometh = corebiometh;
}

#if defined(ENABLE_QAT_HW_RSA) || defined(ENABLE_QAT_SW_RSA)
extern const OSSL_DISPATCH qat_rsa_keymgmt_functions[];
#endif
#if defined(ENABLE_QAT_HW_ECDSA) || defined(ENABLE_QAT_HW_ECDH) \
 || defined(ENABLE_QAT_SW_ECDSA) || defined(ENABLE_QAT_SW_ECDH)
extern const OSSL_DISPATCH qat_ecdh_keymgmt_functions[];
#endif
#if defined(ENABLE_QAT_HW_RSA) || defined(ENABLE_QAT_SW_RSA)
extern const OSSL_DISPATCH qat_rsa_signature_functions[];
#endif
#if defined(ENABLE_QAT_HW_ECDSA) || defined(ENABLE_QAT_SW_ECDSA)
extern const OSSL_DISPATCH qat_ecdsa_signature_functions[];
#endif
#if defined(ENABLE_QAT_HW_ECX) || defined(ENABLE_QAT_SW_ECX)
extern const OSSL_DISPATCH qat_X25519_keyexch_functions[];
#endif
#ifdef ENABLE_QAT_HW_ECX
extern const OSSL_DISPATCH qat_X448_keyexch_functions[];
#endif
#if defined(ENABLE_QAT_HW_ECDH) || defined(ENABLE_QAT_SW_ECDH)
extern const OSSL_DISPATCH qat_ecdh_keyexch_functions[];
#endif
#if defined(ENABLE_QAT_HW_ECX) || defined(ENABLE_QAT_SW_ECX)
extern const OSSL_DISPATCH qat_X25519_keymgmt_functions[];
#endif
#ifdef ENABLE_QAT_HW_ECX
extern const OSSL_DISPATCH qat_X448_keymgmt_functions[];
#endif
#if defined(ENABLE_QAT_HW_GCM) || defined(ENABLE_QAT_SW_GCM)
extern const OSSL_DISPATCH qat_aes128gcm_functions[];
# ifdef ENABLE_QAT_SW_GCM
extern const OSSL_DISPATCH qat_aes192gcm_functions[];
# endif
extern const OSSL_DISPATCH qat_aes256gcm_functions[];
#endif
#ifdef ENABLE_QAT_HW_CCM
extern const OSSL_DISPATCH qat_aes128ccm_functions[];
extern const OSSL_DISPATCH qat_aes192ccm_functions[];
extern const OSSL_DISPATCH qat_aes256ccm_functions[];
#endif
#if defined(ENABLE_QAT_HW_DSA) && defined(QAT_INSECURE_ALGO)
extern const OSSL_DISPATCH qat_dsa_keymgmt_functions[];
#endif
#if defined(ENABLE_QAT_HW_DH) && defined(QAT_INSECURE_ALGO)
extern const OSSL_DISPATCH qat_dh_keymgmt_functions[];
#endif
#if defined(ENABLE_QAT_HW_DSA) && defined(QAT_INSECURE_ALGO)
extern const OSSL_DISPATCH qat_dsa_signature_functions[];
#endif
#if defined(ENABLE_QAT_HW_DH) && defined(QAT_INSECURE_ALGO)
extern const OSSL_DISPATCH qat_dh_keyexch_functions[];
#endif
#ifdef ENABLE_QAT_HW_CIPHERS
# ifdef QAT_INSECURE_ALGO
extern const OSSL_DISPATCH qat_aes128cbc_hmac_sha1_functions[];
extern const OSSL_DISPATCH qat_aes256cbc_hmac_sha1_functions[];
# endif
extern const OSSL_DISPATCH qat_aes128cbc_hmac_sha256_functions[];
extern const OSSL_DISPATCH qat_aes256cbc_hmac_sha256_functions[];
#endif /* ENABLE_QAT_HW_CIPHERS */
#ifdef ENABLE_QAT_HW_CHACHAPOLY
extern const OSSL_DISPATCH qat_chacha20_poly1305_functions[];
#endif /* ENABLE_QAT_HW_CHACHAPOLY */
#if defined(ENABLE_QAT_FIPS) && defined(ENABLE_QAT_SW_SHA2)
# ifdef QAT_INSECURE_ALGO
extern const OSSL_DISPATCH qat_sha224_functions[];
# endif /* QAT_INSECURE_ALGO */
extern const OSSL_DISPATCH qat_sha256_functions[];
extern const OSSL_DISPATCH qat_sha384_functions[];
extern const OSSL_DISPATCH qat_sha512_functions[];
#endif
#ifdef ENABLE_QAT_HW_SHA3
# ifdef QAT_INSECURE_ALGO
extern const OSSL_DISPATCH qat_sha3_224_functions[];
# endif
extern const OSSL_DISPATCH qat_sha3_256_functions[];
extern const OSSL_DISPATCH qat_sha3_384_functions[];
extern const OSSL_DISPATCH qat_sha3_512_functions[];
#endif /* ENABLE_QAT_HW_SHA3 */
#if defined(ENABLE_QAT_HW_SM3) || defined (ENABLE_QAT_SW_SM3)
extern const OSSL_DISPATCH qat_sm3_functions[];
#endif
#ifdef ENABLE_QAT_HW_HKDF
extern const OSSL_DISPATCH qat_kdf_hkdf_functions[];
extern const OSSL_DISPATCH qat_kdf_tls1_3_functions[];
#endif
#ifdef ENABLE_QAT_HW_PRF
extern const OSSL_DISPATCH qat_tls_prf_functions[];
#endif
# if defined(ENABLE_QAT_HW_SM2) || defined(ENABLE_QAT_SW_SM2)
extern const OSSL_DISPATCH qat_sm2_signature_functions[];
extern const OSSL_DISPATCH qat_sm2_keymgmt_functions[];
#endif
#ifdef ENABLE_QAT_SW_SM4_GCM
extern const OSSL_DISPATCH qat_sm4_gcm_functions[];
#endif
#ifdef ENABLE_QAT_SW_SM4_CCM
extern const OSSL_DISPATCH qat_sm4_ccm_functions[];
# endif
#if defined(ENABLE_QAT_HW_SM4_CBC) || defined(ENABLE_QAT_SW_SM4_CBC)
extern const OSSL_DISPATCH qat_sm4_cbc_functions[];
# endif

QAT_PROV_PARAMS qat_params;

static void qat_teardown(void *provctx)
{
    DEBUG("qatprovider teardown\n");
    qat_engine_finish_int(NULL, QAT_RESET_GLOBALS);

#if defined(ENABLE_QAT_FIPS) && defined (ENABLE_QAT_SW_SHA2)
    sha_free_ipsec_mb_mgr();
#endif
#ifdef ENABLE_QAT_FIPS
    shmctl(sm_id, IPC_RMID, 0);
#endif
    if (provctx) {
        QAT_PROV_CTX *qat_ctx = (QAT_PROV_CTX *)provctx;
        BIO_meth_free(ossl_prov_ctx_get0_core_bio_method(qat_ctx));
        OPENSSL_free(qat_ctx);
        OSSL_PROVIDER_unload(prov);
    }
}

/* Parameters we provide to the core */
static const OSSL_PARAM qat_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM *qat_gettable_params(void *provctx)
{
    return qat_param_types;
}

static int qat_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, QAT_PROVIDER_NAME_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, QAT_PROVIDER_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, QAT_PROVIDER_FULL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;
    return 1;
}

static const OSSL_ALGORITHM_CAPABLE qat_deflt_ciphers[] = {
#if defined(ENABLE_QAT_HW_GCM) || defined(ENABLE_QAT_SW_GCM)
    ALG(QAT_NAMES_AES_128_GCM, qat_aes128gcm_functions),
    ALG(QAT_NAMES_AES_256_GCM, qat_aes256gcm_functions),
#endif
#ifdef ENABLE_QAT_SW_GCM
    ALG(QAT_NAMES_AES_192_GCM, qat_aes192gcm_functions),
#endif
#ifdef ENABLE_QAT_HW_CCM
    ALG(QAT_NAMES_AES_128_CCM, qat_aes128ccm_functions),
    ALG(QAT_NAMES_AES_192_CCM, qat_aes192ccm_functions),
    ALG(QAT_NAMES_AES_256_CCM, qat_aes256ccm_functions),
#endif
#if defined(ENABLE_QAT_HW_CIPHERS) && !defined(ENABLE_QAT_FIPS)
# ifdef QAT_INSECURE_ALGO
    ALG(QAT_NAMES_AES_128_CBC_HMAC_SHA1, qat_aes128cbc_hmac_sha1_functions),
    ALG(QAT_NAMES_AES_256_CBC_HMAC_SHA1, qat_aes256cbc_hmac_sha1_functions),
# endif
    ALG(QAT_NAMES_AES_128_CBC_HMAC_SHA256, qat_aes128cbc_hmac_sha256_functions),
    ALG(QAT_NAMES_AES_256_CBC_HMAC_SHA256, qat_aes256cbc_hmac_sha256_functions),
#endif
# ifdef ENABLE_QAT_HW_CHACHAPOLY
    ALG(QAT_NAMES_CHACHA20_POLY1305, qat_chacha20_poly1305_functions),
# endif /* ENABLE_QAT_HW_CHACHAPOLY */
# ifdef ENABLE_QAT_SW_SM4_GCM
    ALG(QAT_NAMES_SM4_GCM, qat_sm4_gcm_functions),
# endif
# ifdef ENABLE_QAT_SW_SM4_CCM
    ALG(QAT_NAMES_SM4_CCM, qat_sm4_ccm_functions),
# endif
#if defined(ENABLE_QAT_HW_SM4_CBC) || defined(ENABLE_QAT_SW_SM4_CBC)
    ALG(QAT_NAMES_SM4_CBC, qat_sm4_cbc_functions),
# endif
    { { NULL, NULL, NULL }, NULL }};

static OSSL_ALGORITHM qat_exported_ciphers[OSSL_NELEM(qat_deflt_ciphers)];

static const OSSL_ALGORITHM qat_keyexch[] = {
#if defined(ENABLE_QAT_HW_ECX) || defined(ENABLE_QAT_SW_ECX)
    {"X25519", QAT_DEFAULT_PROPERTIES, qat_X25519_keyexch_functions, "QAT X25519 keyexch implementation."},
#endif
#if defined(ENABLE_QAT_HW_ECDH) || defined(ENABLE_QAT_SW_ECDH)
    {"ECDH", QAT_DEFAULT_PROPERTIES, qat_ecdh_keyexch_functions, "QAT ECDH keyexch implementation."},
# if !defined(ENABLE_QAT_FIPS)
#  if defined(ENABLE_QAT_HW_SM2) || defined(ENABLE_QAT_SW_SM2)
#   if defined(TONGSUO_VERSION_NUMBER)
    {"SM2DH", QAT_DEFAULT_PROPERTIES, qat_ecdh_keyexch_functions, "QAT SM2 keyexch implementation."},
#   else
    {"SM2", QAT_DEFAULT_PROPERTIES, qat_ecdh_keyexch_functions, "QAT SM2 keyexch implementation."},
#   endif
#  endif
# endif
#endif
#if defined(ENABLE_QAT_HW_DH) && defined(QAT_INSECURE_ALGO)
    {"DH", QAT_DEFAULT_PROPERTIES, qat_dh_keyexch_functions, "QAT DH keyexch implementation"},
#endif
#ifdef ENABLE_QAT_HW_ECX
    {"X448", QAT_DEFAULT_PROPERTIES, qat_X448_keyexch_functions, "QAT X448 keyexch implementation."},
#endif
    {NULL, NULL, NULL}};

static const OSSL_ALGORITHM qat_keymgmt[] = {
#if defined(ENABLE_QAT_HW_RSA) || defined(ENABLE_QAT_SW_RSA)
    {"RSA", QAT_DEFAULT_PROPERTIES, qat_rsa_keymgmt_functions, "QAT RSA Keymgmt implementation."},
#endif
#if defined(ENABLE_QAT_HW_ECX) || defined(ENABLE_QAT_SW_ECX)
    {"X25519", QAT_DEFAULT_PROPERTIES, qat_X25519_keymgmt_functions, "QAT X25519 Keymgmt implementation."},
#endif
#if defined(ENABLE_QAT_HW_ECDH) || defined(ENABLE_QAT_SW_ECDH)
    {"EC", QAT_DEFAULT_PROPERTIES, qat_ecdh_keymgmt_functions, "QAT EC Keymgmt implementation."},
#endif
#if defined(ENABLE_QAT_HW_DSA) && defined(QAT_INSECURE_ALGO)
    {"DSA", QAT_DEFAULT_PROPERTIES, qat_dsa_keymgmt_functions, "QAT DSA Keymgmt implementation."},
# endif
#if defined(ENABLE_QAT_HW_DH) && defined(QAT_INSECURE_ALGO)
    {"DH", QAT_DEFAULT_PROPERTIES, qat_dh_keymgmt_functions, "QAT DH Keymgmt implementation"},
#endif
#ifdef ENABLE_QAT_HW_ECX
    {"X448", QAT_DEFAULT_PROPERTIES, qat_X448_keymgmt_functions, "QAT X448 Keymgmt implementation."},
#endif
#if defined(ENABLE_QAT_HW_SM2) || defined(ENABLE_QAT_SW_SM2)
    {"SM2", QAT_DEFAULT_PROPERTIES, qat_sm2_keymgmt_functions, "QAT SM2 Keymgmt implementation."},
#endif
    {NULL, NULL, NULL}};

static const OSSL_ALGORITHM qat_signature[] = {
#if defined(ENABLE_QAT_HW_RSA) || defined(ENABLE_QAT_SW_RSA)
    {"RSA", QAT_DEFAULT_PROPERTIES, qat_rsa_signature_functions, "QAT RSA Signature implementation."},
#endif
#if defined(ENABLE_QAT_HW_ECDSA) || defined(ENABLE_QAT_SW_ECDSA)
    {"ECDSA", QAT_DEFAULT_PROPERTIES, qat_ecdsa_signature_functions, "QAT ECDSA Signature implementation."},
#endif
#if defined(ENABLE_QAT_HW_DSA) && defined(QAT_INSECURE_ALGO)
    {"DSA", QAT_DEFAULT_PROPERTIES, qat_dsa_signature_functions, "QAT DSA Signature implementation."},
#endif
# if !defined(ENABLE_QAT_FIPS)
#  if defined(ENABLE_QAT_HW_SM2) || defined(ENABLE_QAT_SW_SM2)
    {"SM2", QAT_DEFAULT_PROPERTIES, qat_sm2_signature_functions, "QAT SM2 Signature implementation."},
#  endif
# endif
    {NULL, NULL, NULL}};

#if defined(ENABLE_QAT_HW_HKDF) || defined(ENABLE_QAT_HW_PRF)
static const OSSL_ALGORITHM qat_kdfs[] = {
# ifdef ENABLE_QAT_HW_HKDF
    {"HKDF", QAT_DEFAULT_PROPERTIES, qat_kdf_hkdf_functions, "QAT HKDF implementation"},
    {"TLS13-KDF", QAT_DEFAULT_PROPERTIES, qat_kdf_tls1_3_functions, "QAT HKDF implementation"},
# endif
# ifdef ENABLE_QAT_HW_PRF
    {"TLS1-PRF", QAT_DEFAULT_PROPERTIES, qat_tls_prf_functions, "QAT PRF implementation"},
# endif
    {NULL, NULL, NULL}};
#endif

#if defined(ENABLE_QAT_HW_SHA3) || defined(ENABLE_QAT_SW_SHA2) || defined(ENABLE_QAT_HW_SM3) || defined(ENABLE_QAT_SW_SM3)
static const OSSL_ALGORITHM qat_digests[] = {
#if defined(ENABLE_QAT_FIPS) && defined(ENABLE_QAT_SW_SHA2)
# ifdef QAT_INSECURE_ALGO
    { QAT_NAMES_SHA2_224, QAT_DEFAULT_PROPERTIES, qat_sha224_functions },
# endif
    { QAT_NAMES_SHA2_256, QAT_DEFAULT_PROPERTIES, qat_sha256_functions },
    { QAT_NAMES_SHA2_384, QAT_DEFAULT_PROPERTIES, qat_sha384_functions },
    { QAT_NAMES_SHA2_512, QAT_DEFAULT_PROPERTIES, qat_sha512_functions },
#endif
#ifdef ENABLE_QAT_HW_SHA3
# ifdef QAT_INSECURE_ALGO
    { QAT_NAMES_SHA3_224, QAT_DEFAULT_PROPERTIES, qat_sha3_224_functions },
# endif
    { QAT_NAMES_SHA3_256, QAT_DEFAULT_PROPERTIES, qat_sha3_256_functions },
    { QAT_NAMES_SHA3_384, QAT_DEFAULT_PROPERTIES, qat_sha3_384_functions },
    { QAT_NAMES_SHA3_512, QAT_DEFAULT_PROPERTIES, qat_sha3_512_functions },
#endif
# if defined(ENABLE_QAT_HW_SM3) || defined (ENABLE_QAT_SW_SM3)
    { QAT_NAMES_SM3, QAT_DEFAULT_PROPERTIES, qat_sm3_functions },
# endif
    { NULL, NULL, NULL }};
#endif

#ifdef ENABLE_QAT_FIPS
int qat_operations(int operation_id)
{
    switch (operation_id) {
    case OSSL_OP_DIGEST:
    case OSSL_OP_CIPHER:
    case OSSL_OP_SIGNATURE:
    case OSSL_OP_KEYMGMT:
    case OSSL_OP_KEYEXCH:
    case OSSL_OP_KDF:
        return 1;
    default:
        return 0;							     }
}
#endif

static const OSSL_ALGORITHM *qat_query(void *provctx, int operation_id, int *no_cache)
{
    static int prov_init = 0;
    prov = OSSL_PROVIDER_load(NULL, "default");

#ifdef ENABLE_QAT_FIPS
    /*
     * By using this variable can set FIPs on-demand test internally
     * 1 - ondemand test set
     * 0 - ondemand test unset
     */
    int ondemand = 0;
    static int self_test_init = 0;
    static int count = 1;
    sm_id = shmget((key_t)SM_KEY, 16, 0666);
    sm_ptr = shmat(sm_id, NULL, 0);
    static pid_t init_pid = 0;

    if (prov_init == 2 && self_test_init == 0) {
        prov_init++;
        self_test_init++;
        if (!strcmp((char *)sm_ptr, "KAT_RSET")) {
            strcpy(sm_ptr, "KAT_DONE");
            init_pid = getpid();
            if (qat_hw_offload && qat_sw_offload)
                qat_fips_self_test(provctx, ondemand, 1);
            else
              qat_fips_self_test(provctx, ondemand, 0);
        }
    }

    if (prov_init == 1 && self_test_init == 0) {
        prov_init++;
        if (operation_id != OSSL_OP_RAND) {
            prov_init++;
            self_test_init++;
            if (!strcmp((char *)sm_ptr, "KAT_RSET")) {
                strcpy(sm_ptr, "KAT_DONE");
                init_pid = getpid();
                if (qat_hw_offload && qat_sw_offload)
                    qat_fips_self_test(provctx, ondemand, 1);
                else
                  qat_fips_self_test(provctx, ondemand, 0);
            }
        }
    }
#endif
    if (!prov_init) {
        prov_init = 1;
        /* qat provider takes the highest priority
         * and overwrite the openssl.cnf property. */
        EVP_set_default_properties(NULL, "?provider=qatprovider");
#ifdef ENABLE_QAT_FIPS
        if (qat_operations(operation_id)) {
            prov_init++;
            self_test_init++;
            if (!strcmp((char *)sm_ptr, "KAT_RSET")) {
                strcpy(sm_ptr, "KAT_DONE");
                init_pid = getpid();
                if (qat_hw_offload && qat_sw_offload)
                    qat_fips_self_test(provctx, ondemand, 1);
                else
                  qat_fips_self_test(provctx, ondemand, 0);
            }
        }
#endif
    }

    *no_cache = 0;
#ifdef ENABLE_QAT_FIPS
    while (count && sm_ptr != NULL) {
          if (strcmp((char *)sm_ptr, "KAT_DONE") != 0 || init_pid == getpid()) {
              count = 1;
              break;
          }
          count++;
    }
    if (integrity_status && strcmp((char *)sm_ptr, "KAT_FAIL") != 0) {
#endif
        switch (operation_id) {
#if defined(ENABLE_QAT_HW_SHA3) || defined(ENABLE_QAT_SW_SHA2) || defined(ENABLE_QAT_HW_SM3) || defined(ENABLE_QAT_SW_SM3)
        case OSSL_OP_DIGEST:
            return qat_digests;
#endif
        case OSSL_OP_CIPHER:
            return qat_exported_ciphers;
        case OSSL_OP_SIGNATURE:
            return qat_signature;
        case OSSL_OP_KEYMGMT:
            return qat_keymgmt;
        case OSSL_OP_KEYEXCH:
            return qat_keyexch;
#if defined(ENABLE_QAT_HW_HKDF) || defined(ENABLE_QAT_HW_PRF)
        case OSSL_OP_KDF:
            return qat_kdfs;
#endif
        }
        return OSSL_PROVIDER_query_operation(prov, operation_id, no_cache);
#ifdef ENABLE_QAT_FIPS
    }
    else {
      qat_teardown(provctx);
      exit(EXIT_FAILURE);
    }
#endif
}

static const OSSL_DISPATCH qat_dispatch_table[] = {
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))qat_teardown},
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))qat_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))qat_get_params},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))qat_query},
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
      (void (*)(void))qat_prov_get_capabilities},
    {0, NULL}};

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;
static OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;

int qat_get_params_from_core(const OSSL_CORE_HANDLE *handle)
{
    OSSL_PARAM core_params[10], *p = core_params;
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        "enable_external_polling",
        (char **)&qat_params.enable_external_polling,
        0);

    *p++ = OSSL_PARAM_construct_utf8_ptr(
        "enable_heuristic_polling",
        (char **)&qat_params.enable_heuristic_polling,
        0);

    *p++ = OSSL_PARAM_construct_utf8_ptr(
        "enable_sw_fallback",
        (char **)&qat_params.enable_sw_fallback,
        0);

    *p++ = OSSL_PARAM_construct_utf8_ptr(
        "enable_inline_polling",
        (char **)&qat_params.enable_inline_polling,
        0);

    *p++ = OSSL_PARAM_construct_utf8_ptr(
        "qat_poll_interval",
        (char **)&qat_params.qat_poll_interval,
        0);

    *p++ = OSSL_PARAM_construct_utf8_ptr(
        "qat_epoll_timeout",
        (char **)&qat_params.qat_epoll_timeout,
        0);

    *p++ = OSSL_PARAM_construct_utf8_ptr(
        "enable_event_driven_polling",
        (char **)&qat_params.enable_event_driven_polling,
        0);

    *p++ = OSSL_PARAM_construct_utf8_ptr(
        "enable_instance_for_thread",
        (char **)&qat_params.enable_instance_for_thread,
        0);

    *p++ = OSSL_PARAM_construct_utf8_ptr(
        "qat_max_retry_count",
        (char **)&qat_params.qat_max_retry_count,
        0);

    *p = OSSL_PARAM_construct_end();

    if (!c_get_params(handle, core_params)) {
        WARN("QAT get parameters from core is failed.\n");
        return 0;
    }

    if (qat_params.enable_external_polling == NULL) {
        DEBUG("get_params is NULL. Using the default params\n");
        return 1;
    }

    enable_external_polling = atoi(qat_params.enable_external_polling);
    enable_heuristic_polling = atoi(qat_params.enable_heuristic_polling);

#ifdef QAT_HW
    enable_sw_fallback = atoi(qat_params.enable_sw_fallback);
    enable_inline_polling = atoi(qat_params.enable_inline_polling);
    qat_poll_interval = atoi(qat_params.qat_poll_interval);
    qat_epoll_timeout = atoi(qat_params.qat_epoll_timeout);
    enable_event_driven_polling = atoi(qat_params.enable_event_driven_polling);
    enable_instance_for_thread = atoi(qat_params.enable_instance_for_thread);
    qat_max_retry_count = atoi(qat_params.qat_max_retry_count);
#endif

    return 1;
}

void qat_prov_cache_exported_algorithms(const OSSL_ALGORITHM_CAPABLE *in,
                                        OSSL_ALGORITHM *out)
{
    int i, j;
    if (out[0].algorithm_names == NULL) {
        for (i = j = 0; in[i].alg.algorithm_names != NULL; ++i) {
            if (in[i].capable == NULL || in[i].capable())
                out[j++] = in[i].alg;
        }
        out[j++] = in[i].alg;
    }
}

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    QAT_PROV_CTX *qat_ctx = NULL;
    BIO_METHOD *corebiometh = NULL;
    QAT_DEBUG_LOG_INIT();

    if (!ossl_prov_bio_from_dispatch(in))
        return 0;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_FUNC_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }
#ifdef ENABLE_QAT_FIPS
    /*displaying module_name, ID & version of FIPs module*/
    if(qat_provider_info()) {
        goto err;
    }
#endif
    /* get parameters from qat_provider.cnf */
    if (!qat_get_params_from_core(handle)) {
        return 0;
    }

    if (!bind_qat(NULL, NULL) || !qat_engine_init(NULL)) {
        goto err;
    }

    qat_ctx = OPENSSL_zalloc(sizeof(QAT_PROV_CTX));
    if (qat_ctx == NULL) {
        goto err;
    }

    qat_ctx->handle = handle;
#ifndef ENABLE_QAT_FIPS
    qat_ctx->libctx = (OSSL_LIB_CTX *)c_get_libctx(handle);
#else
    qat_ctx->libctx = (OSSL_LIB_CTX *)OSSL_LIB_CTX_new_from_dispatch(handle, in);
#endif

    *provctx = (void *)qat_ctx;
    corebiometh = ossl_bio_prov_init_bio_method();
    qat_prov_ctx_set_core_bio_method(*provctx, corebiometh);
    *out = qat_dispatch_table;
    qat_prov_cache_exported_algorithms(qat_deflt_ciphers, qat_exported_ciphers);
#ifdef ENABLE_QAT_FIPS
    sm_id = shmget((key_t)SM_KEY, 16, IPC_CREAT|0666);
    sm_ptr = shmat(sm_id, NULL, 0);
    strcpy(sm_ptr, "KAT_RSET");
#endif

    return 1;

err:
    WARN("QAT provider init failed");
    qat_teardown(qat_ctx);
    return 0;
}
