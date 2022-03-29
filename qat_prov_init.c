/* macros defined to allow use of the cpu get and set affinity functions */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#ifndef __USE_GNU
# define __USE_GNU
#endif

#include <openssl/core_names.h>
#include <openssl/params.h>
#include "qat_provider.h"
#include "e_qat.h"
#include "qat_fork.h"
#include "qat_utils.h"

#ifdef QAT_SW
# include "qat_sw_polling.h"
# include "crypto_mb/cpu_features.h"
#endif

#ifdef QAT_SW_IPSEC
# include "qat_sw_gcm.h"
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

extern const OSSL_DISPATCH qat_rsa_keymgmt_functions[];
extern const OSSL_DISPATCH qat_ec_keymgmt_functions[];
extern const OSSL_DISPATCH qat_rsa_signature_functions[];
extern const OSSL_DISPATCH qat_ecdsa_signature_functions[];
extern const OSSL_DISPATCH qat_X25519_keyexch_functions[];
extern const OSSL_DISPATCH qat_X448_keyexch_functions[];
extern const OSSL_DISPATCH qat_ecdh_keyexch_functions[];
extern const OSSL_DISPATCH qat_X25519_keymgmt_functions[];
extern const OSSL_DISPATCH qat_X448_keymgmt_functions[];
extern const OSSL_DISPATCH qat_aes128gcm_functions[];
extern const OSSL_DISPATCH qat_aes192gcm_functions[];
extern const OSSL_DISPATCH qat_aes256gcm_functions[];
QAT_PROV_PARAMS qat_params;

static int qat_provider_bind()
{
#ifdef QAT_HW
    char *config_section = NULL;
#endif

    WARN("QAT Warnings enabled.\n");
    DEBUG("QAT Debug enabled.\n");

    /* Ensure the QAT error handling is set up */
    ERR_load_QAT_strings();

#ifdef QAT_HW
# ifdef QAT_HW_INTREE
    if (icp_sal_userIsQatAvailable() == CPA_TRUE) {
        qat_hw_offload = 1;
    } else {
        WARN("Qat Intree device not available\n");
#  ifndef QAT_SW
        return 0;
#  endif
    }
# else
    if (access(QAT_DEV, F_OK) == 0) {
        qat_hw_offload = 1;
        if (access(QAT_MEM_DEV, F_OK) != 0) {
            WARN("Qat memory driver not present\n");
            return 0;
        }
    } else {
        WARN("Qat device not available\n");
#  ifndef QAT_SW
        return 0;
#  endif
    }
# endif
#endif

#ifdef QAT_SW
# if defined(ENABLE_QAT_SW_RSA) || defined(ENABLE_QAT_SW_ECX)    \
  || defined(ENABLE_QAT_SW_ECDH) || defined(ENABLE_QAT_SW_ECDSA)
    DEBUG("Registering QAT SW supported algorithms\n");
    qat_sw_offload = 1;
# endif

    if (mbx_get_algo_info(MBX_ALGO_RSA_2K) &&
        mbx_get_algo_info(MBX_ALGO_RSA_3K) &&
        mbx_get_algo_info(MBX_ALGO_RSA_4K)) {
        DEBUG("QAT_SW RSA Supported\n");
    }
#endif

#ifdef QAT_SW_IPSEC
    if (hw_support()) {
# ifdef ENABLE_QAT_SW_GCM
        if (!vaesgcm_init_ipsec_mb_mgr()) {
            WARN("IPSec Multi-Buffer Manager Initialization failed\n");
            return 0;
        }
# endif
    }
#endif

#ifdef QAT_HW
# ifdef __GLIBC_PREREQ
#  if __GLIBC_PREREQ(2, 17)
    config_section = secure_getenv("QAT_SECTION_NAME");
#  else
    config_section = getenv("QAT_SECTION_NAME");
#  endif
# else
    config_section = getenv("QAT_SECTION_NAME");
# endif
    if (validate_configuration_section_name(config_section)) {
        strncpy(qat_config_section_name, config_section, QAT_CONFIG_SECTION_NAME_SIZE - 1);
        qat_config_section_name[QAT_CONFIG_SECTION_NAME_SIZE - 1] = '\0';
    }
#endif
    pthread_atfork(engine_finish_before_fork_handler, NULL,
                   engine_init_child_at_fork_handler);
    return 1;
}

static void qat_teardown(void *provctx)
{
    DEBUG("qatprovider teardown\n");
    qat_engine_finish_int(NULL, QAT_RESET_GLOBALS);

    if (provctx) {
        QAT_PROV_CTX *qat_ctx = (QAT_PROV_CTX *)provctx;
        OPENSSL_free(qat_ctx);
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
    ALG(QAT_NAMES_AES_128_GCM, qat_aes128gcm_functions),
#ifdef QAT_SW
    ALG(QAT_NAMES_AES_192_GCM, qat_aes192gcm_functions),
#endif
    ALG(QAT_NAMES_AES_256_GCM, qat_aes256gcm_functions),
    { { NULL, NULL, NULL }, NULL }
};

static OSSL_ALGORITHM qat_exported_ciphers[OSSL_NELEM(qat_deflt_ciphers)];

static const OSSL_ALGORITHM qat_keyexch[] = {
    {"X25519", QAT_DEFAULT_PROPERTIES, qat_X25519_keyexch_functions, "QAT X25519 keyexch implementation."},
    {"ECDH", QAT_DEFAULT_PROPERTIES, qat_ecdh_keyexch_functions, "QAT ECDH keyexch implementation."},
#ifdef QAT_HW
    {"X448", QAT_DEFAULT_PROPERTIES, qat_X448_keyexch_functions, "QAT X448 keyexch implementation."},
#endif
    {NULL, NULL, NULL}};

static const OSSL_ALGORITHM qat_keymgmt[] = {
    {"RSA", QAT_DEFAULT_PROPERTIES, qat_rsa_keymgmt_functions, "QAT RSA Keymgmt implementation."},
    {"X25519", QAT_DEFAULT_PROPERTIES, qat_X25519_keymgmt_functions, "QAT X25519 Keymgmt implementation."},
    {"EC", QAT_DEFAULT_PROPERTIES, qat_ec_keymgmt_functions, "QAT EC Keymgmt implementation."},
#ifdef QAT_HW
    {"X448", QAT_DEFAULT_PROPERTIES, qat_X448_keymgmt_functions, "QAT X448 Keymgmt implementation."},
#endif
    {NULL, NULL, NULL}};

static const OSSL_ALGORITHM qat_signature[] = {
    {"RSA", QAT_DEFAULT_PROPERTIES, qat_rsa_signature_functions, "QAT RSA Signature implementation."},
    {"ECDSA",QAT_DEFAULT_PROPERTIES, qat_ecdsa_signature_functions, "QAT ECDSA Signature implementation."},
    {NULL, NULL, NULL}};


static const OSSL_ALGORITHM *qat_query(void *provctx, int operation_id, int *no_cache)
{
    static int prov_init = 0;
    OSSL_PROVIDER *prov = NULL;
    prov = OSSL_PROVIDER_load(NULL, "default");
    if (!prov_init) {
        prov_init = 1;
        /* qat provider takes the highest priority
         * and overwrite the openssl.cnf property. */
        EVP_set_default_properties(NULL, "?provider=qatprovider");
    }

    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_CIPHER:
        return qat_exported_ciphers;
    case OSSL_OP_SIGNATURE:
        return qat_signature;
    case OSSL_OP_KEYMGMT:
        return qat_keymgmt;
    case OSSL_OP_KEYEXCH:
        return qat_keyexch;
    }
    return OSSL_PROVIDER_query_operation(prov, operation_id, no_cache);
}

static const OSSL_DISPATCH qat_dispatch_table[] = {
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))qat_teardown},
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))qat_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))qat_get_params},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))qat_query},
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
        WARN("please ensure you have enable the qat_provider.cnf or we will use the default parameters.\n");
        WARN("get_params from qat_provider.cnf is NULL. Use default params\n");
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

    /* get parameters from qat_provider.cnf */
    if (!qat_get_params_from_core(handle)) {
        return 0;
    }

    if (!qat_provider_bind() || !qat_engine_init(NULL)) {
        goto err;
    }

    qat_ctx = OPENSSL_zalloc(sizeof(QAT_PROV_CTX));
    if (qat_ctx == NULL) {
        goto err;
    }

    qat_ctx->handle = handle;
    qat_ctx->libctx = (OSSL_LIB_CTX *)c_get_libctx(handle);

    *provctx = (void *)qat_ctx;
    corebiometh = OPENSSL_zalloc(sizeof(BIO_METHOD));
    qat_prov_ctx_set_core_bio_method(*provctx, corebiometh);
    *out = qat_dispatch_table;
    qat_prov_cache_exported_algorithms(qat_deflt_ciphers, qat_exported_ciphers);
    return 1;

err:
    WARN("QAT provider init failed");
    qat_teardown(qat_ctx);
    return 0;
}
