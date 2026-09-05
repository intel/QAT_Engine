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

#ifdef QAT_HW
# include "qat_hw_polling.h"
# include "icp_sal_poll.h"
# include <fcntl.h>
#endif

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
extern const OSSL_DISPATCH qat_rsapss_keymgmt_functions[];
extern const OSSL_DISPATCH qat_rsa_signature_functions[];
#endif
#if defined(ENABLE_QAT_HW_RSA) || defined(ENABLE_QAT_SW_RSA)
extern const OSSL_DISPATCH qat_rsa_asym_cipher_functions[];
#endif
#if defined(ENABLE_QAT_HW_ECDSA) || defined(ENABLE_QAT_SW_ECDSA)
extern const OSSL_DISPATCH qat_ecdsa_signature_functions[];
#endif
#if defined(ENABLE_QAT_HW_ECDH) || defined(ENABLE_QAT_SW_ECDH) || \
    defined(ENABLE_QAT_HW_ECDSA) || defined(ENABLE_QAT_SW_ECDSA)
extern const OSSL_DISPATCH qat_ec_keymgmt_functions[];
#endif
#if defined(ENABLE_QAT_HW_ECDH) || defined(ENABLE_QAT_SW_ECDH)
extern const OSSL_DISPATCH qat_ecdh_keyexch_functions[];
#endif
#if defined(ENABLE_QAT_HW_ECX) || defined(ENABLE_QAT_SW_ECX)
extern const OSSL_DISPATCH qat_X25519_keyexch_functions[];
extern const OSSL_DISPATCH qat_X25519_keymgmt_functions[];
#endif
#ifdef ENABLE_QAT_HW_ECX
extern const OSSL_DISPATCH qat_X448_keyexch_functions[];
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
extern const OSSL_DISPATCH qat_dsa_signature_functions[];
#endif
#if defined(ENABLE_QAT_HW_DH) && defined(QAT_INSECURE_ALGO)
extern const OSSL_DISPATCH qat_dh_keymgmt_functions[];
extern const OSSL_DISPATCH qat_dh_keyexch_functions[];
#endif
#ifdef ENABLE_QAT_HW_CIPHERS
# ifdef QAT_INSECURE_ALGO
extern const OSSL_DISPATCH qat_aes128cbc_hmac_sha1_functions[];
extern const OSSL_DISPATCH qat_aes256cbc_hmac_sha1_functions[];
extern const OSSL_DISPATCH qat_aes128cbc_hmac_sha256_functions[];
# endif
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
#ifdef ENABLE_QAT_SW_ML_KEM
# include "qat_sw_ml_kem.h"
#endif
#ifdef ENABLE_QAT_SW_ML_DSA
# include "qat_sw_ml_dsa.h"
#endif

QAT_PROV_PARAMS qat_params;

/* Reports whether openssl.cnf supplied the polling configuration. */
int qat_prov_configured_from_cnf = 0;

/* Provider-scoped QAT initialization state, cleared on teardown. */
static int qat_prov_inited = 0;

int qat_prov_ensure_init(void)
{
    if (qat_prov_inited)
        return 1;

    if (!qat_engine_init(NULL)) {
        WARN("[QAT_PROV] lazy qat_engine_init failed\n");
        return 0;
    }
    qat_prov_inited = 1;
    DEBUG("[QAT_PROV] QAT initialised lazily on first crypto operation\n");
    return 1;
}

static void qat_teardown(void *provctx)
{
    DEBUG("qatprovider teardown\n");
#ifndef OPENSSL_NO_ENGINE
    qat_free_ciphers();
#endif
    qat_free_digest_meth();
    qat_engine_finish_int(NULL, QAT_RESET_GLOBALS);
    qat_prov_inited = 0;
#ifdef QAT_OPENSSL_PROVIDER
    /* Paired with the registration in the INIT_PROVIDER/POLL handlers: a torn
     * down provider has no application poller any more. */
    qat_app_external_poller = 0;
#endif
    ERR_unload_QAT_strings();

#if defined(ENABLE_QAT_FIPS) && defined (ENABLE_QAT_SW_SHA2)
    sha_free_ipsec_mb_mgr();
#endif
#ifdef ENABLE_QAT_SW_ML_KEM
    qat_sw_ml_kem_free_ipsec_mb_mgr();
#endif
#ifdef ENABLE_QAT_SW_ML_DSA
    qat_sw_ml_dsa_free_ipsec_mb_mgr();
#endif
#ifdef ENABLE_QAT_FIPS
    shmctl(sm_id, IPC_RMID, 0);
#endif
    if (provctx) {
        QAT_PROV_CTX *qat_ctx = (QAT_PROV_CTX *)provctx;
        BIO_meth_free(ossl_prov_ctx_get0_core_bio_method(qat_ctx));
        OPENSSL_free(qat_ctx);
    }
}

/* Provider parameter names are centralized in qat_provider.h. */
#define QAT_MAX_INPUT_STRING_LENGTH 1024

/* Stored heuristic-poll threshold defaults. */
static int qat_prov_hw_asym_threshold = 48;
static int qat_prov_hw_sym_threshold  = 24;
static int qat_prov_sw_threshold      = 8;

static int qat_prov_config_lock(void)
{
    qat_pthread_mutex_lock();
    if (engine_inited) {
        qat_pthread_mutex_unlock();
        return 0;
    }
    return 1;
}

static const OSSL_PARAM qat_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    /* Configuration parameters set by the application. */
    OSSL_PARAM_DEFN(QAT_PROV_PARAM_ENABLE_EXTERNAL_POLLING, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_DEFN(QAT_PROV_PARAM_ENABLE_HEURISTIC_POLLING, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_DEFN(QAT_PROV_PARAM_ENABLE_SW_FALLBACK, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_DEFN(QAT_PROV_PARAM_INTERNAL_POLL_INTERVAL, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_DEFN(QAT_PROV_PARAM_INIT_PROVIDER, OSSL_PARAM_INTEGER, NULL, 0),
    /* Runtime operation params */
    OSSL_PARAM_DEFN(QAT_PROV_PARAM_POLL, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_DEFN(QAT_PROV_PARAM_HEARTBEAT_POLL, OSSL_PARAM_INTEGER, NULL, 0),
    /* In-flight request counters (read by application) */
    OSSL_PARAM_DEFN(QAT_PROV_PARAM_NUM_ASYM_REQUESTS_IN_FLIGHT, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_DEFN(QAT_PROV_PARAM_NUM_KDF_REQUESTS_IN_FLIGHT, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_DEFN(QAT_PROV_PARAM_NUM_CIPHER_REQUESTS_IN_FLIGHT, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_DEFN(QAT_PROV_PARAM_NUM_ASYM_MB_ITEMS_IN_QUEUE, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_DEFN(QAT_PROV_PARAM_NUM_KDF_MB_ITEMS_IN_QUEUE, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_DEFN(QAT_PROV_PARAM_NUM_SYM_MB_ITEMS_IN_QUEUE, OSSL_PARAM_INTEGER, NULL, 0),
    /* Small packet threshold (string: "algo:size,algo2:size2") */
    OSSL_PARAM_DEFN(QAT_PROV_PARAM_SMALL_PKT_OFFLOAD_THRESHOLD, OSSL_PARAM_UTF8_STRING, NULL, 0),
    /* Heuristic-poll thresholds available for application read-back. */
    OSSL_PARAM_DEFN(QAT_PROV_PARAM_HW_ASYM_THRESHOLD, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_DEFN(QAT_PROV_PARAM_HW_SYM_THRESHOLD, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_DEFN(QAT_PROV_PARAM_SW_THRESHOLD, OSSL_PARAM_INTEGER, NULL, 0),
    /* Read-only: openssl.cnf-configured sentinel. */
    OSSL_PARAM_DEFN(QAT_PROV_PARAM_CONFIGURED_FROM_CNF, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM *qat_gettable_params(void *provctx)
{
    return qat_param_types;
}

static int qat_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    int val;

    /* Standard provider metadata */
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

    /* Report whether openssl.cnf supplied the polling configuration. */
    p = OSSL_PARAM_locate(params, QAT_PROV_PARAM_CONFIGURED_FROM_CNF);
    if (p != NULL && !OSSL_PARAM_set_int(p, qat_prov_configured_from_cnf))
        return 0;

    /* Apply caller-supplied configuration and return the effective value. */
    p = OSSL_PARAM_locate(params, QAT_PROV_PARAM_ENABLE_EXTERNAL_POLLING);
    if (p != NULL) {
        /* Zero requests read-back; polling mode is immutable after HW init. */
        if (OSSL_PARAM_get_int(p, &val) && val) {
            if (!qat_prov_config_lock()) {
                WARN("[QAT_PROV] ENABLE_EXTERNAL_POLLING: polling mode already "
                     "committed; ignoring change (restart to apply)\n");
            } else {
                enable_external_polling = 1;
                qat_pthread_mutex_unlock();
                DEBUG("qat_get_params: ENABLE_EXTERNAL_POLLING enabled "
                      "(external=%d)\n", enable_external_polling);
            }
        }
        if (!OSSL_PARAM_set_int(p, enable_external_polling))
            return 0;
    }

    p = OSSL_PARAM_locate(params, QAT_PROV_PARAM_ENABLE_HEURISTIC_POLLING);
    if (p != NULL) {
        /* Apply only a NON-ZERO written value (read-back safe; see the external
         * polling handler above for the rationale). Same post-init guard. */
        if (OSSL_PARAM_get_int(p, &val) && val) {
            if (!qat_prov_config_lock()) {
                WARN("[QAT_PROV] ENABLE_HEURISTIC_POLLING: polling mode already "
                     "committed; ignoring change (restart to apply)\n");
            } else if (!enable_external_polling) {
                qat_pthread_mutex_unlock();
                WARN("ENABLE_HEURISTIC_POLLING: external polling must be "
                     "enabled first\n");
            } else {
                enable_heuristic_polling = 1;
                qat_pthread_mutex_unlock();
                DEBUG("qat_get_params: ENABLE_HEURISTIC_POLLING set "
                      "(heuristic=%d)\n", enable_heuristic_polling);
            }
        }
        if (!OSSL_PARAM_set_int(p, enable_heuristic_polling))
            return 0;
    }

    p = OSSL_PARAM_locate(params, QAT_PROV_PARAM_ENABLE_SW_FALLBACK);
    if (p != NULL) {
        /* An explicit 0 disables SW fallback; absent parameters change nothing. */
        if (OSSL_PARAM_get_int(p, &val)) {
#ifdef QAT_HW
            if (!qat_prov_config_lock()) {
                WARN("[QAT_PROV] ENABLE_SW_FALLBACK: already committed; "
                     "ignoring change (restart to apply)\n");
            } else {
                enable_sw_fallback = val ? 1 : 0;
                qat_pthread_mutex_unlock();
                DEBUG("qat_get_params: ENABLE_SW_FALLBACK=%d\n", val);
            }
#endif
        }
#ifdef QAT_HW
        if (!OSSL_PARAM_set_int(p, enable_sw_fallback))
            return 0;
#else
        if (!OSSL_PARAM_set_int(p, 0))
            return 0;
#endif
    }

    p = OSSL_PARAM_locate(params, QAT_PROV_PARAM_INTERNAL_POLL_INTERVAL);
    if (p != NULL) {
        /* Validate the nanosecond interval before updating the poll thread. */
#ifdef QAT_HW
        if (OSSL_PARAM_get_int(p, &val)) {
            if (!qat_prov_config_lock()) {
                WARN("[QAT_PROV] internal_poll_interval: already committed; "
                     "ignoring change (restart to apply)\n");
            } else if (val >= 1 && val <= 1000000) {
                qat_poll_interval = (useconds_t)val;
                qat_pthread_mutex_unlock();
                DEBUG("qat_get_params: internal_poll_interval=%d ns\n", val);
            } else {
                qat_pthread_mutex_unlock();
                WARN("[QAT_PROV] internal_poll_interval %d out of range "
                     "(1..1000000 ns); keeping %d\n",
                     val, (int)qat_poll_interval);
            }
        }
        if (!OSSL_PARAM_set_int(p, (int)qat_poll_interval))
            return 0;
#else
        if (!OSSL_PARAM_set_int(p, 0))
            return 0;
#endif
    }

    /* INIT_PROVIDER — trigger deferred hardware initialization after all
     * configuration params have been set by the application. */
    p = OSSL_PARAM_locate(params, QAT_PROV_PARAM_INIT_PROVIDER);
    if (p != NULL) {
        int init_result = 1;
        if (OSSL_PARAM_get_int(p, &val) && val) {
    #ifdef QAT_OPENSSL_PROVIDER
            /* The caller registering initialization also owns external polling. */
            qat_app_external_poller = 1;
#endif
            /* qat_engine_init() is idempotent: it takes the engine mutex and
             * returns early if already initialised, so no engine_inited
             * pre-check is needed here (the earlier unguarded read was racy
             * anyway). Call it unconditionally and report any failure. */
            if (!qat_engine_init(NULL)) {
                WARN("[QAT_PROV] INIT_PROVIDER: qat_engine_init FAILED\n");
                init_result = 0;
            } else {
                qat_prov_inited = 1;
            }
        }
        if (!OSSL_PARAM_set_int(p, init_result))
            return 0;
    }

    /* POLL — execute one polling cycle */
    p = OSSL_PARAM_locate(params, QAT_PROV_PARAM_POLL);
    if (p != NULL) {
        /* poll_status write-back contract with the application:
         *   1 = poll serviced (includes a benign CPA_STATUS_RETRY / no work)
         *   0 = hard polling failure; -1 = not ready */
        int poll_status = 1;
        /* Return -1 until external polling and the provider are ready. */
        if (!qat_prov_inited || !enable_external_polling) {
            DEBUG("[QAT_PROV] POLL not serviced: prov_inited=%d "
                  "external_polling=%d\n",
                  qat_prov_inited, enable_external_polling);
            if (!OSSL_PARAM_set_int(p, -1))
                return 0;
        } else {
#ifdef QAT_HW_PROV_SYNC_POLL
            if (qat_hw_offload && !fallback_to_qat_sw &&
                qat_instance_handles != NULL) {
                /* The application is driving external polling. */
                qat_app_external_poller = 1;
                CpaStatus poll_st = poll_instances();
                if (poll_st != CPA_STATUS_SUCCESS &&
                    poll_st != CPA_STATUS_RETRY) {
                    WARN("[QAT_PROV] POLL: poll_instances failed (status=%d)\n",
                         (int)poll_st);
                    poll_status = 0;
                }
            }
#endif
#ifdef QAT_SW
            if (poll_status && qat_sw_offload) {
                /* qat_sw_poll() returns 0 only on a hard failure (external
                 * polling disabled); 1 otherwise (serviced or nothing to do). */
                if (qat_sw_poll() == 0)
                    poll_status = 0;
            }
#endif
            if (!OSSL_PARAM_set_int(p, poll_status))
                return 0;
        }
    }

    /* HEARTBEAT_POLL — check device health */
    p = OSSL_PARAM_locate(params, QAT_PROV_PARAM_HEARTBEAT_POLL);
    if (p != NULL) {
        int hb_status = -1;
#ifdef QAT_HW
        if (qat_prov_inited && enable_external_polling &&
            qat_instance_handles != NULL)
            hb_status = (int)poll_heartbeat();
#endif
        if (!OSSL_PARAM_set_int(p, hb_status))
            return 0;
    }

    /* In-flight request counters — read by application for polling decisions */
    p = OSSL_PARAM_locate(params, QAT_PROV_PARAM_NUM_ASYM_REQUESTS_IN_FLIGHT);
    if (p != NULL && !OSSL_PARAM_set_int(p, num_asym_requests_in_flight))
        return 0;

    p = OSSL_PARAM_locate(params, QAT_PROV_PARAM_NUM_KDF_REQUESTS_IN_FLIGHT);
    if (p != NULL && !OSSL_PARAM_set_int(p, num_kdf_requests_in_flight))
        return 0;

    p = OSSL_PARAM_locate(params, QAT_PROV_PARAM_NUM_CIPHER_REQUESTS_IN_FLIGHT);
    if (p != NULL && !OSSL_PARAM_set_int(p, num_cipher_pipeline_requests_in_flight))
        return 0;

    p = OSSL_PARAM_locate(params, QAT_PROV_PARAM_NUM_ASYM_MB_ITEMS_IN_QUEUE);
    if (p != NULL && !OSSL_PARAM_set_int(p, num_asym_mb_items_in_queue))
        return 0;

    p = OSSL_PARAM_locate(params, QAT_PROV_PARAM_NUM_KDF_MB_ITEMS_IN_QUEUE);
    if (p != NULL && !OSSL_PARAM_set_int(p, num_kdf_mb_items_in_queue))
        return 0;

    p = OSSL_PARAM_locate(params, QAT_PROV_PARAM_NUM_SYM_MB_ITEMS_IN_QUEUE);
    if (p != NULL && !OSSL_PARAM_set_int(p, num_cipher_mb_items_in_queue))
        return 0;

    /* Small packet threshold — string param "algo:size,algo2:size2" */
    p = OSSL_PARAM_locate(params, QAT_PROV_PARAM_SMALL_PKT_OFFLOAD_THRESHOLD);
    if (p != NULL) {
#ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
        char threshold_str[QAT_MAX_INPUT_STRING_LENGTH];
        char *buf = threshold_str;
        /* The caller-provided buffer length lives in p->data_size; probing it
         * with OSSL_PARAM_get_utf8_string(p, NULL, 0) always returns 0 because
         * the API rejects a NULL value pointer, so read the string directly. */
        if (p->data != NULL && p->data_size > 0
            && OSSL_PARAM_get_utf8_string(p, &buf,
                                          QAT_MAX_INPUT_STRING_LENGTH)) {
            char *itr = threshold_str;
            char *token;
            while ((token = strsep(&itr, ","))) {
                char *name_token = strsep(&token, ":");
                char *value_token = strsep(&token, ":");
                char *endp = NULL;
                long  thr;

                if (name_token == NULL || value_token == NULL
                    || value_token[0] == '\0') {
                    WARN("[QAT_PROV] small_pkt_offload_threshold: malformed "
                         "token near '%s'; skipping\n",
                         name_token ? name_token : "?");
                    continue;
                }
                thr = strtol(value_token, &endp, 10);
                if (*endp != '\0' || thr < 0) {
                    WARN("[QAT_PROV] small_pkt_offload_threshold: invalid "
                         "numeric value '%s' for '%s'; skipping\n",
                         value_token, name_token);
                    continue;
                }
                if (!qat_pkt_threshold_table_set_threshold(name_token,
                                                           (int) thr)) {
                    WARN("[QAT_PROV] small_pkt_offload_threshold: unknown "
                         "algorithm '%s'; skipping\n", name_token);
                }
            }
        }
#endif
        /* Input-only: the caller owns this buffer, so do not write it back. */
    }

    /* Store positive heuristic thresholds and return the current values.
     * A zero input requests read-back without replacing configured values. */
    p = OSSL_PARAM_locate(params, QAT_PROV_PARAM_HW_ASYM_THRESHOLD);
    if (p != NULL) {
        if (OSSL_PARAM_get_int(p, &val) && val >= 1)
            qat_prov_hw_asym_threshold = val;
        if (!OSSL_PARAM_set_int(p, qat_prov_hw_asym_threshold))
            return 0;
    }

    p = OSSL_PARAM_locate(params, QAT_PROV_PARAM_HW_SYM_THRESHOLD);
    if (p != NULL) {
        if (OSSL_PARAM_get_int(p, &val) && val >= 1)
            qat_prov_hw_sym_threshold = val;
        if (!OSSL_PARAM_set_int(p, qat_prov_hw_sym_threshold))
            return 0;
    }

    p = OSSL_PARAM_locate(params, QAT_PROV_PARAM_SW_THRESHOLD);
    if (p != NULL) {
        if (OSSL_PARAM_get_int(p, &val) && val >= 1)
            qat_prov_sw_threshold = val;
        if (!OSSL_PARAM_set_int(p, qat_prov_sw_threshold))
            return 0;
    }

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
    ALG(QAT_NAMES_AES_128_CBC_HMAC_SHA256, qat_aes128cbc_hmac_sha256_functions),
# endif
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

static OSSL_ALGORITHM qat_keyexch[] = {
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

static OSSL_ALGORITHM qat_keymgmt[] = {
#if defined(ENABLE_QAT_HW_RSA) || defined(ENABLE_QAT_SW_RSA)
    {"RSA", QAT_DEFAULT_PROPERTIES, qat_rsa_keymgmt_functions, "QAT RSA Keymgmt implementation."},
    {"RSA-PSS", QAT_DEFAULT_PROPERTIES, qat_rsapss_keymgmt_functions, "QAT RSA-PSS Keymgmt implementation."},
#endif
#if defined(ENABLE_QAT_HW_ECX) || defined(ENABLE_QAT_SW_ECX)
    {"X25519", QAT_DEFAULT_PROPERTIES, qat_X25519_keymgmt_functions, "QAT X25519 Keymgmt implementation."},
#endif
#if defined(ENABLE_QAT_HW_ECDH) || defined(ENABLE_QAT_SW_ECDH) || defined(ENABLE_QAT_HW_ECDSA) || defined(ENABLE_QAT_SW_ECDSA)
    {"EC", QAT_DEFAULT_PROPERTIES, qat_ec_keymgmt_functions, "QAT EC Keymgmt implementation."},
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
#ifdef ENABLE_QAT_SW_ML_KEM
    {"ML-KEM-512", QAT_DEFAULT_PROPERTIES, qat_ml_kem_512_keymgmt_functions, "QAT ML-KEM-512 Keymgmt implementation."},
    {"ML-KEM-768", QAT_DEFAULT_PROPERTIES, qat_ml_kem_768_keymgmt_functions, "QAT ML-KEM-768 Keymgmt implementation."},
    {"ML-KEM-1024", QAT_DEFAULT_PROPERTIES, qat_ml_kem_1024_keymgmt_functions, "QAT ML-KEM-1024 Keymgmt implementation."},
#endif
#ifdef ENABLE_QAT_SW_ML_DSA
    {"ML-DSA-44", QAT_DEFAULT_PROPERTIES, qat_ml_dsa_44_keymgmt_functions, "QAT ML-DSA-44 Keymgmt implementation."},
    {"ML-DSA-65", QAT_DEFAULT_PROPERTIES, qat_ml_dsa_65_keymgmt_functions, "QAT ML-DSA-65 Keymgmt implementation."},
    {"ML-DSA-87", QAT_DEFAULT_PROPERTIES, qat_ml_dsa_87_keymgmt_functions, "QAT ML-DSA-87 Keymgmt implementation."},
#endif
    {NULL, NULL, NULL}};

static OSSL_ALGORITHM qat_signature[] = {
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
#ifdef ENABLE_QAT_SW_ML_DSA
    {"ML-DSA-44", QAT_DEFAULT_PROPERTIES, qat_ml_dsa_signature_functions, "QAT ML-DSA-44 Signature implementation."},
    {"ML-DSA-65", QAT_DEFAULT_PROPERTIES, qat_ml_dsa_signature_functions, "QAT ML-DSA-65 Signature implementation."},
    {"ML-DSA-87", QAT_DEFAULT_PROPERTIES, qat_ml_dsa_signature_functions, "QAT ML-DSA-87 Signature implementation."},
#endif
    {NULL, NULL, NULL}};

#ifdef ENABLE_QAT_SW_ML_KEM
static OSSL_ALGORITHM qat_kem[] = {
    {"ML-KEM-512", QAT_DEFAULT_PROPERTIES, qat_ml_kem_functions, "QAT ML-KEM-512 KEM implementation."},
    {"ML-KEM-768", QAT_DEFAULT_PROPERTIES, qat_ml_kem_functions, "QAT ML-KEM-768 KEM implementation."},
    {"ML-KEM-1024", QAT_DEFAULT_PROPERTIES, qat_ml_kem_functions, "QAT ML-KEM-1024 KEM implementation."},
    {NULL, NULL, NULL}};
#endif

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
static OSSL_ALGORITHM qat_digests[] = {
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

#if defined(ENABLE_QAT_HW_RSA) || defined(ENABLE_QAT_SW_RSA)
static OSSL_ALGORITHM qat_asym_cipher[] = {
    { "RSA", QAT_DEFAULT_PROPERTIES, qat_rsa_asym_cipher_functions },
    { NULL, NULL, NULL }
};
#endif
/******************************************************************************
* function:
*         qat_disable_algorithm(OSSL_ALGORITHM *dispatch_table,
*                               const char *qat_algo_name)
*
* @param dispatch_table  [IN]  - Pointer to the algorithm dispatch table.
* @param qat_algo_name   [IN]  - Name of the algorithm to disable (e.g.,"RSA").
*
* description:
*   Searches the given dispatch table for an entry matching the specified
*   algorithm name. If found, the function logs a warning and clears the
*   corresponding OSSL_ALGORITHM entry by setting all fields to NULL.
*
*   This prevents the algorithm from being registered with the OpenSSL core,
*   allowing fallback to software default provider.
*
******************************************************************************/
void qat_disable_algorithm(OSSL_ALGORITHM *dispatch_table, const char *qat_algo_name)
{
    if (dispatch_table == NULL || qat_algo_name == NULL) {
        WARN("Invalid parameters: dispatch_table or qat_algo_name is NULL.\n");
        return;
    }
    for (int i = 0; ; i++) {
        /* Check for end of table - last entry has all fields NULL */
        if (dispatch_table[i].algorithm_names == NULL &&
            dispatch_table[i].property_definition == NULL &&
            dispatch_table[i].implementation == NULL) {
            DEBUG("qat_disable_algorithm: Reached end of table \
		     at index %d for '%s'\n", i, qat_algo_name);
            break;
        }
        /* Skip already disabled entries (algorithm_names starts with underscore) */
        if (dispatch_table[i].algorithm_names != NULL &&
            dispatch_table[i].algorithm_names[0] == '_') {
            DEBUG("qat_disable_algorithm: Skipping already disabled entry at \
		     index %d for '%s'\n", i, qat_algo_name);
            continue;
        }
        if (dispatch_table[i].algorithm_names == NULL) {
            WARN("Table corruption detected at index %d - algorithm_names is \
                    NULL but entry not end-of-table\n", i);
            continue;
        }
        DEBUG("qat_disable_algorithm: Checking index %d: '%s' vs '%s'\n",
                 i, dispatch_table[i].algorithm_names, qat_algo_name);
        if (strcmp(dispatch_table[i].algorithm_names, qat_algo_name) == 0) {
            WARN("%s support not available — Fetching %s implementation from SW!!\n",
                    qat_algo_name, qat_algo_name);
            /* Set a dummy algorithm name that will never match
             * We use a name starting with underscore which is invalid for algorithm names.
             * This allows OpenSSL to properly iterate through the table without getting
             * confused by NULL entries in the middle of the table. */
            dispatch_table[i].algorithm_names = "_DISABLED_";
            DEBUG("qat_disable_algorithm: Successfully disabled '%s' at index %d\n",
		     qat_algo_name, i);
            break;
        }
    }
}

/*
 * Wrapper to disable a signature algorithm using the qat_signature dispatch table.
 */
void qat_disable_signature(const char *qat_algo_name)
{
    qat_disable_algorithm(qat_signature, qat_algo_name);
}

/*
 * Wrapper to disable a key exchange algorithm using the qat_keyexch dispatch table.
 */
void qat_disable_keyexch(const char *qat_algo_name)
{
    qat_disable_algorithm(qat_keyexch, qat_algo_name);
}

/*
 * Wrapper to disable a digest algorithm using the qat_digests dispatch table.
 */
void qat_disable_digest(const char *qat_algo_name)
{
#if defined(ENABLE_QAT_HW_SM3) || defined(ENABLE_QAT_SW_SM3)
    qat_disable_algorithm(qat_digests, qat_algo_name);
#endif
}

/*
 * Wrapper to disable a keymgmt algorithm using the qat_keymgmt dispatch table.
 */
void qat_disable_keymgmt(const char *qat_algo_name)
{
    qat_disable_algorithm((OSSL_ALGORITHM *)qat_keymgmt, qat_algo_name);
}

#ifdef ENABLE_QAT_SW_ML_KEM
/*
 * Wrapper to disable a KEM algorithm using the qat_kem dispatch table.
 */
void qat_disable_kem(const char *qat_algo_name)
{
    qat_disable_algorithm((OSSL_ALGORITHM *)qat_kem, qat_algo_name);
}
#endif

/*
 * Wrapper to disable an asymmetric cipher algorithm using the qat_asym_cipher dispatch table.
 */
void qat_disable_asym_cipher(const char *qat_algo_name)
{
#if defined(ENABLE_QAT_HW_RSA) || defined(ENABLE_QAT_SW_RSA)
    qat_disable_algorithm((OSSL_ALGORITHM *)qat_asym_cipher, qat_algo_name);
#endif
}

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
    case OSSL_OP_KEM:
        return 1;
    default:
        return 0;							     }
}
#endif

static const OSSL_ALGORITHM *qat_query(void *provctx, int operation_id, int *no_cache)
{
    static int prov_init = 0;

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
        if (qat_hw_offload || qat_sw_offload)
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
#ifdef ENABLE_QAT_SW_ML_KEM
        case OSSL_OP_KEM:
            return qat_kem;
#endif
#if defined(ENABLE_QAT_HW_RSA) || defined(ENABLE_QAT_SW_RSA)
        case OSSL_OP_ASYM_CIPHER:
            return qat_asym_cipher;
#endif
        default:
            return NULL;
	}
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

/* Latch invalid openssl.cnf state across by-name reload and fork. */
static int qat_prov_cfg_invalid = 0;

int qat_get_params_from_core(const OSSL_CORE_HANDLE *handle)
{    OSSL_PARAM core_params[24], *p = core_params;
    int        have_cnf = 0;
    /* Track whether openssl.cnf selected a polling mode, independently of
     * unrelated provider configuration. */
    int        have_poll_cnf = 0;

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

    /* Named provider configuration options. */
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        "qat_offload_mode",
        (char **)&qat_params.qat_offload_mode,
        0);

    *p++ = OSSL_PARAM_construct_utf8_ptr(
        "qat_poll_mode",
        (char **)&qat_params.qat_poll_mode,
        0);

    *p++ = OSSL_PARAM_construct_utf8_ptr(
        "qat_sw_fallback",
        (char **)&qat_params.qat_sw_fallback_mode,
        0);

    /* Small-packet threshold straight from the provider section of openssl.cnf,
     * so a single openssl.cnf is self-sufficient (previously settable only via
     * an application's OSSL_PROVIDER_get_params push). */
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        "qat_small_pkt_offload_threshold",
        (char **)&qat_params.qat_small_pkt_offload_threshold,
        0);

    /* Heuristic-poll thresholds from the provider section of openssl.cnf. */
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        "qat_hw_asym_threshold",
        (char **)&qat_params.qat_hw_asym_threshold,
        0);

    *p++ = OSSL_PARAM_construct_utf8_ptr(
        "qat_hw_sym_threshold",
        (char **)&qat_params.qat_hw_sym_threshold,
        0);

    *p++ = OSSL_PARAM_construct_utf8_ptr(
        "qat_sw_threshold",
        (char **)&qat_params.qat_sw_threshold,
        0);

    *p = OSSL_PARAM_construct_end();

    if (!c_get_params(handle, core_params)) {
        WARN("QAT get parameters from core is failed.\n");
        return 0;
    }

    /* Named options map to the same globals as the raw enable_* keys.
     * qat_poll_mode is authoritative and selects one polling mode. */
    if (qat_params.qat_poll_mode != NULL) {
        have_cnf = 1;
        have_poll_cnf = 1;
        /* Reset the mutually-exclusive set, then select exactly one. */
        enable_external_polling = 0;
        enable_heuristic_polling = 0;
        if (strcmp(qat_params.qat_poll_mode, "external") == 0) {
            enable_external_polling = 1;
        } else if (strcmp(qat_params.qat_poll_mode, "heuristic") == 0) {
            enable_external_polling = 1;
            enable_heuristic_polling = 1;
        } else if (strcmp(qat_params.qat_poll_mode, "internal") != 0) {
            /* Rejected outright: silently using internal would hide a typo and
             * run a different mode than openssl.cnf asked for. */
            INFO("[QAT_PROV] invalid qat_poll_mode '%s' in the provider section "
                 "of openssl.cnf - valid values are 'internal', 'external' or "
                 "'heuristic'. Refusing to load the QAT provider.\n",
                 qat_params.qat_poll_mode);
            WARN("[QAT_PROV] invalid qat_poll_mode '%s'\n",
                 qat_params.qat_poll_mode);
            qat_prov_cfg_invalid = 1;
            return 0;
        }
        /* "internal" leaves external/heuristic at 0 (default). */
    }

    /* Warn when offload and polling modes conflict; keep polling unchanged. */
    if (qat_params.qat_offload_mode != NULL) {
        have_cnf = 1;
        int is_sync = strcmp(qat_params.qat_offload_mode, "sync") == 0;
        int is_ext_heur;

        if (qat_params.qat_poll_mode != NULL) {
            /* Derive the effective mode from authoritative qat_poll_mode. */
            is_ext_heur =
                strcmp(qat_params.qat_poll_mode, "external") == 0
                || strcmp(qat_params.qat_poll_mode, "heuristic") == 0;
        } else {
            /* Without qat_poll_mode, derive the mode from raw enable_* keys. */
            is_ext_heur =
                (qat_params.enable_external_polling != NULL
                 && atoi(qat_params.enable_external_polling) != 0)
                || (qat_params.enable_heuristic_polling != NULL
                    && atoi(qat_params.enable_heuristic_polling) != 0);
        }

        if (is_ext_heur && is_sync)
            WARN("[QAT_PROV] qat_offload_mode sync is invalid with external/"
                 "heuristic polling; treating offload mode as async\n");
    }

    if (qat_params.qat_sw_fallback_mode != NULL) {
        have_cnf = 1;
#ifdef QAT_HW
        /* Accept textual on/off and numeric 1/0 values. */
        if (strcmp(qat_params.qat_sw_fallback_mode, "on") == 0
            || strcmp(qat_params.qat_sw_fallback_mode, "1") == 0)
            enable_sw_fallback = 1;
        else if (strcmp(qat_params.qat_sw_fallback_mode, "off") == 0
                 || strcmp(qat_params.qat_sw_fallback_mode, "0") == 0)
            enable_sw_fallback = 0;
#endif
    }

    if (qat_params.qat_poll_interval != NULL) {
        have_cnf = 1;
#ifdef QAT_HW
        {
            /* Nanosecond value (tv_nsec); validate against the same range as
             * the get_params handler and the engine's SET_INTERNAL_POLL_INTERVAL
             * instead of assigning a bare atoi() unchecked. */
            int iv = atoi(qat_params.qat_poll_interval);
            if (iv >= 1 && iv <= 1000000)
                qat_poll_interval = (useconds_t)iv;
            else
                WARN("[QAT_PROV] qat_poll_interval %d out of range "
                     "(1..1000000 ns); keeping %d\n",
                     iv, (int)qat_poll_interval);
        }
#endif
    }

    /* Raw enable_* keys apply only when the authoritative mode is absent. */
    if (qat_params.enable_external_polling != NULL) {
        have_cnf = 1;
        have_poll_cnf = 1;
        if (qat_params.qat_poll_mode != NULL)
            WARN("[QAT_PROV] enable_external_polling ignored: qat_poll_mode "
                 "is authoritative\n");
        else
            enable_external_polling = atoi(qat_params.enable_external_polling);
    }

    if (qat_params.enable_heuristic_polling != NULL) {
        have_cnf = 1;
        have_poll_cnf = 1;
        if (qat_params.qat_poll_mode != NULL)
            WARN("[QAT_PROV] enable_heuristic_polling ignored: qat_poll_mode "
                 "is authoritative\n");
        else
            enable_heuristic_polling = atoi(qat_params.enable_heuristic_polling);
    }

#ifdef QAT_HW
    if (qat_params.enable_sw_fallback != NULL) {
        have_cnf = 1;
        enable_sw_fallback = atoi(qat_params.enable_sw_fallback);
    }

    if (qat_params.qat_epoll_timeout != NULL) {
        have_cnf = 1;
        qat_epoll_timeout = atoi(qat_params.qat_epoll_timeout);
    }

    if (qat_params.enable_event_driven_polling != NULL) {
        have_cnf = 1;
        enable_event_driven_polling =
            atoi(qat_params.enable_event_driven_polling);
    }

    if (qat_params.enable_instance_for_thread != NULL) {
        have_cnf = 1;
        enable_instance_for_thread =
            atoi(qat_params.enable_instance_for_thread);
    }

    if (qat_params.qat_max_retry_count != NULL) {
        have_cnf = 1;
        qat_max_retry_count = atoi(qat_params.qat_max_retry_count);
    }
#endif

    /* Relay heuristic thresholds without treating them as a polling mode.
     * The consuming application validates values read from the provider. */
    if (qat_params.qat_hw_asym_threshold != NULL) {
        have_cnf = 1;
        qat_prov_hw_asym_threshold = atoi(qat_params.qat_hw_asym_threshold);
    }

    if (qat_params.qat_hw_sym_threshold != NULL) {
        have_cnf = 1;
        qat_prov_hw_sym_threshold = atoi(qat_params.qat_hw_sym_threshold);
    }

    if (qat_params.qat_sw_threshold != NULL) {
        have_cnf = 1;
        qat_prov_sw_threshold = atoi(qat_params.qat_sw_threshold);
    }

    /* Small-packet offload threshold ("algo:size,algo2:size2"). Parsed from a
     * private copy because strsep() mutates its buffer and the core-owned
     * string must not be altered. */
    if (qat_params.qat_small_pkt_offload_threshold != NULL
        && qat_params.qat_small_pkt_offload_threshold[0] != '\0') {
        have_cnf = 1;
#ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
        char  tbuf[QAT_MAX_INPUT_STRING_LENGTH];
        char *itr = tbuf;
        char *token;

        strncpy(tbuf, qat_params.qat_small_pkt_offload_threshold,
                sizeof(tbuf) - 1);
        tbuf[sizeof(tbuf) - 1] = '\0';
        while ((token = strsep(&itr, ","))) {
            char *name_token = strsep(&token, ":");
            char *value_token = strsep(&token, ":");
            char *endp = NULL;
            long  thr;

            if (name_token == NULL || value_token == NULL
                || value_token[0] == '\0') {
                WARN("[QAT_PROV] qat_small_pkt_offload_threshold: malformed "
                     "token near '%s' in openssl.cnf; skipping\n",
                     name_token ? name_token : "?");
                continue;
            }
            thr = strtol(value_token, &endp, 10);
            if (*endp != '\0' || thr < 0) {
                WARN("[QAT_PROV] qat_small_pkt_offload_threshold: invalid "
                     "numeric value '%s' for '%s' in openssl.cnf; "
                     "skipping\n", value_token, name_token);
                continue;
            }
            if (!qat_pkt_threshold_table_set_threshold(name_token,
                                                       (int) thr)) {
                WARN("[QAT_PROV] qat_small_pkt_offload_threshold: unknown "
                     "algorithm '%s' in openssl.cnf; skipping\n", name_token);
            }
        }
#endif
    }

    if (!have_poll_cnf && have_cnf) {
        /* A configured provider with no mode uses internal polling. */
        enable_external_polling = 0;
        enable_heuristic_polling = 0;
        have_poll_cnf = 1;
    }

    /* Non-polling configuration must not claim ownership of polling mode. */
    qat_prov_configured_from_cnf = have_poll_cnf;

    if (!have_cnf) {
        DEBUG("[QAT_PROV] No provider config file parameters — polling mode "
              "will be set by application via OSSL_PROVIDER_get_params\n");
        return 1;
    }

    DEBUG("[QAT_PROV] Config file: external_poll=%d, heuristic_poll=%d "
          "(configured_from_cnf=%d)\n",
          enable_external_polling, enable_heuristic_polling,
          qat_prov_configured_from_cnf);

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

    /* Keep rejected configuration latched for the process lifetime.
     * Corrected openssl.cnf settings require a full application restart. */
    if (qat_prov_cfg_invalid) {
        INFO("[QAT_PROV] refusing to load the QAT provider: invalid QAT "
             "configuration in openssl.cnf (see the earlier error). A full "
               "application restart is required after fixing openssl.cnf.\n");
        return 0;
    }

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

    /* Only bind algorithm tables here. Hardware bring-up (qat_engine_init) is
     * owned by qatprovider, not the application:
     *   - When the provider section of openssl.cnf selects a polling mode,
     *     qat_get_params_from_core() above has already applied it, so HW is
     *     initialised right after bind_qat() below.
     *   - Otherwise init is deferred until the polling mode is supplied through
     *     standard provider parameters (OSSL_PROVIDER_get_params) and triggered
     *     by the qat_init_provider parameter, or lazily on the first crypto
     *     operation (internal-polling fallback).
     * Across fork(), the pthread_atfork handlers registered in bind_qat()
     * finish with retained globals in the parent and re-initialise QAT in the
     * child automatically. */
    DEBUG("[QAT_PROV] OSSL_provider_init: binding algorithms; HW init owned "
          "by qatprovider\n");
    if (!bind_qat(NULL, NULL)) {
        goto err;
    }

    /* Provider-owned init for the openssl.cnf-configured path: the polling mode
     * is already known, so bring QAT up now instead of waiting for the
     * application. The fork handlers keep child workers initialised. */
    if (qat_prov_configured_from_cnf && !qat_prov_inited) {
        DEBUG("[QAT_PROV] OSSL_provider_init: configured from openssl.cnf, "
              "initialising QAT now\n");
        if (!qat_engine_init(NULL))
            WARN("[QAT_PROV] OSSL_provider_init: qat_engine_init failed; will "
                 "retry lazily on first crypto operation\n");
        else
            qat_prov_inited = 1;
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
    WARN("QAT provider init failed\n");
    qat_teardown(qat_ctx);
    return 0;
}
