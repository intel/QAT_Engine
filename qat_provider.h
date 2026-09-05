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
 * @file qat_provider.h
 *
 * This file provides an interface to qat provider init
 *
 *****************************************************************************/

#ifndef QAT_PROVIDER_H
# define QAT_PROVIDER_H

# include <openssl/core.h>
# include <openssl/provider.h>
# include <openssl/bio.h>
# include <openssl/core_dispatch.h>

# define QAT_PROVIDER_VERSION_STR "v2.2.0"
# define QAT_PROVIDER_FULL_VERSION_STR "QAT Provider v2.2.0"

# if defined(QAT_HW) && defined(QAT_SW)
#  define QAT_PROVIDER_NAME_STR "QAT Provider for QAT_HW and QAT_SW"
# elif QAT_HW
#  define QAT_PROVIDER_NAME_STR "QAT Provider for QAT_HW"
# else
#  define QAT_PROVIDER_NAME_STR "QAT Provider for QAT_SW"
# endif

/* Provider parameter names for the OSSL_PROVIDER_get_params() wire contract.
 * The caller supplies values and the provider returns status or counters. */
# define QAT_PROV_PARAM_ENABLE_EXTERNAL_POLLING      "qat_enable_external_polling"
# define QAT_PROV_PARAM_ENABLE_HEURISTIC_POLLING     "qat_enable_heuristic_polling"
# define QAT_PROV_PARAM_ENABLE_SW_FALLBACK           "qat_enable_sw_fallback"
# define QAT_PROV_PARAM_INTERNAL_POLL_INTERVAL       "qat_internal_poll_interval"
# define QAT_PROV_PARAM_INIT_PROVIDER                "qat_init_provider"
# define QAT_PROV_PARAM_POLL                         "qat_poll"
# define QAT_PROV_PARAM_HEARTBEAT_POLL               "qat_heartbeat_poll"
# define QAT_PROV_PARAM_NUM_ASYM_REQUESTS_IN_FLIGHT  "qat_num_asym_requests_in_flight"
# define QAT_PROV_PARAM_NUM_KDF_REQUESTS_IN_FLIGHT   "qat_num_kdf_requests_in_flight"
# define QAT_PROV_PARAM_NUM_CIPHER_REQUESTS_IN_FLIGHT "qat_num_cipher_requests_in_flight"
# define QAT_PROV_PARAM_NUM_ASYM_MB_ITEMS_IN_QUEUE   "qat_num_asym_mb_items_in_queue"
# define QAT_PROV_PARAM_NUM_KDF_MB_ITEMS_IN_QUEUE    "qat_num_kdf_mb_items_in_queue"
# define QAT_PROV_PARAM_NUM_SYM_MB_ITEMS_IN_QUEUE    "qat_num_sym_mb_items_in_queue"
# define QAT_PROV_PARAM_SMALL_PKT_OFFLOAD_THRESHOLD  "qat_small_pkt_offload_threshold"
/* Read-only sentinel: 1 if the provider was configured from openssl.cnf. */
# define QAT_PROV_PARAM_CONFIGURED_FROM_CNF          "qat_configured_from_cnf"
/* Heuristic-poll thresholds stored for application read-back. Range 1..512. */
# define QAT_PROV_PARAM_HW_ASYM_THRESHOLD            "qat_hw_asym_threshold"
# define QAT_PROV_PARAM_HW_SYM_THRESHOLD             "qat_hw_sym_threshold"
/* Single QAT_SW multibuff threshold: governs BOTH the SW asym and SW sym
 * queues (there is no separate SW-sym knob), hence the neutral name. */
# define QAT_PROV_PARAM_SW_THRESHOLD                 "qat_sw_threshold"

# define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))
# define QAT_NAMES_AES_128_GCM "AES-128-GCM"
# define QAT_NAMES_AES_192_GCM "AES-192-GCM"
# define QAT_NAMES_AES_256_GCM "AES-256-GCM"
# define QAT_NAMES_AES_128_CCM "AES-128-CCM"
# define QAT_NAMES_AES_192_CCM "AES-192-CCM"
# define QAT_NAMES_AES_256_CCM "AES-256-CCM"
# define QAT_NAMES_AES_128_CBC_HMAC_SHA1 "AES-128-CBC-HMAC-SHA1"
# define QAT_NAMES_AES_256_CBC_HMAC_SHA1 "AES-256-CBC-HMAC-SHA1"
# define QAT_NAMES_AES_128_CBC_HMAC_SHA256 "AES-128-CBC-HMAC-SHA256"
# define QAT_NAMES_AES_256_CBC_HMAC_SHA256 "AES-256-CBC-HMAC-SHA256"
# define QAT_NAMES_CHACHA20_POLY1305 "ChaCha20-Poly1305"
# define QAT_NAMES_SM4_CCM "SM4-CCM:1.2.156.10197.1.104.9"
# define QAT_NAMES_SM4_GCM "SM4-GCM:1.2.156.10197.1.104.8"
# define QAT_NAMES_SM4_CBC "SM4-CBC:SM4:1.2.156.10197.1.104.2"

# define QAT_NAMES_SHA2_224 "SHA2-224:SHA-224:SHA224:2.16.840.1.101.3.4.2.4"
# define QAT_NAMES_SHA2_256 "SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1"
# define QAT_NAMES_SHA2_384 "SHA2-384:SHA-384:SHA384:2.16.840.1.101.3.4.2.2"
# define QAT_NAMES_SHA2_512 "SHA2-512:SHA-512:SHA512:2.16.840.1.101.3.4.2.3"

# define QAT_NAMES_SHA3_224 "SHA3-224:2.16.840.1.101.3.4.2.7"
# define QAT_NAMES_SHA3_256 "SHA3-256:2.16.840.1.101.3.4.2.8"
# define QAT_NAMES_SHA3_384 "SHA3-384:2.16.840.1.101.3.4.2.9"
# define QAT_NAMES_SHA3_512 "SHA3-512:2.16.840.1.101.3.4.2.10"
# define QAT_NAMES_SM3 "SM3:1.2.156.10197.1.401"
# define ALGC(NAMES, FUNC, CHECK) { { NAMES, QAT_DEFAULT_PROPERTIES, FUNC }, CHECK }
# define ALG(NAMES, FUNC) ALGC(NAMES, FUNC, NULL)

static const char QAT_DEFAULT_PROPERTIES[] = "provider=qatprovider";

OSSL_FUNC_provider_get_capabilities_fn qat_prov_get_capabilities;

typedef struct bio_method_st {
    int type;
    char *name;
    int (*bwrite) (BIO *, const char *, size_t, size_t *);
    int (*bwrite_old) (BIO *, const char *, int);
    int (*bread) (BIO *, char *, size_t, size_t *);
    int (*bread_old) (BIO *, char *, int);
    int (*bputs) (BIO *, const char *);
    int (*bgets) (BIO *, char *, int);
    long (*ctrl) (BIO *, int, long, void *);
    int (*create) (BIO *);
    int (*destroy) (BIO *);
    long (*callback_ctrl) (BIO *, int, BIO_info_cb *);
} QAT_BIO_METHOD;

typedef struct qat_provider_ctx_st {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;
    QAT_BIO_METHOD *corebiometh;
} QAT_PROV_CTX;

typedef struct qat_provider_params_st {
    char *enable_external_polling;
    char *enable_heuristic_polling;
    char *enable_sw_fallback;
    char *qat_poll_interval;
    char *qat_epoll_timeout;
    char *enable_event_driven_polling;
    char *enable_instance_for_thread;
    char *qat_max_retry_count;
    /* Named polling options accepted from the provider configuration. */
    char *qat_offload_mode;
    char *qat_poll_mode;
    char *qat_sw_fallback_mode;
    /* Small-packet threshold, so a single openssl.cnf can be the sole source of
     * truth (read from the provider section by the core path, not only pushed
     * later by an application via OSSL_PROVIDER_get_params). */
    char *qat_small_pkt_offload_threshold;
    /* Heuristic-poll thresholds exposed to the consuming application. */
    char *qat_hw_asym_threshold;
    char *qat_hw_sym_threshold;
    char *qat_sw_threshold;
} QAT_PROV_PARAMS;

typedef struct qat_ag_capable_st {
    OSSL_ALGORITHM alg;
    int (*capable)(void);
} OSSL_ALGORITHM_CAPABLE;
void qat_prov_cache_exported_algorithms(const OSSL_ALGORITHM_CAPABLE *in,
                                         OSSL_ALGORITHM *out);
int qat_prov_is_running(void);
OSSL_LIB_CTX *prov_libctx_of(QAT_PROV_CTX *ctx);

int qat_securitycheck_enabled(OSSL_LIB_CTX *libctx);

#endif /* QAT_PROVIDER_H */
