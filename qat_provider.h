/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022-2023 Intel Corporation.
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

# define QAT_PROVIDER_VERSION_STR "v0.6.18"
# define QAT_PROVIDER_FULL_VERSION_STR "QAT Provider v0.6.18"

# if defined(QAT_HW) && defined(QAT_SW)
#  define QAT_PROVIDER_NAME_STR "QAT Provider for QAT_HW and QAT_SW"
# elif QAT_HW
#  define QAT_PROVIDER_NAME_STR "QAT Provider for QAT_HW"
# else
#  define QAT_PROVIDER_NAME_STR "QAT Provider for QAT_SW"
# endif

# define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))
# define QAT_NAMES_AES_128_GCM "AES-128-GCM"
# define QAT_NAMES_AES_192_GCM "AES-192-GCM"
# define QAT_NAMES_AES_256_GCM "AES-256-GCM"
# define QAT_NAMES_AES_128_CBC_HMAC_SHA1 "AES-128-CBC-HMAC-SHA1"
# define QAT_NAMES_AES_256_CBC_HMAC_SHA1 "AES-256-CBC-HMAC-SHA1"
# define QAT_NAMES_AES_128_CBC_HMAC_SHA256 "AES-128-CBC-HMAC-SHA256"
# define QAT_NAMES_AES_256_CBC_HMAC_SHA256 "AES-256-CBC-HMAC-SHA256"
# define QAT_NAMES_CHACHA20_POLY1305 "ChaCha20-Poly1305"
# define QAT_NAMES_SHA3_224 "SHA3-224:2.16.840.1.101.3.4.2.7"
# define QAT_NAMES_SHA3_256 "SHA3-256:2.16.840.1.101.3.4.2.8"
# define QAT_NAMES_SHA3_384 "SHA3-384:2.16.840.1.101.3.4.2.9"
# define QAT_NAMES_SHA3_512 "SHA3-512:2.16.840.1.101.3.4.2.10"
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
    char *enable_inline_polling;
    char *qat_poll_interval;
    char *qat_epoll_timeout;
    char *enable_event_driven_polling;
    char *enable_instance_for_thread;
    char *qat_max_retry_count;
} QAT_PROV_PARAMS;

typedef struct qat_ag_capable_st {
    OSSL_ALGORITHM alg;
    int (*capable)(void);
} OSSL_ALGORITHM_CAPABLE;
void qat_prov_cache_exported_algorithms(const OSSL_ALGORITHM_CAPABLE *in,
                                         OSSL_ALGORITHM *out);
int qat_prov_is_running(void);
OSSL_LIB_CTX *prov_libctx_of(QAT_PROV_CTX *ctx);

#endif /* QAT_PROVIDER_H */
