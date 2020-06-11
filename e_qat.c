/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2020 Intel Corporation.
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
 * @file e_qat.c
 *
 * This file provides a OpenSSL engine for the  quick assist API
 *
 *****************************************************************************/

/* macros defined to allow use of the cpu get and set affinity functions */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#ifndef __USE_GNU
# define __USE_GNU
#endif

/* Defines */
#ifndef OPENSSL_MULTIBUFF_OFFLOAD
# if defined(USE_QAT_CONTIG_MEM) && !defined(USE_QAE_MEM)
#  define QAT_DEV "/dev/qat_contig_mem"
# elif defined(USE_QAE_MEM) && !defined(USE_QAT_CONTIG_MEM)
#  define QAT_DEV "/dev/usdm_drv"
# elif defined(USE_QAE_MEM) && defined(USE_QAT_CONFIG_MEM)
#  error "USE_QAT_CONTIG_MEM and USE_QAE_MEM both defined"
# else
#  error "No memory driver type defined"
# endif
#endif

/* Standard Includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#ifndef __FreeBSD__
# include <sys/epoll.h>
# include <sys/types.h>
# include <sys/eventfd.h>
#endif
#include <unistd.h>
#include <signal.h>
#include <time.h>

/* Local Includes */
#include "e_qat_err.h"
#include "qat_utils.h"
#include "qat_fork.h"
#ifndef OPENSSL_MULTIBUFF_OFFLOAD
# include "qat_parseconf.h"
# include "qat_init.h"
# include "qat_ciphers.h"
# include "qat_rsa.h"
# include "qat_dsa.h"
# include "qat_dh.h"
# include "qat_ec.h"
# include "qat_evp.h"
#else
# include "multibuff_init.h"
# include "multibuff_rsa.h"
#endif

/* OpenSSL Includes */
#include <openssl/err.h>
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#include <openssl/async.h>
#endif
#include <openssl/objects.h>
#include <openssl/crypto.h>

/* Qat engine id declaration */
const char *engine_qat_id = "qat";
const char *engine_qat_name =
    "Reference implementation of QAT crypto engine v0.5.45";

#ifndef OPENSSL_MULTIBUFF_OFFLOAD
# define QAT_CONFIG_SECTION_NAME_SIZE 64
char qat_config_section_name[QAT_CONFIG_SECTION_NAME_SIZE] = "SHIM";
char *ICPConfigSectionName_libcrypto = qat_config_section_name;

const ENGINE_CMD_DEFN qat_cmd_defns[] = {
    {
        QAT_CMD_ENABLE_EXTERNAL_POLLING,
        "ENABLE_EXTERNAL_POLLING",
        "Enables the external polling interface to the engine.",
        ENGINE_CMD_FLAG_NO_INPUT},
    {
        QAT_CMD_POLL,
        "POLL",
        "Polls the engine for any completed requests",
        ENGINE_CMD_FLAG_NO_INPUT},
    {
        QAT_CMD_SET_INSTANCE_FOR_THREAD,
        "SET_INSTANCE_FOR_THREAD",
        "Set instance to be used by this thread",
        ENGINE_CMD_FLAG_NUMERIC},
    {
        QAT_CMD_GET_NUM_OP_RETRIES,
        "GET_NUM_OP_RETRIES",
        "Get number of retries",
        ENGINE_CMD_FLAG_NO_INPUT},
    {
        QAT_CMD_SET_MAX_RETRY_COUNT,
        "SET_MAX_RETRY_COUNT",
        "Set maximum retry count",
        ENGINE_CMD_FLAG_NUMERIC},
    {
        QAT_CMD_SET_INTERNAL_POLL_INTERVAL,
        "SET_INTERNAL_POLL_INTERVAL",
        "Set internal polling interval",
        ENGINE_CMD_FLAG_NUMERIC},
#ifndef __FreeBSD__
    {
        QAT_CMD_GET_EXTERNAL_POLLING_FD,
        "GET_EXTERNAL_POLLING_FD",
        "Returns non blocking fd for crypto engine",
        ENGINE_CMD_FLAG_NO_INPUT},
    {
        QAT_CMD_ENABLE_EVENT_DRIVEN_POLLING_MODE,
        "ENABLE_EVENT_DRIVEN_POLLING_MODE",
        "Set event driven polling mode",
        ENGINE_CMD_FLAG_NO_INPUT},
#endif
    {
        QAT_CMD_GET_NUM_CRYPTO_INSTANCES,
        "GET_NUM_CRYPTO_INSTANCES",
        "Get the number of crypto instances",
        ENGINE_CMD_FLAG_NO_INPUT},
#ifndef __FreeBSD__
    {
        QAT_CMD_DISABLE_EVENT_DRIVEN_POLLING_MODE,
        "DISABLE_EVENT_DRIVEN_POLLING_MODE",
        "Unset event driven polling mode",
        ENGINE_CMD_FLAG_NO_INPUT},
#endif
    {
        QAT_CMD_SET_EPOLL_TIMEOUT,
        "SET_EPOLL_TIMEOUT",
        "Set epoll_wait timeout",
        ENGINE_CMD_FLAG_NUMERIC},
    {
        QAT_CMD_SET_CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD,
        "SET_CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD",
        "Set QAT small packet threshold",
        ENGINE_CMD_FLAG_STRING},
    {
        QAT_CMD_ENABLE_INLINE_POLLING,
        "ENABLE_INLINE_POLLING",
        "Enables the inline polling mode.",
        ENGINE_CMD_FLAG_NO_INPUT},
    {
        QAT_CMD_ENABLE_HEURISTIC_POLLING,
        "ENABLE_HEURISTIC_POLLING",
        "Enable the heuristic polling mode",
        ENGINE_CMD_FLAG_NO_INPUT},
    {
        QAT_CMD_GET_NUM_REQUESTS_IN_FLIGHT,
        "GET_NUM_REQUESTS_IN_FLIGHT",
        "Get the number of in-flight requests",
        ENGINE_CMD_FLAG_NUMERIC},
    {
        QAT_CMD_INIT_ENGINE,
        "INIT_ENGINE",
        "Initializes the engine if not already initialized",
        ENGINE_CMD_FLAG_NO_INPUT},
    {
        QAT_CMD_SET_CONFIGURATION_SECTION_NAME,
        "SET_CONFIGURATION_SECTION_NAME",
        "Set the configuration section to use in QAT driver configuration file",
        ENGINE_CMD_FLAG_STRING},
#ifndef __FreeBSD__
    {
        QAT_CMD_ENABLE_SW_FALLBACK,
        "ENABLE_SW_FALLBACK",
        "Enables the fallback to SW if the acceleration devices go offline",
        ENGINE_CMD_FLAG_NO_INPUT},
    {
        QAT_CMD_HEARTBEAT_POLL,
        "HEARTBEAT_POLL",
        "Check the acceleration devices are still functioning",
        ENGINE_CMD_FLAG_NO_INPUT},
#endif
    {
        QAT_CMD_DISABLE_QAT_OFFLOAD,
        "DISABLE_QAT_OFFLOAD",
        "Perform crypto operations on core",
        ENGINE_CMD_FLAG_NO_INPUT},
    {0, NULL, NULL, 0}
};
#else
static const ENGINE_CMD_DEFN multibuff_cmd_defns[] = {
    {
        MULTIBUFF_CMD_ENABLE_EXTERNAL_POLLING,
        "ENABLE_EXTERNAL_POLLING",
        "Enables the external polling interface to the engine.",
        ENGINE_CMD_FLAG_NO_INPUT},
    {
        MULTIBUFF_CMD_POLL,
        "POLL",
        "Polls the engine for any completed requests",
        ENGINE_CMD_FLAG_NO_INPUT},
    {
        MULTIBUFF_CMD_ENABLE_HEURISTIC_POLLING,
        "ENABLE_HEURISTIC_POLLING",
        "Enable the heuristic polling mode",
        ENGINE_CMD_FLAG_NO_INPUT},
    {
        MULTIBUFF_CMD_GET_NUM_REQUESTS_IN_FLIGHT,
        "GET_NUM_REQUESTS_IN_FLIGHT",
        "Get the number of in-flight requests",
        ENGINE_CMD_FLAG_NUMERIC},
    {0, NULL, NULL, 0}
};


#endif

/******************************************************************************
* function:
*         qat_engine_destroy(ENGINE *e)
*
* @param e [IN] - OpenSSL engine pointer
*
* description:
*   Qat engine destroy function, required by Openssl engine API.
*   Cleanup all the method structures here.
*
******************************************************************************/
static int qat_engine_destroy(ENGINE *e)
{
    DEBUG("---- Destroying Engine...\n\n");
#ifndef OPENSSL_MULTIBUFF_OFFLOAD
    qat_free_ciphers();
    qat_free_EC_methods();
    qat_free_DH_methods();
    qat_free_DSA_methods();
    qat_free_RSA_methods();
#else
    multibuff_free_RSA_methods();
#endif
    QAT_DEBUG_LOG_CLOSE();
    ERR_unload_QAT_strings();
    return 1;
}

/******************************************************************************
* function:
*         bind_qat(ENGINE *e,
*                  const char *id)
*
* @param e  [IN] - OpenSSL engine pointer
* @param id [IN] - engine id
*
* description:
*    Connect Qat engine to OpenSSL engine library
******************************************************************************/
static int bind_qat(ENGINE *e, const char *id)
{
    int ret = 0;

#ifndef OPENSSL_MULTIBUFF_OFFLOAD
# ifndef OPENSSL_ENABLE_QAT_UPSTREAM_DRIVER
    int upstream_flags = 0;
    unsigned int devmasks[] = { 0, 0, 0, 0, 0 };
# endif

    char *config_section = NULL;
#endif
    QAT_DEBUG_LOG_INIT();

    WARN("QAT Warnings enabled.\n");
    DEBUG("QAT Debug enabled.\n");
    WARN("%s - %s \n", id, engine_qat_name);


#ifndef OPENSSL_MULTIBUFF_OFFLOAD
    if (access(QAT_DEV, F_OK) != 0) {
        WARN("Qat memory driver not present\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_MEM_DRV_NOT_PRESENT);
        goto end;
    }

# ifndef OPENSSL_ENABLE_QAT_UPSTREAM_DRIVER
    if (!getDevices(devmasks, &upstream_flags)) {
        WARN("Qat device not present\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_QAT_DEV_NOT_PRESENT);
        goto end;
    }
# endif
#endif

    if (id && (strcmp(id, engine_qat_id) != 0)) {
        WARN("ENGINE_id defined already!\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_ID_ALREADY_DEFINED);
        goto end;
    }

    if (!ENGINE_set_id(e, engine_qat_id)) {
        WARN("ENGINE_set_id failed\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_ID_FAILURE);
        goto end;
    }

    if (!ENGINE_set_name(e, engine_qat_name)) {
        WARN("ENGINE_set_name failed\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_NAME_FAILURE);
        goto end;
    }

    /* Ensure the QAT error handling is set up */
    ERR_load_QAT_strings();

#ifndef OPENSSL_MULTIBUFF_OFFLOAD
    /*
     * Create static structures for ciphers now
     * as this function will be called by a single thread.
     */
    qat_create_ciphers();

    if (!ENGINE_set_RSA(e, qat_get_RSA_methods())) {
        WARN("ENGINE_set_RSA failed\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_RSA_FAILURE);
        goto end;
    }

    if (!ENGINE_set_DSA(e, qat_get_DSA_methods())) {
        WARN("ENGINE_set_DSA failed\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_DSA_FAILURE);
        goto end;
    }

    if (!ENGINE_set_DH(e, qat_get_DH_methods())) {
        WARN("ENGINE_set_DH failed\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_DH_FAILURE);
        goto end;
    }

    if (!ENGINE_set_EC(e, qat_get_EC_methods())) {
        WARN("ENGINE_set_EC failed\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_EC_FAILURE);
        goto end;
    }

    if (!ENGINE_set_ciphers(e, qat_ciphers)) {
        WARN("ENGINE_set_ciphers failed\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_CIPHER_FAILURE);
        goto end;
    }

    if (!ENGINE_set_pkey_meths(e, qat_pkey_methods)) {
        WARN("ENGINE_set_pkey_meths failed\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_PKEY_FAILURE);
        goto end;
    }

#else
    if (!ENGINE_set_RSA(e, multibuff_get_RSA_methods())) {
        WARN("ENGINE_set_RSA failed\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_RSA_FAILURE);
        goto end;
    }
#endif

    pthread_atfork(engine_finish_before_fork_handler, NULL,
                   engine_init_child_at_fork_handler);

    ret = 1;
    ret &= ENGINE_set_destroy_function(e, qat_engine_destroy);
#ifndef OPENSSL_MULTIBUFF_OFFLOAD
    ret &= ENGINE_set_init_function(e, qat_engine_init);
    ret &= ENGINE_set_ctrl_function(e, qat_engine_ctrl);
    ret &= ENGINE_set_finish_function(e, qat_engine_finish);
    ret &= ENGINE_set_cmd_defns(e, qat_cmd_defns);
#else
    ret &= ENGINE_set_init_function(e, multibuff_engine_init);
    ret &= ENGINE_set_ctrl_function(e, multibuff_engine_ctrl);
    ret &= ENGINE_set_finish_function(e, multibuff_engine_finish);
    ret &= ENGINE_set_cmd_defns(e, multibuff_cmd_defns);
#endif
    if (ret == 0) {
        WARN("Engine failed to register init, finish or destroy functions\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_REGISTER_FUNC_FAILURE);
    }

    /*
     * If the QAT_SECTION_NAME environment variable is set, use that.
     * Similar setting made through engine ctrl command takes precedence
     * over this environment variable. It makes sense to use the environment
     * variable because the container orchestrators pass down this
     * configuration as environment variables.
     */

#ifndef OPENSSL_MULTIBUFF_OFFLOAD
# ifndef __FreeBSD__
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
        qat_config_section_name[QAT_CONFIG_SECTION_NAME_SIZE - 1]   = '\0';
    }
#endif

 end:
    return ret;

}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
IMPLEMENT_DYNAMIC_BIND_FN(bind_qat)
    IMPLEMENT_DYNAMIC_CHECK_FN()
#endif                          /* ndef OPENSSL_NO_DYNAMIC_ENGINE */
/* initialize Qat Engine if OPENSSL_NO_DYNAMIC_ENGINE*/
#ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *engine_qat(void)
{
    ENGINE *ret = NULL;
    DEBUG("- Starting\n");

    ret = ENGINE_new();

    if (!ret) {
        WARN("Failed to create Engine\n");
        QATerr(QAT_F_ENGINE_QAT, QAT_R_QAT_CREATE_ENGINE_FAILURE);
        return NULL;
    }

    if (!bind_qat(ret, engine_qat_id)) {
        WARN("Qat engine bind failed\n");
        ENGINE_free(ret);
        return NULL;
    }

    return ret;
}

void ENGINE_load_qat(void)
{
    ENGINE *toadd;
    int error = 0;
    char error_string[QAT_MAX_ERROR_STRING] = { 0 };

    QAT_DEBUG_LOG_INIT();
    DEBUG("- Starting\n");

    toadd = engine_qat();
    if (toadd == NULL) {
        error = ERR_peek_error();
        ERR_error_string_n(error, error_string, QAT_MAX_ERROR_STRING);
        WARN("Error reported by engine load: %s\n", error_string);
        return;
    }

    DEBUG("adding engine\n");
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}

#endif
