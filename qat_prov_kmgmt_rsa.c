/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022 Intel Corporation.
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
#include "qat_utils.h"


typedef struct{
    int id; /* libcrypto internal */
    int name_id;
    char *type_name;
    const char *description;
    OSSL_PROVIDER *prov;

    int refcnt;
    void *lock;

    /* Constructor(s), destructor, information */
    OSSL_FUNC_keymgmt_new_fn *new;
    OSSL_FUNC_keymgmt_free_fn *free;
    OSSL_FUNC_keymgmt_get_params_fn *get_params;
    OSSL_FUNC_keymgmt_gettable_params_fn *gettable_params;
    OSSL_FUNC_keymgmt_set_params_fn *set_params;
    OSSL_FUNC_keymgmt_settable_params_fn *settable_params;

    /* Generation, a complex constructor */
    OSSL_FUNC_keymgmt_gen_init_fn *gen_init;
    OSSL_FUNC_keymgmt_gen_set_template_fn *gen_set_template;
    OSSL_FUNC_keymgmt_gen_set_params_fn *gen_set_params;
    OSSL_FUNC_keymgmt_gen_settable_params_fn *gen_settable_params;
    OSSL_FUNC_keymgmt_gen_fn *gen;
    OSSL_FUNC_keymgmt_gen_cleanup_fn *gen_cleanup;
    OSSL_FUNC_keymgmt_load_fn *load;

    /* Key object checking */
    OSSL_FUNC_keymgmt_query_operation_name_fn *query_operation_name;
    OSSL_FUNC_keymgmt_has_fn *has;
    OSSL_FUNC_keymgmt_validate_fn *validate;
    OSSL_FUNC_keymgmt_match_fn *match;

    /* Import and export routines */
    OSSL_FUNC_keymgmt_import_fn *import;
    OSSL_FUNC_keymgmt_import_types_fn *import_types;
    OSSL_FUNC_keymgmt_export_fn *export;
    OSSL_FUNC_keymgmt_export_types_fn *export_types;
    OSSL_FUNC_keymgmt_dup_fn *dup;

} QAT_RSA_KEYMGMT;


QAT_RSA_KEYMGMT get_default_keymgmt()
{
    static QAT_RSA_KEYMGMT s_keymgmt;
    static int initialized = 0;
    if (!initialized) {
        QAT_RSA_KEYMGMT *keymgmt = (QAT_RSA_KEYMGMT *)EVP_KEYMGMT_fetch(NULL, "RSA", "provider=default");
        if (keymgmt) {
            s_keymgmt = *keymgmt;
            EVP_KEYMGMT_free((EVP_KEYMGMT *)keymgmt);
            initialized = 1;
        } else {
            WARN("EVP_KEYMGMT_fetch from default provider failed");
        }
    }
    return s_keymgmt;
}

static void *qat_keymgmt_rsa_newdata(void *provctx)
{
    typedef void* (*fun_ptr)(void *);
    fun_ptr fun = get_default_keymgmt().new;
    if (!fun)
        return NULL;
    return fun(provctx);
}

static void qat_keymgmt_rsa_freedata(void *keydata)
{
    typedef void (*fun_ptr)(void *);
    fun_ptr fun = get_default_keymgmt().free;
    if (!fun)
        return;
    fun(keydata);
}

static int qat_keymgmt_rsa_has(const void *keydata, int selection)
{
    typedef int (*fun_ptr)(const void *,int);
    fun_ptr fun = get_default_keymgmt().has;
    if (!fun)
        return 0;

    return fun(keydata,selection);
}

static int qat_keymgmt_rsa_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    typedef int (*fun_ptr)(void *, int, const OSSL_PARAM*);
    fun_ptr fun = get_default_keymgmt().import;
    if (!fun)
        return 0;
    return fun(keydata,selection,params);
}

static const OSSL_PARAM *qat_keymgmt_rsa_import_types(int selection)
{
    typedef const OSSL_PARAM* (*fun_ptr)(int);
    fun_ptr fun = get_default_keymgmt().import_types;
    if (!fun)
        return NULL;
    return fun(selection);
}


const OSSL_DISPATCH qat_rsa_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))qat_keymgmt_rsa_newdata},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))qat_keymgmt_rsa_freedata},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))qat_keymgmt_rsa_has},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))qat_keymgmt_rsa_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))qat_keymgmt_rsa_import_types},
    {0, NULL}
};


