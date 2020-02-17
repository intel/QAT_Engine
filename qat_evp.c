/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2019-2020 Intel Corporation.
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
 * @file qat_evp.c
 *
 * This file provides an initialisation of the various operations at the EVP
 * layer for an OpenSSL engine.
 *
 *****************************************************************************/
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include "openssl/ossl_typ.h"
#include "openssl/kdf.h"
#include "openssl/evp.h"
#include "qat_utils.h"
#include "qat_evp.h"
#include "qat_init.h"

/* Supported EVP nids */
int qat_evp_nids[] = {
    EVP_PKEY_TLS1_PRF,
#if OPENSSL_VERSION_NUMBER > 0x10101000L
    EVP_PKEY_HKDF,
    EVP_PKEY_X25519,
    EVP_PKEY_X448
#endif
};
const int num_evp_nids = sizeof(qat_evp_nids) / sizeof(qat_evp_nids[0]);

/******************************************************************************
 * function:
 *         qat_create_pkey_meth(int nid)
 *
 * @param nid    [IN] - EVP operation id
 *
 * description:
 *   Creates qat EVP Pkey methods for the nid
******************************************************************************/
static EVP_PKEY_METHOD *qat_create_pkey_meth(int nid)
{
    switch (nid) {
        case EVP_PKEY_TLS1_PRF:
            return qat_prf_pmeth();
#if OPENSSL_VERSION_NUMBER > 0x10101000L
        case EVP_PKEY_HKDF:
            return qat_hkdf_pmeth();
        case EVP_PKEY_X25519:
            return qat_x25519_pmeth();
        case EVP_PKEY_X448:
            return qat_x448_pmeth();
#endif
        default:
            WARN("Invalid nid %d\n", nid);
            return NULL;
    }
}

/******************************************************************************
 * function:
 *         qat_pkey_methods(ENGINE *e,
 *                          const EVP_PKEY_METHOD **pmeth,
 *                          const int **nids,
 *                          int nid)
 *
 * @param e      [IN] - OpenSSL engine pointer
 * @param pmeth  [IN] - EVP methods structure pointer
 * @param nids   [IN] - EVP functions nids
 * @param nid    [IN] - EVP operation id
 *
 * description:
 *   QAT engine digest operations registrar
******************************************************************************/
int qat_pkey_methods(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                     const int **nids, int nid)
{
    int i;
    if (pmeth == NULL) {
        if (unlikely(nids == NULL)) {
            WARN("Invalid input params.\n");
            return 0;
        }
        *nids = qat_evp_nids;
        return num_evp_nids;
    }

    for (i = 0; i < num_evp_nids; i++) {
        if (nid == qat_evp_nids[i]) {
            *pmeth = qat_create_pkey_meth(nid);
            return 1;
        }
    }

    WARN("NID %d not supported\n", nid);
    *pmeth = NULL;
    return 0;
}
