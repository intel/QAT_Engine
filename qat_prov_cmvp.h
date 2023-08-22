/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2023 Intel Corporation.
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
 * @file qat_prov_cmvp.h
 *
 * This file provides an interface to qatprovider FIPs CMVP features.
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <openssl/ossl_typ.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include "qat_utils.h"
#include "qat_prov_ec.h"
#include "qat_fips.h"

#define QAT_FIPS_PROVIDER_NAME "QAT Provider FIPS"
#define QAT_FIPS_PROVIDER_ID "qatprovider"
#define QAT_FIPS_PROVIDER_VERSION "QAT Engine v1.3.1"
#ifdef QAT_HW
#define QAT_HW_DRIVER_version "QAT20.l.1.0.40-00004"
#endif
#ifdef QAT_SW
#define QAT_FIPS_IPSec_mb_QAT_SW_VERSION "v1.3"
#define QAT_FIPS_IPP_crypto_QAT_SW_VERSION "ippcp_2021.7.1"
#endif

#define FIPS_RSA_SIGN_MIN_SIZE 2048
#define FIPS_RSA_VER_MIN_SIZE 1024
#define FIPS_RSA_MAX_SIZE 4096
#define FIPS_DSA_VER_MIN_SIZE 1024

extern int qat_provider_info(void);
int qat_fips_ec_check_approved_curve(const EC_KEY *eckey);
#ifdef QAT_HW
int qat_fips_dh_safe_group(const DH *dh);
#endif
int qat_fips_ec_key_simple_check_key(const EC_KEY *eckey);
int qat_fips_get_key_zeroize_status(void);
int qat_fips_get_approved_status(void);
#ifdef QAT_HW
int dsa_fips_range_check(int plen, int qlen);
#endif
