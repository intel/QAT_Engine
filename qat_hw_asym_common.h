/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2023 Intel Corporation.
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
 * @file qat_hw_asym_common.h
 *
 * This file contains the interface to common asymmetric functions
 *
 *****************************************************************************/

#ifndef QAT_HW_ASYM_COMMON_H
# define QAT_HW_ASYM_COMMON_H

# include <openssl/ossl_typ.h>

# include "cpa.h"

int qat_BN_to_FB(CpaFlatBuffer * fb, const BIGNUM *bn, int qat_svm);
int qat_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m,
                int *fallback);
# ifdef ENABLE_QAT_HW_SM2
int qat_BN_to_FB_for_sm2(CpaFlatBuffer * fb, const BIGNUM *bn, int qat_svm);
# endif

# ifdef ENABLE_QAT_HW_ECX
void qat_ecx_cb(void *pCallbackTag, CpaStatus status,
                void *pOpData, CpaBoolean multiplyStatus,
                CpaFlatBuffer *pXk, CpaFlatBuffer *pYk);
int reverse_bytes(unsigned char *tobuffer, unsigned char *frombuffer,
                  unsigned int tosize, unsigned int fromsize);
# endif
#endif /* QAT_HW_ASYM_COMMON_H */
