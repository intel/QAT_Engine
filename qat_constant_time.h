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

/*
 * This file is based on modified code from OpenSSL.
 * This is needed because the constant time functions are not exported
 * from OpenSSL forcing engines to have their own copy of the
 * functionality.
 * The code based on OpenSSL code is subject to the following license:
 */

/*
 * Copyright 2014-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*****************************************************************************
 * @file qat_constant_time.h
 *
 * This file provides constant time functions
 *
 *****************************************************************************/

#ifndef QAT_CONST_TIME_H
# define QAT_CONST_TIME_H

#ifdef __cplusplus
extern "C" {
#endif

static inline unsigned int qat_constant_time_msb(unsigned int a)
{
    return 0 - (a >> (sizeof(a) * 8 - 1));
}

static inline unsigned int qat_constant_time_lt(unsigned int a,
                                                unsigned int b)
{
    return qat_constant_time_msb(a ^ ((a ^ b) | ((a - b) ^ b)));
}

static inline unsigned int qat_constant_time_ge(unsigned int a,
                                                unsigned int b)
{
    return ~qat_constant_time_lt(a, b);
}

static inline unsigned char qat_constant_time_ge_8(unsigned int a,
                                                   unsigned int b)
{
    return (unsigned char)(qat_constant_time_ge(a, b));
}

static inline unsigned int qat_constant_time_is_zero(unsigned int a)
{
    return qat_constant_time_msb(~a & (a - 1));
}

static inline unsigned int qat_constant_time_eq(unsigned int a,
                                                unsigned int b)
{
    return qat_constant_time_is_zero(a ^ b);
}

#ifdef __cplusplus
}
#endif

#endif                          /* QAT_CONST_TIME_H */
