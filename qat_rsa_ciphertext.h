/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2020-2026 Intel Corporation.
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
 * @file qat_rsa_ciphertext.h
 *
 * Shared RSA PKCS#1 v1.5 implicit-rejection (Marvin workaround) for
 * CVE-2026-42768.  Used by both the QAT HW and QAT SW RSA paths.
 *
 *****************************************************************************/

#ifndef QAT_RSA_CIPHERTEXT_H
# define QAT_RSA_CIPHERTEXT_H

# include <openssl/rsa.h>

/* Maximum RSA modulus size in bytes supported across all code paths.
 * QAT20 OOT / HW in-tree builds support 8192-bit (1024 byte) keys;
 * other builds cap at 4096-bit (512 byte).  This constant is the
 * stack-allocation upper bound used by qat_rsa_pkcs1_type2_check(). */
# if defined(QAT20_OOT) || defined(QAT_HW_INTREE) || \
     defined(QAT_HW_FBSD_OOT) || defined(QAT_HW_FBSD_INTREE)
#  define QAT_RSA_MAX_MODLEN 1024  /* 8192-bit */
# else
#  define QAT_RSA_MAX_MODLEN  512  /* 4096-bit */
# endif

/******************************************************************************
 * function:
 *   qat_rsa_pkcs1_type2_check(const unsigned char *from,
 *                             int flen,
 *                             unsigned char *to,
 *                             RSA *rsa,
 *                             int rsa_len,
 *                             const unsigned char *padded_buf,
 *                             int padded_len,
 *                             int implicit_rejection)
 *
 * @param from               [IN]  - original ciphertext (for KDK derivation)
 * @param flen               [IN]  - length of ciphertext in bytes
 * @param to                 [OUT] - output plaintext buffer
 * @param rsa                [IN]  - RSA key (private exponent used for KDK)
 * @param rsa_len            [IN]  - RSA modulus length in bytes
 * @param padded_buf         [IN]  - raw decrypted buffer (after RSA primitive)
 * @param padded_len         [IN]  - length of padded_buf in bytes
 * @param implicit_rejection [IN]  - if non-zero apply Marvin implicit rejection
 *
 * Handles RSA_PKCS1_PADDING after raw private decryption.  When
 * implicit_rejection is set the four-step Marvin workaround is applied so
 * that bad-padding ciphertexts produce a deterministic synthetic output
 * indistinguishable from a good decryption.  When implicit_rejection is
 * zero the plain RSA_padding_check_PKCS1_type_2() call is performed.
 *
 * Returns: plaintext length on success; -1 on padding error
 *          (only possible when implicit_rejection == 0).
 *****************************************************************************/
int qat_rsa_pkcs1_type2_check(const unsigned char *from, int flen,
                               unsigned char *to, RSA *rsa, int rsa_len,
                               const unsigned char *padded_buf, int padded_len,
                               int implicit_rejection);

#endif /* QAT_RSA_CIPHERTEXT_H */
