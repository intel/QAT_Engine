/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2021 Intel Corporation.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/kdf.h>
#include "tests.h"
#include "../qat_utils.h"

#define MD_SERVER_FINISHED_SEED2_LEN      32
#define MD_SERVER_FINISHED_SEC_LEN        48
#define MD_SERVER_FINISHED_BUFF_SIZE      12
#define MD_SERVER_FINISHED_MASTER_SEC_LEN 12

#define MD_CLIENT_FINISHED_SEED2_LEN      32
#define MD_CLIENT_FINISHED_SEC_LEN        48
#define MD_CLIENT_FINISHED_BUFF_SIZE      12
#define MD_CLIENT_FINISHED_MASTER_SEC_LEN 12

#define MD_KEY_EXPANSION_SEED2_LEN        32
#define MD_KEY_EXPANSION_SEED3_LEN        32
#define MD_KEY_EXPANSION_SEC_LEN          48
#define MD_KEY_EXPANSION_BUFF_SIZE        104
#define MD_KEY_EXPANSION_MASTER_SEC_LEN   104

#define MASTER_SECRET_SEED2_LEN           32
#define MASTER_SECRET_SEED4_LEN           32
#define MASTER_SECRET_SEC_LEN             48

#define EXTENDED_MASTER_SECRET_SEED2_LEN  32
#define EXTENDED_MASTER_SECRET_SEC_LEN    48

static const unsigned char prf_sf_lseed2[] = {
    0xD8, 0xDD, 0x4A, 0xC2, 0x78, 0xD2, 0x2C, 0xE6,
    0x22, 0x9C, 0x18, 0x2C, 0x88, 0x1B, 0x4D, 0x7F,
    0xC7, 0xC0, 0x71, 0x46, 0x8C, 0xE8, 0x86, 0x5B,
    0x87, 0x5A, 0x31, 0x2E, 0x53, 0x33, 0xE1, 0x39
};

static const unsigned char prf_sf_lsec[] = {
    0x57, 0x0A, 0xD8, 0x78, 0x67, 0x2B, 0x0B, 0x11,
    0xE1, 0x51, 0x51, 0x71, 0x3B, 0xAF, 0xB2, 0xFE,
    0xE4, 0x33, 0x41, 0x67, 0x35, 0x3F, 0x20, 0xB1,
    0x6F, 0x9B, 0xF8, 0x91, 0x2F, 0xD9, 0xF6, 0x3B,
    0x32, 0x7A, 0xAD, 0x77, 0xBD, 0xC2, 0x35, 0x6D,
    0x30, 0x53, 0x39, 0x53, 0xE0, 0x09, 0x7E, 0xE9
};

static const unsigned char prf_sf_resMasSec_TLS1_2_SHA256[] = {
    0x68, 0xCA, 0xCC, 0xAF, 0x1A, 0x9F, 0xAE, 0xE4,
    0xFC, 0x23, 0xD5, 0xC6
};

static const unsigned char prf_sf_resMasSec_TLS1_2_SHA384[] = {
    0xD3, 0xF1, 0xF1, 0x54, 0x13, 0x84, 0xD5, 0x48,
    0x85, 0xDD, 0xEC, 0xD0
};

static const unsigned char prf_sf_resMasSec_TLS1_2_SHA512[] = {
    0x3D, 0xFB, 0x40, 0x47, 0x89, 0x66, 0x7C, 0xDE,
    0xFB, 0xDD, 0x59, 0x52
};

static const unsigned char prf_sf_resMasSec_TLS1_TLS1_1_MD5SHA1[] = {
    0x1D, 0xFA, 0xC3, 0xDE, 0xAE, 0x74, 0x2B, 0xE1,
    0x87, 0xC0, 0x0B, 0x9B
};

static const unsigned char prf_cf_lseed2[] = {
    0xC2, 0xFA, 0x5E, 0xE1, 0x95, 0xCF, 0x3C, 0xF8,
    0x09, 0xC8, 0x37, 0xC5, 0x80, 0x41, 0xFA, 0xC2,
    0xE3, 0x7C, 0x2F, 0xCC, 0xA7, 0x50, 0x82, 0x6C,
    0x9E, 0x5D, 0x87, 0x5F, 0x46, 0xD4, 0xF7, 0x02
};

static const unsigned char prf_cf_lsec[] = {
    0x57, 0x0A, 0xD8, 0x78, 0x67, 0x2B, 0x0B, 0x11,
    0xE1, 0x51, 0x51, 0x71, 0x3B, 0xAF, 0xB2, 0xFE,
    0xE4, 0x33, 0x41, 0x67, 0x35, 0x3F, 0x20, 0xB1,
    0x6F, 0x9B, 0xF8, 0x91, 0x2F, 0xD9, 0xF6, 0x3B,
    0x32, 0x7A, 0xAD, 0x77, 0xBD, 0xC2, 0x35, 0x6D,
    0x30, 0x53, 0x39, 0x53, 0xE0, 0x09, 0x7E, 0xE9
};

static const unsigned char prf_cf_resMasSec_TLS1_2_SHA256[] = {
    0xC9, 0x86, 0xD8, 0xFE, 0x8D, 0x26, 0xCB, 0x11,
    0xC8, 0xB3, 0xF6, 0xD3
};

static const unsigned char prf_cf_resMasSec_TLS1_2_SHA384[] = {
    0x62, 0x8C, 0x23, 0xB7, 0x10, 0x0D, 0x85, 0x08,
    0x35, 0x74, 0x14, 0x73
};

static const unsigned char prf_cf_resMasSec_TLS1_2_SHA512[] = {
    0x9A, 0xEF, 0x80, 0x3C, 0xEE, 0x32, 0xBC, 0xBC,
    0x1A, 0xC0, 0xA7, 0xDD
};

static const unsigned char prf_cf_resMasSec_TLS1_TLS1_1_MD5SHA1[] = {
    0x67, 0x18, 0x75, 0xEF, 0xBE, 0x50, 0xAD, 0xD5,
    0x94, 0x78, 0x53, 0x85
};

static const unsigned char prf_ke_lseed2[] = {
    0xEF, 0x14, 0xF7, 0x48, 0x0C, 0x36, 0xB2, 0xF3,
    0xFB, 0x4F, 0x9F, 0xBF, 0xBA, 0x6C, 0x6F, 0x0A,
    0x27, 0xAB, 0xF8, 0x16, 0xFF, 0x37, 0xE9, 0x88,
    0x0D, 0x8A, 0x3B, 0x59, 0x57, 0xA6, 0xC1, 0x7E
};

static const unsigned char prf_ke_lseed3[] = {
    0x88, 0x3E, 0x61, 0xAE, 0xE3, 0xB6, 0xD8, 0x62,
    0x18, 0x86, 0x4A, 0x7D, 0x4B, 0x0A, 0xA5, 0xF9,
    0xE7, 0xE7, 0xAA, 0xD5, 0x8B, 0xB1, 0xBD, 0x54,
    0x1F, 0xF2, 0x47, 0xCC, 0xDA, 0xA8, 0x3F, 0x2D
};

static const unsigned char prf_ke_lsec[] = {
    0x57, 0x0A, 0xD8, 0x78, 0x67, 0x2B, 0x0B, 0x11,
    0xE1, 0x51, 0x51, 0x71, 0x3B, 0xAF, 0xB2, 0xFE,
    0xE4, 0x33, 0x41, 0x67, 0x35, 0x3F, 0x20, 0xB1,
    0x6F, 0x9B, 0xF8, 0x91, 0x2F, 0xD9, 0xF6, 0x3B,
    0x32, 0x7A, 0xAD, 0x77, 0xBD, 0xC2, 0x35, 0x6D,
    0x30, 0x53, 0x39, 0x53, 0xE0, 0x09, 0x7E, 0xE9
};

static const unsigned char prf_ke_resMasSec_TLS1_2_SHA256[] = {
    0x5E, 0xD9, 0x1F, 0x2F, 0x5C, 0x3A, 0x78, 0x82,
    0x7C, 0xC3, 0xEA, 0x22, 0x47, 0x5F, 0x24, 0xD6,
    0xEA, 0x8B, 0xCC, 0x40, 0xF5, 0xAD, 0xC1, 0x39,
    0xBE, 0x15, 0x87, 0x85, 0x3A, 0x4C, 0x63, 0xA6,
    0xBD, 0x5C, 0x58, 0x5D, 0xD8, 0xD9, 0x1F, 0x1D,
    0xE1, 0x60, 0xD2, 0x2E, 0x59, 0x31, 0x0E, 0xFC,
    0xB7, 0xFB, 0x0D, 0x9A, 0x4E, 0xF8, 0x8D, 0x72,
    0x35, 0x6D, 0x8C, 0xEC, 0x99, 0x6F, 0x08, 0x41,
    0xB3, 0xB5, 0xDA, 0xB6, 0x7F, 0x97, 0xF0, 0xFF,
    0xAF, 0xF4, 0x05, 0x26, 0xC2, 0x05, 0x3D, 0x60,
    0x18, 0xAD, 0x01, 0x59, 0xE6, 0x16, 0x06, 0x0C,
    0x90, 0x81, 0x8D, 0x23, 0x08, 0x90, 0x57, 0x73,
    0x56, 0xAE, 0xD6, 0x7F, 0x64, 0x2B, 0x29, 0x72
};

static const unsigned char prf_ke_resMasSec_TLS1_2_SHA384[] = {
    0xB7, 0xC3, 0x82, 0xDE, 0x7C, 0x72, 0xA0, 0x3F,
    0x4E, 0xF6, 0x4B, 0x3B, 0x92, 0x1A, 0xBA, 0x44,
    0x58, 0x28, 0x3D, 0xA6, 0x2F, 0x02, 0x34, 0x2F,
    0x0B, 0x75, 0x73, 0xB1, 0x69, 0x43, 0x40, 0xA5,
    0x8A, 0x9B, 0xDC, 0x88, 0x06, 0x4E, 0x57, 0x62,
    0xBC, 0x3A, 0xB6, 0x38, 0x30, 0x8A, 0x3E, 0x8C,
    0x41, 0xA9, 0xF1, 0x54, 0xB9, 0xA5, 0x83, 0xDC,
    0x3A, 0x3D, 0x52, 0x0C, 0xB9, 0x79, 0xC9, 0xAC,
    0x10, 0xBD, 0x4F, 0x13, 0x8C, 0xBC, 0xA2, 0x99,
    0x17, 0xBA, 0xA9, 0x0C, 0xF8, 0x20, 0x0C, 0x4F,
    0x96, 0xA3, 0x39, 0x9B, 0x78, 0x8D, 0x1B, 0x21,
    0x93, 0x14, 0x76, 0xBF, 0x7A, 0xA7, 0x80, 0x5E,
    0xF3, 0x94, 0x56, 0xFB, 0x4B, 0x51, 0x01, 0x13
};

static const unsigned char prf_ke_resMasSec_TLS1_2_SHA512[] = {
    0xBC, 0x50, 0xE2, 0x72, 0x61, 0xAC, 0x97, 0x4E,
    0x89, 0x41, 0xAB, 0xBA, 0x39, 0xBD, 0xAC, 0x82,
    0xCD, 0x7A, 0x8C, 0x4E, 0x2D, 0x22, 0xC5, 0x62,
    0x3F, 0x2D, 0x4F, 0xB2, 0x55, 0x53, 0x7D, 0xC6,
    0x58, 0xE2, 0xBF, 0x23, 0xF7, 0x03, 0x44, 0xF7,
    0x1B, 0xE8, 0x13, 0x4A, 0xDC, 0x03, 0xFD, 0x49,
    0x43, 0xB1, 0xB7, 0xAE, 0x60, 0x78, 0x41, 0x20,
    0x27, 0x17, 0x0F, 0x18, 0x1F, 0xE4, 0x39, 0x49,
    0x2E, 0xF9, 0x87, 0x2F, 0x3F, 0x45, 0xC1, 0x7D,
    0x68, 0xC0, 0xCF, 0x4D, 0x6B, 0xA7, 0x55, 0x8D,
    0xFF, 0x38, 0xE4, 0x22, 0x4F, 0x86, 0x86, 0xD1,
    0x71, 0xA1, 0x51, 0x5B, 0x61, 0xA1, 0xFC, 0xB0,
    0xEE, 0x5C, 0x07, 0x17, 0xA0, 0x90, 0x9F, 0x50
};

static const unsigned char prf_ke_resMasSec_TLS1_TLS1_1_MD5SHA1[] = {
    0x6C, 0x73, 0xAE, 0xFE, 0xB0, 0xBC, 0x7A, 0x0C,
    0xF6, 0xBB, 0x28, 0xE7, 0x19, 0x01, 0x5C, 0x95,
    0x4D, 0x46, 0xDA, 0xC2, 0xC6, 0xCD, 0x10, 0xE8,
    0xF5, 0x19, 0xE9, 0x7A, 0xED, 0x75, 0x7F, 0xAC,
    0x7F, 0x16, 0xAB, 0x42, 0x98, 0x52, 0x0D, 0x1C,
    0xED, 0x73, 0x23, 0x57, 0x19, 0x45, 0x26, 0x51,
    0xD2, 0xA1, 0xF2, 0xA1, 0x3D, 0xA9, 0x59, 0xBB,
    0xD8, 0x63, 0x26, 0xFD, 0xCF, 0x95, 0x67, 0x71,
    0x4A, 0xF0, 0xBB, 0xA1, 0xE4, 0xAE, 0xE1, 0x8C,
    0xAE, 0xA7, 0xC3, 0xA6, 0xDE, 0xB1, 0x8C, 0x75,
    0x12, 0x61, 0x27, 0xB0, 0x07, 0x78, 0x94, 0xF9,
    0x8C, 0xDC, 0xF9, 0xE5, 0x1A, 0x3C, 0x90, 0x0B,
    0xB5, 0x65, 0x17, 0x7E, 0xB9, 0x23, 0x71, 0x0C
};

static const unsigned char prf_ms_lseed2[] = {
    0x88, 0x3E, 0x61, 0xAE, 0xE3, 0xB6, 0xD8, 0x62,
    0x18, 0x86, 0x4A, 0x7D, 0x4B, 0x0A, 0xA5, 0xF9,
    0xE7, 0xE7, 0xAA, 0xD5, 0x8B, 0xB1, 0xBD, 0x54,
    0x1F, 0xF2, 0x47, 0xCC, 0xDA, 0xA8, 0x3F, 0x2D
};

static const unsigned char prf_ms_lseed4[] = {
    0xEF, 0x14, 0xF7, 0x48, 0x0C, 0x36, 0xB2, 0xF3,
    0xFB, 0x4F, 0x9F, 0xBF, 0xBA, 0x6C, 0x6F, 0x0A,
    0x27, 0xAB, 0xF8, 0x16, 0xFF, 0x37, 0xE9, 0x88,
    0x0D, 0x8A, 0x3B, 0x59, 0x57, 0xA6, 0xC1, 0x7E
};

static const unsigned char prf_ms_lsec[] = {
    0x03, 0x03, 0x0B, 0x03, 0x07, 0xEF, 0x7A, 0xDC,
    0xFB, 0xD1, 0x86, 0xE3, 0x46, 0xC0, 0x45, 0x36,
    0xA2, 0x73, 0x31, 0xE3, 0x7A, 0xC8, 0x45, 0x3A,
    0xB9, 0x58, 0x0A, 0x4E, 0xA1, 0xC0, 0x73, 0x55,
    0x57, 0x92, 0xA5, 0xCD, 0x1A, 0x76, 0xE8, 0xDD,
    0xCF, 0xE3, 0x7A, 0x77, 0x48, 0xEE, 0x16, 0xAE
};

static const unsigned char prf_ms_resMasSec_TLS1_2_SHA256[] = {
    0x57, 0x0A, 0xD8, 0x78, 0x67, 0x2B, 0x0B, 0x11,
    0xE1, 0x51, 0x51, 0x71, 0x3B, 0xAF, 0xB2, 0xFE,
    0xE4, 0x33, 0x41, 0x67, 0x35, 0x3F, 0x20, 0xB1,
    0x6F, 0x9B, 0xF8, 0x91, 0x2F, 0xD9, 0xF6, 0x3B,
    0x32, 0x7A, 0xAD, 0x77, 0xBD, 0xC2, 0x35, 0x6D,
    0x30, 0x53, 0x39, 0x53, 0xE0, 0x09, 0x7E, 0xE9
};

static const unsigned char prf_ms_resMasSec_TLS1_2_SHA384[] = {
    0xD0, 0x90, 0xDE, 0x77, 0xDB, 0x2C, 0xBB, 0x24,
    0x37, 0xEB, 0xB2, 0x9E, 0x65, 0xE4, 0xCB, 0xD0,
    0x15, 0x60, 0x90, 0x61, 0x90, 0x82, 0x44, 0x86,
    0x9B, 0x9C, 0x70, 0xB6, 0xBB, 0x17, 0x37, 0x6E,
    0x55, 0xCD, 0x04, 0x61, 0x9F, 0xC1, 0x7A, 0x40,
    0x32, 0x82, 0xCB, 0xC1, 0x70, 0xD5, 0xC4, 0xDA
};

static const unsigned char prf_ms_resMasSec_TLS1_2_SHA512[] = {
    0x36, 0x25, 0x70, 0x6A, 0x23, 0x20, 0x5D, 0x88,
    0x3B, 0xAA, 0x7E, 0x7C, 0x72, 0xE1, 0x91, 0x9B,
    0x6F, 0x91, 0x21, 0xAB, 0x51, 0x36, 0x12, 0xCB,
    0x77, 0x10, 0x26, 0xBA, 0xC8, 0xC5, 0xAE, 0x8F,
    0x05, 0x1C, 0x6D, 0xD0, 0x79, 0xED, 0x57, 0x0F,
    0x4C, 0x0B, 0x79, 0xD3, 0x45, 0x22, 0x71, 0xCE
};

static const unsigned char prf_ms_resMasSec_TLS1_TLS1_1_MD5SHA1[] = {
    0xB0, 0xCC, 0x9D, 0xAB, 0xA4, 0xA4, 0xF9, 0x9C,
    0x0D, 0x17, 0x25, 0xF4, 0x82, 0xBB, 0x91, 0x20,
    0x1F, 0xF8, 0xA3, 0x7A, 0x9A, 0x69, 0x00, 0x0B,
    0x35, 0x4F, 0xE7, 0xA7, 0xBB, 0xBC, 0x96, 0x90,
    0x83, 0x80, 0x42, 0xB5, 0x33, 0xE9, 0x60, 0x42,
    0x9C, 0x4B, 0x8F, 0x7B, 0xA1, 0x2E, 0x4E, 0x19
};

static const unsigned char prf_ems_lseed2[] = {
    0xFF, 0x77, 0x85, 0x63, 0xD4, 0x23, 0x6A, 0x57,
    0xD4, 0x68, 0x83, 0x29, 0x6F, 0x86, 0x18, 0x6A,
    0x4C, 0xF3, 0xC3, 0xF4, 0xC8, 0xDC, 0xDF, 0x97,
    0x30, 0xD2, 0x2F, 0x9C, 0x5B, 0xA7, 0xD0, 0x5E
};

static const unsigned char prf_ems_lsec[] = {
    0x03, 0x03, 0xE3, 0x11, 0xC5, 0xED, 0xE6, 0x51,
    0x41, 0xC3, 0x99, 0xC9, 0x87, 0x56, 0x8C, 0x46,
    0xD0, 0x07, 0xA8, 0x3E, 0xE3, 0x7F, 0xBD, 0x60,
    0x56, 0xA2, 0xD0, 0x61, 0x83, 0xFF, 0xA3, 0x0E,
    0x21, 0x9A, 0x6C, 0x59, 0x79, 0x9D, 0x27, 0x23,
    0xDD, 0xBC, 0x0C, 0x5D, 0xB9, 0x76, 0xA9, 0xC5
};

static const unsigned char prf_ems_resMasSec_TLS1_2_SHA256[] = {
    0x44, 0x31, 0xBF, 0x20, 0xBF, 0xD7, 0xA8, 0x48,
    0x0D, 0x6F, 0x4E, 0xE8, 0xC9, 0xF8, 0xC1, 0x6A,
    0x65, 0xD1, 0x93, 0xE7, 0x54, 0x32, 0xA6, 0x10,
    0x3F, 0x73, 0x4B, 0x32, 0x14, 0xE8, 0xE6, 0x33,
    0x91, 0x84, 0x1F, 0x2F, 0xED, 0x71, 0xBC, 0x4C,
    0x67, 0x11, 0x97, 0xCE, 0x0F, 0xB3, 0x5D, 0x0D
};

static const unsigned char prf_ems_resMasSec_TLS1_2_SHA384[] = {
    0xAA, 0x39, 0xE6, 0xF6, 0x6D, 0xD0, 0xA6, 0x3E,
    0x09, 0x2D, 0xA2, 0xCA, 0x17, 0x2D, 0x91, 0xF4,
    0xFB, 0x1F, 0x14, 0x3A, 0xB2, 0xF2, 0x55, 0xD8,
    0xDA, 0x3B, 0xE4, 0x10, 0xEB, 0x02, 0x98, 0x72,
    0xBA, 0xD7, 0xC0, 0x18, 0x18, 0xED, 0xB3, 0xE8,
    0x52, 0x60, 0x90, 0x53, 0xB1, 0x4F, 0x89, 0x00
};

static const unsigned char prf_ems_resMasSec_TLS1_2_SHA512[] = {
    0xD2, 0xBA, 0xC7, 0x9D, 0x39, 0xA4, 0x6B, 0x34,
    0xBE, 0x3D, 0xA2, 0xEA, 0xE7, 0x8C, 0xDD, 0x66,
    0xF2, 0xAF, 0x4E, 0xD1, 0x19, 0xAB, 0x65, 0x50,
    0x58, 0xBB, 0x27, 0x87, 0x99, 0xCF, 0x1A, 0x0E,
    0x8C, 0x65, 0x41, 0x57, 0x5F, 0xF4, 0xE2, 0xAB,
    0x94, 0x1A, 0x75, 0xC8, 0x71, 0x33, 0x1C, 0x5B
};

static const unsigned char prf_ems_resMasSec_TLS1_TLS1_1_MD5SHA1[] = {
    0xC3, 0x5D, 0xF1, 0xC2, 0x5B, 0x8B, 0x01, 0xB7,
    0xA8, 0x9A, 0x71, 0x03, 0x0E, 0x01, 0x4C, 0x0E,
    0xF9, 0xBB, 0x07, 0xC4, 0xDC, 0x62, 0xE6, 0xE0,
    0x4C, 0x48, 0x02, 0x2E, 0x94, 0x94, 0xC9, 0x85,
    0x38, 0xA4, 0x26, 0x4F, 0xDE, 0x90, 0xE8, 0x8A,
    0xD6, 0x5D, 0xB9, 0x96, 0x7A, 0xA9, 0xC8, 0xF8
};

static int qat_PRF(const EVP_MD **md,int md_count,
                   const void *seed1, int seed1_len,
                   const void *seed2, int seed2_len,
                   const void *seed3, int seed3_len,
                   const void *seed4, int seed4_len,
                   const void *seed5, int seed5_len,
                   const unsigned char *sec, int slen,
                   unsigned char *out, int olen);

void populateMdServerFinished(void **seed2, int *seed2_len,
                              void **seed3, int *seed3_len,
                              void **seed4, int *seed4_len,
                              void **seed5, int *seed5_len,
                              unsigned char **sec, int *sec_len,
                              int *buff_size,  size_t *masterSecLen,
                              unsigned char **expectedMasterSecret,
                              int tls_version,
                              char *digest_kdf)
{
    *seed2_len = MD_SERVER_FINISHED_SEED2_LEN;
    *seed2 = (void *)&prf_sf_lseed2;
    seed3 = NULL;
    seed4 = NULL;
    seed5 = NULL;

    *sec_len = MD_SERVER_FINISHED_SEC_LEN;
    *sec = (void *)&prf_sf_lsec;

    *buff_size = MD_SERVER_FINISHED_BUFF_SIZE;
    *masterSecLen = MD_SERVER_FINISHED_MASTER_SEC_LEN;

    if (TLS1_2_VERSION == tls_version) {
        if (!strcmp(digest_kdf, "SHA256"))
            *expectedMasterSecret = (void *)&prf_sf_resMasSec_TLS1_2_SHA256;
        else if (!strcmp(digest_kdf, "SHA384"))
            *expectedMasterSecret = (void *)&prf_sf_resMasSec_TLS1_2_SHA384;
        else if (!strcmp(digest_kdf, "SHA512"))
            *expectedMasterSecret = (void *)&prf_sf_resMasSec_TLS1_2_SHA512;
    } else
        *expectedMasterSecret = (void *)&prf_sf_resMasSec_TLS1_TLS1_1_MD5SHA1;
}

void populateMdClientFinished(void **seed2, int *seed2_len,
                              void **seed3, int *seed3_len,
                              void **seed4, int *seed4_len,
                              void **seed5, int *seed5_len,
                              unsigned char **sec, int *sec_len,
                              int *buff_size,  size_t *masterSecLen,
                              unsigned char **expectedMasterSecret,
                              int tls_version,
                              char *digest_kdf)
{
    *seed2_len = MD_CLIENT_FINISHED_SEED2_LEN;
    *seed2 = (void *)&prf_cf_lseed2;
    seed3 = NULL;
    seed4 = NULL;
    seed5 = NULL;

    *sec_len = MD_CLIENT_FINISHED_SEC_LEN;
    *sec = (void *)&prf_cf_lsec;

    *buff_size = MD_CLIENT_FINISHED_BUFF_SIZE;
    *masterSecLen = MD_CLIENT_FINISHED_MASTER_SEC_LEN;

    if (TLS1_2_VERSION == tls_version) {
        if(!strcmp(digest_kdf, "SHA256") ){
            *expectedMasterSecret = (void *)&prf_cf_resMasSec_TLS1_2_SHA256;
        } else if(!strcmp(digest_kdf, "SHA384")){
            *expectedMasterSecret = (void *)&prf_cf_resMasSec_TLS1_2_SHA384;
        } else if(!strcmp(digest_kdf, "SHA512")){
            *expectedMasterSecret = (void *)&prf_cf_resMasSec_TLS1_2_SHA512;
        }
    } else {
        *expectedMasterSecret = (void *)&prf_cf_resMasSec_TLS1_TLS1_1_MD5SHA1;
    }
}

void populateMdKeyExpansion(void **seed2, int *seed2_len,
                            void **seed3, int *seed3_len,
                            void **seed4, int *seed4_len,
                            void **seed5, int *seed5_len,
                            unsigned char **sec, int *sec_len,
                            int *buff_size,  size_t *masterSecLen,
                            unsigned char **expectedMasterSecret,
                            int tls_version,
                            char *digest_kdf)
{
    *seed2_len = MD_KEY_EXPANSION_SEED2_LEN;
    *seed2 = (void *)&prf_ke_lseed2;
    *seed3_len = MD_KEY_EXPANSION_SEED3_LEN;
    *seed3 = (void *)&prf_ke_lseed3;
    seed4 = NULL;
    seed5 = NULL;

    *sec_len = MD_KEY_EXPANSION_SEC_LEN;
    *sec = (void *)&prf_ke_lsec;

    *buff_size = MD_KEY_EXPANSION_BUFF_SIZE;
    *masterSecLen = MD_KEY_EXPANSION_MASTER_SEC_LEN;

    if (TLS1_2_VERSION == tls_version) {
        if(!strcmp(digest_kdf, "SHA256") ){
            *expectedMasterSecret = (void *)&prf_ke_resMasSec_TLS1_2_SHA256;
        } else if(!strcmp(digest_kdf, "SHA384")){
            *expectedMasterSecret = (void *)&prf_ke_resMasSec_TLS1_2_SHA384;
        } else if(!strcmp(digest_kdf, "SHA512")){
            *expectedMasterSecret = (void *)&prf_ke_resMasSec_TLS1_2_SHA512;
        }
    } else {
        *expectedMasterSecret = (void *)&prf_ke_resMasSec_TLS1_TLS1_1_MD5SHA1;
    }
}

void populateMasterSecret(void **seed2, int *seed2_len,
                          void **seed3, int *seed3_len,
                          void **seed4, int *seed4_len,
                          void **seed5, int *seed5_len,
                          unsigned char **sec, int *sec_len,
                          int *buff_size,  size_t *masterSecLen,
                          unsigned char **expectedMasterSecret,
                          int tls_version,
                          char *digest_kdf)
{
    *seed2_len = MASTER_SECRET_SEED2_LEN;
    *seed2 = (void *)&prf_ms_lseed2;
    seed3 = NULL;
    *seed4_len = MASTER_SECRET_SEED4_LEN;
    *seed4 = (void *)&prf_ms_lseed4;
    seed5 = NULL;

    *sec_len = MASTER_SECRET_SEC_LEN;
    *sec = (void *)&prf_ms_lsec;

    *buff_size = SSL_MAX_MASTER_KEY_LENGTH;
    *masterSecLen = SSL_MAX_MASTER_KEY_LENGTH;

    if (TLS1_2_VERSION == tls_version) {
        if(!strcmp(digest_kdf, "SHA256") ){
            *expectedMasterSecret = (void *)&prf_ms_resMasSec_TLS1_2_SHA256;
        } else if(!strcmp(digest_kdf, "SHA384")){
            *expectedMasterSecret = (void *)&prf_ms_resMasSec_TLS1_2_SHA384;
        } else if(!strcmp(digest_kdf, "SHA512")){
            *expectedMasterSecret = (void *)&prf_ms_resMasSec_TLS1_2_SHA512;
        }
    } else {
        *expectedMasterSecret = (void *)&prf_ms_resMasSec_TLS1_TLS1_1_MD5SHA1;
    }
}

void populateExtendedMasterSecret(void **seed2, int *seed2_len,
                                  void **seed3, int *seed3_len,
                                  void **seed4, int *seed4_len,
                                  void **seed5, int *seed5_len,
                                  unsigned char **sec, int *sec_len,
                                  int *buff_size,  size_t *masterSecLen,
                                  unsigned char **expectedMasterSecret,
                                  int tls_version,
                                  char *digest_kdf)
{
    *seed2_len = EXTENDED_MASTER_SECRET_SEED2_LEN;
    *seed2 = (void *)&prf_ems_lseed2;
    seed3 = NULL;
    seed4 = NULL;
    seed5 = NULL;

    *sec_len = EXTENDED_MASTER_SECRET_SEC_LEN;
    *sec = (void *)&prf_ems_lsec;

    *buff_size = SSL_MAX_MASTER_KEY_LENGTH;
    *masterSecLen = SSL_MAX_MASTER_KEY_LENGTH;

    if (TLS1_2_VERSION == tls_version) {
        if(!strcmp(digest_kdf, "SHA256") ){
            *expectedMasterSecret = (void *)&prf_ems_resMasSec_TLS1_2_SHA256;
        } else if(!strcmp(digest_kdf, "SHA384")){
            *expectedMasterSecret = (void *)&prf_ems_resMasSec_TLS1_2_SHA384;
        } else if(!strcmp(digest_kdf, "SHA512")){
            *expectedMasterSecret = (void *)&prf_ems_resMasSec_TLS1_2_SHA512;
        }
    } else {
        *expectedMasterSecret = (void *)&prf_ems_resMasSec_TLS1_TLS1_1_MD5SHA1;
    }
}

static int qat_PRF(const EVP_MD **md,int md_count,
                   const void *seed1, int seed1_len,
                   const void *seed2, int seed2_len,
                   const void *seed3, int seed3_len,
                   const void *seed4, int seed4_len,
                   const void *seed5, int seed5_len,
                   const unsigned char *sec, int slen,
                   unsigned char *out, int olen)
{
    EVP_PKEY_CTX *pctx = NULL;

    int ret = 0;
    size_t outlen = olen;

    if (md == NULL) {
        /* Should never happen */
        WARN("# FAIL: md has not been set\n");
        return 0;
    }
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
    if (pctx == NULL || EVP_PKEY_derive_init(pctx) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, *md) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, sec, slen) <= 0)
        goto err;
    if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed1, seed1_len) <= 0)
        goto err;
    if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed2, seed2_len) <= 0)
        goto err;
    if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed3, seed3_len) <= 0)
        goto err;
    if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed4, seed4_len) <= 0)
        goto err;
    if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed5, seed5_len) <= 0)
        goto err;

    if (EVP_PKEY_derive(pctx, out, &outlen) <= 0)
        goto err;
    ret = 1;

err:
    if (ret == 0)
        WARN("# FAIL: performing qat_PRF operations\n");
    EVP_PKEY_CTX_free(pctx);
    return ret;
}


static int runTlsPrfOps(void *args)
{
    TEST_PARAMS *temp_args = (TEST_PARAMS *)args;
    struct async_additional_args_kdf *temp_add_args =
         (struct async_additional_args_kdf *) temp_args->additional_args;
    int operation = temp_add_args->operation;
    int print_output = temp_args->print_output;
    int verify = temp_args->verify;
    char *tls_version = temp_args->tls_version;
    char *digest_kdf = temp_args->digest_kdf;
    const EVP_MD *md[SSL_MAX_DIGEST];
    int md_count = 0, version = 0;
    void *seed1 = NULL, *seed2 = NULL, *seed3 = NULL, *seed4 = NULL,
        *seed5 = NULL;
    int seed1_len = 0, seed2_len = 0, seed3_len = 0, seed4_len = 0,
        seed5_len = 0;
    int secSize = 0, buff_len = 0;
    unsigned char *secret = NULL, *expectedMasterSecret = NULL;
    unsigned char *masterSecret = NULL;
    int res = 0;
    size_t masterSecretSize = 0;
    int count = 0;

    OpenSSL_add_all_digests();

    for (count = 0; count < *(temp_args->count); count++) {
        if(!strcmp(tls_version, "TLSv1_2")) {
            md_count=1;
            version = TLS1_2_VERSION;
            if(!strcmp(digest_kdf, "SHA256") ){
                md[0] = EVP_get_digestbyname(SN_sha256);
            } else if(!strcmp(digest_kdf, "SHA384")){
                md[0] = EVP_get_digestbyname(SN_sha384);
            } else if(!strcmp(digest_kdf, "SHA512")){
                md[0] = EVP_get_digestbyname(SN_sha512);
            }
        } else if(!strcmp(tls_version, "TLSv1") ||
                  !strcmp(tls_version, "TLSv1_1")) {
            md_count = 1;

            /* This does not need to be done when using the QAT Engine
             * but we will do it anyway as otherwise if prf is disabled
             *in the build we will crash when we drop to software. */
            md[0] = EVP_get_digestbyname(SN_md5_sha1);
            if (!strcmp(tls_version, "TLSv1"))
                version = TLS1_VERSION;
            else
                version = TLS1_1_VERSION;
        } else if(!strcmp(tls_version, "SSLv3")) {
            WARN("# FAIL: SSL3 version is currently not supported!!\n");
            return res;
        }

        switch(operation) {
            case 0: /*TLS_MD_MASTER_SECRET_CONST*/
                if (count == 0)
                    printf("Validating: TLS_MD_MASTER_SECRET_CONST\n");
                seed1 = TLS_MD_MASTER_SECRET_CONST;
                seed1_len = TLS_MD_MASTER_SECRET_CONST_SIZE;
                populateMasterSecret(&seed2, &seed2_len, &seed3, &seed3_len,
                                     &seed4, &seed4_len, &seed5, &seed5_len,
                                     &secret, &secSize, &buff_len,
                                     &masterSecretSize, &expectedMasterSecret,
                                     version, digest_kdf);
                break;
            case 1: /*TLS_MD_KEY_EXPANSION_CONST*/
                if (count == 0)
                    printf("Validating: TLS_MD_KEY_EXPANSION_CONST\n");
                seed1 = TLS_MD_KEY_EXPANSION_CONST;
                seed1_len = TLS_MD_KEY_EXPANSION_CONST_SIZE;
                populateMdKeyExpansion(&seed2, &seed2_len, &seed3, &seed3_len,
                                       &seed4, &seed4_len, &seed5, &seed5_len,
                                       &secret, &secSize, &buff_len,
                                       &masterSecretSize, &expectedMasterSecret,
                                       version, digest_kdf);
                break;
            case 2: /*TLS_MD_CLIENT_FINISH_CONST*/
                if (count == 0)
                    printf("Validating: TLS_MD_CLIENT_FINISH_CONST\n");
                seed1 = TLS_MD_CLIENT_FINISH_CONST;
                seed1_len = TLS_MD_CLIENT_FINISH_CONST_SIZE;
                populateMdClientFinished(&seed2, &seed2_len, &seed3, &seed3_len,
                                         &seed4, &seed4_len, &seed5, &seed5_len,
                                         &secret, &secSize, &buff_len,
                                         &masterSecretSize, &expectedMasterSecret,
                                         version, digest_kdf);
                break;
            case 3: /*TLS_MD_SERVER_FINISH_CONST*/
                if (count == 0)
                    printf("Validating: TLS_MD_SERVER_FINISH_CONST\n");
                seed1 = TLS_MD_SERVER_FINISH_CONST;
                seed1_len = TLS_MD_SERVER_FINISH_CONST_SIZE;
                populateMdServerFinished(&seed2, &seed2_len, &seed3, &seed3_len,
                                         &seed4, &seed4_len, &seed5, &seed5_len,
                                         &secret, &secSize, &buff_len,
                                         &masterSecretSize, &expectedMasterSecret,
                                         version, digest_kdf);
                break;
            case 4: /*TLS_MD_EXTENDED_MASTER_SECRET_CONST*/
                if (count == 0)
                    printf("Validating: TLS_MD_EXTENDED_MASTER_SECRET_CONST\n");
                seed1 = TLS_MD_EXTENDED_MASTER_SECRET_CONST;
                seed1_len = TLS_MD_EXTENDED_MASTER_SECRET_CONST_SIZE;
                populateExtendedMasterSecret(&seed2, &seed2_len, &seed3, &seed3_len,
                                             &seed4, &seed4_len, &seed5, &seed5_len,
                                             &secret, &secSize, &buff_len,
                                             &masterSecretSize, &expectedMasterSecret,
                                             version, digest_kdf);
                break;
        }

        masterSecret = OPENSSL_malloc(sizeof (unsigned char) * masterSecretSize);

        res = qat_PRF(md,
                      md_count,
                      seed1, seed1_len,
                      seed2, seed2_len,
                      seed3, seed3_len,
                      seed4, seed4_len,
                      seed5, seed5_len,
                      secret, secSize,
                      masterSecret, masterSecretSize);

        if ((verify && count == 0) || res == 0) {
            if (memcmp(masterSecret,expectedMasterSecret,masterSecretSize)) {
                INFO("# FAIL verify for PRF.\n");
                tests_hexdump("PRF actual  :", masterSecret, masterSecretSize);
                tests_hexdump("PRF expected:", expectedMasterSecret, masterSecretSize);
                res = 0;
            }
            else {
                INFO("# PASS verify for PRF.\n");
            }
        }
        if (print_output)
            tests_hexdump("PRF master secret:", masterSecret, masterSecretSize);

        if (masterSecret)
            OPENSSL_free(masterSecret);
    }
    return res;
}


/******************************************************************************
* function:
*   tests_run_prf     (TEST_PARAMS *args)
*
*
* @param args         [IN] - the test parameters
*
* Description:
*  This is a function to test the PRF (Pseudo Random Function) used in TLS1.2
******************************************************************************/

void tests_run_prf(TEST_PARAMS *args)
{
    struct async_additional_args_kdf extra_args;
    int operation = 0;

    args->additional_args =  &extra_args;
    extra_args.operation = 0; /* Operation if not specified for performance tests */

    if (args->performance || args->prf_op != -1 ) {
        if (args->prf_op != -1)
            extra_args.operation = args->prf_op;
        if (!args->enable_async) {
            runTlsPrfOps(args);
        } else {
            start_async_job(args, runTlsPrfOps);
        }
        return;
    }
    if (!args->enable_async) {
        for (operation = 0; operation < 5; operation++) {
            extra_args.operation = operation;
            runTlsPrfOps(args);
        }
    } else {
        for (operation = 0; operation < 5; operation++) {
            extra_args.operation = operation;
            start_async_job(args, runTlsPrfOps);
        }
    }
}
