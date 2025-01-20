/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2021-2025 Intel Corporation.
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

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/async.h>
#include <openssl/objects.h>
#include <openssl/dh.h>
#include <openssl/engine.h>

#include "tests.h"
#include "../qat_utils.h"

#ifndef QAT_OPENSSL_PROVIDER
static const unsigned char BNp_512[] = {
    0xFA, 0xF7, 0x2D, 0x97, 0x66, 0x5C, 0x47, 0x66,
    0xB9, 0xBB, 0x3C, 0x33, 0x75, 0xCC, 0x54, 0xE0,
    0x71, 0x12, 0x1F, 0x90, 0xB4, 0xAA, 0x94, 0x4C,
    0xB8, 0x8E, 0x4B, 0xEE, 0x64, 0xF9, 0xD3, 0xF8,
    0x71, 0xDF, 0xB9, 0xA7, 0x05, 0x55, 0xDF, 0xCE,
    0x39, 0x19, 0x3D, 0x1B, 0xEB, 0xD5, 0xFA, 0x63,
    0x01, 0x52, 0x2E, 0x01, 0x7B, 0x05, 0x33, 0x5F,
    0xF5, 0x81, 0x6A, 0xF9, 0xC8, 0x65, 0xC7, 0x65
};

static const unsigned char BNp_1024[] = {
    0xC1, 0xF1, 0x54, 0x26, 0x9C, 0x53, 0xC7, 0x22,
    0x29, 0xBC, 0x03, 0x29, 0x00, 0x73, 0x61, 0xA7,
    0x20, 0x7A, 0x1E, 0x75, 0x6C, 0x01, 0xCA, 0x8D,
    0xE8, 0x9B, 0x4E, 0x1C, 0xC7, 0x59, 0x14, 0x35,
    0x63, 0x29, 0x56, 0x09, 0x57, 0xD8, 0x01, 0x2F,
    0xAD, 0x8F, 0x16, 0x78, 0x78, 0x9D, 0xA1, 0x03,
    0x74, 0x5F, 0xAC, 0x7A, 0x37, 0x76, 0x12, 0x50,
    0xF4, 0xBB, 0x4C, 0xCE, 0xD8, 0xF7, 0x87, 0x31,
    0xD9, 0x45, 0xFC, 0xB6, 0xBF, 0xD5, 0x08, 0xFB,
    0xA9, 0xBC, 0xA4, 0xA8, 0x65, 0x77, 0x69, 0xA4,
    0x89, 0xD4, 0xB4, 0x40, 0x58, 0xCC, 0xF8, 0x62,
    0x1A, 0x3E, 0x7B, 0x7A, 0x0E, 0x01, 0xA5, 0x8B,
    0x1D, 0x5B, 0xED, 0xB1, 0x0D, 0x4A, 0x44, 0x70,
    0x3B, 0xE7, 0x93, 0x4A, 0xC8, 0xFB, 0xAE, 0x81,
    0x77, 0xC0, 0x23, 0x7D, 0xBB, 0x96, 0x72, 0xF7,
    0x42, 0xFF, 0x80, 0xD6, 0x87, 0xE5, 0x97, 0xCB
};

static const unsigned char BNp_2048[]= {
    0xFC, 0x90, 0x16, 0xE9, 0x4B, 0xE4, 0x28, 0x49,
    0xC2, 0xDF, 0x6E, 0xFC, 0xF4, 0xB1, 0xC5, 0xBC,
    0x48, 0xD1, 0xEC, 0x3C, 0xE6, 0xEA, 0xDC, 0x8E,
    0x5B, 0x51, 0x8A, 0x48, 0xCF, 0xC9, 0xB1, 0xAC,
    0x29, 0x30, 0x45, 0x22, 0x07, 0x71, 0x6C, 0x05,
    0x2D, 0xE8, 0xEE, 0x46, 0x16, 0xC3, 0x8B, 0xFE,
    0x65, 0xF5, 0xDA, 0x68, 0x76, 0x4F, 0x0D, 0x05,
    0x15, 0x9B, 0x21, 0xF6, 0x1C, 0x92, 0xCD, 0xFE,
    0xBE, 0x2F, 0xD0, 0x79, 0xA5, 0x6C, 0x23, 0xC6,
    0x00, 0xC9, 0xBB, 0xD1, 0x63, 0xCD, 0x06, 0x21,
    0xD1, 0xD3, 0x55, 0x2F, 0x1E, 0x38, 0x5A, 0xCC,
    0x49, 0x85, 0x13, 0xFE, 0xA0, 0x55, 0x1F, 0x51,
    0xE3, 0xE3, 0xA2, 0x3F, 0x00, 0x04, 0xAB, 0xB4,
    0xF3, 0x5A, 0x53, 0x82, 0xD0, 0xD5, 0xD7, 0x5A,
    0x11, 0xE5, 0xE3, 0xDB, 0x57, 0xA8, 0xB3, 0xB8,
    0x70, 0xF8, 0x6E, 0xEC, 0xC0, 0x46, 0x82, 0xEC,
    0x98, 0xBD, 0xE0, 0xD2, 0xB2, 0x5E, 0x44, 0x51,
    0x41, 0x18, 0x66, 0x93, 0xF1, 0xA5, 0xF3, 0x86,
    0xC9, 0x9D, 0xEC, 0x80, 0x78, 0x0B, 0x7E, 0x13,
    0xF9, 0xDF, 0x78, 0x0E, 0x0D, 0x23, 0xBB, 0x6A,
    0xF2, 0x9C, 0xBF, 0x2F, 0xD3, 0xF1, 0xFA, 0xC4,
    0xA1, 0xEB, 0xF3, 0x53, 0xBD, 0x4C, 0xDF, 0x8C,
    0xBB, 0x4A, 0x41, 0x90, 0x54, 0x72, 0x8B, 0x8D,
    0xAA, 0xAF, 0x3B, 0x2C, 0x52, 0x6F, 0x27, 0x0E,
    0xDD, 0x82, 0xF8, 0xC8, 0x72, 0xDB, 0xE1, 0x6A,
    0x81, 0x5D, 0xA4, 0xE2, 0x45, 0xA6, 0xA6, 0x7D,
    0x7B, 0x82, 0x08, 0x8B, 0x03, 0xD2, 0x70, 0xD3,
    0x9B, 0x9B, 0x05, 0x6D, 0x63, 0x1F, 0x37, 0x32,
    0xCF, 0xAE, 0xA9, 0x4B, 0xAD, 0x50, 0xB0, 0xF1,
    0xA1, 0x75, 0x4B, 0xF9, 0xEF, 0x38, 0x18, 0x94,
    0x2C, 0x30, 0x26, 0x0D, 0x63, 0x70, 0x24, 0xED,
    0x7D, 0x2F, 0xDD, 0x96, 0xD2, 0x7E, 0xD1, 0xD7
};


static const unsigned char BNp_4096[]= {
    0xBF, 0x01, 0x78, 0x3A, 0x05, 0xC6, 0x8E, 0xFA,
    0x4E, 0x42, 0x93, 0xFC, 0x2F, 0x80, 0x26, 0x09,
    0xC5, 0x59, 0x7A, 0xC6, 0x5E, 0x15, 0xD8, 0xBF,
    0x46, 0x0F, 0xAB, 0x10, 0xD9, 0x01, 0x3A, 0x76,
    0x32, 0xCE, 0xB6, 0x8D, 0x7D, 0x10, 0x7E, 0xA3,
    0xE1, 0x12, 0x9F, 0xCF, 0x64, 0x54, 0xB9, 0x38,
    0x96, 0x0D, 0x2B, 0xDC, 0xE8, 0x1D, 0x6E, 0x34,
    0x45, 0xAE, 0x4E, 0x49, 0x36, 0x5C, 0x33, 0x1E,
    0x1E, 0xE4, 0xB5, 0x76, 0x87, 0x19, 0x82, 0x4B,
    0xDA, 0xC6, 0x0F, 0x5B, 0x28, 0x8A, 0x82, 0xB7,
    0x2D, 0x3A, 0xDC, 0x0C, 0x68, 0x0B, 0xA5, 0xE6,
    0x69, 0xCC, 0x9F, 0x87, 0x19, 0xFE, 0x65, 0xDE,
    0xFE, 0x6A, 0xDD, 0xE2, 0x68, 0x08, 0x2B, 0x79,
    0x4D, 0xA7, 0x23, 0x7C, 0x96, 0x92, 0x8B, 0x3A,
    0x6E, 0x36, 0x64, 0xD0, 0x91, 0x01, 0xDC, 0x7B,
    0x7B, 0x44, 0x2A, 0xAD, 0xA2, 0x26, 0x6D, 0x3A,
    0xD5, 0xF6, 0xEA, 0x56, 0x58, 0x4D, 0xA7, 0x4E,
    0xC7, 0x8C, 0x4B, 0x61, 0x9C, 0x9F, 0x1F, 0xFD,
    0x65, 0xC2, 0xA8, 0xAC, 0x94, 0x8A, 0xF8, 0x65,
    0x73, 0x08, 0x5A, 0x27, 0x6E, 0x0B, 0xE3, 0xAF,
    0xB5, 0x19, 0xEA, 0x22, 0xFA, 0x91, 0x5A, 0x65,
    0xD1, 0x5A, 0x28, 0x4C, 0xF3, 0x06, 0xAA, 0x37,
    0xDD, 0xB7, 0x19, 0x38, 0xCD, 0x5B, 0xED, 0x0D,
    0x9C, 0x59, 0xED, 0x02, 0x44, 0x3C, 0x02, 0xC2,
    0xEC, 0xAF, 0xCF, 0x62, 0xC8, 0xD4, 0x36, 0x78,
    0x68, 0x43, 0x86, 0x6F, 0x3F, 0xFD, 0x58, 0x4D,
    0x15, 0x86, 0xCB, 0xF3, 0x3E, 0xE0, 0xEF, 0x2F,
    0xD5, 0x5E, 0x3A, 0x81, 0xAB, 0x6D, 0x85, 0xD2,
    0x8E, 0x6D, 0x84, 0x35, 0xC8, 0xFD, 0x42, 0x3A,
    0xCB, 0x9A, 0x5C, 0x25, 0xC6, 0x92, 0x60, 0xAB,
    0xED, 0xC3, 0x04, 0x6E, 0xDE, 0x7F, 0xD4, 0x68,
    0xC9, 0xAE, 0xB6, 0xC1, 0xF7, 0xCE, 0x28, 0x2C,
    0xE7, 0x66, 0xA1, 0xF9, 0x62, 0x50, 0x3C, 0x20,
    0x57, 0x1E, 0x7F, 0x74, 0xB8, 0x52, 0x42, 0xB8,
    0x70, 0xFF, 0x32, 0x46, 0x8C, 0x34, 0xC5, 0x6A,
    0x11, 0x62, 0x1E, 0x03, 0xFB, 0x79, 0x1F, 0x9B,
    0xAC, 0xAF, 0xED, 0x9E, 0x98, 0xC8, 0xF9, 0x4F,
    0x68, 0x85, 0xD3, 0x3C, 0x07, 0xE9, 0xBB, 0x41,
    0x67, 0x0C, 0x79, 0x28, 0x3F, 0xF5, 0x8B, 0x8E,
    0xAC, 0xB5, 0x80, 0x40, 0x0C, 0x90, 0x33, 0x68,
    0xE3, 0x4F, 0x97, 0xE7, 0x94, 0x22, 0x20, 0x80,
    0x01, 0x1A, 0x9F, 0x1F, 0x6F, 0x22, 0x06, 0x05,
    0xC7, 0x86, 0x85, 0x1B, 0xF8, 0x7A, 0xB0, 0xF6,
    0xFB, 0xA5, 0x59, 0xF8, 0xA5, 0xFB, 0xC1, 0x88,
    0xF9, 0x33, 0xF0, 0x38, 0xBB, 0xF0, 0x14, 0x1C,
    0xFE, 0xAF, 0x14, 0x9A, 0xCF, 0xBE, 0xF4, 0xF6,
    0x9C, 0x73, 0xE4, 0xF4, 0x81, 0x41, 0x30, 0x8C,
    0x53, 0xA9, 0x17, 0xA2, 0x8C, 0xF9, 0xA4, 0x0C,
    0xFD, 0x29, 0x26, 0x49, 0x70, 0x20, 0xFB, 0xB5,
    0x34, 0x5C, 0x04, 0x86, 0x49, 0x4C, 0xFF, 0x8D,
    0x45, 0x25, 0xFB, 0x80, 0x37, 0x54, 0xCC, 0x74,
    0xCC, 0xBF, 0x39, 0x3B, 0x9A, 0x43, 0xF6, 0x44,
    0xEB, 0x0B, 0x88, 0xE8, 0xFF, 0x9F, 0x82, 0xCE,
    0x6F, 0x0A, 0x16, 0x7E, 0x5A, 0x50, 0x34, 0x8A,
    0x8A, 0x39, 0x19, 0x4D, 0x1B, 0x1F, 0x4E, 0x1D,
    0x7A, 0x12, 0x9A, 0x5B, 0x29, 0xD0, 0x3D, 0xAA,
    0x2D, 0x4B, 0x59, 0xCA, 0x29, 0xC3, 0x7F, 0xF9,
    0xD7, 0x36, 0x74, 0xE7, 0x86, 0x11, 0x83, 0x7C,
    0xDD, 0x45, 0xC8, 0x27, 0x39, 0xC1, 0x9D, 0x2A,
    0xDB, 0x57, 0xA4, 0x5B, 0x8F, 0x50, 0x4A, 0x3D,
    0xFD, 0x98, 0x45, 0xE6, 0x33, 0x50, 0xA1, 0xF4,
    0xF7, 0x4D, 0xB7, 0x99, 0x7E, 0x04, 0x3E, 0xC7,
    0x9E, 0xF0, 0x4C, 0xA9, 0xB3, 0x25, 0x88, 0xE3,
    0x25, 0xCA, 0x2A, 0x6F, 0xDD, 0xD3, 0xE3, 0xBF
};

static const unsigned char BNp_8192[]= {
    0xd5, 0x02, 0x2e, 0xc7, 0xc1, 0xd7, 0x19, 0xbe,
    0x50, 0xea, 0x20, 0xa6, 0x51, 0x0e, 0x6f, 0x2b,
    0x92, 0xe4, 0x47, 0x76, 0xca, 0x16, 0xbe, 0x93,
    0x4b, 0x8d, 0xb8, 0xeb, 0x28, 0x60, 0xb5, 0x64,
    0x42, 0xb2, 0x0b, 0x93, 0x9b, 0x45, 0xc7, 0xcc,
    0x58, 0x5e, 0x65, 0x90, 0x98, 0x5e, 0x40, 0xdb,
    0xd8, 0x57, 0x7e, 0x2b, 0x6f, 0x48, 0x37, 0xce,
    0x4f, 0x95, 0x5b, 0xae, 0x25, 0xb5, 0x2e, 0x1f,
    0x4f, 0xc9, 0xf4, 0xd5, 0x71, 0x47, 0x21, 0xfd,
    0xf0, 0x4f, 0x93, 0xb0, 0x10, 0x6e, 0x1b, 0x19,
    0xd4, 0x23, 0xc7, 0xe7, 0x5c, 0x35, 0x7e, 0x38,
    0xfb, 0xf7, 0xa0, 0xc8, 0x08, 0x20, 0x9d, 0x1c,
    0x3c, 0xd4, 0x17, 0xcf, 0xe8, 0x0f, 0x94, 0xa4,
    0x1f, 0x56, 0x38, 0xfa, 0xc7, 0x5e, 0x43, 0xd1,
    0xbe, 0x16, 0xc7, 0xe9, 0xd7, 0x7e, 0xf1, 0x30,
    0x2a, 0xe0, 0xa2, 0x3e, 0xdc, 0xf9, 0x6d, 0x14,
    0x03, 0xa8, 0x9f, 0x98, 0xf7, 0x1b, 0x96, 0x2f,
    0x21, 0xf1, 0x04, 0xa0, 0x18, 0x33, 0x99, 0x14,
    0x91, 0x86, 0x29, 0xb4, 0x76, 0xb3, 0x21, 0x23,
    0x92, 0x14, 0x1f, 0x71, 0x29, 0x15, 0x51, 0xb0,
    0x42, 0xf8, 0xd3, 0xa8, 0xd7, 0xae, 0x6d, 0xf7,
    0x03, 0x59, 0x43, 0xf0, 0x2d, 0xd8, 0x9b, 0xdc,
    0x76, 0x1b, 0xb4, 0x9f, 0x18, 0xb7, 0x2e, 0xbb,
    0x43, 0x1a, 0x1a, 0xe4, 0xac, 0xde, 0x16, 0xfb,
    0xc8, 0xdb, 0x27, 0xae, 0xe7, 0x42, 0xae, 0x81,
    0x02, 0x9b, 0x1f, 0x53, 0x45, 0xa3, 0x40, 0xa8,
    0x62, 0x46, 0x68, 0x89, 0xfc, 0x7f, 0x07, 0x54,
    0xb3, 0x30, 0x17, 0xe0, 0x26, 0xde, 0x32, 0xc6,
    0x26, 0x1b, 0xf4, 0x10, 0x17, 0xf0, 0xd0, 0xd7,
    0xfa, 0x66, 0xaa, 0x13, 0x21, 0x98, 0x64, 0x10,
    0xd5, 0xf3, 0x8b, 0x06, 0x4c, 0xa0, 0xa6, 0x49,
    0x7f, 0x61, 0x78, 0xea, 0xa8, 0xe5, 0x55, 0xfb,
    0x01, 0x5e, 0x06, 0x9d, 0x3b, 0x6d, 0x39, 0x49,
    0x3d, 0x9c, 0xc3, 0x6a, 0x67, 0x1e, 0x58, 0xd6,
    0xa4, 0x06, 0x3f, 0xf2, 0xa0, 0x84, 0x45, 0xaa,
    0xaf, 0x06, 0x0e, 0x9a, 0xa4, 0x8e, 0x57, 0x30,
    0xa2, 0x1f, 0xc5, 0xc8, 0x41, 0x9e, 0x7f, 0x7b,
    0xfb, 0xa4, 0x2c, 0x66, 0x50, 0x08, 0xff, 0xca,
    0x80, 0x09, 0x1b, 0xd3, 0x63, 0xc5, 0x01, 0xe0,
    0x9d, 0xbf, 0xf5, 0x17, 0xe6, 0xa4, 0xc7, 0xd5,
    0x37, 0x2c, 0x87, 0x11, 0x13, 0x35, 0xeb, 0x67,
    0xee, 0xad, 0x75, 0x67, 0x09, 0xbf, 0x0e, 0x98,
    0x01, 0xa3, 0xc2, 0x21, 0x94, 0x91, 0xec, 0x88,
    0x22, 0xb3, 0x8c, 0xd4, 0x55, 0x73, 0x00, 0x8e,
    0xf4, 0xea, 0x65, 0xca, 0x2b, 0x08, 0xc3, 0x8a,
    0x85, 0xe5, 0x4b, 0x78, 0x10, 0xe7, 0x4e, 0x29,
    0x84, 0x2d, 0x26, 0xf6, 0x7c, 0x3f, 0xe4, 0x82,
    0x97, 0xb0, 0x63, 0x2e, 0x58, 0xb0, 0xf9, 0x75,
    0xd1, 0x1d, 0x5a, 0x10, 0x65, 0xfb, 0xcc, 0xa4,
    0x08, 0x79, 0x80, 0x7e, 0x04, 0xb4, 0x23, 0xe1,
    0x31, 0x1e, 0xcb, 0x4c, 0x84, 0x47, 0x80, 0xc4,
    0x80, 0x67, 0xb0, 0x00, 0x8c, 0xe9, 0x8b, 0x7f,
    0xcc, 0xfe, 0xd4, 0xe8, 0xc6, 0x1a, 0xa0, 0xd8,
    0xc2, 0x0d, 0xe7, 0x10, 0x5f, 0xdf, 0xf5, 0xe8,
    0xe9, 0x52, 0x08, 0x1f, 0xfe, 0x67, 0xd5, 0x14,
    0x18, 0x11, 0x40, 0xba, 0x23, 0x34, 0x53, 0x34,
    0x63, 0x75, 0x6a, 0xc4, 0x62, 0x99, 0x2a, 0x63,
    0x91, 0xbd, 0xd5, 0x93, 0x39, 0xff, 0x5c, 0x06,
    0x90, 0x2c, 0x9a, 0xc2, 0x22, 0x70, 0x1b, 0x85,
    0x22, 0xfe, 0x9c, 0x7d, 0xc0, 0x2f, 0x6a, 0xd2,
    0xa5, 0x59, 0xd9, 0x7a, 0x60, 0xd2, 0xe0, 0xd2,
    0x24, 0xfd, 0x1c, 0xc5, 0x06, 0xe8, 0xf6, 0x6a,
    0x67, 0x56, 0x17, 0x81, 0x33, 0xdc, 0x37, 0x5a,
    0x1a, 0xc2, 0x18, 0x51, 0xf1, 0x27, 0xca, 0x8d,
    0xd3, 0x4f, 0xe3, 0x21, 0x98, 0x26, 0xf4, 0xd9,
    0x26, 0xca, 0xb3, 0x2c, 0x46, 0x26, 0x1c, 0x2f,
    0xa9, 0x97, 0xe8, 0x25, 0xd7, 0x5d, 0x6e, 0xf1,
    0x81, 0x5b, 0x19, 0x49, 0x56, 0xc5, 0x6b, 0xdc,
    0x2d, 0x97, 0x20, 0x30, 0x9f, 0x87, 0x68, 0x6e,
    0x6f, 0x64, 0xec, 0x08, 0x69, 0x88, 0x3f, 0x53,
    0x26, 0x30, 0x80, 0x82, 0xee, 0x0d, 0x00, 0xca,
    0x1b, 0x83, 0x98, 0xe6, 0x91, 0x3c, 0x6c, 0x56,
    0x7b, 0xf9, 0xeb, 0x0f, 0x92, 0xe4, 0x3d, 0x7c,
    0x6c, 0x22, 0x33, 0x61, 0xe2, 0x04, 0x9f, 0x6b,
    0x91, 0xac, 0x29, 0x56, 0x2f, 0x91, 0x3c, 0x5a,
    0x5b, 0x5b, 0x18, 0x8e, 0x1b, 0xc9, 0xae, 0x50,
    0x2a, 0x9d, 0x40, 0x1c, 0x50, 0xa6, 0x87, 0xc4,
    0x08, 0xaa, 0x72, 0xae, 0xc0, 0xab, 0x76, 0x5f,
    0x1b, 0x27, 0x35, 0x0e, 0x1e, 0x45, 0x59, 0xc3,
    0x82, 0xe0, 0x15, 0xc7, 0x88, 0x8e, 0x70, 0x6d,
    0x83, 0x0a, 0x1f, 0x22, 0x57, 0x16, 0x85, 0xf3,
    0xc0, 0x6f, 0xa5, 0x3a, 0x4f, 0x1c, 0x52, 0xbc,
    0x21, 0x3c, 0x48, 0xfc, 0x47, 0x8c, 0xdf, 0x31,
    0xfb, 0xdb, 0x85, 0xdd, 0x45, 0xf3, 0x40, 0x52,
    0x5d, 0xa0, 0x92, 0x32, 0x20, 0x77, 0x06, 0x0a,
    0xb5, 0xe1, 0x1c, 0xea, 0x62, 0xc7, 0x7d, 0xfa,
    0x0d, 0x8d, 0x9a, 0x74, 0x61, 0xc2, 0xfc, 0x08,
    0xd7, 0x5b, 0x72, 0x37, 0x7e, 0xbd, 0x77, 0xa1,
    0x1e, 0xc8, 0xb8, 0x3f, 0x29, 0x53, 0x1c, 0xcc,
    0x16, 0x23, 0xd9, 0x90, 0x36, 0xdd, 0xca, 0x15,
    0x14, 0xa7, 0x2d, 0xbb, 0xeb, 0xfb, 0xfc, 0xf5,
    0x62, 0x12, 0xab, 0x61, 0xba, 0xb3, 0x3b, 0x1b,
    0x6e, 0x3f, 0x5c, 0x5a, 0xda, 0x08, 0x5a, 0x34,
    0x18, 0xd0, 0x81, 0xbf, 0x7b, 0x77, 0x72, 0x1d,
    0x02, 0xd3, 0xe3, 0xe9, 0xa9, 0x71, 0x73, 0x8e,
    0x76, 0x14, 0xeb, 0xcf, 0xb6, 0xf3, 0x7f, 0x99,
    0xfd, 0x62, 0x9e, 0x43, 0x09, 0xbd, 0x44, 0xee,
    0xfc, 0xbf, 0xd0, 0x63, 0x52, 0xa0, 0x8e, 0xe4,
    0x98, 0x37, 0xb1, 0x99, 0xb1, 0xab, 0x59, 0xf5,
    0x34, 0xa2, 0xa5, 0x08, 0x89, 0x0f, 0x5b, 0x81,
    0x8a, 0xc7, 0x35, 0x05, 0xfd, 0x63, 0xfa, 0xb4,
    0xb4, 0x15, 0xd0, 0x0a, 0xee, 0xaa, 0x20, 0xf1,
    0x49, 0x7f, 0x24, 0xa5, 0x0f, 0xb1, 0x0c, 0x57,
    0x19, 0xcd, 0xca, 0xb3, 0x83, 0xfc, 0x9b, 0x29,
    0x06, 0x75, 0xc2, 0x34, 0xed, 0x5e, 0x3f, 0x60,
    0x34, 0xb2, 0x1e, 0xcf, 0x9e, 0x60, 0xbf, 0x90,
    0xb0, 0xfa, 0xa4, 0xfc, 0x88, 0x9b, 0x10, 0x3b,
    0x96, 0xa4, 0xaf, 0xfe, 0x79, 0xc4, 0xdd, 0xca,
    0x27, 0xbe, 0xed, 0x8c, 0xc8, 0x77, 0x0f, 0x6b,
    0x8e, 0xa0, 0x29, 0x48, 0xb9, 0xd2, 0xc1, 0xb1,
    0x93, 0x75, 0xe4, 0xb5, 0xcc, 0x10, 0x22, 0x75,
    0xad, 0xdd, 0x93, 0x33, 0xbd, 0xbe, 0xdb, 0xb6,
    0x2c, 0xdc, 0xaa, 0xda, 0x96, 0x36, 0x89, 0x58,
    0xce, 0x12, 0x15, 0xc6, 0xe7, 0x68, 0xd2, 0x34,
    0x33, 0x73, 0x69, 0x1c, 0xa8, 0x17, 0x35, 0x26,
    0x85, 0x9e, 0x6d, 0xb2, 0xf4, 0x97, 0x3f, 0xbd,
    0xce, 0xe7, 0xe4, 0xf8, 0x69, 0x8e, 0xf9, 0x80,
    0xce, 0x0c, 0xb2, 0x07, 0x26, 0x75, 0x43, 0x58,
    0xca, 0x3b, 0x63, 0x68, 0xe5, 0x9f, 0x98, 0xbc,
    0x5e, 0xf6, 0x1e, 0xd5, 0x81, 0x5b, 0xc9, 0x0c,
    0x94, 0xd7, 0x0b, 0x13, 0xd9, 0x34, 0x68, 0xbf,
    0x73, 0xa2, 0xff, 0x0b, 0x19, 0x66, 0xda, 0x21,
    0xa5, 0x38, 0x0a, 0x5a, 0xa2, 0x98, 0xb4, 0x5f,
    0x53, 0x04, 0x10, 0x3f, 0x87, 0xdf, 0xf8, 0x11,
    0xa8, 0xcd, 0x29, 0xc3, 0x91, 0xb6, 0x03, 0xe1,
    0x19, 0x19, 0x2c, 0xc4, 0x98, 0x1a, 0x00, 0xce,
    0xaa, 0xd3, 0x60, 0x8c, 0xb3, 0xcd, 0xd5, 0x9b,
    0x2d, 0x07, 0x6b, 0x4c, 0x85, 0x50, 0xd0, 0xf7
};

static const unsigned char BNg[] = {0x05};
#endif

#ifdef QAT_OPENSSL_PROVIDER

#define NID_dh2048 1126
#define NID_dh3072 1127
#define NID_dh4096 1128
#define NID_dh8192 1130

#define MAX_DH_SIZE 1024

static unsigned int get_dh_nid(int size)
{
    switch (size)
    {
    case 2048:
        return NID_dh2048;
    case 3072:
        return NID_dh3072;
    case 4096:
        return NID_dh4096;
    case 8192:
        return NID_dh8192;
    default:
        INFO("dh %d size is not supported!\n", size);
    }
    return 0;
}

#endif

/******************************************************************************
* function:
*           run_dh (void *args)
*
* @param args [IN] - the test parameters
*
* description:
*   The function is design to test DH key generation and verify using qat engine.
*   If the verify flag raised, two DH public keys are generate separately
*   with and without DH_FLAG_NO_EXP_CONSTTIME flag. And the verification compares
*   the outputs of each DH_compute_key() after exchange two public keys.
*
********************************************************************************/
static int run_dh(void *args)
{
    TEST_PARAMS *temp_args = (TEST_PARAMS *)args;
    int size = temp_args->size;
    int ret = 1;

#ifndef QAT_OPENSSL_PROVIDER
    int count = *(temp_args->count);
    int print_output = temp_args->print_output;
    int verify = temp_args->verify;

    DH *dh_a = NULL;
    DH *dh_b = NULL;
    BIGNUM *p_a = NULL, *q_a = NULL;
    BIGNUM *g_a = NULL;
    const BIGNUM *pub_key_a = NULL, *priv_key_a = NULL;
    BIGNUM *p_b = NULL, *q_b = NULL;
    BIGNUM *g_b = NULL;
    const BIGNUM *pub_key_b = NULL, *priv_key_b = NULL;
    char buf[12] = {0};
    unsigned char *abuf = NULL, *bbuf = NULL;
    int i = 0, alen = 0, blen = 0, aout = 0, bout = 0;
    BIO *out = NULL;
    out = BIO_new(BIO_s_file());
    if (out == NULL)
        goto err;
    BIO_set_fp(out, stdout, BIO_NOCLOSE);

    if ((dh_a = DH_new()) == NULL) {
        WARN("# FAIL DH creating object dh_a.\n");
        ret = 0;
        goto err;
    }

    if (size <= 512)
        p_a = BN_bin2bn(BNp_512, sizeof(BNp_512), NULL);
    if (size > 512 && size <= 1024)
        p_a = BN_bin2bn(BNp_1024, sizeof(BNp_1024), NULL);
    if (size > 1024 && size <= 2048)
        p_a = BN_bin2bn(BNp_2048, sizeof(BNp_2048), NULL);
    if (size > 2048 && size <= 4096)
        p_a = BN_bin2bn(BNp_4096, sizeof(BNp_4096), NULL);
    if (size > 4096)
        p_a = BN_bin2bn(BNp_8192, sizeof(BNp_8192), NULL);

    g_a = BN_bin2bn(BNg, sizeof(BNg), NULL);

    if (!p_a || !g_a) {
        WARN("# FAIL DH creating p and g.\n");
        ret = 0;
        if (p_a) BN_free(p_a);
        if (g_a) BN_free(g_a);
        goto err;
    }

    if (!DH_set0_pqg(dh_a, p_a, q_a, g_a)) {
        WARN("# FAIL DH setting p and g for key a.\n");
        ret = 0;
        if (p_a) BN_free(p_a);
        if (g_a) BN_free(g_a);
        goto err;
    }

    dh_b = DH_new();
    if (dh_b == NULL) {
        WARN("# FAIL DH creating object dh_b.\n");
        ret = 0;
        goto err;
    }

    /*
     * we copy over prime and generator values from dh_a, just save time to
     * generate and validate values
     */
    p_b = BN_dup(p_a);
    g_b = BN_dup(g_a);
    if ((p_b == NULL) || (g_b == NULL)) {
        WARN("# FAIL DH duplicating p and g.\n");
        ret = 0;
        if (p_b) BN_free(p_b);
        if (g_b) BN_free(g_b);
        goto err;
    }

    if (!DH_set0_pqg(dh_b, p_b, q_b, g_b)) {
        WARN("# FAIL DH setting p and g for key b.\n");
        ret = 0;
        if (p_b) BN_free(p_b);
        if (g_b) BN_free(g_b);
        goto err;
    }

    /*
     * Set dh_a to run with normal modexp and dh_b to use constant time. The
     * built-in DH implementation now uses constant time modular
     * exponentiation for secret exponents by default. DH_FLAG_NO_EXP_CONTTIME
     * flag causes the faster variable sliding window method to be used for
     * all exponents
     */
    DH_clear_flags(dh_b, DH_FLAG_NO_EXP_CONSTTIME);
    DH_set_flags(dh_a, DH_FLAG_NO_EXP_CONSTTIME);

    aout = DH_generate_key(dh_a);
    if (aout <= 0) {
        WARN("# FAIL DH generating key a.\n");
        ret = 0;
        goto err;
    }

    DH_get0_key(dh_a, &pub_key_a, &priv_key_a);

    if (print_output) {
        BIO_puts(out, "pri 1=");
        BN_print(out, priv_key_a);
        BIO_puts(out, "\npub 1=");
        BN_print(out, pub_key_a);
        BIO_puts(out, "\n");
    }

    bout = DH_generate_key(dh_b);
    if (bout <= 0) {
        WARN("# FAIL DH generating key b.\n");
        ret = 0;
        goto err;
    }

    DH_get0_key(dh_b, &pub_key_b, &priv_key_b);

    if (print_output) {
        BIO_puts(out, "pri 2=");
        BN_print(out, priv_key_b);
        BIO_puts(out, "\npub 2=");
        BN_print(out, pub_key_b);
        BIO_puts(out, "\n");
    }

    alen = DH_size(dh_a);
    abuf = (unsigned char *)OPENSSL_malloc(alen);
    if (abuf == NULL) {
        WARN("# FAIL DH abuf malloc failed ! \n");
        ret = 0;
        goto err;
    }

    for (i = 0; i < count; i++) {
        aout = DH_compute_key(abuf, pub_key_b, dh_a);
        if (aout <= 0) {
            WARN("# FAIL DH compute key a.\n");
            ret = 0;
            goto err;
        }

        if (print_output) {
            BIO_puts(out, "key1 =");
            for (i = 0; i < aout; i++) {
                sprintf(buf, "%02X", abuf[i]);
                BIO_puts(out, buf);
            }
            BIO_puts(out, "\n");
        }
    }
    if (verify) {
        blen = DH_size(dh_b);
        bbuf = (unsigned char *)OPENSSL_malloc(blen);
        if (bbuf == NULL) {
            WARN("# FAIL DH bbuf malloc failed ! \n");
            ret = 0;
            goto err;
        }

        bout = DH_compute_key(bbuf, pub_key_a, dh_b);
        if (bout <= 0) {
            WARN("# FAIL DH compute key b.\n");
            ret = 0;
            goto err;
        }

        if (print_output) {
            BIO_puts(out, "key2 =");
            for (i = 0; i < bout; i++) {
                sprintf(buf, "%02X", bbuf[i]);
                BIO_puts(out, buf);
            }
            BIO_puts(out, "\n");
        }

        if ((aout < 4) || (bout != aout) || (memcmp(abuf, bbuf, aout) != 0)) {
            INFO("# FAIL verify for DH.\n");
            ret = 0; /* Fail */
        } else
            INFO("# PASS verify for DH. \n");
    }
#endif
#ifdef QAT_OPENSSL_PROVIDER
    EVP_PKEY *pkey_A = NULL;
    EVP_PKEY *pkey_B = NULL;
    EVP_PKEY_CTX *dh_ctx = NULL;
    EVP_PKEY_CTX *test_ctx = NULL;
    unsigned char *secret_ff_a = NULL;
    unsigned char *secret_ff_b = NULL;
    size_t secret_size;
    size_t test_out;

    pkey_A = EVP_PKEY_new();
    if (!pkey_A){
        WARN("# FAIL while initialising EVP_PKEY (out of memory?).\n");
        ret = 0;
        goto err;
    }
    pkey_B = EVP_PKEY_new();
    if (!pkey_B){
        WARN("# FAIL while initialising EVP_PKEY (out of memory?).\n");
        ret = 0;
        goto err;
    }

    dh_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (!dh_ctx){
        WARN("# FAIL while allocating EVP_PKEY_CTX.\n");
        ret = 0;
        goto err;
    }
    if (EVP_PKEY_keygen_init(dh_ctx) <= 0){
        WARN("# FAIL while initialising EVP_PKEY_CTX.\n");
        ret = 0;
        goto err;
    }
    if (EVP_PKEY_CTX_set_dh_nid(dh_ctx, get_dh_nid(size)) <= 0){
        WARN("# FAIL setting DH key size for keygen.\n");
        ret = 0;
        goto err;
    }

    if (EVP_PKEY_keygen(dh_ctx, &pkey_A) <= 0 ||
        EVP_PKEY_keygen(dh_ctx, &pkey_B) <= 0){
        WARN("# FAIL FFDH key generation failure.\n");
        ret = 0;
        goto err;
    }

    EVP_PKEY_CTX_free(dh_ctx);

    dh_ctx = EVP_PKEY_CTX_new(pkey_A, NULL);
    if (dh_ctx == NULL){
        WARN("# FAIL while allocating EVP_PKEY_CTX.\n");
        ret = 0;
        goto err;
    }
    if (EVP_PKEY_derive_init(dh_ctx) <= 0){
        WARN("# FAIL FFDH derivation context init failure.\n");
        ret = 0;
        goto err;
    }
    if (EVP_PKEY_derive_set_peer(dh_ctx, pkey_B) <= 0){
        WARN("# FAIL Assigning peer key for derivation failed.\n");
        ret = 0;
        goto err;
    }
    if (EVP_PKEY_derive(dh_ctx, NULL, &secret_size) <= 0){
        WARN("# FAIL Checking size of shared secret failed.\n");
        ret = 0;
        goto err;
    }
    if (secret_size > MAX_DH_SIZE){
        WARN("# FAIL Assertion failure: shared secret too large.\n");
        ret = 0;
        goto err;
    }

    secret_ff_a = OPENSSL_malloc(MAX_DH_SIZE);
    if (secret_ff_a == NULL){
        WARN("# FAIL Secret buf a malloc failed!\n");
        ret = 0;
        goto err;
    }
    secret_ff_b = OPENSSL_malloc(MAX_DH_SIZE);
    if (secret_ff_b == NULL){
        WARN("# FAIL Secret buf b malloc failed!\n");
        ret = 0;
        goto err;
    }

    if (EVP_PKEY_derive(dh_ctx, secret_ff_a, &secret_size) <= 0){
        WARN("# FAIL Shared secret derive failure.\n");
        ret = 0;
        goto err;
    }

    /* Now check from side B */
    test_ctx = EVP_PKEY_CTX_new(pkey_B, NULL);
    if (!test_ctx){
        WARN("# FAIL while allocating EVP_PKEY_CTX.\n");
        ret = 0;
        goto err;
    }
    if (!EVP_PKEY_derive_init(test_ctx) ||
        !EVP_PKEY_derive_set_peer(test_ctx, pkey_A) ||
        !EVP_PKEY_derive(test_ctx, NULL, &test_out) ||
        !EVP_PKEY_derive(test_ctx, secret_ff_b, &test_out) ||
        test_out != secret_size){
        WARN("# FAIL DH computation failure.\n");
        ret = 0;
        goto err;
    }

    /* compare the computed secrets */
    if (CRYPTO_memcmp(secret_ff_a, secret_ff_b, secret_size)){
        WARN("# FAIL DH computations don't match.\n");
        ret = 0;
        goto err;
    }

    INFO("# PASS verify for DH. \n");
#endif

err:
#ifndef ENABLE_QAT_FIPS
    if (ret != 1)
        ERR_print_errors_fp(stderr);
#endif
#ifdef QAT_OPENSSL_PROVIDER
    EVP_PKEY_free(pkey_A);
    pkey_A = NULL;
    EVP_PKEY_free(pkey_B);
    pkey_B = NULL;
    EVP_PKEY_CTX_free(test_ctx);
    test_ctx = NULL;
    OPENSSL_free(secret_ff_a);
    secret_ff_a = NULL;
    OPENSSL_free(secret_ff_b);
    secret_ff_b = NULL;
#endif
#ifndef QAT_OPENSSL_PROVIDER
    if (abuf != NULL)
        OPENSSL_free(abuf);
    if (bbuf != NULL)
        OPENSSL_free(bbuf);
    if (dh_b != NULL)
        DH_free(dh_b);
    if (dh_a != NULL)
        DH_free(dh_a);
    BIO_free(out);
#endif
    return ret;
}

/******************************************************************************
* function:
*       tests_run_dh (TEST_PARAMS *args)
*
* @param args [IN] - the test parameters
*
* description:
*   specify a test case
*
******************************************************************************/
void tests_run_dh(TEST_PARAMS *args)
{
    args->additional_args = NULL;

    if (!args->enable_async)
        run_dh(args);
    else
        start_async_job(args, run_dh);
}
