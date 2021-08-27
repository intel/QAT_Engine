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

/*****************************************************************************
 * @file qat_hw_chachapoly.h
 *
 * This file provides an interface for CHACHAPOLY operations
 *
 *****************************************************************************/

#ifndef QAT_HW_CHACHAPOLY_H
# define QAT_HW_CHACHAPOLY_H

# define QAT_POLY1305_DIGEST_SIZE 16
# define QAT_POLY1305_BLOCK_SIZE 16
# define QAT_CHACHA20_POLY1305_MAX_IVLEN 12
# define QAT_CHACHA_KEY_SIZE 32
# define QAT_CHACHA_BLK_SIZE 64
# define QAT_CHACHA_CTR_SIZE 16
# define QAT_CP_SW_CTX_MEM_SIZE 456

typedef struct qat_chachapoly_ctx_t {
    void *sw_ctx_cipher_data;
    int inst_num;
    int context_params_set;
    int session_init;

    CpaCySymSessionSetupData *session_data;
    CpaCySymSessionCtx session_ctx;
    CpaCySymOpData *opd;
    CpaBufferList pSrcBufferList;
    CpaBufferList pDstBufferList;
    CpaFlatBuffer src_buffer[2];
    CpaFlatBuffer dst_buffer[2];

    unsigned char tag[QAT_POLY1305_BLOCK_SIZE];
    unsigned char *tls_aad;
    unsigned char cipher_key[QAT_CHACHA_KEY_SIZE];
    unsigned char mac_key[QAT_CHACHA_BLK_SIZE];
    unsigned char nonce[QAT_CHACHA20_POLY1305_MAX_IVLEN];
    unsigned char derived_iv[QAT_CHACHA20_POLY1305_MAX_IVLEN];
    unsigned int counter[QAT_CHACHA_CTR_SIZE/4];
    unsigned int iv[3];
    unsigned int chacha_key[QAT_CHACHA_KEY_SIZE/4];

    int key_set;
    int iv_set;
    int mac_key_set;
    int tag_len;
    int nonce_len;
    int tls_aad_len;
    size_t tls_payload_length;
    int packet_size;
}qat_chachapoly_ctx;

/* Standalone utility structure for chacha core operation. */
typedef union {
    unsigned int u[QAT_CHACHA_CTR_SIZE];
    unsigned char c[QAT_CHACHA_BLK_SIZE];
}chacha_buf;

const EVP_CIPHER *chachapoly_cipher_meth(int nid, int keylen);

# define qat_chachapoly_data(ctx) \
    ((qat_chachapoly_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx))

# define NO_TLS_PAYLOAD_LENGTH ((size_t)-1)


# define CHACHA_U8TOU32(p)  ( \
                ((unsigned int)(p)[0])     | ((unsigned int)(p)[1]<<8) | \
                ((unsigned int)(p)[2]<<16) | ((unsigned int)(p)[3]<<24)  )

#define U8C(v) (v##U)
#define U8V(v) ((unsigned char)(v) & U8C(0xFF))
#define U32TOU8(p, v) \
	          do { \
                     (p)[0] = U8V((v)      ); \
		     (p)[1] = U8V((v) >>  8); \
		     (p)[2] = U8V((v) >> 16); \
		     (p)[3] = U8V((v) >> 24); \
		  } while (0)
# define ROTATE(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

# define U32TO8_LITTLE(p, v) do { \
                                (p)[0] = (u8)(v >>  0); \
                                (p)[1] = (u8)(v >>  8); \
                                (p)[2] = (u8)(v >> 16); \
                                (p)[3] = (u8)(v >> 24); \
                                } while(0)
# define U8TO32_LITTLE(p) \
    (((uint32_t)((p)[0]) << 0) | \
     ((uint32_t)((p)[1]) << 8) | \
     ((uint32_t)((p)[2]) << 16) | \
     ((uint32_t)((p)[3]) << 24))

/* QUARTERROUND updates a, b, c, d with a ChaCha "quarter" round. */
# define QUARTERROUND(a,b,c,d) ( \
                x[a] += x[b], x[d] = ROTATE((x[d] ^ x[a]),16), \
                x[c] += x[d], x[b] = ROTATE((x[b] ^ x[c]),12), \
                x[a] += x[b], x[d] = ROTATE((x[d] ^ x[a]), 8), \
                x[c] += x[d], x[b] = ROTATE((x[b] ^ x[c]), 7)  )

# define FLATBUFF_ALLOC_AND_CHAIN(b1, b2, len) \
                do { \
                    (b1).pData = qaeCryptoMemAlloc(len, __FILE__, __LINE__); \
                    (b2).pData = (b1).pData; \
                    (b1).dataLenInBytes = len; \
                    (b2).dataLenInBytes = len; \
                } while(0)

#endif
