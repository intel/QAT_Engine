/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2020 Intel Corporation.
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
 * @file vaes_gcm.c
 *
 * This file provides an interface for engine vectorized AES-GCM
 * cipher operations
 *
 ****************************************************************************/

/* Standard Includes */
#include <stdio.h>
#include <string.h>

/* OpenSSL Includes */
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/tls1.h>

/* Intel IPsec library include */
#include <intel-ipsec-mb.h>

/* Local Includes */
#include "e_qat.h"
#include "e_qat_err.h"
#include "qat_evp.h"
#include "qat_utils.h"
#include "vaes_gcm.h"

#define QAT_GCM_TLS_TOTAL_IV_LEN (EVP_GCM_TLS_FIXED_IV_LEN + EVP_GCM_TLS_EXPLICIT_IV_LEN)
#define QAT_GCM_TLS_PAYLOADLENGTH_MSB_OFFSET 2
#define QAT_GCM_TLS_PAYLOADLENGTH_LSB_OFFSET 1
#define QAT_BYTE_SHIFT 8

#define AES_GCM_BLOCK_SIZE 1

#define TLS_VIRT_HDR_SIZE 13

#define AES_KEY_SIZE_128 16
#define AES_KEY_SIZE_192 24
#define AES_KEY_SIZE_256 32

/* The length of valid GCM Tag must be between 0 and 16 Bytes */
#define QAT_GCM_TAG_MIN_LEN 0
#define QAT_GCM_TAG_MAX_LEN 16

#define GET_TLS_HDR(qctx) ((qctx)->tls_aad)

#define GET_TLS_VERSION(hdr) (((hdr)[9]) << QAT_BYTE_SHIFT | (hdr)[10])

#define GET_TLS_PAYLOAD_LEN(hdr) (((((hdr)[11]) << QAT_BYTE_SHIFT) & 0xff00) | ((hdr)[12] & 0x00ff))

#define SET_TLS_PAYLOAD_LEN(hdr, len)               \
    do {                                            \
        hdr[11] = (len & 0xff00) >> QAT_BYTE_SHIFT; \
        hdr[12] = len & 0xff;                       \
    } while (0)


#ifndef OPENSSL_DISABLE_VAES_GCM
IMB_MGR *ipsec_mgr = NULL;

static int vaesgcm_ciphers_init(EVP_CIPHER_CTX*      ctx,
                                const unsigned char* inkey,
                                const unsigned char* iv,
                                int                  enc);
static int vaesgcm_ciphers_cleanup(EVP_CIPHER_CTX* ctx);
static int vaesgcm_ciphers_do_cipher(EVP_CIPHER_CTX*      ctx,
                                     unsigned char*       out,
                                     const unsigned char* in,
                                     size_t               len);
static int vaesgcm_ciphers_ctrl(EVP_CIPHER_CTX* ctx, int type, int arg, void* ptr);

int aes_gcm_tls_cipher(EVP_CIPHER_CTX*      evp_ctx,
                       unsigned char*       out,
                       const unsigned char* in,
                       size_t               len,
                       vaesgcm_ctx*         qctx,
                       int                  enc);

int vaesgcm_init_key(EVP_CIPHER_CTX* ctx, const unsigned char* inkey);
int vaesgcm_init_gcm(EVP_CIPHER_CTX* ctx);

static int qat_check_gcm_nid(int nid)
{
   if (nid == NID_aes_128_gcm ||
       nid == NID_aes_192_gcm ||
       nid == NID_aes_256_gcm)
       return 1;
   else
      return 0;
}

#endif

static inline const EVP_CIPHER *qat_gcm_cipher_sw_impl(int nid)
{
    switch (nid) {
        case NID_aes_128_gcm:
            return EVP_aes_128_gcm();
        case NID_aes_192_gcm:
            return EVP_aes_192_gcm();
        case NID_aes_256_gcm:
            return EVP_aes_256_gcm();
        default:
            WARN("Invalid nid %d\n", nid);
            return NULL;
    }
}

/******************************************************************************
 * function:
 *         vaesgcm_create_cipher_meth(int nid, int keylen)
 *
 * @param nid    [IN] - Cipher NID to be created
 * @param keylen [IN] - Key length of cipher [128|192|256]
 * @retval            - EVP_CIPHER * to created cipher
 * @retval            - NULL if failure
 *
 * description:
 *   create a new EVP_CIPHER based on requested nid
 ******************************************************************************/
const EVP_CIPHER *vaesgcm_create_cipher_meth(int nid, int keylen)
{
#ifndef OPENSSL_DISABLE_VAES_GCM
    EVP_CIPHER* c   = NULL;
    int         res = 1;

    if ((c = EVP_CIPHER_meth_new(nid, AES_GCM_BLOCK_SIZE, keylen)) == NULL) {
        WARN("Failed to allocate cipher methods for specified nid %d\n", nid);
        QATerr(QAT_F_VAESGCM_CREATE_CIPHER_METH, ERR_R_INTERNAL_ERROR);
        return NULL;
    }

    res &= EVP_CIPHER_meth_set_iv_length(c, GCM_IV_DATA_LEN);
    res &= EVP_CIPHER_meth_set_flags(c, VAESGCM_FLAG);
    res &= EVP_CIPHER_meth_set_init(c, vaesgcm_ciphers_init);
    res &= EVP_CIPHER_meth_set_do_cipher(c, vaesgcm_ciphers_do_cipher);
    res &= EVP_CIPHER_meth_set_cleanup(c, vaesgcm_ciphers_cleanup);
    res &= EVP_CIPHER_meth_set_impl_ctx_size(c, sizeof(vaesgcm_ctx));
    res &= EVP_CIPHER_meth_set_set_asn1_params(c, NULL);
    res &= EVP_CIPHER_meth_set_get_asn1_params(c, NULL);
    res &= EVP_CIPHER_meth_set_ctrl(c, vaesgcm_ciphers_ctrl);

    if (res == 0) {
        WARN("Failed to set cipher methods for nid %d\n", nid);
        QATerr(QAT_F_VAESGCM_CREATE_CIPHER_METH, ERR_R_INTERNAL_ERROR);
        EVP_CIPHER_meth_free(c);
        c = NULL;
    }
    return c;
#else
    return qat_gcm_cipher_sw_impl(nid);
#endif
}

#ifndef OPENSSL_DISABLE_VAES_GCM
/******************************************************************************
 * function:
 *         vaesgcm_ciphers_init(EVP_CIPHER_CTX *ctx,
 *                              const unsigned char *inkey,
 *                              const unsigned char *iv,
 *                              int enc)
 *
 * @param ctx    [IN]  - pointer to existing cipher ctx
 * @param inKey  [IN]  - cipher key
 * @param iv     [IN]  - initialisation vector
 * @param enc    [IN]  - 1 = encrypt, 0 = decrypt, -1 = keep prior setting
 *
 * @retval 1      function succeeded
 * @retval 0      function failed
 *
 * description:
 *    This function initialises the cipher parameters for this EVP context.
 *    This function can and will be **called multiple times** with some args
 *    being NULL as happens with 'openssl speed -evp aes-128-gcm'
 *
 ******************************************************************************/
int vaesgcm_ciphers_init(EVP_CIPHER_CTX*      ctx,
                         const unsigned char* inkey,
                         const unsigned char* iv,
                         int                  enc)
{
    vaesgcm_ctx* qctx   = NULL;
    int          retval = 1;

    /* Make sure we have an initalized ipsec mb manager before we start calling APIs */
    if (!ipsec_mgr) {
        WARN("Intel IPsec MB Manager not Initialized.\n");
        QATerr(QAT_F_VAESGCM_CIPHERS_INIT, QAT_R_INIT_FAILURE);
        return 0;
    }

    DEBUG("CTX = %p, key = %p, iv = %p, enc = %d\n",
         (void*)ctx, (void*)inkey, (void*)iv, enc);

    if (ctx == NULL) {
        WARN("ctx == NULL\n");
        QATerr(QAT_F_VAESGCM_CIPHERS_INIT, QAT_R_CTX_NULL);
        return 0;
    }

    qctx = vaesgcm_data(ctx);
    if (qctx == NULL) {
        WARN("qctx == NULL\n");
        QATerr(QAT_F_VAESGCM_CIPHERS_INIT, QAT_R_QCTX_NULL);
        return 0;
    }

    /* If a key is set and a tag has already been calculated
     * this cipher ctx is being reused, so zero the gcm ctx and tag state variables */
    if (qctx->ckey_set && qctx->tag_calculated) {
        memset(&(qctx->gcm_ctx), 0, sizeof(qctx->gcm_ctx));
        qctx->tag_set = 0;
        qctx->tag_calculated = 0;
        }

    /* Allocate gcm auth tag */
    if (!qctx->tag) {
        qctx->tag = OPENSSL_zalloc(EVP_GCM_TLS_TAG_LEN);

        if (qctx->tag) {
            qctx->tag_len = EVP_GCM_TLS_TAG_LEN;
            qctx->tag_set = 0;
        } else {
            qctx->tag_len = 0;
            WARN("Failed to allocate qctx->tag\n");
            QATerr(QAT_F_VAESGCM_CIPHERS_INIT, QAT_R_ALLOC_TAG_FAILURE);
            return 0;
        }
    }

    /* Allocate gcm calculated_tag */
    if (!qctx->calculated_tag) {
        qctx->calculated_tag = OPENSSL_zalloc(EVP_GCM_TLS_TAG_LEN);

        if (qctx->calculated_tag) {
            qctx->tag_calculated = 0;
        } else {
            qctx->tag_len = 0;
            WARN("Failed to allocate qctx->calculated_tag\n");
            QATerr(QAT_F_VAESGCM_CIPHERS_INIT, QAT_R_ALLOC_TAG_FAILURE);
            return 0;
        }
    }

    /* If we have an IV passed in, and the iv_len has not yet been set
     *  default to QAT_GCM_TLS_TOTAL_IV_LEN (if IV size isn't 12 bytes,
     *  it would have been set via ctrl function before we got here) */
    if (qctx->iv_len <=0) {
        qctx->iv_len = QAT_GCM_TLS_TOTAL_IV_LEN;
        DEBUG("Setting IV length = %d\n", qctx->iv_len);
    }

    /* If we have an IV passed in and have yet to allocate memory for the IV */
    qctx->iv = OPENSSL_realloc(qctx->iv, qctx->iv_len);
    DEBUG("Reallocated IV Buffer = %p, with size %d\n",
           qctx->iv, qctx->iv_len);

    qctx->next_iv = OPENSSL_realloc(qctx->next_iv, qctx->iv_len);
    DEBUG("Reallocated Next_IV Buffer = %p, with size %d\n",
           qctx->next_iv, qctx->iv_len);

    qctx->iv_set = 0;

    /* IV passed in */
   if (iv != NULL) {
       if (qctx->iv) {
           DEBUG("Copying iv to qctx->iv with qctx->iv_len = %d\n", qctx->iv_len);
           memcpy(qctx->iv, iv, qctx->iv_len);
           memcpy(qctx->next_iv, iv, qctx->iv_len);
           qctx->iv_set = 1;
        }
        qctx->iv_gen = 0;
    }

    qctx->tls_aad_len = -1;

    /* If we got a key passed in, inialize the key schedule */
    if (inkey)
        retval = vaesgcm_init_key(ctx, inkey);

    /* If both the cipher key and the IV have been set,
     * then init the gcm context */
    if (qctx->ckey_set && qctx->iv_set)
        retval = vaesgcm_init_gcm(ctx);

    return retval;
}

/****************************************************************************
 * function:
 *         aes_gcm_increment_counter(unsigned char *ifc)
 *
 *  @param ifc    [IN,OUT]  - pointer to invocation field counter
 *
 * description:
 *     Increment provided invocation field counter (64-bit int) by 1
 *
 * *************************************************************************/
static inline void aes_gcm_increment_counter(unsigned char* ifc)
{
    int inv_field_size = 8;
    unsigned char byte = 0;
    int i = 0;

    /* Loop over ifc starting with the least significant byte
     * and work towards the most significant byte of ifc*/
    for (i = inv_field_size; i > 0; --i) {
        byte = ifc[i];

        /* Increment by one and copy back to invocation field */
        byte++;
        ifc[i] = byte;

        /* Check if incremented invocation field counter wrapped to zero,
         * if greater than zero then break, else continue to loop and
         * increment the next ifc byte */
        if (byte > 0)
            break;
    }
}

/******************************************************************************
 * function:
 *    vaesgcm_ciphers_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
 *
 * @param ctx    [IN]  - pointer to existing ctx
 * @param type   [IN]  - type of request either
 *                       EVP_CTRL_AEAD_SET_MAC_KEY or EVP_CTRL_AEAD_TLS1_AAD
 * @param arg    [IN]  - size of the pointed to by ptr
 * @param ptr    [IN]  - input buffer contain the necessary parameters
 *
 * @retval x         The return value is dependent on the type of request being made
 *                   EVP_CTRL_AEAD_TLS1_AAD return value indicates the amount fo
 *                   padding to be applied to the SSL/TLS record
 * @retval 0, -1     function failed
 *
 * description:
 *    This function is a generic control interface provided by the EVP API.
 *    The second type is used to specify the TLS virtual header which is
 *    used in the authentication calculation and to identify record payload size.
 *
 ******************************************************************************/
int vaesgcm_ciphers_ctrl(EVP_CIPHER_CTX* ctx, int type, int arg, void* ptr)
{
    vaesgcm_ctx* qctx    = NULL;
    int ret_val = 0;
    int enc = 0;

    if (ctx == NULL) {
        WARN("ctx == NULL\n");
        QATerr(QAT_F_VAESGCM_CIPHERS_CTRL, QAT_R_CTX_NULL);
        return -1;
    }

    qctx = vaesgcm_data(ctx);

    if (qctx == NULL) {
        WARN("qctx == NULL\n");
        QATerr(QAT_F_VAESGCM_CIPHERS_CTRL, QAT_R_QCTX_NULL);
        return -1;
    }

    enc = EVP_CIPHER_CTX_encrypting(ctx);

    switch (type) {
        case EVP_CTRL_INIT: {
            DEBUG("CTRL Type = EVP_CTRL_INIT, ctx = %p, type = %d, "
                  "arg = %d, ptr = %p\n", (void*)ctx, type, arg, ptr);

            memset(qctx, 0, sizeof(vaesgcm_ctx));

            qctx->tls_aad_len     = -1;
            qctx->iv_gen          = -1;

            ret_val = 1;
            break;
        }

        case EVP_CTRL_GCM_SET_IVLEN: {
            DEBUG("CTRL Type = EVP_CTRL_GCM_SET_IVLEN, ctx = %p, type = %d,"
                  " arg = %d, ptr = %p\n", (void*)ctx, type, arg, ptr);

            if (arg <= 0) {
                WARN("Invalid IV length provided\n");
                QATerr(QAT_F_VAESGCM_CIPHERS_CTRL, QAT_R_INVALID_IVLEN);
                ret_val = 0;
                break;
            }

            qctx->iv_len = arg;
            qctx->iv_set = 0;

            ret_val = 1;
            break;
        }

        case EVP_CTRL_GCM_SET_TAG: {
            DEBUG("CTRL Type = EVP_CTRL_GCM_SET_TAG, ctx = %p, type = %d,"
                  " arg = %d, ptr = %p\n", (void*)ctx, type, arg, ptr);

            if (enc || arg <= QAT_GCM_TAG_MIN_LEN || arg > QAT_GCM_TAG_MAX_LEN) {
                ret_val = 0;
                WARN("Bad input parameters\n");
                break;
            }

            if (qctx->tag) {
                OPENSSL_free(qctx->tag);
                qctx->tag = NULL;
            }

            qctx->tag = OPENSSL_zalloc(arg);
            if (qctx->tag) {
                memcpy(qctx->tag, ptr, arg);
                qctx->tag_len = arg;
                DUMPL("Setting Tag", (const unsigned char*)qctx->tag, arg);
                qctx->tag_set = 1;
                ret_val = 1;
            } else {
                WARN("Tag alloc failure\n");
                QATerr(QAT_F_VAESGCM_CIPHERS_CTRL, QAT_R_ALLOC_TAG_FAILURE);
                ret_val = 0;
            }
            break;
        }

        case EVP_CTRL_GCM_GET_TAG: {
            DEBUG("CTRL Type = EVP_CTRL_GCM_GET_TAG, ctx = %p, type = %d,"
                  " arg = %d, ptr = %p\n", (void*)ctx, type, arg, ptr);

            if (!enc || arg <= QAT_GCM_TAG_MIN_LEN || arg > QAT_GCM_TAG_MAX_LEN ||
                qctx->tag_len <= 0) {
                WARN("Bad input parameters\n");
                QATerr(QAT_F_VAESGCM_CIPHERS_CTRL, QAT_R_INVALID_TAG_LEN);
                ret_val = 0;
                break;
            }

            if (!qctx->tag_set || (ptr == NULL)) {
                WARN("Tag not set\n");
                ret_val = 0;
                break;
            } else
                memcpy(ptr, qctx->tag, arg);

            DUMPL("Getting Tag", (const unsigned char*)qctx->tag, arg);
            qctx->iv_set = 0;
            qctx->tag_calculated = 0;
            qctx->tag_set = 0;

            ret_val = 1;
            break;
        }

        case EVP_CTRL_GCM_SET_IV_FIXED: {
            DEBUG("CTRL Type = EVP_CTRL_GCM_SET_IV_FIXED, ctx = %p, type = %d,"
                  " arg = %d, ptr = %p\n", (void*)ctx, type, arg, ptr);

            if (ptr == NULL || qctx->next_iv == NULL) {
                WARN("ptr || next_iv == NULL \n");
                QATerr(QAT_F_VAESGCM_CIPHERS_CTRL, QAT_R_INVALID_PTR_IV);
                ret_val = 0;
                break;
            }
            /* Special case: -1 length restores whole IV */
            if (arg == -1) {
                DEBUG("Special case - Restoring IV, arg = %d\n", arg);
                memcpy(qctx->next_iv, ptr, qctx->iv_len);
                qctx->iv_gen = 1;
                ret_val      = 1;
                break;
            }

            /* Fixed field must be at least 4 bytes (EVP_GCM_TLS_FIXED_IV_LEN)
             * and invocation field at least 8 (EVP_GCM_TLS_EXPLICIT_IV_LEN)
             */
            if ((arg < EVP_GCM_TLS_FIXED_IV_LEN) ||
                (qctx->iv_len - arg) < EVP_GCM_TLS_EXPLICIT_IV_LEN) {
                WARN("Length is not valid\n");
                QATerr(QAT_F_VAESGCM_CIPHERS_CTRL, QAT_R_INVALID_IVLEN);
                ret_val = 0;
                break;
            }

            if (arg != EVP_GCM_TLS_FIXED_IV_LEN) {
                WARN("IV length is not currently supported, iv_len = %d\n", arg);
                QATerr(QAT_F_VAESGCM_CIPHERS_CTRL, QAT_R_INVALID_IVLEN);
                ret_val = 0;
                break;
            }

            int iv_len = EVP_GCM_TLS_FIXED_IV_LEN;

            if (!qctx->iv) {
                qctx->iv = OPENSSL_zalloc(iv_len);

                if (qctx->iv == NULL) {
                    WARN("Failed to allocate %d bytes\n", arg);
                    QATerr(QAT_F_VAESGCM_CIPHERS_CTRL, QAT_R_IV_ALLOC_FAILURE);
                    qctx->iv_len = 0;
                    qctx->iv_gen = 0;
                    ret_val      = 0;
                    break;
                } else
                    qctx->iv_len = iv_len;
            }

            if (!qctx->next_iv) {
                qctx->next_iv = OPENSSL_zalloc(iv_len);

                if (qctx->next_iv == NULL) {
                    WARN("Failed to allocate %d bytes\n", arg);
                    QATerr(QAT_F_VAESGCM_CIPHERS_CTRL, QAT_R_IV_ALLOC_FAILURE);
                    qctx->iv_len = 0;
                    qctx->iv_gen = 0;
                    ret_val      = 0;
                    break;
                } else
                    qctx->iv_len = iv_len;
            }

            DUMPL("EVP_CTRL_GCM_SET_IV_FIXED - next_iv Pre",
                 (const unsigned char*)qctx->next_iv, qctx->iv_len);

            if (arg) {
                memcpy(qctx->next_iv, ptr, arg);
            }
            DUMPL("EVP_CTRL_GCM_SET_IV_FIXED - next_iv Post",
                 (const unsigned char*)qctx->next_iv, qctx->iv_len);

            /* Generate the explicit part of the IV for encryption */
            if (enc && RAND_bytes(qctx->next_iv + arg, qctx->iv_len - arg) <= 0) {
                WARN("RAND_Bytes Failed to generate explicit IV\n");
                QATerr(QAT_F_VAESGCM_CIPHERS_CTRL, QAT_R_RAND_BYTES_FAILURE);
                ret_val = 0;
                break;
            }

            DUMPL("EVP_CTRL_GCM_SET_IV_FIXED - next _iv explicit",
                  (const unsigned char*)qctx->next_iv, qctx->iv_len);

            qctx->iv_gen = 1;
            ret_val      = 1;
            break;
        }

        case EVP_CTRL_GCM_IV_GEN: {
            DEBUG("CTRL Type = EVP_CTRL_GCM_IV_GEN, ctx = %p, type = %d,"
                  " arg = %d, ptr = %p\n", (void*)ctx, type, arg, ptr);

            /* Called in TLS case before encryption */
            if (NULL == qctx->iv || NULL == qctx->next_iv || NULL == ptr) {
                WARN("Invalid memory ptr\n");
                QATerr(QAT_F_VAESGCM_CIPHERS_CTRL, QAT_R_INVALID_QCTX_MEMORY);
                ret_val = 0;
                break;
            }

            if (0 == qctx->iv_gen) {
                WARN("Operation not valid\n");
                QATerr(QAT_F_VAESGCM_CIPHERS_CTRL, QAT_R_INVALID_QCTX_MEMORY);
                ret_val = 0;
                break;
            }

            /* Set the IV that will be used in the current operation */
            memcpy(qctx->iv, qctx->next_iv, qctx->iv_len);
            if (arg <= 0 || arg > qctx->iv_len) {
                arg = qctx->iv_len;
            }

            /* Copy the explicit IV in the output buffer */
            memcpy(ptr, qctx->next_iv + qctx->iv_len - arg, arg);

            /* Increment invocation field counter (last 8 bytes of IV) */
            aes_gcm_increment_counter(qctx->next_iv + qctx->iv_len - 8);

            qctx->iv_set = 1;
            ret_val = 1;
            break;
        }

        case EVP_CTRL_GCM_SET_IV_INV: {
            /* Called in TLS case before decryption */
            DEBUG("CTRL Type = EVP_CTRL_GCM_SET_IV_INV, ctx = %p, type = %d,"
                  " arg = %d, ptr = %p\n", (void*)ctx, type, arg, ptr);

            if (0 == qctx->iv_gen || enc) {
                WARN("Operation not valid\n");
                ret_val = 0;
                break;
            }

            if (NULL == qctx->iv || NULL == qctx->next_iv || NULL == ptr) {
                WARN("Memory Pointer not valid\n");
                QATerr(QAT_F_VAESGCM_CIPHERS_CTRL, QAT_R_INVALID_QCTX_MEMORY);
                ret_val = 0;
                break;
            }

            /* Retrieve the explicit IV from the message buffer */
            memcpy(qctx->next_iv + qctx->iv_len - arg, ptr, arg);
            /* Set the IV that will be used in the current operation */
            memcpy(qctx->iv, qctx->next_iv, qctx->iv_len);

            qctx->iv_set = 1;
            ret_val = 1;
            break;
        }

        case EVP_CTRL_AEAD_TLS1_AAD: {
            DEBUG("CTRL Type = EVP_CTRL_AEAD_TLS1_AAD, ctx = %p, type = %d,"
                  " arg = %d, ptr = %p\n", (void*)ctx, type, arg, ptr);

            if (arg != EVP_AEAD_TLS1_AAD_LEN) {
                WARN("AAD Length not valid %d\n", arg);
                ret_val = 0;
                break;
            }

            /* Check to see if tls_aad already allocated with correct size,
             * if so, reuse and save ourselves a free and malloc */
            if ((qctx->tls_aad_len == EVP_AEAD_TLS1_AAD_LEN) && qctx->tls_aad)
                memcpy(qctx->tls_aad, ptr, qctx->tls_aad_len);
            else {
                if (qctx->tls_aad) {
                    OPENSSL_free(qctx->tls_aad);
                    qctx->tls_aad_len = -1;
                    qctx->tls_aad_set = 0;
                }

                qctx->tls_aad_len = EVP_AEAD_TLS1_AAD_LEN;

                qctx->tls_aad = OPENSSL_malloc(qctx->tls_aad_len);
                if (qctx->tls_aad) {
                    /* Copy the header from payload into the buffer */
                    memcpy(qctx->tls_aad, ptr, qctx->tls_aad_len);
                } else {
                    WARN("AAD alloc failed\n");
                    QATerr(QAT_F_VAESGCM_CIPHERS_CTRL, QAT_R_MALLOC_FAILURE);
                    ret_val = 0;
                    break;
                }
            }

            /* Extract the length of the payload from the TLS header */
            unsigned int plen = qctx->tls_aad[arg - QAT_GCM_TLS_PAYLOADLENGTH_MSB_OFFSET]
                                    << QAT_BYTE_SHIFT |
                                qctx->tls_aad[arg - QAT_GCM_TLS_PAYLOADLENGTH_LSB_OFFSET];

            /* The payload contains the explicit IV -> correct the length */
            plen -= EVP_GCM_TLS_EXPLICIT_IV_LEN;

            /* If decrypting correct for tag too */
            if (!enc) {
                plen -= EVP_GCM_TLS_TAG_LEN;
            }

            /* Fix the length like in the SW version of GCM */
            qctx->tls_aad[EVP_AEAD_TLS1_AAD_LEN - QAT_GCM_TLS_PAYLOADLENGTH_MSB_OFFSET] =
                plen >> QAT_BYTE_SHIFT;
            qctx->tls_aad[EVP_AEAD_TLS1_AAD_LEN - QAT_GCM_TLS_PAYLOADLENGTH_LSB_OFFSET] =
                plen;  // & 0xff;
            qctx->tls_aad_set = 1;

            /* Extra padding: tag appended to record */
            ret_val = EVP_GCM_TLS_TAG_LEN;
            break;
        }

        case EVP_CTRL_GET_IVLEN: {
            DEBUG("CTRL Type = EVP_CTRL_GET_IVLEN, ctx = %p, type = %d,"
                  " arg = %d, ptr = %p\n", (void*)ctx, type, arg, ptr);

            *(int*)ptr = qctx->iv_len;
            ret_val    = 1;
            break;
        }

        default: {
            WARN("Invalid type %d\n", type);
            QATerr(QAT_F_VAESGCM_CIPHERS_CTRL, QAT_R_INVALID_TYPE);
            ret_val = -1;
            break;
        }
    }

    return ret_val;
}

/******************************************************************************
 * function:
 *    vaesgcm_ciphers_cleanup(EVP_CIPHER_CTX *ctx)
 *
 * @param ctx    [IN]  - pointer to existing ctx
 *
 * @retval 1      function succeeded
 * @retval 0      function failed
 *
 * description:
 *    This function will cleanup all allocated resources required to perfrom the
 *  cryptographic transform.
 *
 ******************************************************************************/
int vaesgcm_ciphers_cleanup(EVP_CIPHER_CTX* ctx)
{
    vaesgcm_ctx* qctx = vaesgcm_data(ctx);
    if (qctx) {
        if (qctx->iv) {
            DEBUG("qctx->iv_len = %d\n", qctx->iv_len);
            OPENSSL_free(qctx->iv);
            qctx->iv     = NULL;
            qctx->iv_len = 0;
            qctx->iv_set = 0;
        }

        if (qctx->next_iv) {
            OPENSSL_free(qctx->next_iv);
            qctx->next_iv     = NULL;
        }

        if (qctx->tls_aad) {
            DEBUG("qctx->tls_aad_len = %d\n", qctx->tls_aad_len);
            OPENSSL_free(qctx->tls_aad);
            qctx->tls_aad     = NULL;
            qctx->tls_aad_len = -1;
            qctx->tls_aad_set = 0;
        }

        if (qctx->calculated_tag) {
            OPENSSL_free(qctx->calculated_tag);
            qctx->calculated_tag     = NULL;
            qctx->tag_calculated = 0;
        }

        if (qctx->tag) {
            DEBUG("qctx->tag_len = %d\n", qctx->tag_len);
            OPENSSL_free(qctx->tag);
            qctx->tag     = NULL;
            qctx->tag_len = 0;
            qctx->tag_set = 0;
        }

    }
    return 1;
}

/******************************************************************************
 * function:
 *    vaesgcm_ciphers_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
 *                              const unsigned char *in, size_t len)
 *
 * @param ctx    [IN]  - pointer to existing ctx
 * @param out   [OUT]  - output buffer for transform result
 * @param in     [IN]  - input buffer
 * @param len    [IN]  - length of input buffer
 *
 * @retval -1      function failed
 * @retval 0,1     function succeeded
 *
 * description:
 *    This function performs the cryptographic transform according to the
 *  parameters setup during initialisation.
 *
 ******************************************************************************/
int vaesgcm_ciphers_do_cipher(EVP_CIPHER_CTX*      ctx,
                              unsigned char*       out,
                              const unsigned char* in,
                              size_t               len)
{
    vaesgcm_ctx* qctx = NULL;
    int  enc = 0;
    int  nid = 0;
    struct gcm_key_data* key_data_ptr = NULL;
    struct gcm_context_data* gcm_ctx_ptr = NULL;

    if (ctx == NULL) {
        WARN("ctx == NULL\n");
        QATerr(QAT_F_VAESGCM_CIPHERS_DO_CIPHER, QAT_R_CTX_NULL);
        return -1;
    }

    qctx = vaesgcm_data(ctx);
    if (qctx == NULL) {
        WARN("qctx == NULL\n");
        QATerr(QAT_F_VAESGCM_CIPHERS_DO_CIPHER, QAT_R_QCTX_NULL);
        return -1;
    }

    enc = EVP_CIPHER_CTX_encrypting(ctx);

    nid = EVP_CIPHER_CTX_nid(ctx);
    if (!qat_check_gcm_nid(nid)) {
        WARN("NID not supported %d\n", nid);
        QATerr(QAT_F_VAESGCM_CIPHERS_DO_CIPHER, QAT_R_NID_NOT_SUPPORTED);
        return -1;
    }

    DEBUG("enc = %d - ctx = %p, NID = %d out = %p, in = %p, len = %zu\n",
           enc, (void*)ctx, nid, (void*)out, (void*)in, len);

    /* Distinguish between a regular crypto update and the TLS case
     * qctx->tls_aad_len only set when EVP_CTRL_AEAD_TLS1_AAD control is sent */
    if (qctx->tls_aad_len >= 0)
        return aes_gcm_tls_cipher(ctx, out, in, len, qctx, enc);

    key_data_ptr = &(qctx->key_data);
    gcm_ctx_ptr  = &(qctx->gcm_ctx);

    /* If we have a case where out == NULL, and in != NULL,
     * then its aad being passed */
    if ((out == NULL) && (in != NULL)) {
        qat_imb_aes_gcm_init_var_iv(nid, ipsec_mgr,
                                    key_data_ptr,
                                    gcm_ctx_ptr,
                                    qctx->iv, qctx->iv_len, in, len);

        DEBUG("AAD passsed in\n");
        return 0;
    }

    /* Handle the case where EVP_EncryptFinal_ex is called with a NULL input buffer.
     * Note: Null CT/PT provided to EVP_Encrypt|DecryptUpdate shares the same function
     * signature as if EVP_Encrypt|DecryptFinal_ex() was called */
    if (in == NULL && out != NULL) {

        if (enc) {
            if (qctx->tag == NULL || qctx->tag_len <= 0) {
                WARN("AES-GCM Tag == NULL || tag_len <=0\n");
                return -1;
            }

            /* if we haven't already calculated and the set the tag,
             * then do so */
            if (qctx->tag_set < 1) {
                qat_imb_aes_gcm_enc_finalize(nid, ipsec_mgr, key_data_ptr,
                                             gcm_ctx_ptr, qctx->tag,
                                             qctx->tag_len);
            }
            qctx->tag_set = 1;

           return len;

        } else {  /* Decrypt Flow */

            if (qctx->tag_calculated < 1) {
                qat_imb_aes_gcm_dec_finalize(nid, ipsec_mgr, key_data_ptr,
                        gcm_ctx_ptr, out,
                        qctx->tag_len);

                /* Stash the calculated tag from the decryption,
                 * so it can get compared to expected value below */
                if (qctx->calculated_tag)
                    memcpy(qctx->calculated_tag, out, qctx->tag_len);

                DUMPL("Decrypt - Calculated Tag",
                     (const unsigned char*)qctx->calculated_tag ,
                      qctx->tag_len);
                qctx->tag_calculated = 1;
            }

            DUMPL("Decrypt - Set Tag", (const unsigned char*)qctx->tag,
                  qctx->tag_len);

            /* Wait until signaled by EVP_CTRL_GCM_SET_TAG, that a tag
             * has been set via the control function before we compared
             * the one we calculated if qctx->tag_set == 0, then itsi
             * likely that NULL plaintext was sent in and this looksi
             * just like a DecryptFinal_Ex() call, so wait until control
             * function calls to set the tag */
            if (qctx->tag_set) {
                DEBUG("Decrypt - GCM Tag Set so calling memcmp\n");
                if (memcmp(qctx->calculated_tag, qctx->tag, qctx->tag_len) == 0)
                    return 0;
                else{
                    WARN("AES-GCM calculated tag comparison failed\n");
                    DUMPL("Expected   Tag:", (const unsigned char *)qctx->tag, qctx->tag_len);
                    DUMPL("Calculated Tag:", (const unsigned char *)qctx->calculated_tag, qctx->tag_len);
                    DUMPL("Decrypt - Calculated Tag",
                         (const unsigned char*)qctx->calculated_tag ,
                          qctx->tag_len);
                    return -1;
                }
            }
        }
    } else {
        if (enc)
            qat_imb_aes_gcm_enc_update(nid, ipsec_mgr, key_data_ptr,
                                       gcm_ctx_ptr, out, in, len);
        else
            qat_imb_aes_gcm_dec_update(nid, ipsec_mgr, key_data_ptr,
                                       gcm_ctx_ptr, out, in, len);
    }

    return len;
}

/******************************************************************************
 * function:
 *    aes_gcm_tls_cipher(EVP_CIPHER_CTX *evp_ctx, unsigned char *out,
 *                           const unsigned char *in, size_t len)
 *
 * @param evp_ctx [IN]  - pointer to existing context
 * @param out     [OUT] - output buffer for transform result
 * @param in      [IN]  - input buffer
 * @param len     [IN]  - length of input buffer
 *
 * @retval -1      function failed
 * @retval  1      function succeeded
 *
 * description:
 *    This function performs the cryptographic transform according to the
 *  parameters setup during initialisation.
 *
 *  This is the function used in the TLS case.
 *
 ******************************************************************************/
int aes_gcm_tls_cipher(EVP_CIPHER_CTX*      ctx,
                       unsigned char*       out,
                       const unsigned char* in,
                       size_t               len,
                       vaesgcm_ctx*         qctx,
                       int                  enc)
{
    unsigned int   message_len      = 0;
    int  nid = 0;
    void* tag = NULL;
    unsigned int   tag_offset       = len - EVP_GCM_TLS_TAG_LEN;
    unsigned char* orig_payload_loc = (unsigned char*)in;
    struct gcm_key_data* key_data_ptr = NULL;
    struct gcm_context_data* gcm_ctx_ptr = NULL;

    DEBUG("enc = %d - ctx = %p, out = %p, in = %p, len = %zu\n", enc, (void*)ctx, (void*)out,
          (void*)in, len);

    if (NULL == in || out != in || len < (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN)) {
        WARN("Input parameters are not valid\n");
        QATerr(QAT_F_AES_GCM_TLS_CIPHER, QAT_R_INVALID_INPUT_PARAMETER);
        return -1;
    }

    /* Encryption: generate explicit IV and write to start of buffer.
     * Decryption: read the explicit IV from start of buffer
     */
    if (EVP_CIPHER_CTX_ctrl(ctx, enc ? EVP_CTRL_GCM_IV_GEN : EVP_CTRL_GCM_SET_IV_INV,
                            EVP_GCM_TLS_EXPLICIT_IV_LEN, out) <= 0) {
        WARN("EVP_CIPHER_CTRL Failed\n");
        return -1;
    }

    nid = EVP_CIPHER_CTX_nid(ctx);

    /* The key has been set in the init function: no need to check it here*/
    /* Initialize the session if not done before */

    if (0 == vaesgcm_init_gcm(ctx)) {
        WARN("Failed to initialize GCM Context\n");
        QATerr(QAT_F_AES_GCM_TLS_CIPHER, QAT_R_INITIALIZE_CTX_FAILURE);
        return -1;
    }

    /* Include the explicit part of the IV at the beginning of the output  */
    in += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    out += EVP_GCM_TLS_EXPLICIT_IV_LEN;

    /* This is the length of the message that must be encrypted */
    message_len = len - (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN);

    key_data_ptr = &(qctx->key_data);
    gcm_ctx_ptr  = &(qctx->gcm_ctx);

    tag = orig_payload_loc + tag_offset;

    if (enc) {
        /* Encrypt the payload */
        qat_imb_aes_gcm_enc_update(nid, ipsec_mgr, key_data_ptr,
                                   gcm_ctx_ptr, out, in, message_len);

        /* Finalize to get the GCM Tag */
        qat_imb_aes_gcm_enc_finalize(nid, ipsec_mgr, key_data_ptr,
                                     gcm_ctx_ptr, tag,
                                     EVP_GCM_TLS_TAG_LEN);

        qctx->tag_set = 1;
    } else {
        qat_imb_aes_gcm_dec_update(nid, ipsec_mgr, key_data_ptr,
                                   gcm_ctx_ptr, out, in, message_len);

        DUMPL("Payload Dump After - Decrypt Update",
             (const unsigned char*)orig_payload_loc, len);

        uint8_t tempTag[EVP_GCM_TLS_TAG_LEN];
        memset(tempTag, 0, EVP_GCM_TLS_TAG_LEN);

        qat_imb_aes_gcm_enc_finalize(nid, ipsec_mgr, key_data_ptr,
                                     gcm_ctx_ptr, tempTag,
                                     EVP_GCM_TLS_TAG_LEN);

        if (memcmp(tag, tempTag, EVP_GCM_TLS_TAG_LEN) == 0) {
            DEBUG("ctx = %p, nid = %d,GCM TAG Verification Successful\n", ctx, nid);
        }

        else {
            WARN("ctx = %p, nid = %d, GCM TAG Verification Failed\n", ctx, nid);
            DUMPL("Expected GCM TAG", (const unsigned char*)tag, EVP_GCM_TLS_TAG_LEN);
            DUMPL("Computed GCM TAG", (const unsigned char*)tag, EVP_GCM_TLS_TAG_LEN);
            DUMPL("Payload After Decrypt Finalize", (const unsigned char*)orig_payload_loc,
                   len);
            QATerr(QAT_F_AES_GCM_TLS_CIPHER, QAT_R_GCM_TAG_VERIFY_FAILURE);
            return -1;
        }
    }

    if (enc)
        return len;
    else
        return message_len;
}

/******************************************************************************
 * function:
 *    vaesgcm_init_key(EVP_CIPHER_CTX* ctx, const unsigned char* inkey)
 *
 * @param evp_ctx [IN]  - pointer to existing context
 * @param inkey [IN]    - pointer to input key
 *
 * @retval 0      function failed
 * @retval 1      function succeeded
 *
 * description:
 *    Allocate and Initialize the Key
 *
 * ***************************************************************************/
int vaesgcm_init_key(EVP_CIPHER_CTX* ctx, const unsigned char* inkey)
{

    int nid = 0;
    struct gcm_key_data* key_data_ptr = NULL;
    const void*          key          = NULL;

    if (ctx == NULL || inkey == NULL) {
        WARN("Either ctx or inkey is NULL \n");
        QATerr(QAT_F_VAESGCM_INIT_KEY, QAT_R_CTX_NULL);
        return 0;
    }

    vaesgcm_ctx* qctx = vaesgcm_data(ctx);
    if (qctx == NULL) {
        WARN("qctx is NULL\n");
        QATerr(QAT_F_VAESGCM_INIT_KEY, QAT_R_QCTX_NULL);
        return 0;
    }

    nid = EVP_CIPHER_CTX_nid(ctx);
    if (!qat_check_gcm_nid(nid)) {
        WARN("NID not supported %d\n", nid);
        QATerr(QAT_F_VAESGCM_INIT_KEY, QAT_R_NID_NOT_SUPPORTED);
        return -1;
    }
    key_data_ptr = &(qctx->key_data);
    key = (const void*)(inkey);

    qat_imb_aes_gcm_precomp(nid, ipsec_mgr, key, key_data_ptr);

    qctx->ckey_set = 1;
    return 1;
}

/******************************************************************************
 * function:
 *    vaesgcm_init_gcm(EVP_CIPHER_CTX* ctx)
 *
 * @param evp_ctx [IN]  - pointer to cipher context
 *
 * @retval 0      function failed
 * @retval 1      function succeeded
 *
 * description:
 *    Allocate and Initialize the gcm ctx
 *
 ******************************************************************************/

int vaesgcm_init_gcm(EVP_CIPHER_CTX* ctx)
{
    int nid = 0;
    int aad_len = 0;
    struct gcm_key_data* key_data_ptr = NULL;
    struct gcm_context_data* gcm_ctx_ptr = NULL;
    const unsigned char* aad_ptr      = NULL;

    if (ctx == NULL) {
        WARN("ctx is NULL\n");
        QATerr(QAT_F_VAESGCM_INIT_GCM, QAT_R_CTX_NULL);
        return 0;
    }

    vaesgcm_ctx* qctx = vaesgcm_data(ctx);

    if (qctx == NULL) {
        WARN("qctx == NULL\n");
        QATerr(QAT_F_VAESGCM_INIT_GCM, QAT_R_QCTX_NULL);
        return 0;
    }

    nid = EVP_CIPHER_CTX_nid(ctx);
    if (!qat_check_gcm_nid(nid)) {
        WARN("NID not supported %d\n", nid);
        QATerr(QAT_F_VAESGCM_INIT_GCM, QAT_R_NID_NOT_SUPPORTED);
        return 0;
    }

    /* if both the cipher key and the IV have been set, then init */
    if (qctx->ckey_set && (qctx->iv_set || qctx->iv_gen)) {
        key_data_ptr = &(qctx->key_data);
        gcm_ctx_ptr  = &(qctx->gcm_ctx);
        aad_ptr      = qctx->tls_aad;
        aad_len      = qctx->tls_aad_len;
        if (qctx->tls_aad_len < 0)
            aad_len = 0;

        qat_imb_aes_gcm_init_var_iv(nid, ipsec_mgr, key_data_ptr,
                                    gcm_ctx_ptr, qctx->iv,
                                    qctx->iv_len, aad_ptr, aad_len);

        return 1;
    } else {
        WARN("Cipher key, IV and iv_gen not set\n");
        QATerr(QAT_F_VAESGCM_INIT_GCM, QAT_R_INVALID_INPUT_PARAMETER);
        return 0;
    }
}

/******************************************************************************
 * function:
 *    vaesgcm_init_ipsec_mb_mgr(void)
 *
 * @retval 0      function failed
 * @retval 1      function succeeded
 *
 * description:
 *    Allocate and Initialize the Intel IPsec Multi-Buffer Library Manager
 *    to help dispatch AVX512 APIS
 *
 ******************************************************************************/
int vaesgcm_init_ipsec_mb_mgr()
{
    if (ipsec_mgr == NULL)
    {
        ipsec_mgr = alloc_mb_mgr(0);

        if (ipsec_mgr == NULL) {
            WARN("Error allocating Intel IPsec MB_MGR!\n");
            QATerr(QAT_F_VAESGCM_INIT_IPSEC_MB_MGR, QAT_R_IPSEC_MGR_NULL);
            return 0;
        } else {
            /* Initialize the manager to dispatch AVX512 IPsec APIs */
            init_mb_mgr_avx512(ipsec_mgr);
            return 1;
        }
    }

    WARN("Error: Intel IPsec MB_MGR already allocated\n");
    return 0;
}

/******************************************************************************
 * function:
 *    vaesgcm_free_ipsec_mb_mgr(void)
 *
 * description:
 *    Free Intel IPsec Multi-Buffer Library Manager resources
 *
 ******************************************************************************/
void vaesgcm_free_ipsec_mb_mgr()
{
    if (ipsec_mgr) {
        free_mb_mgr(ipsec_mgr);
        ipsec_mgr = NULL;
    }
}

#endif
