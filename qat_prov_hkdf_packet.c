/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2023-2024 Intel Corporation.
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
 * @file qat_prov_hkdf_packet.c
 *
 * This file contains the TLS13-KDF hkdflabel implementation
 *
 *****************************************************************************/
#include "qat_prov_hkdf_packet.h"
#include "qat_prov_sign_sm2.h"
#include <openssl/err.h>

#define DEFAULT_BUF_SIZE    256

#define QAT_DER_OID_V_ecdsa_with_SHA1 QAT_DER_P_OBJECT, 7, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01
#define QAT_DER_OID_SZ_ecdsa_with_SHA1 9
extern const unsigned char qat_der_oid_ecdsa_with_SHA1[QAT_DER_OID_SZ_ecdsa_with_SHA1];

#define QAT_DER_OID_V_ecdsa_with_SHA224 QAT_DER_P_OBJECT, 8, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x01
#define QAT_DER_OID_SZ_ecdsa_with_SHA224 10
extern const unsigned char qat_der_oid_ecdsa_with_SHA224[QAT_DER_OID_SZ_ecdsa_with_SHA224];

#define QAT_DER_OID_V_ecdsa_with_SHA256 QAT_DER_P_OBJECT, 8, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02
#define QAT_DER_OID_SZ_ecdsa_with_SHA256 10
extern const unsigned char qat_der_oid_ecdsa_with_SHA256[QAT_DER_OID_SZ_ecdsa_with_SHA256];

#define QAT_DER_OID_V_ecdsa_with_SHA384 QAT_DER_P_OBJECT, 8, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03
#define QAT_DER_OID_SZ_ecdsa_with_SHA384 10
extern const unsigned char qat_der_oid_ecdsa_with_SHA384[QAT_DER_OID_SZ_ecdsa_with_SHA384];

#define QAT_DER_OID_V_ecdsa_with_SHA512 QAT_DER_P_OBJECT, 8, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04
#define QAT_DER_OID_SZ_ecdsa_with_SHA512 10
extern const unsigned char qat_der_oid_ecdsa_with_SHA512[QAT_DER_OID_SZ_ecdsa_with_SHA512];

const unsigned char qat_der_oid_ecdsa_with_SHA1[QAT_DER_OID_SZ_ecdsa_with_SHA1] = {
    QAT_DER_OID_V_ecdsa_with_SHA1
};

const unsigned char qat_der_oid_ecdsa_with_SHA224[QAT_DER_OID_SZ_ecdsa_with_SHA224] = {
    QAT_DER_OID_V_ecdsa_with_SHA224
};

const unsigned char qat_der_oid_ecdsa_with_SHA256[QAT_DER_OID_SZ_ecdsa_with_SHA256] = {
    QAT_DER_OID_V_ecdsa_with_SHA256
};

const unsigned char qat_der_oid_ecdsa_with_SHA384[QAT_DER_OID_SZ_ecdsa_with_SHA384] = {
    QAT_DER_OID_V_ecdsa_with_SHA384
};

const unsigned char qat_der_oid_ecdsa_with_SHA512[QAT_DER_OID_SZ_ecdsa_with_SHA512] = {
    QAT_DER_OID_V_ecdsa_with_SHA512
};

/* Aliases so we can have a uniform MD_CASE */
#define qat_der_oid_id_ecdsa_with_sha1   qat_der_oid_ecdsa_with_SHA1
#define qat_der_oid_id_ecdsa_with_sha224 qat_der_oid_ecdsa_with_SHA224
#define qat_der_oid_id_ecdsa_with_sha256 qat_der_oid_ecdsa_with_SHA256
#define qat_der_oid_id_ecdsa_with_sha384 qat_der_oid_ecdsa_with_SHA384
#define qat_der_oid_id_ecdsa_with_sha512 qat_der_oid_ecdsa_with_SHA512

#define QAT_MD_CASE(name)                                                   \
    case NID_##name:                                                    \
        precompiled = qat_der_oid_id_ecdsa_with_##name;                \
        precompiled_sz = sizeof(qat_der_oid_id_ecdsa_with_##name);     \
        break;

unsigned char qat_der_oid_sm2_with_SM3[DER_OID_SZ_sm2_with_SM3] = {
    6, 8, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x75
};

int QAT_WPACKET_allocate_bytes(qat_WPACKET *pkt, size_t len,
                               unsigned char **allocbytes)
{
    if (!QAT_WPACKET_reserve_bytes(pkt, len, allocbytes))
        return 0;

    pkt->written += len;
    pkt->curr += len;
    return 1;
}

#define GETBUF(p)   (((p)->staticbuf != NULL) \
                     ? (p)->staticbuf \
                     : ((p)->buf != NULL \
                        ? (unsigned char *)(p)->buf->data \
                        : NULL))
int QAT_WPACKET_reserve_bytes(qat_WPACKET *pkt, size_t len,
                              unsigned char **allocbytes)
{
    /* Internal API, so should not fail */
    if (!ossl_assert(pkt->subs != NULL && len != 0))
        return 0;

    if (pkt->maxsize - pkt->written < len)
        return 0;

    if (pkt->buf != NULL && (pkt->buf->length - pkt->written < len)) {
        size_t newlen;
        size_t reflen;

        reflen = (len > pkt->buf->length) ? len : pkt->buf->length;

        if (reflen > SIZE_MAX / 2) {
            newlen = SIZE_MAX;
        } else {
            newlen = reflen * 2;
            if (newlen < DEFAULT_BUF_SIZE)
                newlen = DEFAULT_BUF_SIZE;
        }
        if (BUF_MEM_grow(pkt->buf, newlen) == 0)
            return 0;
    }
    if (allocbytes != NULL) {
        *allocbytes = QAT_WPACKET_get_curr(pkt);
        if (pkt->endfirst && *allocbytes != NULL)
            *allocbytes -= len;
    }

    return 1;
}

static size_t QAT_maxmaxsize(size_t lenbytes)
{
    if (lenbytes >= sizeof(size_t) || lenbytes == 0)
        return SIZE_MAX;

    return ((size_t)1 << (lenbytes * 8)) - 1 + lenbytes;
}

static int QAT_wpacket_intern_init_len(qat_WPACKET *pkt, size_t lenbytes)
{
    unsigned char *lenchars;

    pkt->curr = 0;
    pkt->written = 0;

    if ((pkt->subs = OPENSSL_zalloc(sizeof(*pkt->subs))) == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (lenbytes == 0)
        return 1;

    pkt->subs->pwritten = lenbytes;
    pkt->subs->lenbytes = lenbytes;

    if (!QAT_WPACKET_allocate_bytes(pkt, lenbytes, &lenchars)) {
        OPENSSL_free(pkt->subs);
        pkt->subs = NULL;
        return 0;
    }
    pkt->subs->packet_len = 0;

    return 1;
}

int QAT_WPACKET_init_static_len(qat_WPACKET *pkt, unsigned char *buf,
                                size_t len, size_t lenbytes)
{
    size_t max = QAT_maxmaxsize(lenbytes);

    /* Internal API, so should not fail */
    if (!ossl_assert(buf != NULL && len > 0))
        return 0;

    pkt->staticbuf = buf;
    pkt->buf = NULL;
    pkt->maxsize = (max < len) ? max : len;
    pkt->endfirst = 0;

    return QAT_wpacket_intern_init_len(pkt, lenbytes);
}

/* Store the |value| of length |len| at location |data| */
static int QAT_put_value(unsigned char *data, uint64_t value, size_t len)
{
    if (data == NULL)
        return 1;

    for (data += len - 1; len > 0; len--) {
        *data = (unsigned char)(value & 0xff);
        data--;
        value >>= 8;
    }

    /* Check whether we could fit the value in the assigned number of bytes */
    if (value > 0)
        return 0;

    return 1;
}

/*
 * Internal helper function used by qat_QAT_WPACKET_close(), QAT_WPACKET_finish() and
 * qat_WPACKET_fill_lengths() to close a sub-packet and write out its length if
 * necessary. If |doclose| is 0 then it goes through the motions of closing
 * (i.e. it fills in all the lengths), but doesn't actually close anything.
 */
static int QAT_wpacket_intern_close(qat_WPACKET *pkt, qat_WPACKET_SUB *sub,
                                    int doclose)
{
    size_t packlen = pkt->written - sub->pwritten;

    if (packlen == 0 && (sub->flags & QAT_WPACKET_FLAGS_NON_ZERO_LENGTH) != 0)
        return 0;

    if (packlen == 0 && sub->flags & QAT_WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH) {
        /* We can't handle this case. Return an error */
        if (!doclose)
            return 0;

        /* Deallocate any bytes allocated for the length of the qat_WPACKET */
        if ((pkt->curr - sub->lenbytes) == sub->packet_len) {
            pkt->written -= sub->lenbytes;
            pkt->curr -= sub->lenbytes;
        }

        /* Don't write out the packet length */
        sub->packet_len = 0;
        sub->lenbytes = 0;
    }

    /* Write out the qat_WPACKET length if needed */
    if (sub->lenbytes > 0) {
        unsigned char *buf = GETBUF(pkt);

        if (buf != NULL
            && !QAT_put_value(&buf[sub->packet_len], packlen, sub->lenbytes))
            return 0;
    } else if (pkt->endfirst && sub->parent != NULL
               && (packlen != 0
                   || (sub->flags
                       & QAT_WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH) == 0)) {
        size_t tmplen = packlen;
        size_t numlenbytes = 1;

        while ((tmplen = tmplen >> 8) > 0)
            numlenbytes++;
        if (!QAT_WPACKET_put_bytes__(pkt, packlen, numlenbytes))
            return 0;
        if (packlen > 0x7f) {
            numlenbytes |= 0x80;
            if (!QAT_WPACKET_put_bytes_u8(pkt, numlenbytes))
                return 0;
        }
    }

    if (doclose) {
        pkt->subs = sub->parent;
        OPENSSL_free(sub);
    }

    return 1;
}

int QAT_WPACKET_close(qat_WPACKET *pkt)
{
    /*
     * Internal API, so should not fail - but we do negative testing of this
     * so no assert (otherwise the tests fail)
     */
    if (pkt->subs == NULL || pkt->subs->parent == NULL)
        return 0;

    return QAT_wpacket_intern_close(pkt, pkt->subs, 1);
}

int QAT_WPACKET_finish(qat_WPACKET *pkt)
{
    int ret;

    /*
     * Internal API, so should not fail - but we do negative testing of this
     * so no assert (otherwise the tests fail)
     */
    if (pkt->subs == NULL || pkt->subs->parent != NULL)
        return 0;

    ret = QAT_wpacket_intern_close(pkt, pkt->subs, 1);
    if (ret) {
        OPENSSL_free(pkt->subs);
        pkt->subs = NULL;
    }

    return ret;
}

int QAT_WPACKET_start_sub_packet_len__(qat_WPACKET *pkt, size_t lenbytes)
{
    qat_WPACKET_SUB *sub;
    unsigned char *lenchars;

    /* Internal API, so should not fail */
    if (!ossl_assert(pkt->subs != NULL))
        return 0;

    /* We don't support lenbytes greater than 0 when doing endfirst writing */
    if (lenbytes > 0 && pkt->endfirst)
        return 0;

    if ((sub = OPENSSL_zalloc(sizeof(*sub))) == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    sub->parent = pkt->subs;
    pkt->subs = sub;
    sub->pwritten = pkt->written + lenbytes;
    sub->lenbytes = lenbytes;

    if (lenbytes == 0) {
        sub->packet_len = 0;
        return 1;
    }

    sub->packet_len = pkt->written;

    if (!QAT_WPACKET_allocate_bytes(pkt, lenbytes, &lenchars))
        return 0;

    return 1;
}

int QAT_WPACKET_start_sub_packet(qat_WPACKET *pkt)
{
    return QAT_WPACKET_start_sub_packet_len__(pkt, 0);
}

int QAT_WPACKET_put_bytes__(qat_WPACKET *pkt, uint64_t val, size_t size)
{
    unsigned char *data;

    /* Internal API, so should not fail */
    if (!ossl_assert(size <= sizeof(uint64_t))
        || !QAT_WPACKET_allocate_bytes(pkt, size, &data)
        || !QAT_put_value(data, val, size))
        return 0;

    return 1;
}

int QAT_WPACKET_memcpy(qat_WPACKET *pkt, const void *src, size_t len)
{
    unsigned char *dest;

    if (len == 0)
        return 1;

    if (!QAT_WPACKET_allocate_bytes(pkt, len, &dest))
        return 0;

    if (dest != NULL)
        memcpy(dest, src, len);

    return 1;
}

int QAT_WPACKET_sub_memcpy__(qat_WPACKET *pkt, const void *src, size_t len,
                             size_t lenbytes)
{
    if (!QAT_WPACKET_start_sub_packet_len__(pkt, lenbytes)
        || !QAT_WPACKET_memcpy(pkt, src, len)
        || !QAT_WPACKET_close(pkt))
        return 0;

    return 1;
}

int QAT_WPACKET_get_total_written(qat_WPACKET *pkt, size_t *written)
{
    /* Internal API, so should not fail */
    if (!ossl_assert(written != NULL))
        return 0;

    *written = pkt->written;

    return 1;
}

unsigned char *QAT_WPACKET_get_curr(qat_WPACKET *pkt)
{
    unsigned char *buf = GETBUF(pkt);

    if (buf == NULL)
        return NULL;

    if (pkt->endfirst)
        return buf + pkt->maxsize - pkt->curr;

    return buf + pkt->curr;
}

int WPACKET_is_null_buf(qat_WPACKET *pkt)
{
    return pkt->buf == NULL && pkt->staticbuf == NULL;
}

void QAT_WPACKET_cleanup(qat_WPACKET *pkt)
{
    qat_WPACKET_SUB *sub, *parent;

    for (sub = pkt->subs; sub != NULL; sub = parent) {
        parent = sub->parent;
        OPENSSL_free(sub);
    }
    pkt->subs = NULL;
}

int QAT_WPACKET_init_der(qat_WPACKET *pkt, unsigned char *buf, size_t len)
{
    /* Internal API, so should not fail */
    if (!ossl_assert(buf != NULL && len > 0))
        return 0;

    pkt->staticbuf = buf;
    pkt->buf = NULL;
    pkt->maxsize = len;
    pkt->endfirst = 1;

    return QAT_wpacket_intern_init_len(pkt, 0);
}

int QAT_WPACKET_set_flags(qat_WPACKET *pkt, unsigned int flags)
{
    /* Internal API, so should not fail */
    if (!ossl_assert(pkt->subs != NULL))
        return 0;

    pkt->subs->flags = flags;

    return 1;
}

/*SM2 releated functions*/

int qat_int_end_context(qat_WPACKET *pkt, int tag)
{
    /*
     * If someone set the flag WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH on this
     * sub-packet and this sub-packet has nothing written to it, the DER length
     * will not be written, and the total written size will be unchanged before
     * and after WPACKET_close().  We use size1 and size2 to determine if
     * anything was written, and only write our tag if it has.
     *
     */
    size_t size1, size2;

    if (tag < 0)
        return 1;
    if (!ossl_assert(tag <= 30))
        return 0;

    /* Context specific are normally (?) constructed */
    tag |= QAT_DER_F_CONSTRUCTED | QAT_DER_C_CONTEXT;

    return QAT_WPACKET_get_total_written(pkt, &size1)
        && QAT_WPACKET_close(pkt)
        && QAT_WPACKET_get_total_written(pkt, &size2)
        && (size1 == size2 || QAT_WPACKET_put_bytes_u8(pkt, tag));
}

int qat_int_start_context(qat_WPACKET *pkt, int tag)
{
    if (tag < 0)
        return 1;
    if (!ossl_assert(tag <= 30))
        return 0;
    return QAT_WPACKET_start_sub_packet(pkt);
}

int qat_DER_w_end_sequence(qat_WPACKET *pkt, int tag)
{
    /*
     * If someone set the flag WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH on this
     * sub-packet and this sub-packet has nothing written to it, the DER length
     * will not be written, and the total written size will be unchanged before
     * and after WPACKET_close().  We use size1 and size2 to determine if
     * anything was written, and only write our tag if it has.
     *
     * Because we know that qat_int_end_context() needs to do the same check,
     * we reproduce this flag if the written length was unchanged, or we will
     * have an erroneous context tag.
     */
    size_t size1, size2;

    return QAT_WPACKET_get_total_written(pkt, &size1)
        && QAT_WPACKET_close(pkt)
        && QAT_WPACKET_get_total_written(pkt, &size2)
        && (size1 == size2
            ? QAT_WPACKET_set_flags(pkt, QAT_WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH)
            : QAT_WPACKET_put_bytes_u8(pkt, QAT_DER_F_CONSTRUCTED | QAT_DER_P_SEQUENCE))
        && qat_int_end_context(pkt, tag);
}

int qat_DER_w_precompiled(qat_WPACKET *pkt, int tag,
                           const unsigned char *precompiled,
                           size_t precompiled_n)
{
    return qat_int_start_context(pkt, tag)
        && QAT_WPACKET_memcpy(pkt, precompiled, precompiled_n)
        && qat_int_end_context(pkt, tag);
}

/* Constructed things need a start and an end */
int qat_DER_w_begin_sequence(qat_WPACKET *pkt, int tag)
{
    return qat_int_start_context(pkt, tag)
        && QAT_WPACKET_start_sub_packet(pkt);
}

int qat_DER_w_algorithmIdentifier_ECDSA_with_MD(qat_WPACKET *pkt, int cont,
                                                 EC_KEY *ec, int mdnid)
{
    const unsigned char *precompiled = NULL;
    size_t precompiled_sz = 0;

    switch (mdnid) {
        QAT_MD_CASE(sha1);
        QAT_MD_CASE(sha224);
        QAT_MD_CASE(sha256);
        QAT_MD_CASE(sha384);
        QAT_MD_CASE(sha512);
    default:
        return 0;
    }

    return qat_DER_w_begin_sequence(pkt, cont)
        /* No parameters (yet?) */
        && qat_DER_w_precompiled(pkt, -1, precompiled, precompiled_sz)
        && qat_DER_w_end_sequence(pkt, cont);
}

int qat_DER_w_algorithmIdentifier_SM2_with_MD(qat_WPACKET *pkt, int cont,
                                               EC_KEY *ec, int mdnid)
{
    const unsigned char *precompiled = NULL;
    size_t precompiled_sz = 0;

    switch (mdnid) {
    case NID_sm3:
        precompiled = qat_der_oid_sm2_with_SM3;
        precompiled_sz = sizeof(qat_der_oid_sm2_with_SM3);
    default:
        return 0;
    }

    return qat_DER_w_begin_sequence(pkt, cont)
        /* No parameters (yet?) */
        && qat_DER_w_precompiled(pkt, -1, precompiled, precompiled_sz)
        && qat_DER_w_end_sequence(pkt, cont);
}

