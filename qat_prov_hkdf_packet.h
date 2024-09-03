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
 * @file qat_prov_hkdf_packet.h
 *
 * This file provides an interface to TLS13-KDF hkdflabel.
 *
 *****************************************************************************/

# pragma once

# include <string.h>
# include <openssl/bn.h>
# include <openssl/buffer.h>
# include <openssl/crypto.h>
# include <openssl/e_os2.h>


/*
 * QAT_DER UNIVERSAL tags, occupying bits 1-5 in the QAT_DER identifier byte
 * These are only valid for the UNIVERSAL class.  With the other classes,
 * these bits have a different meaning.
 */
#define QAT_DER_P_EOC                       0 /* BER End Of Contents tag */
#define QAT_DER_P_BOOLEAN                   1
#define QAT_DER_P_INTEGER                   2
#define QAT_DER_P_BIT_STRING                3
#define QAT_DER_P_OCTET_STRING              4
#define QAT_DER_P_NULL                      5
#define QAT_DER_P_OBJECT                    6
#define QAT_DER_P_OBJECT_DESCRIPTOR         7
#define QAT_DER_P_EXTERNAL                  8
#define QAT_DER_P_REAL                      9
#define QAT_DER_P_ENUMERATED               10
#define QAT_DER_P_UTF8STRING               12
#define QAT_DER_P_SEQUENCE                 16
#define QAT_DER_P_SET                      17
#define QAT_DER_P_NUMERICSTRING            18
#define QAT_DER_P_PRINTABLESTRING          19
#define QAT_DER_P_T61STRING                20
#define QAT_DER_P_VIDEOTEXSTRING           21
#define QAT_DER_P_IA5STRING                22
#define QAT_DER_P_UTCTIME                  23
#define QAT_DER_P_GENERALIZEDTIME          24
#define QAT_DER_P_GRAPHICSTRING            25
#define QAT_DER_P_ISO64STRING              26
#define QAT_DER_P_GENERALSTRING            27
#define QAT_DER_P_UNIVERSALSTRING          28
#define QAT_DER_P_BMPSTRING                30

/* QAT_DER Flags, occupying bit 6 in the QAT_DER identifier byte */
#define QAT_DER_F_PRIMITIVE              0x00
#define QAT_DER_F_CONSTRUCTED            0x20

/* QAT_DER classes tags, occupying bits 7-8 in the QAT_DER identifier byte */
#define QAT_DER_C_UNIVERSAL              0x00
#define QAT_DER_C_APPLICATION            0x40
#define QAT_DER_C_CONTEXT                0x80
#define QAT_DER_C_PRIVATE                0xC0

#ifdef NDEBUG
# define ossl_assert(x) ((x) != 0)
#else
__owur static ossl_inline int ossl_assert_int(int expr, const char *exprstr,
                                              const char *file, int line)
{
    if (!expr)
        OPENSSL_die(exprstr, file, line);

    return expr;
}

# define ossl_assert(x) ossl_assert_int((x) != 0, "Assertion failed: "#x, \
                                         __FILE__, __LINE__)

#endif

/*
 * Convenience macros for calling WPACKET_start_sub_packet_len with different
 * lengths
 */
#define QAT_WPACKET_start_sub_packet_u8(pkt) \
    QAT_WPACKET_start_sub_packet_len__((pkt), 1)
#define QAT_WPACKET_start_sub_packet_u16(pkt) \
    QAT_WPACKET_start_sub_packet_len__((pkt), 2)
#define QAT_WPACKET_start_sub_packet_u24(pkt) \
    QAT_WPACKET_start_sub_packet_len__((pkt), 3)
#define QAT_WPACKET_start_sub_packet_u32(pkt) \
    QAT_WPACKET_start_sub_packet_len__((pkt), 4)


typedef struct {
    /* Pointer to where we are currently reading from */
    const unsigned char *curr;
    /* Number of bytes remaining */
    size_t remaining;
} PACKET;

/* Internal unchecked shorthand; don't use outside this file. */
static ossl_inline void packet_forward(PACKET *pkt, size_t len)
{
    pkt->curr += len;
    pkt->remaining -= len;
}

/*
 * Returns the number of bytes remaining to be read in the PACKET
 */
static ossl_inline size_t PACKET_remaining(const PACKET *pkt)
{
    return pkt->remaining;
}

/*
 * Returns a pointer to the first byte after the packet data.
 * Useful for integrating with non-PACKET parsing code.
 * Specifically, we use PACKET_end() to verify that a d2i_... call
 * has consumed the entire packet contents.
 */
static ossl_inline const unsigned char *PACKET_end(const PACKET *pkt)
{
    return pkt->curr + pkt->remaining;
}

/*
 * Returns a pointer to the PACKET's current position.
 * For use in non-PACKETized APIs.
 */
static ossl_inline const unsigned char *PACKET_data(const PACKET *pkt)
{
    return pkt->curr;
}

/*
 * Initialise a PACKET with |len| bytes held in |buf|. This does not make a
 * copy of the data so |buf| must be present for the whole time that the PACKET
 * is being used.
 */
__owur static ossl_inline int PACKET_buf_init(PACKET *pkt,
                                              const unsigned char *buf,
                                              size_t len)
{
    /* Sanity check for negative values. */
    if (len > (size_t)(SIZE_MAX / 2))
        return 0;

    pkt->curr = buf;
    pkt->remaining = len;
    return 1;
}

/* Initialize a PACKET to hold zero bytes. */
static ossl_inline void PACKET_null_init(PACKET *pkt)
{
    pkt->curr = NULL;
    pkt->remaining = 0;
}

/*
 * Returns 1 if the packet has length |num| and its contents equal the |num|
 * bytes read from |ptr|. Returns 0 otherwise (lengths or contents not equal).
 * If lengths are equal, performs the comparison in constant time.
 */
__owur static ossl_inline int PACKET_equal(const PACKET *pkt, const void *ptr,
                                           size_t num)
{
    if (PACKET_remaining(pkt) != num)
        return 0;
    return CRYPTO_memcmp(pkt->curr, ptr, num) == 0;
}

/*
 * Peek ahead and initialize |subpkt| with the next |len| bytes read from |pkt|.
 * Data is not copied: the |subpkt| packet will share its underlying buffer with
 * the original |pkt|, so data wrapped by |pkt| must outlive the |subpkt|.
 */
__owur static ossl_inline int PACKET_peek_sub_packet(const PACKET *pkt,
                                                     PACKET *subpkt, size_t len)
{
    if (PACKET_remaining(pkt) < len)
        return 0;

    return PACKET_buf_init(subpkt, pkt->curr, len);
}

/*
 * Initialize |subpkt| with the next |len| bytes read from |pkt|. Data is not
 * copied: the |subpkt| packet will share its underlying buffer with the
 * original |pkt|, so data wrapped by |pkt| must outlive the |subpkt|.
 */
__owur static ossl_inline int PACKET_get_sub_packet(PACKET *pkt,
                                                    PACKET *subpkt, size_t len)
{
    if (!PACKET_peek_sub_packet(pkt, subpkt, len))
        return 0;

    packet_forward(pkt, len);

    return 1;
}

/*
 * Peek ahead at 2 bytes in network order from |pkt| and store the value in
 * |*data|
 */
__owur static ossl_inline int PACKET_peek_net_2(const PACKET *pkt,
                                                unsigned int *data)
{
    if (PACKET_remaining(pkt) < 2)
        return 0;

    *data = ((unsigned int)(*pkt->curr)) << 8;
    *data |= *(pkt->curr + 1);

    return 1;
}

/* Equivalent of n2s */
/* Get 2 bytes in network order from |pkt| and store the value in |*data| */
__owur static ossl_inline int PACKET_get_net_2(PACKET *pkt, unsigned int *data)
{
    if (!PACKET_peek_net_2(pkt, data))
        return 0;

    packet_forward(pkt, 2);

    return 1;
}

/* Same as PACKET_get_net_2() but for a size_t */
__owur static ossl_inline int PACKET_get_net_2_len(PACKET *pkt, size_t *data)
{
    unsigned int i;
    int ret = PACKET_get_net_2(pkt, &i);

    if (ret)
        *data = (size_t)i;

    return ret;
}

/*
 * Peek ahead at 3 bytes in network order from |pkt| and store the value in
 * |*data|
 */
__owur static ossl_inline int PACKET_peek_net_3(const PACKET *pkt,
                                                unsigned long *data)
{
    if (PACKET_remaining(pkt) < 3)
        return 0;

    *data = ((unsigned long)(*pkt->curr)) << 16;
    *data |= ((unsigned long)(*(pkt->curr + 1))) << 8;
    *data |= *(pkt->curr + 2);

    return 1;
}

/* Equivalent of n2l3 */
/* Get 3 bytes in network order from |pkt| and store the value in |*data| */
__owur static ossl_inline int PACKET_get_net_3(PACKET *pkt, unsigned long *data)
{
    if (!PACKET_peek_net_3(pkt, data))
        return 0;

    packet_forward(pkt, 3);

    return 1;
}

/* Same as PACKET_get_net_3() but for a size_t */
__owur static ossl_inline int PACKET_get_net_3_len(PACKET *pkt, size_t *data)
{
    unsigned long i;
    int ret = PACKET_get_net_3(pkt, &i);

    if (ret)
        *data = (size_t)i;

    return ret;
}

/*
 * Peek ahead at 4 bytes in network order from |pkt| and store the value in
 * |*data|
 */
__owur static ossl_inline int PACKET_peek_net_4(const PACKET *pkt,
                                                unsigned long *data)
{
    if (PACKET_remaining(pkt) < 4)
        return 0;

    *data = ((unsigned long)(*pkt->curr)) << 24;
    *data |= ((unsigned long)(*(pkt->curr + 1))) << 16;
    *data |= ((unsigned long)(*(pkt->curr + 2))) << 8;
    *data |= *(pkt->curr + 3);

    return 1;
}

/*
 * Peek ahead at 8 bytes in network order from |pkt| and store the value in
 * |*data|
 */
__owur static ossl_inline int PACKET_peek_net_8(const PACKET *pkt,
                                                uint64_t *data)
{
    if (PACKET_remaining(pkt) < 8)
        return 0;

    *data = ((uint64_t)(*pkt->curr)) << 56;
    *data |= ((uint64_t)(*(pkt->curr + 1))) << 48;
    *data |= ((uint64_t)(*(pkt->curr + 2))) << 40;
    *data |= ((uint64_t)(*(pkt->curr + 3))) << 32;
    *data |= ((uint64_t)(*(pkt->curr + 4))) << 24;
    *data |= ((uint64_t)(*(pkt->curr + 5))) << 16;
    *data |= ((uint64_t)(*(pkt->curr + 6))) << 8;
    *data |= *(pkt->curr + 7);

    return 1;
}

/* Equivalent of n2l */
/* Get 4 bytes in network order from |pkt| and store the value in |*data| */
__owur static ossl_inline int PACKET_get_net_4(PACKET *pkt, unsigned long *data)
{
    if (!PACKET_peek_net_4(pkt, data))
        return 0;

    packet_forward(pkt, 4);

    return 1;
}

/* Same as PACKET_get_net_4() but for a size_t */
__owur static ossl_inline int PACKET_get_net_4_len(PACKET *pkt, size_t *data)
{
    unsigned long i;
    int ret = PACKET_get_net_4(pkt, &i);

    if (ret)
        *data = (size_t)i;

    return ret;
}

/* Get 8 bytes in network order from |pkt| and store the value in |*data| */
__owur static ossl_inline int PACKET_get_net_8(PACKET *pkt, uint64_t *data)
{
    if (!PACKET_peek_net_8(pkt, data))
        return 0;

    packet_forward(pkt, 8);

    return 1;
}

/* Peek ahead at 1 byte from |pkt| and store the value in |*data| */
__owur static ossl_inline int PACKET_peek_1(const PACKET *pkt,
                                            unsigned int *data)
{
    if (!PACKET_remaining(pkt))
        return 0;

    *data = *pkt->curr;

    return 1;
}

/* Get 1 byte from |pkt| and store the value in |*data| */
__owur static ossl_inline int PACKET_get_1(PACKET *pkt, unsigned int *data)
{
    if (!PACKET_peek_1(pkt, data))
        return 0;

    packet_forward(pkt, 1);

    return 1;
}

/* Same as PACKET_get_1() but for a size_t */
__owur static ossl_inline int PACKET_get_1_len(PACKET *pkt, size_t *data)
{
    unsigned int i;
    int ret = PACKET_get_1(pkt, &i);

    if (ret)
        *data = (size_t)i;

    return ret;
}

/*
 * Peek ahead at 4 bytes in reverse network order from |pkt| and store the value
 * in |*data|
 */
__owur static ossl_inline int PACKET_peek_4(const PACKET *pkt,
                                            unsigned long *data)
{
    if (PACKET_remaining(pkt) < 4)
        return 0;

    *data = *pkt->curr;
    *data |= ((unsigned long)(*(pkt->curr + 1))) << 8;
    *data |= ((unsigned long)(*(pkt->curr + 2))) << 16;
    *data |= ((unsigned long)(*(pkt->curr + 3))) << 24;

    return 1;
}

/* Equivalent of c2l */
/*
 * Get 4 bytes in reverse network order from |pkt| and store the value in
 * |*data|
 */
__owur static ossl_inline int PACKET_get_4(PACKET *pkt, unsigned long *data)
{
    if (!PACKET_peek_4(pkt, data))
        return 0;

    packet_forward(pkt, 4);

    return 1;
}

/*
 * Peek ahead at |len| bytes from the |pkt| and store a pointer to them in
 * |*data|. This just points at the underlying buffer that |pkt| is using. The
 * caller should not free this data directly (it will be freed when the
 * underlying buffer gets freed
 */
__owur static ossl_inline int PACKET_peek_bytes(const PACKET *pkt,
                                                const unsigned char **data,
                                                size_t len)
{
    if (PACKET_remaining(pkt) < len)
        return 0;

    *data = pkt->curr;

    return 1;
}

/*
 * Read |len| bytes from the |pkt| and store a pointer to them in |*data|. This
 * just points at the underlying buffer that |pkt| is using. The caller should
 * not free this data directly (it will be freed when the underlying buffer gets
 * freed
 */
__owur static ossl_inline int PACKET_get_bytes(PACKET *pkt,
                                               const unsigned char **data,
                                               size_t len)
{
    if (!PACKET_peek_bytes(pkt, data, len))
        return 0;

    packet_forward(pkt, len);

    return 1;
}

/* Peek ahead at |len| bytes from |pkt| and copy them to |data| */
__owur static ossl_inline int PACKET_peek_copy_bytes(const PACKET *pkt,
                                                     unsigned char *data,
                                                     size_t len)
{
    if (PACKET_remaining(pkt) < len)
        return 0;

    memcpy(data, pkt->curr, len);

    return 1;
}

/*
 * Read |len| bytes from |pkt| and copy them to |data|.
 * The caller is responsible for ensuring that |data| can hold |len| bytes.
 */
__owur static ossl_inline int PACKET_copy_bytes(PACKET *pkt,
                                                unsigned char *data, size_t len)
{
    if (!PACKET_peek_copy_bytes(pkt, data, len))
        return 0;

    packet_forward(pkt, len);

    return 1;
}

/*
 * Copy packet data to |dest|, and set |len| to the number of copied bytes.
 * If the packet has more than |dest_len| bytes, nothing is copied.
 * Returns 1 if the packet data fits in |dest_len| bytes, 0 otherwise.
 * Does not forward PACKET position (because it is typically the last thing
 * done with a given PACKET).
 */
__owur static ossl_inline int PACKET_copy_all(const PACKET *pkt,
                                              unsigned char *dest,
                                              size_t dest_len, size_t *len)
{
    if (PACKET_remaining(pkt) > dest_len) {
        *len = 0;
        return 0;
    }
    *len = pkt->remaining;
    memcpy(dest, pkt->curr, pkt->remaining);
    return 1;
}

/*
 * Copy |pkt| bytes to a newly allocated buffer and store a pointer to the
 * result in |*data|, and the length in |len|.
 * If |*data| is not NULL, the old data is OPENSSL_free'd.
 * If the packet is empty, or malloc fails, |*data| will be set to NULL.
 * Returns 1 if the malloc succeeds and 0 otherwise.
 * Does not forward PACKET position (because it is typically the last thing
 * done with a given PACKET).
 */
__owur static ossl_inline int PACKET_memdup(const PACKET *pkt,
                                            unsigned char **data, size_t *len)
{
    size_t length;

    OPENSSL_free(*data);
    *data = NULL;
    *len = 0;

    length = PACKET_remaining(pkt);

    if (length == 0)
        return 1;

    *data = OPENSSL_memdup(pkt->curr, length);
    if (*data == NULL)
        return 0;

    *len = length;
    return 1;
}

/*
 * Read a C string from |pkt| and copy to a newly allocated, NUL-terminated
 * buffer. Store a pointer to the result in |*data|.
 * If |*data| is not NULL, the old data is OPENSSL_free'd.
 * If the data in |pkt| does not contain a NUL-byte, the entire data is
 * copied and NUL-terminated.
 * Returns 1 if the malloc succeeds and 0 otherwise.
 * Does not forward PACKET position (because it is typically the last thing done
 * with a given PACKET).
 */
__owur static ossl_inline int PACKET_strndup(const PACKET *pkt, char **data)
{
    OPENSSL_free(*data);

    /* This will succeed on an empty packet, unless pkt->curr == NULL. */
    *data = OPENSSL_strndup((const char *)pkt->curr, PACKET_remaining(pkt));
    return (*data != NULL);
}

/* Returns 1 if |pkt| contains at least one 0-byte, 0 otherwise. */
static ossl_inline int PACKET_contains_zero_byte(const PACKET *pkt)
{
    return memchr(pkt->curr, 0, pkt->remaining) != NULL;
}

/* Move the current reading position forward |len| bytes */
__owur static ossl_inline int PACKET_forward(PACKET *pkt, size_t len)
{
    if (PACKET_remaining(pkt) < len)
        return 0;

    packet_forward(pkt, len);

    return 1;
}

/*
 * Reads a variable-length vector prefixed with a one-byte length, and stores
 * the contents in |subpkt|. |pkt| can equal |subpkt|.
 * Data is not copied: the |subpkt| packet will share its underlying buffer with
 * the original |pkt|, so data wrapped by |pkt| must outlive the |subpkt|.
 * Upon failure, the original |pkt| and |subpkt| are not modified.
 */
__owur static ossl_inline int PACKET_get_length_prefixed_1(PACKET *pkt,
                                                           PACKET *subpkt)
{
    unsigned int length;
    const unsigned char *data;
    PACKET tmp = *pkt;
    if (!PACKET_get_1(&tmp, &length) ||
        !PACKET_get_bytes(&tmp, &data, (size_t)length)) {
        return 0;
    }

    *pkt = tmp;
    subpkt->curr = data;
    subpkt->remaining = length;

    return 1;
}

/*
 * Like PACKET_get_length_prefixed_1, but additionally, fails when there are
 * leftover bytes in |pkt|.
 */
__owur static ossl_inline int PACKET_as_length_prefixed_1(PACKET *pkt,
                                                          PACKET *subpkt)
{
    unsigned int length;
    const unsigned char *data;
    PACKET tmp = *pkt;
    if (!PACKET_get_1(&tmp, &length) ||
        !PACKET_get_bytes(&tmp, &data, (size_t)length) ||
        PACKET_remaining(&tmp) != 0) {
        return 0;
    }

    *pkt = tmp;
    subpkt->curr = data;
    subpkt->remaining = length;

    return 1;
}

/*
 * Reads a variable-length vector prefixed with a two-byte length, and stores
 * the contents in |subpkt|. |pkt| can equal |subpkt|.
 * Data is not copied: the |subpkt| packet will share its underlying buffer with
 * the original |pkt|, so data wrapped by |pkt| must outlive the |subpkt|.
 * Upon failure, the original |pkt| and |subpkt| are not modified.
 */
__owur static ossl_inline int PACKET_get_length_prefixed_2(PACKET *pkt,
                                                           PACKET *subpkt)
{
    unsigned int length;
    const unsigned char *data;
    PACKET tmp = *pkt;

    if (!PACKET_get_net_2(&tmp, &length) ||
        !PACKET_get_bytes(&tmp, &data, (size_t)length)) {
        return 0;
    }

    *pkt = tmp;
    subpkt->curr = data;
    subpkt->remaining = length;

    return 1;
}

/*
 * Like PACKET_get_length_prefixed_2, but additionally, fails when there are
 * leftover bytes in |pkt|.
 */
__owur static ossl_inline int PACKET_as_length_prefixed_2(PACKET *pkt,
                                                          PACKET *subpkt)
{
    unsigned int length;
    const unsigned char *data;
    PACKET tmp = *pkt;

    if (!PACKET_get_net_2(&tmp, &length) ||
        !PACKET_get_bytes(&tmp, &data, (size_t)length) ||
        PACKET_remaining(&tmp) != 0) {
        return 0;
    }

    *pkt = tmp;
    subpkt->curr = data;
    subpkt->remaining = length;

    return 1;
}

/*
 * Reads a variable-length vector prefixed with a three-byte length, and stores
 * the contents in |subpkt|. |pkt| can equal |subpkt|.
 * Data is not copied: the |subpkt| packet will share its underlying buffer with
 * the original |pkt|, so data wrapped by |pkt| must outlive the |subpkt|.
 * Upon failure, the original |pkt| and |subpkt| are not modified.
 */
__owur static ossl_inline int PACKET_get_length_prefixed_3(PACKET *pkt,
                                                           PACKET *subpkt)
{
    unsigned long length;
    const unsigned char *data;
    PACKET tmp = *pkt;
    if (!PACKET_get_net_3(&tmp, &length) ||
        !PACKET_get_bytes(&tmp, &data, (size_t)length)) {
        return 0;
    }

    *pkt = tmp;
    subpkt->curr = data;
    subpkt->remaining = length;

    return 1;
}

/* Writeable packets */

typedef struct qat_wpacket_sub qat_WPACKET_SUB;
struct qat_wpacket_sub {
    /* The parent WPACKET_SUB if we have one or NULL otherwise */
    qat_WPACKET_SUB *parent;

    /*
     * Offset into the buffer where the length of this WPACKET goes. We use an
     * offset in case the buffer grows and gets reallocated.
     */
    size_t packet_len;

    /* Number of bytes in the packet_len or 0 if we don't write the length */
    size_t lenbytes;

    /* Number of bytes written to the buf prior to this packet starting */
    size_t pwritten;

    /* Flags for this sub-packet */
    unsigned int flags;
};
typedef struct qat_wpacket_st qat_WPACKET;
struct qat_wpacket_st {
    /* The buffer where we store the output data */
    BUF_MEM *buf;

    /* Fixed sized buffer which can be used as an alternative to buf */
    unsigned char *staticbuf;

    /*
     * Offset into the buffer where we are currently writing. We use an offset
     * in case the buffer grows and gets reallocated.
     */
    size_t curr;

    /* Number of bytes written so far */
    size_t written;

    /* Maximum number of bytes we will allow to be written to this WPACKET */
    size_t maxsize;

    /* Our sub-packets (always at least one if not finished) */
    qat_WPACKET_SUB *subs;

    /* Writing from the end first? */
    unsigned int endfirst : 1;
};
/* Flags */

/* Default */
#define QAT_WPACKET_FLAGS_NONE                      0

/* Error on QAT_WPACKET_close() if no data written to the WPACKET */
#define QAT_WPACKET_FLAGS_NON_ZERO_LENGTH           1

/*
 * Abandon all changes on QAT_WPACKET_close() if no data written to the WPACKET,
 * i.e. this does not write out a zero packet length
 */
#define QAT_WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH    2

int QAT_WPACKET_init_static_len(qat_WPACKET *pkt, unsigned char *buf, size_t len,
                            size_t lenbytes);

/*
 * Same as WPACKET_init_static_len except lenbytes is always 0, and we set the
 * WPACKET to write to the end of the buffer moving towards the start and use
 * QAT_DER length encoding for sub-packets.
 */

int QAT_WPACKET_close(qat_WPACKET *pkt);

/*
 * The same as QAT_WPACKET_close() but only for the top most WPACKET. Additionally
 * frees memory resources for this WPACKET.
 */
int QAT_WPACKET_finish(qat_WPACKET *pkt);

/*
 * Iterate through all the sub-packets and write out their lengths as if they
 * were being closed. The lengths will be overwritten with the final lengths
 * when the sub-packets are eventually closed (which may be different if more
 * data is added to the WPACKET). This function fails if a sub-packet is of 0
 * length and QAT_WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH is set.
 */

int QAT_WPACKET_start_sub_packet_len__(qat_WPACKET *pkt, size_t lenbytes);

/*
 * Same as QAT_WPACKET_start_sub_packet_len__() except no bytes are pre-allocated
 * for the sub-packet length.
 */

int QAT_WPACKET_allocate_bytes(qat_WPACKET *pkt, size_t len,
                           unsigned char **allocbytes);

/*
 * The same as QAT_WPACKET_allocate_bytes() except additionally a new sub-packet is
 * started for the allocated bytes, and then closed immediately afterwards. The
 * number of length bytes for the sub-packet is in |lenbytes|. Don't call this
 * directly. Use the convenience macros below instead.
 */

/*
 * The same as QAT_WPACKET_allocate_bytes() except the reserved bytes are not
 * actually counted as written. Typically this will be for when we don't know
 * how big arbitrary data is going to be up front, but we do know what the
 * maximum size will be. If this function is used, then it should be immediately
 * followed by a QAT_WPACKET_allocate_bytes() call before any other WPACKET
 * functions are called (unless the write to the allocated bytes is abandoned).
 *
 * For example: If we are generating a signature, then the size of that
 * signature may not be known in advance. We can use QAT_WPACKET_reserve_bytes() to
 * handle this:
 *
 *  if (!WPACKET_sub_reserve_bytes_u16(&pkt, EVP_PKEY_get_size(pkey), &sigbytes1)
 *          || EVP_SignFinal(md_ctx, sigbytes1, &siglen, pkey) <= 0
 *          || !WPACKET_sub_allocate_bytes_u16(&pkt, siglen, &sigbytes2)
 *          || sigbytes1 != sigbytes2)
 *      goto err;
 */
int QAT_WPACKET_reserve_bytes(qat_WPACKET *pkt, size_t len, unsigned char **allocbytes);

/*
 * The "reserve_bytes" equivalent of WPACKET_sub_allocate_bytes__()
 */
/*
 * Write the value stored in |val| into the WPACKET. The value will consume
 * |bytes| amount of storage. An error will occur if |val| cannot be
 * accommodated in |bytes| storage, e.g. attempting to write the value 256 into
 * 1 byte will fail. Don't call this directly. Use the convenience macros below
 * instead.
 */
int QAT_WPACKET_put_bytes__(qat_WPACKET *pkt, uint64_t val, size_t bytes);

/*
 * Convenience macros for calling WPACKET_put_bytes with different
 * lengths
 */
#define QAT_WPACKET_put_bytes_u8(pkt, val) \
    QAT_WPACKET_put_bytes__((pkt), (val), 1)
#define QAT_WPACKET_put_bytes_u16(pkt, val) \
    QAT_WPACKET_put_bytes__((pkt), (val), 2)
#define QAT_WPACKET_put_bytes_u24(pkt, val) \
    QAT_WPACKET_put_bytes__((pkt), (val), 3)
#define QAT_WPACKET_put_bytes_u32(pkt, val) \
    QAT_WPACKET_put_bytes__((pkt), (val), 4)
#define QAT_WPACKET_put_bytes_u64(pkt, val) \
    QAT_WPACKET_put_bytes__((pkt), (val), 8)


/* Copy |len| bytes of data from |*src| into the WPACKET. */
int QAT_WPACKET_memcpy(qat_WPACKET *pkt, const void *src, size_t len);


/*
 * Copy |len| bytes of data from |*src| into the WPACKET and prefix with its
 * length (consuming |lenbytes| of data for the length). Don't call this
 * directly. Use the convenience macros below instead.
 */
int QAT_WPACKET_sub_memcpy__(qat_WPACKET *pkt, const void *src, size_t len,
                       size_t lenbytes);

/* Convenience macros for calling WPACKET_sub_memcpy with different lengths */
#define QAT_WPACKET_sub_memcpy_u8(pkt, src, len) \
    QAT_WPACKET_sub_memcpy__((pkt), (src), (len), 1)
#define QAT_WPACKET_sub_memcpy_u16(pkt, src, len) \
    QAT_WPACKET_sub_memcpy__((pkt), (src), (len), 2)
#define QAT_WPACKET_sub_memcpy_u24(pkt, src, len) \
    QAT_WPACKET_sub_memcpy__((pkt), (src), (len), 3)
#define QAT_WPACKET_sub_memcpy_u32(pkt, src, len) \
    QAT_WPACKET_sub_memcpy__((pkt), (src), (len), 4)

/*
 * Return the total number of bytes written so far to the underlying buffer
 * including any storage allocated for length bytes
 */
int QAT_WPACKET_get_total_written(qat_WPACKET *pkt, size_t *written);


/*
 * Returns a pointer to the current write location, but does not allocate any
 * bytes.
 */
unsigned char *QAT_WPACKET_get_curr(qat_WPACKET *pkt);

int WPACKET_is_null_buf(qat_WPACKET *pkt);

/* Release resources in a WPACKET if a failure has occurred. */
void QAT_WPACKET_cleanup(qat_WPACKET *pkt);

int QAT_WPACKET_init_der(qat_WPACKET *pkt, unsigned char *buf, size_t len);

int QAT_WPACKET_set_flags(qat_WPACKET *pkt, unsigned int flags);

int QAT_WPACKET_start_sub_packet(qat_WPACKET *pkt);

int qat_int_end_context(qat_WPACKET *pkt, int tag);

int qat_int_start_context(qat_WPACKET *pkt, int tag);

int qat_DER_w_end_sequence(qat_WPACKET *pkt, int tag);

int qat_DER_w_algorithmIdentifier_SM2_with_MD(qat_WPACKET *pkt, int cont,
                                               EC_KEY *ec, int mdnid);

int qat_DER_w_algorithmIdentifier_ECDSA_with_MD(qat_WPACKET *pkt, int cont,
                                               EC_KEY *ec, int mdnid);
