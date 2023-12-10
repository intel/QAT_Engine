#ifndef QAT_HW_HKDF_H
# define QAT_HW_HKDF_H
#endif

#ifdef ENABLE_QAT_HW_HKDF

# ifdef QAT_OPENSSL_3
#  include <openssl/core_names.h>
#  include <openssl/crypto.h>
#  include <openssl/obj_mac.h>
#  include <openssl/params.h>
#  include "qat_prov_hkdf_packet.h"
# endif

# include "openssl/ossl_typ.h"
# include "openssl/kdf.h"
# include "openssl/evp.h"
# include "openssl/ssl.h"

# include "qat_evp.h"
# include "qat_utils.h"
# include "e_qat.h"

# include "cpa.h"
# include "cpa_types.h"
# include "cpa_cy_key.h"

/* These limits are based on QuickAssist limits.
 * OpenSSL is more generous but better to restrict and fail
 * early on here if they are exceeded rather than later on
 * down in the driver.
 */
# define QAT_HKDF_INFO_MAXBUF 1024
#ifdef QAT_OPENSSL_3
# define QAT_KDF_MAX_INFO_SZ  80
# define QAT_KDF_MAX_SEED_SZ  48
# define QAT_KDF_MAX_KEY_SZ   80
#endif

# define EVP_KDF_HKDF_MODE_EXPAND_LABEL         2
#define EVP_PKEY_ALG_CTRL    0x1000
#define EVP_PKEY_CTRL_HKDF_PREFIX    (EVP_PKEY_ALG_CTRL + 14)
#define EVP_PKEY_CTRL_HKDF_LABEL      (EVP_PKEY_ALG_CTRL + 15)
#define EVP_PKEY_CTRL_HKDF_DATA       (EVP_PKEY_ALG_CTRL + 16)

extern char *kdf_name;

/* QAT TLS  pkey context structure */
typedef struct {
    /* Mode: Extract, Expand or both */
    int mode;
    /* Digest to use for HKDF */
    const EVP_MD *qat_md;
    void *sw_hkdf_ctx_data;
    /* Struct that contains salt, key and info */
    CpaCyKeyGenHKDFOpData *hkdf_op_data;
    /* HKDF cipherSuite */
    CpaCyKeyHKDFCipherSuite cipher_suite;
    /* fallback: SW offload */
    unsigned int fallback;
    int qat_svm;

    /* Below are used for SW fallback when compiled
     * with openssl 3.0 engine API. It uses the openssl
     * default provider. */
#ifdef QAT_OPENSSL_3
    /* input keying material */
    unsigned char sw_ikm[QAT_KDF_MAX_KEY_SZ];
    size_t sw_ikm_size;
    /* application specific information */
    unsigned char sw_info[QAT_KDF_MAX_INFO_SZ];
    size_t sw_info_size;
    /* salt */
    unsigned char sw_salt[QAT_KDF_MAX_SEED_SZ];
    size_t sw_salt_size;
#endif
#ifdef QAT_OPENSSL_PROVIDER
    unsigned char *prefix;
    size_t prefix_len;
    unsigned char *label;
    size_t label_len;
    unsigned char *data;
    size_t data_len;
#endif
} QAT_HKDF_CTX;

#ifndef QAT_KDF_SUPPORT
typedef struct {
    int mode;
    const EVP_MD *md;
    unsigned char *salt;
    size_t salt_len;
    unsigned char *key;
    size_t key_len;
    unsigned char info[QAT_HKDF_INFO_MAXBUF];
    size_t info_len;
} QAT_HKDF_PKEY_CTX;
#endif

/* Function Declarations */
int qat_hkdf_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
int qat_hkdf_init(EVP_PKEY_CTX *ctx);
void qat_hkdf_cleanup(EVP_PKEY_CTX *ctx);
int qat_hkdf_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                                size_t *olen);
#endif /* ENABLE_QAT_HW_HKDF */
