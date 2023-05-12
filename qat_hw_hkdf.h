#ifndef QAT_HW_HKDF_H
# define QAT_HW_HKDF_H
#endif

#ifdef ENABLE_QAT_HW_HKDF

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

/* QAT TLS  pkey context structure */
typedef struct {
    /* Mode: Extract, Expand or both */
    int mode;
    /* Digest to use for HKDF */
    const EVP_MD *qat_md;
    void *sw_hkdf_ctx_data;
    /* Struct that contains salt, key and info */
    CpaCyKeyGenHKDFOpData *hkdf_op_data;
} QAT_HKDF_CTX;


/* Function Declarations */
int qat_hkdf_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
int qat_hkdf_init(EVP_PKEY_CTX *ctx);
void qat_hkdf_cleanup(EVP_PKEY_CTX *ctx);
int qat_hkdf_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                                size_t *olen);

#endif /* ENABLE_QAT_HW_HKDF */
