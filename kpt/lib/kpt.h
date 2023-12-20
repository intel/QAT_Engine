#ifndef __KPT_H__
# define __KPT_H__

/* Openssl */
#include <openssl/pem.h>
#include <openssl/asn1t.h>
#ifdef QAT_OPENSSL_3
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/engine.h>
#endif

/* QAT includes */
#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_cy_kpt.h"
#include "qae_mem.h"

#define MAX_ESWK_SIZE                 (512)
#define MAX_IV_SIZE                   (12)
#define MAX_AAD_SIZE                  (16)

/* Support RSA 8k at most */
#define MAX_KPT_RSA_KEY_TYPE1_SIZE    (2064)
#define MAX_KPT_RSA_KEY_TYPE2_SIZE    (3600)
#define MAX_KPT_RSA_KEY_N_SIZE        (1024)
#define MAX_KPT_RSA_KEY_E_SIZE        (1024)

#define MAX_KPT_ECC_KEY_SIZE          (1024)

#define PEM_STRING_WRAPPED_RSA_KEY    "KPT RSA KEY"
#define PEM_STRING_WRAPPED_ECC_KEY    "KPT ECC KEY"
#define PEM_TYPE_RSA_WPK              (1)
#define PEM_TYPE_ECC_WPK              (2)
#define KEY_WRAP_STORAGE_INDEX        (143)

#define MAX_SOCKET_NUM                (32)
#define MAX_WPK_NUM                   (32)
#define INVALID_WPK_IDX               (-1)
#define MAX_CRYPTO_INSTANCES          (64)

/* ASN1 encoded Wrapped Private Key context format */
/* ESWK part */
typedef struct e_swk{
    ASN1_OCTET_STRING *devSig;
    ASN1_OCTET_STRING *secSWK;
} ESWK;
DEFINE_STACK_OF(ESWK)
DECLARE_ASN1_FUNCTIONS(ESWK)

typedef struct wrapping_metadata {
    ASN1_OCTET_STRING *aesNonce;
    ASN1_OBJECT *wrappingAlg;
    STACK_OF(ESWK) *eSWKs;
} WRAPPINGMETADATA;
DECLARE_ASN1_FUNCTIONS(WRAPPINGMETADATA)

/* RSA part */
typedef struct rsa_public_key {
    ASN1_INTEGER *n;
    ASN1_INTEGER *e;
} RSAPUBLICKEY;
DECLARE_ASN1_FUNCTIONS(RSAPUBLICKEY)

typedef struct kpt_rsa_key {
    long version;
    ASN1_OCTET_STRING *privateKeyType1;
    ASN1_OCTET_STRING *privateKeyType2;
    long size;
    ASN1_OBJECT *kptRSADsi;
    RSAPUBLICKEY *publicKey;
    WRAPPINGMETADATA *wrappingMetadata;
} KPTRSAKEY;
DECLARE_ASN1_FUNCTIONS(KPTRSAKEY)

/* ECC part */
typedef struct kpt_ecc_key {
    long version;
    ASN1_OCTET_STRING *privateKey;
    ASN1_OBJECT *curveName;
    ASN1_BIT_STRING *publicKey;
    WRAPPINGMETADATA *wrappingMetadata;
} KPTECCKEY;
DECLARE_ASN1_FUNCTIONS(KPTECCKEY)


/* Local struct to store content of WPK file */
typedef struct kpt_rsa_wpk_st {
    long version; 
    long size; 
    unsigned char wpk_type1[MAX_KPT_RSA_KEY_TYPE1_SIZE];
    unsigned char wpk_type2[MAX_KPT_RSA_KEY_TYPE2_SIZE];
    unsigned char n[MAX_KPT_RSA_KEY_N_SIZE];
    unsigned char e[MAX_KPT_RSA_KEY_E_SIZE];
    int wpk_type1_size;
    int wpk_type2_size;
    int n_size;
    int e_size;
    int wrapping_alg_nid;
    /* for global wpk<->eswk<->instance mapping */
    int wpk_index;
}kpt_rsa_wpk;

typedef struct kpt_ecc_wpk_st {
    long version; 
    unsigned char wpk[MAX_KPT_ECC_KEY_SIZE];
    unsigned char pub_key[MAX_KPT_ECC_KEY_SIZE];
    int wpk_size;
    int pub_key_size;
    /* optional NID for named curve */
    int curve_nid;
    int wrapping_alg_nid;
    /* for global wpk<->eswk<->instance mapping */
    int wpk_index;
}kpt_ecc_wpk;

/* Encrypted Symmetric Wrapping Key metadata for KPT provision */
typedef struct {
    unsigned char eswk[MAX_ESWK_SIZE];
    int len_eswk;
    unsigned char iv[MAX_IV_SIZE];
    int len_iv;
    unsigned char aad[MAX_AAD_SIZE];
    int len_aad;
} kpt_eswk_meta_data_st;

/* Signature of KPT Per-Part Key to distinguish QAT devices */
typedef struct {
    unsigned char signature[MAX_ESWK_SIZE];
    int len_sig;
} kpt_dev_identity_st;

/* Device credentials loaded from WPK file */
typedef struct {
    int total;
    kpt_eswk_meta_data_st eswk_data[MAX_SOCKET_NUM];
    kpt_dev_identity_st dev_id[MAX_SOCKET_NUM];
} kpt_dev_credential_st;

typedef enum {
    NON_WPK = 0,
    RSA_WPK,
    ECC_WPK,
} kpt_wpk_type;

#define KPT_DEV_CREDENTIAL_SIZE_IN_BYTE    (384)
#define KPT_ENCRYPTED_SWK_SIZE_IN_BYTE     (384)
#define KPT_PER_PART_PUBKEY_N_SIZE_IN_BYTE (384)
#define KPT_PER_PART_PUBKEY_E_SIZE_IN_BYTE (8)

typedef enum {
    KPT_NON_SHARE_MODE = 0,
    KPT_SHARE_MODE
} kpt_share_mode;

/* KPT provision metadata for each ESWK */
typedef struct {
    int swk_provisioned;
    CpaCyKptUnwrapContext unwrap_ctx;
    CpaCyKptLoadKey wrapping_key;
} kpt_provision_meta_cxt_st;

/* KPT provision context for each instance */
typedef struct {
    int kpt_enabled;
    kpt_share_mode mode;
    CpaInstanceHandle instance_handle;
    kpt_provision_meta_cxt_st meta_ctx[MAX_WPK_NUM];
} kpt_inst_provision_context_st;


typedef void (*kpt_rsa_cb_func)(void *pCallbackTag,
                                CpaStatus status,
                                void *pOpdata,
                                CpaFlatBuffer *pOut);

typedef void (*kpt_ecdsa_cb_func)(void *pCallbackTag, CpaStatus status,
                                 void *pOpData, CpaBoolean bEcdsaSignStatus,
                                 CpaFlatBuffer * pResultR,
                                 CpaFlatBuffer * pResultS);

/* WPK file parse function. It retrieves private key information from ASN1 
 * encoded stream and saves the data into kpt_rsa_wpk struct.
 * The kpt_rsa_wpk will be stored into EVP_PKEY->ex_data for later usage. */
EVP_PKEY *kpt_load_priv_key(ENGINE *e, const char *wpk);

/* Reset the index of WPK loading for Nginx reload case. */
int kpt_reset_wpk_num();

/* Check the instance whether is provisioned or not. */
int kpt_instance_available(int qat_inst_index, int wpk_index);

/* KPT init functions, doing SWK provision. 
 * Note that this library is not responsible for the QAT instance management,
 * so instances should be inited and started out of the library. */
int kpt_init(int qat_inst_index, CpaInstanceHandle qat_inst_handle);

/* KPT finish functions, deleting provisioned SWK. */
void kpt_finish(int qat_inst_index, CpaInstanceHandle qat_inst_handle);

/* RSA Operations*/
int kpt_check_rsa_wpk(RSA *rsa);

int kpt_rsa_prepare(int flen, const unsigned char *from,
                    unsigned char *to, RSA *rsa, int padding,
                    CpaFlatBuffer **output_buffer, 
                    CpaCyKptRsaDecryptOpData **kpt_dec_op_data,
                    int alloc_pad, int *wpk_index);

int kpt_rsa_decrypt(int qat_inst_index,
                    const kpt_rsa_cb_func cb, void *cb_data, 
                    CpaCyKptRsaDecryptOpData *dec_op_data, 
                    CpaFlatBuffer *output_buf, int wpk_index);

void kpt_rsa_finish(CpaCyKptRsaDecryptOpData *dec_op_data,
                    CpaFlatBuffer *out_buf, int *wpk_index);


/* ECDSA Operations */
int kpt_check_ec_wpk(EC_KEY *eckey);

int kpt_ecdsa_prepare(const unsigned char *dgst, int dgst_len,
                        const BIGNUM *in_kinv, const BIGNUM *in_r,
                        EC_KEY *eckey, BN_CTX **ctx, ECDSA_SIG **ret, 
                        CpaFlatBuffer **pResultR, CpaFlatBuffer **pResultS,
                        BIGNUM **ecdsa_sig_r, BIGNUM **ecdsa_sig_s,
                        CpaCyKptEcdsaSignRSOpData **opData, int *wpk_index);

int kpt_ecdsa_do_sign(int qat_inst_index,
                        const kpt_ecdsa_cb_func cb, void *cb_data, 
                        CpaCyKptEcdsaSignRSOpData *opData,
                        CpaBoolean *bEcdsaSignStatus,
                        CpaFlatBuffer *pResultR, CpaFlatBuffer *pResultS,
                        int wpk_index);

void kpt_ecdsa_finish(CpaFlatBuffer *pResultR, CpaFlatBuffer *pResultS, 
                        CpaCyKptEcdsaSignRSOpData *opData, BN_CTX *ctx,
                        int *wpk_index);
#endif
