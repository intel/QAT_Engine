#ifndef __QAT_HW_KPT_H__
# define __QAT_HW_KPT_H__

/* Openssl */
#  include <openssl/bio.h>
#  include <openssl/pem.h>
#  include <openssl/rsa.h>
#  include <openssl/ec.h>
#  include <openssl/x509.h>
#  include <openssl/x509v3.h>
#  include <openssl/asn1t.h>

/* QAT includes */
#  include "cpa.h"
#  include "cpa_cy_im.h"
#  include "cpa_cy_kpt.h"
#  include "qae_mem.h"
#  include "qae_mem_utils.h"
#  include "icp_sal_versions.h"
#  include "icp_sal_poll.h"

/* Local Includes */
#  include "qat_utils.h"

/* KPT2 Library Includes */
#  include "kpt.h"

/******************************************************************************
* function:
*         EVP_PKEY *qat_hw_kpt_load_privkey(ENGINE *e, const char *wpk)
*
* @param e   [IN] - OpenSSL engine pointer
* @param wpk [IN] - Path of WPK file
*
* @return - Openssl EVP_PKEY key struct
*
* description:
*   WPK file loading and parsing function. It will retrieve key information from 
*   ASN1 encoded stream and save the data into EVP_PKEY->ex_data for later usage.
*   
******************************************************************************/
EVP_PKEY *qat_hw_kpt_load_privkey(ENGINE *e, const char *wpk);

/******************************************************************************
* function:
*         qat_hw_kpt_init()
*
* @return - 1 represent successful, 0 represent failed
*
* description:
*   KPT init functions. Provision the ESWK to QAT HW devices.
* 
******************************************************************************/
int qat_hw_kpt_init();

/******************************************************************************
* function:
*         void qat_hw_kpt_finish();
*
* description:
*   KPT finish functions. Delete the provisioned SWK.
*   
******************************************************************************/
void qat_hw_kpt_finish();

/******************************************************************************
* function:
*         int is_kpt_mode(void);
*
* @return - 1 represent KPT mode, 0 represent Non-KPT mode.
*
* description:
*   KPT mode availability check.
*   
******************************************************************************/
int is_kpt_mode(void);

/******************************************************************************
* function:
*         qat_check_rsa_wpk(RSA *rsa);
*
* @return - 1 represent the RSA WPK is used, 0 represent the opposition.
*
* description:
*   Check whether the RSA Wrapped Private Key is used.
*   
******************************************************************************/
int qat_check_rsa_wpk(RSA *rsa);

/******************************************************************************
* function:
*  qat_hw_kpt_rsa_priv_enc (int flen,
*                           const unsigned char *from,
*                           unsigned char *to,
*                           RSA *rsa,
*                           int padding)
*
* @param flen    [IN]  - length in bytes of input file
* @param from    [IN]  - pointer to the input file
* @param to      [OUT] - pointer to output signature
* @param rsa     [IN]  - pointer to private key structure
* @param padding [IN]  - Padding scheme
*
* description: Perform a KPT RSA private encrypt (RSA Sign)
*              We use the decrypt implementation to achieve this.
******************************************************************************/
int qat_hw_kpt_rsa_priv_enc(int flen, const unsigned char *from,
                            unsigned char *to, RSA *rsa, int padding);

/******************************************************************************
* function:
*  qat_hw_kpt_rsa_priv_dec(int flen,
*                          const unsigned char *from,
*                          unsigned char *to,
*                          RSA * rsa,
*                          int padding)
*
* @param flen    [IN]  - length in bytes of input
* @param from    [IN]  - pointer to the input
* @param to      [OUT] - pointer to output
* @param rsa     [IN]  - pointer to the private key structure
* @param padding [IN]  - Padding scheme
*
* description:
* description: Perform a KPT RSA private decrypt. (RSA Decrypt)
******************************************************************************/
int qat_hw_kpt_rsa_priv_dec(int flen, const unsigned char *from,
                            unsigned char *to, RSA *rsa, int padding);

/******************************************************************************
* function:
*         qat_check_ec_wpk(EC_KEY *eckey);
*
* @return - 1 represent the EC WPK is used, 0 represent the opposition.
*
* description:
*   Check whether the EC Wrapped Private Key is used.
*   
******************************************************************************/
int qat_check_ec_wpk(EC_KEY *eckey);

/******************************************************************************
* function:
* qat_hw_kpt_ecdsa_do_sign (const unsigned char *dgst,
*                           int dgst_len,
*                           const BIGNUM *in_kinv,
*                           const BIGNUM *in_r,
*                           EC_KEY *eckey)
*
* @param dgst     [IN]  - digest to be signed
* @param dgst_len [IN]  - length in bytes of digest
* @param in_kinv  [IN]  - pointer to k_inv
* @param in_r     [IN]  - pointer to r
* @param eckey    [IN]  - pointer to the private key structure
* @return 
*
* description: Perform a KPT ECDSA operation.
******************************************************************************/
ECDSA_SIG *qat_hw_kpt_ecdsa_do_sign(const unsigned char *dgst, int dgst_len,
                                    const BIGNUM *in_kinv, const BIGNUM *in_r,
                                    EC_KEY *eckey);

#endif
