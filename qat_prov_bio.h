#include <stdarg.h>
#include <openssl/bio.h>
#include <openssl/core.h>
#include "qat_provider.h"

int ossl_prov_bio_from_dispatch(const OSSL_DISPATCH *fns);

OSSL_CORE_BIO *ossl_prov_bio_new_file(const char *filename, const char *mode);
OSSL_CORE_BIO *ossl_prov_bio_new_membuf(const char *filename, int len);
int ossl_prov_bio_read_ex(OSSL_CORE_BIO *bio, void *data, size_t data_len,
                          size_t *bytes_read);
int ossl_prov_bio_write_ex(OSSL_CORE_BIO *bio, const void *data, size_t data_len,
                           size_t *written);
int ossl_prov_bio_gets(OSSL_CORE_BIO *bio, char *buf, int size);
int ossl_prov_bio_puts(OSSL_CORE_BIO *bio, const char *str);
int ossl_prov_bio_ctrl(OSSL_CORE_BIO *bio, int cmd, long num, void *ptr);
int ossl_prov_bio_up_ref(OSSL_CORE_BIO *bio);
int ossl_prov_bio_free(OSSL_CORE_BIO *bio);
int ossl_prov_bio_vprintf(OSSL_CORE_BIO *bio, const char *format, va_list ap);
int ossl_prov_bio_printf(OSSL_CORE_BIO *bio, const char *format, ...);

BIO_METHOD *ossl_bio_prov_init_bio_method(void);
BIO *ossl_bio_new_from_core_bio(QAT_PROV_CTX *provctx, OSSL_CORE_BIO *corebio);
BIO_METHOD *ossl_prov_ctx_get0_core_bio_method(QAT_PROV_CTX *ctx);
