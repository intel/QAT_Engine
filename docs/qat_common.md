# QAT_HW and QAT_SW Co-existence Feature

Intel&reg; QAT OpenSSL\* Engine supports QAT_HW and QAT_SW Co-existence build
with both QAT_HW and QAT_SW dependant libraries(QAT Driver, cryptom_mb and
ipsec_mb) linked in the qatengine.so library. This support can be enabled at
build time when both QAT_HW flag `--with-qat_hw_dir=/path/to/QAT_Driver`
and QAT_SW flag `--enable-qat_sw` configured together in the build configure
option.

If the platform has support for both QAT_HW and QAT_SW, the default
behaviour is to accelerate asymmetric algorithms and Symmetric chained ciphers
using QAT Hardware and Symmetric GCM Ciphers using QAT Software. If the platform
doesn't have QAT Hardware support then it will use QAT_SW Acceleration for
QAT_SW asymmetric algorithms that are supported in the qatengine.

The default behaviour can be changed using corresponding algorithm's enable
flags (eg:--enable-qat_sw_rsa) in which case the individual algorithms enabled
(either qat_hw or qat_sw) in the build configure will get accelerated.

# OpenSSL 3.0 Provider Support

Intel&reg; QAT OpenSSL\* Engine supports Provider interface for OpenSSL 3.0.
The qatprovider support can be enabled using configure flag `--enable-qat_provider`
and the default if not specified will use engine interface.

| Algorithms | Supported by |
| :---: | :---: |
| RSA | QAT_HW & QAT_SW |
| ECDSA | QAT_HW & QAT_SW |
| ECDH | QAT_HW & QAT_SW |
| ECX | QAT_HW & QAT_SW |
| AES-GCM | QAT_HW & QAT_SW |
| DSA | QAT_HW |
| DH | QAT_HW |
| HKDF | QAT_HW |
| PRF | QAT_HW |
| AES128_CBC_HMAC_SHA1 | QAT_HW |
| AES256_CBC_HMAC_SHA1 | QAT_HW |
| AES128_CBC_HMAC_SHA256 | QAT_HW |
| AES256_CBC_HMAC_SHA256 | QAT_HW |
| SHA3-224 | QAT_HW |
| SHA3-256 | QAT_HW |
| SHA3-384 | QAT_HW |
| SHA3-512 | QAT_HW |

This support is added as an experimental feature and tested with
OpenSSL Speed and testapp only and not tested with any application.

Example OpenSSL Speed command to test using qatprovider:

* QAT_HW
     ./openssl speed -provider qatprovider -elapsed -async_jobs 72 rsa2048
* QAT_SW
     ./openssl speed -provider qatprovider -elapsed -async_jobs 8 rsa2048
