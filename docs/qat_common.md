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
| SM2 | QAT_SW |
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
| ChachaPoly | QAT_HW |
| SM4-GCM (BabaSSL only) | QAT_SW |
| SM4-CCM (BabaSSL only) | QAT_SW |

This support is added as an experimental feature and tested with
OpenSSL Speed and testapp only and not tested with any application.

Example OpenSSL Speed command to test using qatprovider:

* QAT_HW
     ./openssl speed -provider qatprovider -elapsed -async_jobs 72 rsa2048
* QAT_SW
     ./openssl speed -provider qatprovider -elapsed -async_jobs 8 rsa2048

# FIPS 140-3 Certification requirements Support using QAT Provider

Intel&reg; QAT OpenSSL\* Engine contains changes to comply with FIPS 140-3 Level-1
Certification requirements using QAT Provider against OpenSSL 3.0.8. The FIPS
support can be enabled using the configure flag `--enable-qat_fips` only with
OpenSSL 3.0 using provider interface which needs to be enabled using `--enable-qat_provider`.

When FIPS flag is enabled along with provider for OpenSSL3.0, it will run
self tests, integrity tests and will satisfy other FIPS 140-3 CMVP & CAVP
requirements. The FIPS is build as RPM using the specfile fips/qatengine_fips.spec
with QAT_HW & QAT_SW Coexistence enabled along with other flags enabled.

Please note that the version v1.3.1 is only satisfying FIPS 140-3 Level-1
certification requirements and not FIPS certified yet.
The FIPS 140-3 certification is under process.

## Support Algorithms in FIPS mode
| Mode | Algorithms |
| :---: | :---: |
| QAT_HW | RSA, ECDSA, ECDH, ECDHX25519, ECDHX448, DSA, DH, TLS1.2-KDF(PRF), TLS1.3-KDF(HKDF), SHA3 & AES-GCM |
| QAT_SW | RSA, ECDSA, ECDH, ECDHX25519, SHA2 & AES-GCM |
