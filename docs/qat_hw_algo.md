# QAT_HW Algorithms list, its supported platforms and default behaviour

| QAT_HW Algorithms | v1.7 | v1.8 | v2.0 | qatlib(intree) |
| :---: | :---: | :---: | :---: | :---: |
| RSA Key size < 2048 | ** | ** | ** | ** |
| RSA Key size >= 2048 <= 4096 | * | * | * | * |
| RSA Key size 8192 |  |  | * | * |
| ECDSA Curves with bitlen < 256 | ** | ** | ** | ** |
| ECDSA Curves with bitlen >= 256 | * | * | * | * |
| ECDH Curves with bitlen  < 256| ** | ** | ** | ** |
| ECDH Curves with bitlen >= 256 | * | * | * | * |
| ECDH X25519 & X448(ECX)| * | * | * | * |
| DSA | ** | ** | ** | ** |
| DH key size < 8192 | ** | ** | ** | ** |
| DH key size >=8192 |  |  | ** | ** |
| HKDF | *** | *** | *** | *** |
| PRF | * | * | * | * |
| AES-128-GCM | *** | *** | *** | *** |
| AES-256-GCM | *** | *** | *** | *** |
| AES128_CBC_HMAC_SHA1 | ** | ** | ** | ** |
| AES256_CBC_HMAC_SHA1 | ** | ** | ** | ** |
| AES128_CBC_HMAC_SHA256 | * | * | * | * |
| AES256_CBC_HMAC_SHA256 | * | * | * | * |
| SHA3-224 |  | ** | ** | ** |
| SHA3-256/384/512 |  | *** | *** | *** |
| ChachaPoly | | *** | *** | *** |
| SM4-CBC |  | # | # |  |
| SM3 | | *** | *** | |

\* Enabled in the default build of qatengine for the specified platforms when `--with-qat_hw_dir` is provided in qatengine/qatprovider build configure.<br>
\** Insecure algorithms which are disabled by default in QAT_HW driver version 1.7 & 1.8 and qatengine/qatprovider. Can be enabled using configure flag `--enable-qat_insecure_algorithms`. Driver will also needs to be built with the flag `./configure --enable-legacy-algorithms` to enable these algorithms at driver.<br>
\*** Algorithms disabled by default as those are experimental.<br>
\# Disabled by default as it is specific to BabaSSL and not applicable to OpenSSL. To be enabled when qatengine is built with BabaSSL.

Please refer [config_options](config_options.md) on details about algorithm enable/disable flags.
