# QAT_HW Algorithms list, its supported platforms and default behaviour

| QAT_HW Algorithms | v1.7 | v1.8 | v2.x | qatlib(intree) |
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
| AES-128-GCM | ** | ** | ** | ** |
| AES-256-GCM | *** | *** | *** | *** |
| AES-128-CCM | ** | ** | ** | ** |
| AES-192-CCM |  |  | ** | ** |
| AES-256-CCM |  |  | * | * |
| AES128_CBC_HMAC_SHA1 | ** | ** | ** | ** |
| AES256_CBC_HMAC_SHA1 | ** | ** | ** | ** |
| AES128_CBC_HMAC_SHA256 | ** | ** | ** | ** |
| AES256_CBC_HMAC_SHA256 | * | * | * | * |
| SHA3-224 |  | ** | ** | ** |
| SHA3-256/384/512 |  | *** | *** | *** |
| ChachaPoly | | *** | *** | *** |
| SM4-CBC |  | # | # |  |
| SM3 | | *** | *** | |
| SM2 | | *** | *** | |

\* Enabled in the default QAT_Engine build for the specified platforms when `--with-qat_hw_dir` is provided (QAT Engine or QAT Provider).<br>
\** Insecure algorithms are disabled by default in the QAT_HW driver and both QAT interfaces. Enable them with the `--enable-qat_insecure_algorithms` configure flag. The driver must also be built with `./configure --enable-legacy-algorithms`.<br>
\*** Algorithms disabled by default as those are experimental.<br>
\# Disabled by default because it is specific to Tongsuo and not applicable to OpenSSL. Enable it for Tongsuo builds.

See [Configuration Options](config_options.md) for details about algorithm enable and disable flags.
