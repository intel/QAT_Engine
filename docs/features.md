# Features

## qat_hw Features
* Synchronous and [Asynchronous](async_job.md) Operation
* Asymmetric PKE Acceleration
    * RSA Support for Key Sizes 512/1024/2048/4096.
    * DH Support for Key Sizes 768/1024/1536/2048/3072/4096.
    * DSA Support for Key Sizes 160/1024, 224/2048, 256/2048, 256/3072.
    * ECDH Support for the following curves:
        * NIST Prime Curves: P-192/P-224/P-256/P-384/P-521.
        * NIST Binary Curves: B-163/B-233/B-283/B-409/B-571.
        * NIST Koblitz Curves: K-163/K-233/K-283/K-409/K-571.
        * Montgomery EC Curves: X25519/X448 (ECX).
    * ECDSA Support for the following curves:
        * NIST Prime Curves: P-192/P-224/P-256/P-384/P-521.
        * NIST Binary Curves: B-163/B-233/B-283/B-409/B-571.
        * NIST Koblitz Curves: K-163/K-233/K-283/K-409/K-571.
* Symmetric Chained Cipher acceleration with pipelining capability:
    * AES128-CBC-HMAC-SHA1/AES256-CBC-HMAC-SHA1.
    * AES128-CBC-HMAC-SHA256/AES256-CBC-HMAC-SHA256.
* Symmetric ciphers AES128-GCM and AES256-GCM
* Pseudo Random Function (PRF) Acceleration.
* [HMAC Key Derivation Function (HKDF) Acceleration.](qat_hw.md#intel-qat-openssl-engine-hkdf-support)
* [Pipelined Operations](qat_hw.md#using-the-openssl-pipelining-capability)
* [Intel&reg; QAT OpenSSL\* Engine Software Fallback](qat_hw.md#intel-qat-openssl-engine-software-fallback-feature)
* [BoringSSL Support](bssl_support.md)
* Algorithms specific to Hardware driver v2.0 and qatlib(QAT gen4 devices)
  *  RSA8K
  *  DH8K
  *  SM4-CBC (Not supported in qatlib)
  *  SHA3-224/256/384/512
  *  ChaCha20-Poly1305

Please refer [here](qat_hw_algo.md) for supported platforms list and default behaviour.

## qat_sw Features
* [Intel&reg; QAT Software Acceleration for Asymmetric PKE and AES-GCM](qat_sw.md)
    * RSA Support for Key size 2048, 3072, 4096
    * ECDH Support for the following curves:
        * Montgomery EC Curve: X25519
        * NIST Prime Curves: P-256/P-384
        * SM2
    * ECDSA Support for the following curves:
        * NIST Prime Curves: P-256/P-384
        * SM2
    * SM3 Hash Support using 16 Multibuffer requests (Experimental)
    * SM4-CBC Support using 16 Multibuffer requests (BabaSSL only)
    * SM4-GCM Support using 16 Multibuffer requests (BabaSSL only)
    * SM4-CCM Support using 16 Multibuffer requests (BabaSSL only)
    * AES128-GCM, AES192-GCM and AES256-GCM

## Common Features to qat_hw & qat_sw
* [QAT_HW & QAT_SW Co-existence with runtime configuration](qat_common.md#qat-hw-and-qat-sw-co-existence)
* [OpenSSL 3.0 Provider Support](qat_common.md#openssl-30-provider-support)

Note: RSA Padding schemes are handled by OpenSSL\* or BoringSSL\* rather than accelerated, so the
engine supports the same padding schemes as OpenSSL\* or BoringSSL\* does natively.
