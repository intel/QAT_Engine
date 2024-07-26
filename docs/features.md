# Features

## qat_hw Features
* Asymmetric PKE
    * RSA for Key Sizes 512/1024/2048/4096/8192.
    * DH for Key Sizes 768/1024/1536/2048/3072/4096/8192.
    * DSA for Key Sizes 160/1024, 224/2048, 256/2048, 256/3072.
    * ECDH for the following curves:
        * NIST Prime Curves: P-192/P-224/P-256/P-384/P-521.
        * NIST Binary Curves: B-163/B-233/B-283/B-409/B-571.
        * NIST Koblitz Curves: K-163/K-233/K-283/K-409/K-571.
        * Montgomery EC Curves: X25519/X448 (ECX).
    * ECDSA for the following curves:
        * NIST Prime Curves: P-192/P-224/P-256/P-384/P-521.
        * NIST Binary Curves: B-163/B-233/B-283/B-409/B-571.
        * NIST Koblitz Curves: K-163/K-233/K-283/K-409/K-571.
    * SM2
* Symmetric Ciphers
    * AES128-CBC-HMAC-SHA1/AES256-CBC-HMAC-SHA1.
    * AES128-CBC-HMAC-SHA256/AES256-CBC-HMAC-SHA256.
    * AES128-CCM, AES192-CCM, AES256-CCM.
    * AES128-GCM, AES256-GCM.
    * ChaCha20-Poly1305
    * SM4-CBC
* Key Derivation 
    * PRF
    * HKDF
* Hashing
    * SHA3-224/256/384/512
    * SM3
* Synchronous and [Asynchronous](async_job.md) Operation
* [Pipelined Operations](qat_hw.md#using-the-openssl-pipelining-capability)
* [Intel&reg; QAT OpenSSL\* Engine Software Fallback](qat_hw.md#intel-qat-openssl-engine-software-fallback-feature)
* [Key Protection Technology (KPT) Support using QAT_HW driver v2.0](qat_hw_kpt.md)

Please refer [here](qat_hw_algo.md) for applicable QAT Hardware versions and algorithms enabled by default.

## qat_sw Features
* [Intel&reg; QAT Software Acceleration](qat_sw.md)
* Asymmetric PKE
    * RSA for Key size 2048, 3072, 4096
    * ECDH for the following curves:
        * Montgomery EC Curve: X25519
        * NIST Prime Curves: P-256/P-384
        * SM2
    * ECDSA for the following curves:
        * NIST Prime Curves: P-256/P-384
        * SM2
* Symmetric Ciphers
    * AES128-GCM, AES192-GCM and AES256-GCM
    * SM4-CBC using 16 Multibuffer requests (Tongsuo only)
    * SM4-GCM using 16 Multibuffer requests (Tongsuo only)
    * SM4-CCM using 16 Multibuffer requests (Tongsuo only)
* Hashing
    * SM3 Hash using 16 Multibuffer requests (Experimental)

## Common Features to qat_hw & qat_sw
* [BoringSSL Support](bssl_support.md)
* [OpenSSL 3.0 Provider Support](qat_common.md#openssl-30-provider-support)
* [QAT_HW & QAT_SW Co-existence](qat_coex.md#qat-hw-and-qat-sw-co-existence)
* [FIPS 140-3 Certification](qat_common.md#fips-140-3-certification)

Note: RSA Padding schemes are handled by OpenSSL\* or BoringSSL\* rather than accelerated, so the
engine supports the same padding schemes as OpenSSL\* or BoringSSL\* does natively.
