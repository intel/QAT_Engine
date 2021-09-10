# Features

## qat_hw Features
* Synchronous and [Asynchronous](async_job.md) Operation
* Asymmetric PKE Acceleration
    * RSA Support for Key Sizes 1024/2048/4096.
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
* Pseudo Random Function (PRF) Acceleration.
* [HMAC Key Derivation Function (HKDF) Acceleration.](qat_hw.md#intel-qat-openssl-engine-hkdf-support)
* [Pipelined Operations](qat_hw.md#using-the-openssl-pipelining-capability)
* [Intel&reg; QAT OpenSSL\* Engine Software Fallback](qat_hw.md#intel-qat-openssl-engine-software-fallback-feature)
* RSA8K, SHA3-224/256/384/512 and ChaCha20-Poly1305 using 4xxx (QAT gen4 devices) only.

## qat_sw Features
* [Intel&reg; QAT Software Acceleration for Asymmetric PKE and AES-GCM](qat_sw.md)
    * RSA Support for Key size 2048, 3072, 4096
    * ECDH Support for the following curves:
        * Montgomery EC Curve: X25519
        * NIST Prime Curves: P-256/P-384
    * ECDSA Support for the following curves:
        * NIST Prime Curves: P-256/P-384
    * AES128-GCM, AES192-GCM and AES256-GCM

[QAT_HW & QAT_SW Co-existence Feature](qat_hw.md#qat-hw-and-qat-sw-co-existence-feature)

Note: RSA Padding schemes are handled by OpenSSL\* rather than accelerated, so the
engine supports the same padding schemes as OpenSSL does natively.
