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

> **Algorithm default status:**
> - **Enabled by default:** RSA (2048–4096 on all platforms; up to 8192 on QAT Gen4/v2.x and intree),
>   ECDH/ECDSA (curves ≥256-bit, X25519/X448), PRF,
>   AES-256-CBC-HMAC-SHA256, AES-256-CCM (v2.x/intree only).
> - **Insecure — disabled by default** (enable with `--enable-qat_insecure_algorithms`):
>   RSA (<2048), DSA, DH (all key sizes), ECDH/ECDSA on curves <256-bit (Binary/Koblitz),
>   AES-128-GCM, AES-128/192-CCM, AES-128/256-CBC-HMAC-SHA1, AES-128-CBC-HMAC-SHA256, SHA3-224.
> - **Experimental — disabled by default** (enable with corresponding `--enable-qat_hw_*` flag):
>   AES-256-GCM, HKDF, SHA3-256/384/512, ChaCha20-Poly1305, SM2, SM3.
> - **Tongsuo/BabaSSL only — disabled by default:** SM4-CBC.
>
> See [qat_hw_algo.md](qat_hw_algo.md) for the full per-platform default status and configure flags.

## qat_sw Features
[Intel&reg; QAT Software Acceleration](qat_sw.md) provides multi-buffer based acceleration
for the following algorithms:

| QAT_SW Algorithm | Status |
| :--- | :---: |
| RSA 2048/3072/4096 | \* |
| ECDH X25519, P-256/P-384, SM2 | \* |
| ECDSA P-256/P-384, SM2 | \* |
| AES128-GCM, AES192-GCM, AES256-GCM | \* |
| SM4-CBC, SM4-GCM, SM4-CCM (16 multibuffer requests) | \# |
| SM3 (16 multibuffer requests) | \*\* |

\* Enabled by default in the standard build.<br>
\# Disabled by default; applicable to Tongsuo/BabaSSL builds only.<br>
\*\* Disabled by default due to performance degradation in multithreaded scenarios; see [Known Issues](limitations.md#known-issues).

## Common Features to qat_hw & qat_sw
* [BoringSSL Support](bssl_support.md)
* [QAT Provider Interface](qat_common.md#qat-provider-interface)
* [QAT_HW & QAT_SW Co-existence](qat_coex.md#qat-hw-and-qat-sw-co-existence)
* [FIPS 140-3 Certification](qat_common.md#fips-140-3-certification)
* [Hybrid PQC Interoperability](qat_common.md#interoperability-with-openssl-default-provider-for-hybrid-pqc)

Note: RSA Padding schemes are handled by OpenSSL\* or BoringSSL\* rather than accelerated, so the
engine supports the same padding schemes as OpenSSL\* or BoringSSL\* does natively.
