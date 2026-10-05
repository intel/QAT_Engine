# Features

## Interfaces
This project exposes QAT acceleration through two OpenSSL\* interfaces:

* [QAT Provider (`qatprovider`)](qat_provider.md) — default and recommended for OpenSSL 3.x and later,
  and the only supported interface for OpenSSL 4.0 and later.
* QAT Engine (`qatengine`) — legacy OpenSSL ENGINE interface, built only with `--enable-qat_engine`.

The algorithm support listed below applies to both QAT interfaces unless stated otherwise.

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
* [QAT_HW Software Fallback](qat_hw.md#qat_hw-software-fallback-feature)
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
| ML-KEM-512/768/1024 (`qatprovider` with OpenSSL 3.5+) | \*\*\* |
| ML-DSA-44/65/87 (`qatprovider` with OpenSSL 3.5+) | \*\*\* |
| SM4-CBC, SM4-GCM, SM4-CCM (16 multibuffer requests) | \# |
| SM3 (16 multibuffer requests) | \*\* |

\* Enabled by default in the standard build.<br>
\*\*\* Disabled by default; enable with `--enable-qat_sw_ml_kem` and/or
`--enable-qat_sw_ml_dsa`. Requires OpenSSL 3.5.0+ and IPsec MB v3.0.0+. See
[ML-KEM and ML-DSA Offload](qat_provider_pqc.md#ml-kem-and-ml-dsa-offload-via-ipsec-mb).<br>
\# Disabled by default; applicable to Tongsuo/BabaSSL builds only.<br>
\*\* Disabled by default due to performance degradation in multithreaded scenarios; see [Known Issues](limitations.md#known-issues).

## Co-existence Features

A co-existence build enables both QAT_HW and QAT_SW. Algorithms with
implementations on both paths use the routing policy below:

| Algorithm | Supported variants | Default routing | Driver/interface notes |
| :--- | :--- | :--- | :--- |
| RSA | 2048/3072/4096 | QAT_HW first; route requests to QAT_SW when QAT_HW capacity is reached | OOT uses QAT_HW `RETRY`; intree uses the in-flight request threshold. |
| ECDSA | P-256 | QAT_SW | QAT_SW is preferred for P-256. |
| ECDSA | P-384 | QAT_HW first; route requests to QAT_SW when QAT_HW capacity is reached | OOT uses QAT_HW `RETRY`; intree uses the in-flight request threshold. |
| ECDH | P-256/P-384 | QAT_HW first; route requests to QAT_SW when QAT_HW capacity is reached | OOT uses QAT_HW `RETRY`; intree uses the in-flight request threshold. |
| X25519 | X25519 | QAT_HW first; route requests to QAT_SW when QAT_HW capacity is reached | OOT uses QAT_HW `RETRY`; intree uses the in-flight request threshold. |
| AES-GCM | AES-128/192/256-GCM | QAT_SW | In a QAT Provider build, enabling both implementations activates only QAT_SW at runtime. Build with `--enable-qat_hw_gcm --disable-qat_sw_gcm` to use QAT_HW. Both QAT Provider and QAT Engine builds define a 4096-byte QAT_HW GCM threshold; payloads up to and including that threshold use OpenSSL software. AES-192-GCM has no QAT_HW implementation. |
| SM2 | ECDSA/SM2 key exchange | QAT_HW preferred | QAT_SW can be selected when the QAT_HW implementation is unavailable or disabled. |
| SM4-CBC | SM4-CBC | QAT_HW | In a QAT Provider build, QAT_HW takes priority when both implementations are enabled. The legacy QAT Engine module supports packet-size-based routing with QAT_SW spillover on QAT_HW `RETRY`; this requires Tongsuo/BabaSSL and the OOT driver. |
| SM3 | SM3 | QAT_HW or QAT_SW | Select one implementation at build time; simultaneous QAT_HW and QAT_SW SM3 is not supported. |

Algorithms implemented by only one acceleration path remain available in a
co-existence build through that path:

| Acceleration path | Algorithms |
| :--- | :--- |
| QAT_HW | DSA, DH, X448, PRF, HKDF, AES-CBC-HMAC-SHA, AES-CCM, ChaCha20-Poly1305, SHA3 |
| QAT_SW | SM4-GCM, SM4-CCM, ML-KEM-512/768/1024, ML-DSA-44/65/87 |

Algorithm configure flags and platform restrictions still apply. ML-KEM and
ML-DSA are disabled by default and available only through `qatprovider` with
OpenSSL 3.5.0+ and IPsec MB support. The `HW_ALGO_BITMAP` and `SW_ALGO_BITMAP`
runtime controls apply only to QAT Engine (`qatengine`). See
[QAT_HW and QAT_SW Co-existence](qat_coex.md#qat_hw-and-qat_sw-co-existence) for
the OOT/intree routing design, recommended settings, and Engine bitmap details.

## Common Features to qat_hw & qat_sw
* [PQC and Hybrid PQC Support](qat_provider_pqc.md)
* [BoringSSL Support](bssl_support.md)
* [FIPS 140-3 Certification](qat_provider.md#fips-140-3-certification)

Note: RSA Padding schemes are handled by OpenSSL\* or BoringSSL\* rather than accelerated, so the
engine supports the same padding schemes as OpenSSL\* or BoringSSL\* does natively.
