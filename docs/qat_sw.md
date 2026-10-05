## Intel&reg; QAT Software Acceleration

QAT_SW supports multi-buffer software
acceleration for asymmetric PKE algorithms RSA, ECDH X25519, ECDH P-256/P-384
and ECDSA P-256/P-384, SM2, SM3, SM4-CBC, SM4-GCM, SM4-CCM using the
Intel&reg; Crypto Multi-buffer library based on Intel&reg; AVX-512 Integer
Fused Multiply Add (IFMA) operations.

When enabled using the
[build instructions](install.md#build-qat-provider-for-qat_sw) for the QAT_SW
target, this support batches queued requests and uses the OpenSSL asynchronous
infrastructure to submit up to eight requests to the Crypto Multi-buffer API.
The API processes them in parallel using AVX-512 vector instructions. QAT_SW
multi-buffer acceleration is most beneficial in asynchronous mode with enough
parallel connections to fully utilize multi-buffer processing.

Software-based acceleration for AES-GCM is supported through the Intel&reg;
Multi-Buffer Crypto for IPsec Library. The implementation at engine for AES-GCM
uses a synchronous mechanism to submit requests to the IPsec MB library, which
processes requests in multiple blocks using vectorized AES, AVX2, and AVX-512
instructions from the processor.

QAT_SW also supports ML-KEM-512/768/1024 and ML-DSA-44/65/87 through IPsec MB
v3.0.0 with QAT Provider (`qatprovider`) and OpenSSL 3.5.0 or later.
IPsec MB provides SSE implementations for both algorithms and AVX2-optimized
Number Theoretic Transform (NTT) implementations. On AVX-512 systems,
ML-DSA also uses an AVX-512VL-optimized Keccak1600 implementation. See
[PQC and Hybrid PQC Support](qat_provider_pqc.md) and the
[IPsec MB implementation matrix](https://github.com/intel/intel-ipsec-mb#1-overview)
for details.

Software acceleration features are only supported in the system that supports
Intel® AVX-512 with the following instruction set extensions:

`
AVX512F
AVX512_IFMA
VAES
VPCLMULQDQ
AVX2
`
