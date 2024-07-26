## Intel&reg; QAT Software Acceleration

This Intel&reg; QAT OpenSSL\* Engine supports Multi-buffer based software
acceleration for asymmetric PKE algorithms RSA, ECDH X25519, ECDH P-256/P-384
and ECDSA(sign) P-256/P-384, SM2, SM3, SM4-CBC, SM4-GCM, SM4-CCM using the
Intel&reg; Crypto Multi-buffer library based on Intel&reg; AVX-512 Integer
Fused Multiply Add (IFMA) operations.

This Support, when enabled by the user using the
[build instructions](install.md#build-qat-engine-for-qat_sw) for qat_sw target
performs operation by batching up multiple requests maintained in queues
and uses the OpenSSL asynchronous infrastructure to submit the batched requests
up to 8 to Crypto Multi-buffer API which processes them in parallel using AVX512
vector instructions. QAT SW Multi-buffer acceleration will be beneficial to
use only in asynchronous mode where there are many parallel connections to fully
utilize multibuffer operation.

Software based acceleration for AES-GCM is supported via the Intel&reg;
Multi-Buffer Crypto for IPsec Library. The implementation at engine for AES-GCM
follows synchronous mechanism to submit requests to the IPSec_MB library which
processes requests in multiple blocks using vectorized AES and AVX512
instructions from the processor.

Software acceleration features are only supported in the system that supports
Intel® AVX-512 with the following instruction set extensions:

`
AVX512F
AVX512_IFMA
VAES
VPCLMULQDQ
`
