## Intel&reg; QAT Software Acceleration for Asymmetric PKE and AES-GCM

This Intel&reg; QAT OpenSSL\* Engine supports Multi-buffer based software
acceleration for asymmetric PKE algorithms RSA, ECDH X25519, ECDH P-256/P-384
and ECDSA(sign) P-256/P-384 using the Intel&reg; Crypto Multi-buffer library
based on Intel&reg; AVX-512 Integer Fused Multiply Add (IFMA) operations.

This Support, when enabled by the user using the
[build instructions](../README.md#installation-instructions) for qat_sw target
performs operation by batching up multiple requests maintained in queues
and uses the OpenSSL asynchronous infrastructure to submit the batched requests
up to 8 to Crypto Multi-buffer API which processes them in parallel using AVX512
vector instructions. QAT SW Multi-buffer acceleration will be beneficial to
use in asynchronous operations where there are many parallel connections.

Software based acceleration for AES-GCM is supported via the Intel&reg;
Multi-Buffer Crypto for IPsec Library. The implementation at engine for AES-GCM
follows synchronous mechanism to submit requests to the IPSec_MB library which
processes requests in multiple blocks using vectorized AES and AVX512
instructions from the processor.
