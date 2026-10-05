# PQC and Hybrid PQC Support

This page covers post-quantum cryptography (PQC) with the QAT Provider
(`qatprovider`): direct ML-KEM and ML-DSA offload, and hybrid PQC
configurations with OpenSSL. For provider loading, runtime parameters, and
application integration, see [QAT Provider Interface](qat_provider.md).

## ML-KEM and ML-DSA Offload via QAT_SW(IPsec_MB)

`qatprovider` offloads ML-KEM key encapsulation and ML-DSA signatures through
the QAT_SW path using the Intel Multi-Buffer Crypto for IPsec Library
(IPsec MB). This direct offload is available only through the OpenSSL Provider
interface and is disabled by default.

Requirements:

- OpenSSL 3.5.0 or later, which provides the ML-KEM and ML-DSA algorithm
  definitions used by the OpenSSL Provider interface.
- QAT_SW enabled with `--enable-qat_sw`. A QAT_SW build requires both the
  Intel Crypto Multi-buffer library (`crypto_mb`) and IPsec MB, even though
  ML-KEM and ML-DSA are offloaded through IPsec MB.
- [IPsec MB v3.0.0](https://github.com/intel/intel-ipsec-mb/releases/tag/v3.0.0)
  or later, with ML-KEM and ML-DSA support.

Enable either algorithm, or both, when configuring QAT_Engine. Omit either
`--with-qat_sw_*_install_dir` option when that library is installed in its
default location:

```bash
./configure --enable-qat_sw --enable-qat_sw_ml_kem --enable-qat_sw_ml_dsa \
        --with-openssl_install_dir=/path/to/openssl-3.5+ \
        --with-qat_sw_crypto_mb_install_dir=/path/to/crypto_mb \
        --with-qat_sw_ipsec_mb_install_dir=/path/to/ipsec_mb
```

The individual configure options are:

- `--enable-qat_sw_ml_kem` for ML-KEM-512, ML-KEM-768, and ML-KEM-1024.
- `--enable-qat_sw_ml_dsa` for ML-DSA-44, ML-DSA-65, and ML-DSA-87.

Do not combine these options with `--enable-qat_engine`. When invoking OpenSSL
explicitly, load both `qatprovider` and the `default` provider so that software
algorithms and operations not supplied by QAT remain available:

```bash
./openssl list -kem-algorithms -signature-algorithms \
        -provider qatprovider -provider default
```

## Hybrid PQC Support with OpenSSL Default Provider

Two related but distinct PQC scenarios are supported:

| Scenario | Example algorithms | Provider path | Offload behavior |
| :--- | :--- | :--- | :--- |
| Pure PQC primitive offload | ML-KEM-512/768/1024, ML-DSA-44/65/87 | Direct `qatprovider` implementation through QAT_SW and IPsec MB | ML-KEM and ML-DSA operations are offloaded through IPsec MB. |
| OpenSSL 3.5 hybrid PQC interoperability | `X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` | OpenSSL composes the hybrid KEM from QAT-supported components | The classical component can use QAT_HW, QAT_SW, or co-existence routing; ML-KEM uses QAT_SW through IPsec MB. |

Pure PQC offload is described in
[ML-KEM and ML-DSA Offload via IPsec MB](#ml-kem-and-ml-dsa-offload-via-qat_swipsec_mb).

OpenSSL hybrid PQC uses a composite KEM that combines a classical key exchange
with ML-KEM. OpenSSL supplies the composite implementation, while
`qatprovider` supplies the QAT implementations used by its components. The
classical component can use QAT_HW, QAT_SW, or QAT_HW/QAT_SW co-existence;
the ML-KEM component uses QAT_SW through IPsec MB. The composite operation
itself is not a single IPsec MB primitive.

The following provider configurations have been tested:

| Configuration | OpenSSL Version | PQC Provider |
| :--- | :---: | :--- |
| [OpenSSL 3.5.x built-in](#option-1-openssl-35x-built-in-default-provider) | 3.5.x | Built-in `default` provider (ML-KEM, ML-DSA) |
| [liboqs + oqs-provider](#option-2-openssl-34x-with-liboqs-and-oqs-provider) | 3.x (<=3.4.x) | [`oqs-provider`](https://github.com/open-quantum-safe/oqs-provider) backed by [`liboqs`](https://github.com/open-quantum-safe/liboqs) |

---

### Option 1: OpenSSL 3.5.x built-in default provider

OpenSSL 3.5.x ships ML-KEM and ML-DSA natively in its `default` provider; no
additional PQC provider is needed for hybrid interoperability. IPsec MB is
still required for direct ML-KEM/ML-DSA offload through `qatprovider`.

#### Provider configuration

For the OpenSSL 3.5.x hybrid configurations below, load both `qatprovider` and
the OpenSSL `default` provider:

**openssl.cnf - stacked provider configuration:**
```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_section

[provider_section]
qatprovider = qat_prov_section
default     = default_sect

[qat_prov_section]
module   = /usr/local/lib64/ossl-modules/qatprovider.so
activate = 1

[default_sect]
activate = 1
```

#### OpenSSL Hybrid PQC Support

The following OpenSSL 3.5 hybrid KEM groups are supported:

| Hybrid KEM group | Classical component | PQC component |
| :--- | :--- | :--- |
| `X25519MLKEM768` | X25519 | ML-KEM-768 |
| `SecP256r1MLKEM768` | ECDH P-256 | ML-KEM-768 |
| `SecP384r1MLKEM1024` | ECDH P-384 | ML-KEM-1024 |

For each group, configure the classical component independently from ML-KEM:

| Classical offload mode | X25519 component | P-256/P-384 component | ML-KEM component |
| :--- | :--- | :--- | :--- |
| QAT_HW | `--enable-qat_hw_ecx --disable-qat_sw_ecx` | `--enable-qat_hw_ecdh --disable-qat_sw_ecdh` | QAT_SW through IPsec MB |
| QAT_SW | `--disable-qat_hw_ecx --enable-qat_sw_ecx` | `--disable-qat_hw_ecdh --enable-qat_sw_ecdh` | QAT_SW through IPsec MB |
| Co-existence | `--enable-qat_hw_ecx --enable-qat_sw_ecx` | `--enable-qat_hw_ecdh --enable-qat_sw_ecdh` | QAT_SW through IPsec MB |

Therefore, a "QAT_HW hybrid" configuration means that the classical component
uses QAT_HW; it does not mean that ML-KEM runs on QAT_HW. All three modes require
`--enable-qat_sw --enable-qat_sw_ml_kem` and an IPsec MB build with ML-KEM
support. QAT_HW and co-existence modes also require a QAT_HW build configured
with `--with-qat_hw_dir`. In co-existence mode, the classical component follows
the normal QAT_HW/QAT_SW capacity routing described in
[Co-existence Features](features.md#co-existence-features).

**Test hybrid KEM speed:**
```bash
./openssl speed -provider qatprovider -provider default \
    -elapsed X25519MLKEM768 SecP256r1MLKEM768 SecP384r1MLKEM1024
```

**TLS handshake with hybrid KEM groups:**
```bash
# Server
./openssl s_server \
    -provider qatprovider -provider default \
    -cert server.crt -key server.key -port 4433 \
    -groups X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024 &

# Client
./openssl s_client \
    -provider qatprovider -provider default \
    -connect localhost:4433 \
    -groups X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024
```

---

### Option 2: OpenSSL 3.4.x with liboqs and oqs-provider

For OpenSSL versions prior to 3.5.x, use [`liboqs`](https://github.com/open-quantum-safe/liboqs)
and [`oqs-provider`](https://github.com/open-quantum-safe/oqs-provider) as a
stacked PQC provider. `oqs-provider` supplies the PQC algorithms for pure PQC
operations and hybrid scenarios; `qatprovider` accelerates supported classical
components in the latter. This stack does not enable direct ML-KEM/ML-DSA
offload in `qatprovider`. Follow the
[oqs-provider build instructions](https://github.com/open-quantum-safe/oqs-provider#building-and-installing)
for setup and algorithm names.
