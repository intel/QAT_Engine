# QAT Provider Interface
Intel® QAT OpenSSL Engine uses the OpenSSL 3.x Provider interface (`qatprovider`),
which is the recommended integration point for OpenSSL 3.x applications and provides
the same QAT acceleration capabilities as the legacy Engine interface. Legacy Engine
support can be enabled using the `--enable-qat_engine` configure flag. As the Engine
interface has been removed in OpenSSL 4.0, only qatprovider is supported with
OpenSSL 4.0 and later.

Example commands to test using qatprovider:
> **Note:** If `qatprovider.so` is not installed in the default OpenSSL\* modules
> directory (`<openssl-install>/lib64/ossl-modules/`), add
> `-provider-path /path/to/ossl-modules` before `-provider qatprovider` in all
> commands below.

> **Note:** When loading `qatprovider` explicitly, always also load the OpenSSL\*
> `default` provider (add `-provider default` to command-line invocations, or
> activate `[default_sect]` in `openssl.cnf`). The `default` provider supplies
> algorithms not offloaded by QAT (e.g. certificate parsing, key encoding,
> digest algorithms used internally). Omitting it can cause unexpected failures.

> **Note:** When QAT HW or SW offload is supported and enabled on the platform,
> `qatprovider` takes the highest priority over all other stacked providers for
> the algorithms it offloads.
* QAT_HW
     ./openssl speed -provider qatprovider -provider default -elapsed -async_jobs 72 rsa2048
* QAT_SW
     ./openssl speed -provider qatprovider -provider default -elapsed -async_jobs 8 rsa2048

**RSA Sign/Verify:**
```
./openssl genrsa -provider qatprovider -provider default -out rsa_key.pem 2048
./openssl dgst -provider qatprovider -provider default -sha256 -sign rsa_key.pem -out sig.bin plain.txt
./openssl dgst -provider qatprovider -provider default -sha256 -verify <(./openssl rsa -in rsa_key.pem -pubout) -signature sig.bin plain.txt
```

**ECDSA Sign/Verify (P-256):**
```
./openssl genpkey -provider qatprovider -provider default -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec_key.pem
./openssl dgst -provider qatprovider -provider default -sha256 -sign ec_key.pem -out ec_sig.bin plain.txt
./openssl dgst -provider qatprovider -provider default -sha256 -verify <(./openssl pkey -in ec_key.pem -pubout) -signature ec_sig.bin plain.txt
```

**AES-GCM Encrypt/Decrypt:**
```
./openssl enc -provider qatprovider -provider default -aes-256-gcm -pbkdf2 -in plain.txt -out enc.bin
./openssl enc -provider qatprovider -provider default -aes-256-gcm -pbkdf2 -d -in enc.bin -out dec.txt
```

**TLS Handshake (s_server / s_client):**
```
# Server
./openssl s_server -provider qatprovider -provider default -cert server.crt -key server.key -port 4433 &
# Client
./openssl s_client -provider qatprovider -provider default -connect localhost:4433
```

## Interoperability with OpenSSL Default Provider for Hybrid PQC

`qatprovider` supports hybrid post-quantum cryptography (PQC) by stacking with a second
provider that supplies PQC algorithms. QAT accelerates the classical component
(e.g. ECDH P-256/P-384, RSA, AES-GCM) while the PQC provider supplies the
post-quantum component (ML-KEM, ML-DSA). Two configurations have been tested:

| Configuration | OpenSSL Version | PQC Provider |
| :--- | :---: | :--- |
| [OpenSSL 3.5.x built-in](#option-1-openssl-35x-built-in-default-provider) | 3.5.x | Built-in `default` provider (ML-KEM, ML-DSA) |
| [liboqs + oqs-provider](#option-2-openssl-34x-with-liboqs--oqs-provider) | 3.x (≤3.4.x) | [`oqs-provider`](https://github.com/open-quantum-safe/oqs-provider) backed by [`liboqs`](https://github.com/open-quantum-safe/liboqs) |

---

### Option 1: OpenSSL 3.5.x built-in default provider

OpenSSL 3.5.x ships ML-KEM and ML-DSA natively in its `default` provider — no
additional libraries are needed.

**openssl.cnf — stacked provider configuration:**
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

**Test hybrid KEM speed:**
```bash
./openssl speed -provider qatprovider -provider default \
    -elapsed X25519MLKEM768 p256_mlkem768
```

**TLS handshake with hybrid KEM groups:**
```bash
# Server
./openssl s_server \
    -provider qatprovider -provider default \
    -cert server.crt -key server.key -port 4433 \
    -groups X25519MLKEM768:p256_mlkem768:X25519 &

# Client
./openssl s_client \
    -provider qatprovider -provider default \
    -connect localhost:4433 \
    -groups X25519MLKEM768:p256_mlkem768:X25519
```

**Generate a hybrid key and self-signed certificate (hybrid signatures):**
```bash
./openssl genpkey \
    -provider qatprovider -provider default \
    -algorithm p256_mldsa44 -out hybrid_key.pem

./openssl req -new -x509 \
    -provider qatprovider -provider default \
    -key hybrid_key.pem -out hybrid_cert.pem \
    -subj "/CN=QAT Hybrid Test"
```

**TLS handshake with hybrid signature authentication:**
```bash
# Server
./openssl s_server \
    -provider qatprovider -provider default \
    -cert hybrid_cert.pem -key hybrid_key.pem -port 4433 &

# Client
./openssl s_client \
    -provider qatprovider -provider default \
    -connect localhost:4433 \
    -CAfile hybrid_cert.pem
```

---

### Option 2: OpenSSL 3.4.x with liboqs + oqs-provider

For OpenSSL versions prior to 3.5.x, use [`liboqs`](https://github.com/open-quantum-safe/liboqs)
and [`oqs-provider`](https://github.com/open-quantum-safe/oqs-provider) to supply PQC algorithms.
Build and install them following the [oqs-provider build instructions](https://github.com/open-quantum-safe/oqs-provider#building-and-installing).

**openssl.cnf — stacked provider configuration:**
```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_section

[provider_section]
qatprovider = qat_prov_section
oqsprovider  = oqs_prov_section
default      = default_sect

[qat_prov_section]
module   = /usr/local/lib64/ossl-modules/qatprovider.so
activate = 1

[oqs_prov_section]
module   = /usr/local/lib64/ossl-modules/oqsprovider.so
activate = 1

[default_sect]
activate = 1
```

**Test hybrid KEM speed:**
```bash
./openssl speed -provider qatprovider -provider oqsprovider -provider default \
    -elapsed X25519_kyber768 p256_kyber768
```

**TLS handshake with hybrid KEM groups:**
```bash
# Server
./openssl s_server \
    -provider qatprovider -provider oqsprovider -provider default \
    -cert server.crt -key server.key -port 4433 \
    -groups X25519_kyber768:p256_kyber768:X25519 &

# Client
./openssl s_client \
    -provider qatprovider -provider oqsprovider -provider default \
    -connect localhost:4433 \
    -groups X25519_kyber768:p256_kyber768:X25519
```

# FIPS 140-3 Certification

The Intel® QAT OpenSSL* Engine (version v1.3.1) has obtained FIPS 140-3 Level-1
certification for the QAT Provider. The certificate is available at [NIST CMVP Certificate #5032](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5032).

FIPS support for the qatprovider can be enabled using the `--enable-qat_fips` configure option.
This option is supported when building against OpenSSL 3.0.8 and later using the Provider interface.
When enabled, the qatprovider performs the required self-tests, integrity tests, and other FIPS-related operations.

While `--enable-qat_fips` enables FIPS-compatible functionality in the qatprovider, FIPS compliance
can only be claimed when it is used as part of a validated OpenSSL FIPS configuration.

## Support Algorithms in FIPS mode

| Mode | Algorithms |
| :---: | :---: |
| QAT_HW | RSA, ECDSA, ECDH, ECDHX25519, ECDHX448, DSA, DH, TLS1.2-KDF(PRF), TLS1.3-KDF(HKDF), SHA3 & AES-GCM |
| QAT_SW | RSA, ECDSA, ECDH, ECDHX25519, SHA2 & AES-GCM |

# Binary RPM Package

QAT_Engine supports Binary Package via RPM which can be found in the Release page (Assests section)
The Current Binary RPM Package is created for the distros RHEL 9.2, Ubuntu 22.04 and SUSE SLES15 SP3 with
with default Kernel and other dependent packages from the system default.
The RPM is generated using QAT2.0 OOT driver with QAT_SW Co-existence which means
it will accelerate via QAT_HW for asymmetic PKE and QAT_SW for AES-GCM and supported only on
[Intel® Xeon® Scalable Processor family with Intel® QAT Gen4/Gen4m][1] with the default build
configuration QAT Provider (`qatprovider.so`) against OpenSSL 3.x and installs it under `ossl-modules/`.
It can be built using the `make rpm_oot` target. Dependent library versions used for building the
binary package are mentioned in Software requirements section.

Example commands below to install and uninstall RPM Package

```
install:
    RHEL & SUSE: rpm -ivh QAT_Engine-<version>.x86_64.rpm --target noarch
    Ubuntu: alien -i QAT_Engine-<version>.x86_64.rpm --scripts
uninstall
    RHEL & SUSE: rpm -e QAT_Engine
    Ubuntu: apt-get remove QAT_Engine
```

The binary RPM Package will take care of installing dependent libraries and kernel modules in the
default path and OpenSSL being installed in `/usr/local/ssl`
Since it is using different OpenSSL version(refer Software requirements for version) than what is
present in the system. LD_LIBRARY_PATH must be set to this path below.

```
export LD_LIBRARY_PATH=/usr/local/ssl/lib64
```

[1]:https://www.intel.com/content/www/us/en/products/docs/processors/xeon-accelerated/4th-gen-xeon-scalable-processors.html
