# OpenSSL 3.0 Provider Support

Intel&reg; QAT OpenSSL\* Engine supports Provider interface for OpenSSL 3.0.
The qatprovider support can be enabled using configure flag `--enable-qat_provider`
and the default if not specified will use engine interface.

This support is added as an experimental feature and tested with
OpenSSL Speed and testapp only and not tested with any application.

Example OpenSSL Speed command to test using qatprovider:

* QAT_HW
     ./openssl speed -provider qatprovider -elapsed -async_jobs 72 rsa2048
* QAT_SW
     ./openssl speed -provider qatprovider -elapsed -async_jobs 8 rsa2048

# FIPS 140-3 Certification

Intel&reg; QAT OpenSSL\* Engine contains changes to comply with FIPS 140-3 Level-1
Certification requirements using QAT Provider against OpenSSL 3.0.8. The FIPS
support can be enabled using the configure flag `--enable-qat_fips` only with
OpenSSL 3.0 using provider interface which needs to be enabled using `--enable-qat_provider`.

When FIPS flag is enabled along with provider for OpenSSL3.0, it will run
self tests, integrity tests and will satisfy other FIPS 140-3 CMVP & CAVP
requirements. The FIPS is build as RPM using the specfile fips/qatengine_fips.spec
with QAT_HW & QAT_SW Coexistence enabled along with other flags enabled.

Please note that the version v1.3.1 is only satisfying FIPS 140-3 Level-1
certification requirements and not FIPS certified yet.
The FIPS 140-3 certification is under process.

## Support Algorithms in FIPS mode

| Mode | Algorithms |
| :---: | :---: |
| QAT_HW | RSA, ECDSA, ECDH, ECDHX25519, ECDHX448, DSA, DH, TLS1.2-KDF(PRF), TLS1.3-KDF(HKDF), SHA3 & AES-GCM |
| QAT_SW | RSA, ECDSA, ECDH, ECDHX25519, SHA2 & AES-GCM |

# Binary RPM Package

QAT_Engine supports Binary Package via RPM which can be found in the Release page (Assests section)
The Current Binary RPM Package is created for the distros RHEL 9.1, Ubuntu 22.04 and SUSE SLES15 SP3 with
with default Kernel and other dependent packages from the system default.
The RPM is generated using QAT2.0 OOT driver with QAT_SW Co-existence which means
it will accelerate via QAT_HW for asymmetic PKE and QAT_SW for AES-GCM and supported only on
[Intel® Xeon® Scalable Processor family with Intel® QAT Gen4/Gen4m][1] with default build configuration
in QAT Engine against OpenSSL 3.0 engine and can be build using `make rpm` target.
Dependent library versions used for building binary package are mentioned in Software requirements section.

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
