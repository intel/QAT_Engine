# Software Requirements

## qat_hw Requirements
Successful operation of QAT Hardware acceleration requires a software tool chain
that supports OpenSSL\* 1.1.1 or OpenSSL\* 3.0 or BoringSSL\* and Intel&reg; QuickAssist
Technology Driver for Linux or Intel&reg;  QuickAssist Technology
Driver for FreeBSD. This release was validated on the following:

* Intel&reg; QuickAssist Technology Driver for Linux\* HW Version 2.0 (RHEL\* 8.6) - **QAT20.L.1.0.50-00003**
* Intel&reg; QuickAssist Technology Driver for Linux\* HW Version 1.7 & 1.8 (CentOS\* 8.4 & Ubuntu\* 20.04.2) - **QAT.L.4.22.0-00001**
* Intel&reg; QuickAssist Technology Driver for FreeBSD\* HW Version 1.7 (FreeBSD\* 12.4) - **QAT.B.3.12.0-00004**
* OpenSSL\* 1.1.1v & 3.0.10
* BoringSSL\* commit - [23ed9d3][1]
* BabaSSL - 8.3.2

## qat_sw Requirements
Successful operation of the Intel&reg; QAT Software acceleration requires a
software tool chain that supports OpenSSL\* 1.1.1 or OpenSSL\* 3.0 and Intel&reg;
Crypto Multi-buffer library(for Asymmetric PKE) cloned from the [ipp-crypto][2] repo.
The crypto_mb library needs to be installed using the instructions from the
[Crypto Multi-buffer Library][3] Readme.

For QAT SW AES-GCM acceleration, prerequisite is to have Intel&reg;
Multi-Buffer crypto for IPsec Library cloned from the [intel-ipsec-mb][4]
repo and installed using the instructions from the intel-ipsec-mb README.
The Intel&reg; QAT Engine supports QAT SW AES-GCM from OpenSSL\* 1.1.1d.

This release was validated on the following:

* Operating system: Ubuntu\* 20.04.2 LTS
* Intel&reg; Crypto Multi-buffer library from the [ipp-crypto][2] release
  version **IPP Crypto 2021.8**
* Intel&reg; Multi-Buffer crypto for IPsec Library release version **v1.4**
* OpenSSL\* 1.1.1v & 3.0.10
* BoringSSL\* commit - [23ed9d3][1]
* BabaSSL - 8.3.2

--------------------------------------------------------------------------------

Note : OpenSSL\* Version 1.1.1 will be EOL from Sep'23 for general use hence
QAT Engine(qat_hw & qat_sw) is also planning to drop the support for OpenSSL\*
1.1.1 after the OpenSSL\* 1.1.1 EOL.

--------------------------------------------------------------------------------

[1]:https://github.com/google/boringssl/commit/23ed9d3852bbc738bebeaa0fe4a0782f91d7873c
[2]:https://github.com/intel/ipp-crypto
[3]:https://github.com/intel/ipp-crypto/tree/develop/sources/ippcp/crypto_mb
[4]:https://github.com/intel/intel-ipsec-mb
