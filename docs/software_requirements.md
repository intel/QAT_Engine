# Software Requirements

## qat_hw Requirements
Successful operation of QAT Hardware acceleration requires a software tool chain
that supports OpenSSL\* 1.1.1 or OpenSSL\* 3.0 or BoringSSL\* and Intel&reg; QuickAssist
Technology Driver for Linux or Intel&reg;  QuickAssist Technology
Driver for FreeBSD. This release was validated on the following:

* Operating system: CentOS* 8.4, Ubuntu\* 20.04.2 LTS & FreeBSD\* 12.3
* Intel&reg; Communications Chipset C62X Series Software for Linux\*, version **4.19**
* Intel&reg; Communications Chipset C62X Series Software for FreeBSD\*, version **3.12**
* OpenSSL\* 1.1.1q & 3.0.5
* BoringSSL\* commit - [15596efa5f][1]
* BabaSSL - 8.3.1

## qat_sw Requirements
Successful operation of the Intel&reg; QAT Software acceleration requires a
software tool chain that supports OpenSSL\* 1.1.1 or OpenSSL\* 3.0 and Intel&reg;
Crypto Multi-buffer library(for Asymmetric PKE) cloned from the [ipp-crypto][2] repo.
The crypto_mb library needs to be installed using the instructions from the
[Crypto Multi-buffer Library][3] Readme.

For QAT SW AES-GCM acceleration, prequisite is to have Intel&reg;
Multi-Buffer crypto for IPsec Library cloned from the [intel-ipsec-mb][4]
repo and installed using the instructions from the intel-ipsec-mb README.
The Intel&reg; QAT Engine supports QAT SW AES-GCM from OpenSSL\* 1.1.1d.

This release was validated on the following:

* Operating system: Ubuntu\* 20.04.2 LTS
* Intel&reg; Crypto Multi-buffer library from the [ipp-crypto][2] release
  version **IPP Crypto 2021.6**
* Intel&reg; Multi-Buffer crypto for IPsec Library release version **v1.2**
* OpenSSL\* 1.1.1q & 3.0.5
* BoringSSL\* commit - [15596efa5f][1]
* BabaSSL - 8.3.1

[1]:https://github.com/google/boringssl/tree/15596efa5fe18e43bdc0ecd32d4ef93437f51d49
[2]:https://github.com/intel/ipp-crypto
[3]:https://github.com/intel/ipp-crypto/tree/develop/sources/ippcp/crypto_mb
[4]:https://github.com/intel/intel-ipsec-mb
