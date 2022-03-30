# Software Requirements

## qat_hw Requirements
Successful operation of QAT Hardware acceleration requires a software tool chain
that supports OpenSSL\* 1.1.1 or OpenSSL\* 3.0 and Intel&reg; QuickAssist
Technology Driver for Linux or Intel&reg;  QuickAssist Technology
Driver for FreeBSD. This release was validated on the following:

* Operating system: CentOS\* 7.4 64-bit version & FreeBSD\* 11.4 64-bit version
* Kernel: GNU\*/Linux\* 3.10.0-693
* Intel&reg; Communications Chipset C62X Series Software for Linux\*, version **4.16**
* Intel&reg; Communications Chipset C62X Series Software for FreeBSD\*, version **3.11**
* OpenSSL\* 1.1.1n & 3.0.1

## qat_sw Requirements
Successful operation of the Intel&reg; QAT Software acceleration requires a
software tool chain that supports OpenSSL\* 1.1.1 or OpenSSL\* 3.0 and Intel&reg;
Crypto Multi-buffer library(for Asymmetric PKE) cloned from the [ipp-crypto][1] repo.
The crypto_mb library needs to be installed using the instructions from the
[Crypto Multi-buffer Library][2] Readme.

For QAT SW AES-GCM acceleration, prequisite is to have Intel&reg;
Multi-Buffer crypto for IPsec Library cloned from the [intel-ipsec-mb][3]
repo and installed using the instructions from the intel-ipsec-mb README.
The Intel&reg; QAT Engine supports QAT SW AES-GCM from OpenSSL\* 1.1.1d.

This release was validated on the following:

* Operating system: Ubuntu 20.04.2 LTS
* Kernel: 5.4.0-62-generic
* Intel&reg; Crypto Multi-buffer library from the [ipp-crypto][1] release
  version **IPP Crypto 2021.5**
* Intel&reg; Multi-Buffer crypto for IPsec Library release version **v1.2**
* OpenSSL\* 1.1.1n & 3.0.1

[1]:https://github.com/intel/ipp-crypto
[2]:https://github.com/intel/ipp-crypto/tree/develop/sources/ippcp/crypto_mb
[3]:https://github.com/intel/intel-ipsec-mb
