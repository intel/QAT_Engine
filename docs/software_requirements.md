# Software Requirements

Successful operation of QAT Hardware(QAT_HW) acceleration requires a 
[QAT Hardware driver][1] depending on the platform and OS mentioned below. 
QAT Software(QAT_SW) acceleration requires optimized software libraries
[Intel® Crypto Multi-buffer library][2] and [intel-ipsec-mb][3]. Depending on the use 
case crypto library like OpenSSL, TongSuo(BabaSSL) and BoringSSL needs to be installed along
with a QAT_HW driver or QAT_SW libraries or both.

This release was validated on the following versions and expected to work on all Linux distributions
and also from the latest versions from the links below.

## QAT_HW Drivers:
* [Intel® QuickAssist Technology Driver for Linux\* HW Version 2.0][4] - **QAT20.L.1.1.50-00003**
* [Intel® QuickAssist Technology Driver for Linux\* HW Version 1.x][5] - **QAT.L.4.26.0-00008**
* Intel® QuickAssist Technology Driver for FreeBSD\* HW Version 1.x and 2.0 - **QAT.B.3.14.31-00003** (FreeBSD 13.2)
* [Intel® QATlib for Linux with intree driver][7] - **QATlib 24.09.0** & **QATlib 24.02.0** (for Dockerfile only)
* [Intel®  QATlib for FreeBSD with intree driver(FreeBSD 14)][8] - **FreeBSD QATlib 23.09.0** (FreeBSD 14)

## QAT_SW Libraries:
* [Intel&reg; Crypto Multi-buffer library][2] - **IPP Crypto v1.0.0** & **IPP Crypto 2021.10** (for BoringSSL only)
* [Intel&reg; Multi-Buffer crypto for IPsec Library release version][3] **v2.0**

## Crypto Libraries:
* [OpenSSL\*][9] 1.1.1w (for FreeBSD only) & 3.0.15
* BoringSSL\* commit - [23ed9d3][10]
* [Tongsuo][11] - 8.4.0 (BabaSSL)

[1]:https://www.intel.com/content/www/us/en/developer/topic-technology/open/quick-assist-technology/overview.html
[2]:https://github.com/intel/cryptography-primitives/tree/develop/sources/ippcp/crypto_mb
[3]:https://github.com/intel/intel-ipsec-mb
[4]:https://www.intel.com/content/www/us/en/download/765501/intel-quickassist-technology-driver-for-linux-hw-version-2-0.html
[5]:https://www.intel.com/content/www/us/en/download/19734/intel-quickassist-technology-driver-for-linux-hw-version-1-x.html
[6]:https://www.intel.com/content/www/us/en/download/19735/intel-quickassist-technology-driver-for-freebsd-hw-version-1-x.html
[7]:https://github.com/intel/qatlib
[8]:https://github.com/intel/qatlib-freebsd
[9]:https://github.com/openssl/openssl
[10]:https://github.com/google/boringssl/commit/23ed9d3852bbc738bebeaa0fe4a0782f91d7873c
[11]:https://github.com/Tongsuo-Project/Tongsuo
