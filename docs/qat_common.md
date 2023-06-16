# QAT_HW and QAT_SW Co-existence

Intel&reg; QAT OpenSSL\* Engine supports QAT_HW and QAT_SW Co-existence build
with both QAT_HW and QAT_SW dependant libraries(QAT Driver, crypto_mb and
ipsec_mb) linked in the qatengine.so library. This support can be enabled at
build time when both QAT_HW flag `--with-qat_hw_dir=/path/to/QAT_Driver`
and QAT_SW flag `--enable-qat_sw` configured together in the build configure
option.

If the platform has support for both QAT_HW and QAT_SW, the default
behavior is to accelerate asymmetric algorithms and Symmetric chained ciphers
using QAT Hardware and Symmetric GCM Ciphers using QAT Software. If the platform
doesn't have QAT Hardware support then it will use QAT_SW Acceleration for
QAT_SW asymmetric algorithms that are supported in the qatengine.

The default behavior can be changed using corresponding algorithm's enable
flags (eg:--enable-qat_sw_rsa) in which case the individual algorithms enabled
(either qat_hw or qat_sw) in the build configure will get accelerated.

## Run time Co-existence configuration using HW & SW algorithm bitmap
Intel&reg; QAT OpenSSL\* Engine supports a runtime mechanism to dynamically choose
the QAT_HW or QAT_SW or both for each algorithm, using QAT_HW and QAT_SW dependent
libraries linked in a single qatengine.
It can be accomplished through two ENGINE ctrl commands:
**HW_ALGO_BITMAP** & **SW_ALGO_BITMAP**,
and the bit map of each algorithm is defined below:
| Algorithm | Bit | HW or SW supported(Priority) |
| :- | :- | :-: |
| RSA | 0x00001 | Both (HW > SW) |
| DSA | 0x00002 | HW |
| DH | 0x00004 | HW |
| ECDSA | 0x00008 | Both (HW > SW) |
| ECDH | 0x00010 | Both (HW > SW) |
| ECX25519 | 0x00020 | Both (HW > SW) |
| ECX448 | 0x00040 | HW |
| PRF | 0x00080 | HW |
| HKDF | 0x00100 | HW |
| SM2(ECDSA) | 0x00200 | SW |
| AES_GCM | 0x00400 | Both (SW > HW) |
| AES_CBC_HMAC_SHA | 0x00800 | HW |
| SM4_CBC | 0x01000 | Both (HW > SW) |
| CHACHA_POLY | 0x02000 | HW |
| SHA3 | 0x04000 | HW |
| SM3 | 0x08000 | SW |
| SM4-GCM | 0x10000 | SW |
| SM4-CCM | 0x20000 | SW |

## QAT_HW & QAT_SW Co-existence recommended settings and working mechanism

1. For those algorithms that can achieve stronger performance with QAT_SW, we
   only use QAT_SW by default. These algorithms include:`AES-GCM, ECDSA-P256`.
2. For those algorithms that can achieve stronger performance with QAT_HW, the
   request will be offloaded to QAT_HW first, and after QAT_HW capacity is
   reached, it will be processed through QAT_SW. These algorithms include:
   `RSA-2K/3K/4K`, `ECDSA-P384`, `ECDH-P256/P384/X25519`.
3. It is recomended to set "LimitDevAccess" to 0 in QAT_HW driver config file to
   utilize all the available device per process for Co-existence mode to fully
   utilize QAT_HW first and then utilize QAT_SW.

**Note: ECDH-SM2 is included in ECDH SW group.**

If one algorithm is expected to be enabled, the preconditions are:
1. Supported in configuration, e.g., `--enable-qat_hw_gcm`.
2. Enabled in [default algorithm] directive, e.g., `RSA/EC/DH/DSA/CIPHER/PKEY/DIGEST/ALL`.

Algorithms that are enabled in HW_ALGO_BITMAP will gets accelerated via QAT_HW method and algorithms that are enabled in SW_ALGO_BITMAP will gets accelerated via QAT_SW method. If an algorithm is enabled in both HW_ALGO_BITMAP and SW_ALGO_BITMAP then the one that has highest priority (listed above) will be accelerated. If none is enabled, OpenSSL SW will be used.

**Note:** 
1. The default HW_ALGO_BITMAP and SW_ALGO_BITMAP value for each algorithm are set to 0xFFFF, which means all algorithms are enabled by default. If both HW&SW bitmap aren't set, QAT_Engine will offload the algorithm depending on the configuration and [default algorithm] setup.
2. The XX_ALGO_BITMAP commands are only workable when the corresponding offload mode is enabled, e.g. SW_ALGO_BITMAP is supported only if the QAT_SW is enabled.
3. In case the QAT_HW&QAT_SW are both enabled, it's recommanded to set both HW_ALGO_BITMAP and SW_ALGO_BITMAP in the meantime, disabling the unnessary and enabling the nessary offload mode for each algorithm.
4. The offload mode with higher priority must be disabled when you want to enable the lower priority one for each algorithm.

**Example 1:**  
Algorithm combination to be enabled: RSA(HW), ECDSA(HW), ECDH(SW), ECX25519(HW), SM2(SW), AES-GCM(SW). Make sure these algorithms are supported in configuration and already set
`RSA,EC,PKEY,CIPHER` or `ALL` in the [default algorithm].
```
HW_ALGO_BITMAP: RSA(0x0001) + ECDSA(0x0008) + ECX25519(0x0020) = 0x0029.
SW_ALGO_BITMAP: ECDH(0x0010) + SM2(0x0200) + AES-GCM(0x0400) = 0x0610.
```
* openssl.conf
```
[qatengine_section]
engine_id = qatengine
default_algorithms = ALL
HW_ALGO_BITMAP = 0x0029
SW_ALGO_BITMAP = 0x0610
```

* testapp
```
./testapp -engine qatengine -async_jobs 1 -c 1 -n 1 -nc 1 -v -hw_algo 0x0029 -sw_algo 0x0610 [test_case]
```

**Example 2:**  
Lower priority Algorithms need to be enabled: RSA(SW), AES-GCM(HW):
```
HW_ALGO_BITMAP: 0xFFFF - RSA(0x0001) = 0xFFFE. # Disable the RSA HW BITMAP because it has higher priority.
SW_ALGO_BITMAP: 0xFFFF - AES-GCM(0x0400) = 0xFBFF. # Disable the AES-GCM SW BITMAP because it has higher priority.
```

# OpenSSL 3.0 Provider Support

Intel&reg; QAT OpenSSL\* Engine supports Provider interface for OpenSSL 3.0.
The qatprovider support can be enabled using configure flag `--enable-qat_provider`
and the default if not specified will use engine interface.

| Algorithms | Supported by |
| :---: | :---: |
| RSA | QAT_HW & QAT_SW |
| ECDSA | QAT_HW & QAT_SW |
| ECDH | QAT_HW & QAT_SW |
| ECX | QAT_HW & QAT_SW |
| AES-GCM | QAT_HW & QAT_SW |
| SM2 | QAT_SW |
| DSA | QAT_HW |
| DH | QAT_HW |
| HKDF | QAT_HW |
| PRF | QAT_HW |
| AES128_CBC_HMAC_SHA1 | QAT_HW |
| AES256_CBC_HMAC_SHA1 | QAT_HW |
| AES128_CBC_HMAC_SHA256 | QAT_HW |
| AES256_CBC_HMAC_SHA256 | QAT_HW |
| SHA3-224 | QAT_HW |
| SHA3-256 | QAT_HW |
| SHA3-384 | QAT_HW |
| SHA3-512 | QAT_HW |
| ChachaPoly | QAT_HW |

This support is added as an experimental feature and tested with
OpenSSL Speed and testapp only and not tested with any application.

Example OpenSSL Speed command to test using qatprovider:

* QAT_HW
     ./openssl speed -provider qatprovider -elapsed -async_jobs 72 rsa2048
* QAT_SW
     ./openssl speed -provider qatprovider -elapsed -async_jobs 8 rsa2048

# FIPS 140-3 Certification requirements Support using QAT Provider

Intel&reg; QAT OpenSSL\* Engine contains changes to comply with FIPS 140-3 Level-1
Certification requirements using QAT Provider against OpenSSL 3.0.8. The FIPS
support can be enabled using the configure flag `--enable-qat_fips` only with
OpenSSL 3.0 using provider interface which needs to be enabled using `--enable-qat_provider`.

When FIPS flag is enabled along with provider for OpenSSL3.0, it will run
self tests, integrity tests and will satisfy other FIPS 140-3 CMVP & CAVP
requirements. The FIPS is build as RPM using the specfile fips/qatengine_fips.spec
with QAT_HW & QAT_SW Coexistence enabled along with other flags enabled.

Please note that the version v1.2.0 is only satisfying FIPS 140-3 Level-1
certification requirements and not FIPS certified yet.
The FIPS 140-3 certification is under process.

## Support Algorithms in FIPS mode
| Mode | Algorithms |
| :---: | :---: |
| QAT_HW | RSA, ECDSA, ECDH, ECDHX25519, ECDHX448, DSA, DH, TLS1.2-KDF(PRF), TLS1.3-KDF(HKDF), SHA3 & AES-GCM |
| QAT_SW | RSA, ECDSA, ECDH, ECDHX25519, SHA2 & AES-GCM |
