## Limitations

* When **forking** within an application it is not valid for a cryptographic
  operation to be started in the parent process, and completed in the child
  process.
* Only **one level of forking is permitted**, if a child process forks again then
  the Intel&reg; QAT OpenSSL\* Engine will not be available in that forked
  process.
* **Event driven mode** of polling operation is not supported in the FreeBSD
  Operating system or in the qatlib RPM.
* **qat_contig_mem** memory driver is not supported when running under FreeBSD
  Operating system or in the qatlib RPM. The default is to use the USDM memory
  driver supplied as part of the Intel&reg; QAT Driver.
* **SM2, SM3 & SM4** application testing is done using BabaSSL only since OpenSSL
  doesn't support SMx cipher suites.
* QAT Engine doesn't support **ENCRYPT_THEN_MAC**(default) mode of operation meaning
  when Encrypt then MAC is negotiated for symmetric ciphers say AES-CBC, the requests will not
  get offloaded via QAT_HW, instead uses OpenSSL SW. Disable ENCRYPT_THEN_MAC with the flag
  `SSL_OP_NO_ENCRYPT_THEN_MAC` programmatically using SSL_CTX_set_options() to offload
  symmetric chained ciphers via QAT_HW. Please note disabling ENCRYPT_THEN_MAC has security
  implications.
* Support for cipher AES-128-CBC-HMAC-SHA1 and its related ciphers was broken
  in release OpenSSL\* 1.1.1d. This was later fixed in OpenSSL\* 1.1.1e release.
* OpenSSL 1.1.1n introduced misleading error message(undefined symbol: **EVP_PKEY_get_base_id**)
  during engine load which can be ignored as it is not a real failure. This is later fixed in
  OpenSSL\* 1.1.1o release.
* X25519/X448 support is available only from **version 4.9** of the Intel&reg; QAT
  driver for Linux. Use `--disable-qat_hw_ecx` in the Intel&reg; QAT OpenSSL\* Engine
  configure when building against earlier versions of the Linux driver.
* Support for qaeMemFreeNonZeroNUMA() USDM API is available only from **version 4.10**
  of the Intel&reg; QAT driver for Linux. Use `--with-cc-opt="-DQAT_HW_DISABLE_NONZERO_MEMFREE"`
  in the Intel&reg; QAT OpenSSL\* Engine configuration when building against earlier
  versions of the Linux driver.
* From **version 4.19 and later** of Intel&reg; QAT driver for Linux, legacy or insecure
  algorithms such as DH, DSA, SHA1, RSA keysizes < 2048, EC curves < 256 bits are
  disabled by default hence there will be algo unsupported failures in the relevant ciphers.
  Driver needs to be built with flag "--enable-legacy-algorithms" to enable those
  algorithm support.
* QAT Engine built for OpenSSL3.0 is only compatible with dependant libraries also linked with OpenSSL3.0
  libraries due to [OpenSSL#17112][1]. Same applies for OpenSSL 1.1.1.
* SM4-GCM and SM4-CCM are only supported with BabaSSL versions based on OpenSSL 1.1.1.
  They are not supported with OpenSSL 1.1.1, OpenSSL 3.0 and BabaSSL versions based
  on OpenSSL 3.0.
* HKDF based on SM3 is not supported in QAT_HW, The request will fallback to OpenSSL software if
  fallback been enabled otherwise failures are observed.

## Known Issues

### Functional
* Known issue with OpenSSL 3.0 s_server using qatengine with cipher **"DHE-RSA-CHACHA20-POLY1305"** which
  works fine with Nginx. The issue is due to failure at EVP_PKEY_copy_parameter() in OpenSSL.
* AES-CBC-HMAC-SHA chained ciphers does not support **pipeline feature** when built with
  OpenSSL 3.0 as the corresponding support is not available in OpenSSL 3.0 - [OpenSSL#18298][2]
* There is an issue in **sshd** daemon application when using the QAT for default openssl.
  sshd looks to be closing the file descriptors associated with QAT engine and driver after
  initialising openssl. Similar issue was present which prevents the ability to ssh out of
  the system using the QAT engine in versions of the ssh application before OpenSSH 8.7.
  The issue has been fixed with this commit [c9f7bba][4] . This update can be applied to
  sshd to work-around the issue.
* Known issue with QAT_SW SM2 in ntls mode since QAT_SW SM2 doesn't have plain sign and
  verify operation support in engine. Disable QAT_SW SM2 to workaround the issue with ntls.
  No issues with TLS mode since it uses digestsign and digestverify which is supported.

### Performance
* There is known performance scaling issue (performance drop with threads >32)
  with ECDSA Ciphers in the QAT Software acceleration using multithread mode
  in the Haproxy application. This issue is not observed when using RSA ciphers
  or in multi-process mode.
* SM3 is disabled by default due to performance drop observed in **mulithread scenario**
  for all ciphers suites due to the additional locks at engine_table_select introduced by
  engine digest registration in OpenSSL - [OpenSSL#18509][5]
* In Co-Existence mode, performance will drop for PKE algorithms compared with
  QAT_SW when process number >= 64.

[1]:https://github.com/openssl/openssl/pull/17112
[2]:https://github.com/openssl/openssl/issues/18298
[3]:https://github.com/openssh/openssh-portable/commit/c9f7bba2e6f70b7ac1f5ea190d890cb5162ce127
[4]:https://github.com/openssl/openssl/issues/18509
