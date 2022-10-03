## Limitations

* When forking within an application it is not valid for a cryptographic
  operation to be started in the parent process, and completed in the child
  process.
* Only one level of forking is permitted, if a child process forks again then
  the Intel&reg; QAT OpenSSL\* Engine will not be available in that forked
  process.
* Event driven mode of polling operation is not supported in the FreeBSD
  Operating system or in the qatlib RPM.
* qat_contig_mem memory driver is not supported when running under FreeBSD
  Operating system or in the qatlib RPM. The default is to use the USDM memory
  driver supplied as part of the Intel&reg; QAT Driver.
* Support for cipher AES-128-CBC-HMAC-SHA1 and its related ciphers was broken
  in release OpenSSL\* 1.1.1d. This was later fixed in OpenSSL\* 1.1.1e release.
* X25519/X448 support is available only from version 4.9 of the Intel&reg; QAT
  driver for Linux. Use `--disable-qat_hw_ecx` in the Intel&reg; QAT OpenSSL\* Engine
  configure when building against earlier versions of the Linux driver.
* Support for qaeMemFreeNonZeroNUMA() USDM API is available only from version 4.10
  of the Intel&reg; QAT driver for Linux. Use `--with-cc-opt="-DQAT_HW_DISABLE_NONZERO_MEMFREE"`
  in the Intel&reg; QAT OpenSSL\* Engine configuration when building against earlier
  versions of the Linux driver.
* Support for QAT HW ECX, QAT SW ECX, QAT SW SM2 ECDSA, QAT HW PRF and QAT HW HKDF is disabled
  when built against OpenSSL 3.0 engine interface since OpenSSL doesn't have default implementation
  methods accessible from OpenSSL3.0 engine interface, instead it uses non-accelerated
  implementation from OpenSSL default provider.
* There is known performance scaling issue (performance drop with threads >32)
  with ECDSA Ciphers in the QAT Software acceleration using multithread mode
  in the Haproxy application. This issue is not observed when using RSA ciphers
  or in multi-process mode.
* There is an issue in sshd daemon application when using the QAT for default openssl.
  sshd looks to be closing the file descriptors associated with QAT engine and driver after
  initialising openssl. Similar issue was present which prevents the ability to ssh out of
  the system using the QAT engine in versions of the ssh application before OpenSSH 8.7.
  The issue has been fixed with this commit [c9f7bba][1] . This update can be applied to
  sshd to work-around the issue.
* SM2 ECDH and ECDSA application testing is done using BabaSSL only since OpenSSL
  doesn't support SMx cipher suites.
* SM3 is disabled by default due to performance drop observed in mulithread scenario
  for all ciphers suites due to the locks at engine_table_select in OpenSSL.
* OpenSSL 1.1.1n introduced misleading error message(undefined symbol: EVP_PKEY_get_base_id)
  during engine load which can be ignored as it is not a real failure. This is later fixed in
  OpenSSL\* 1.1.1o release.
* AES-CBC-HMAC-SHA chained ciphers does not support pipeline feature when built with
  OpenSSL 3.0 as the corresponding support is not available in OpenSSL 3.0.
* QAT Engine doesn't support ENCRYPT_THEN_MAC(default) mode of operation meaning
  when Encrypt then MAC is negotiated for symmetric ciphers say AES-CBC, the requests will not
  get offloaded via QAT_HW, instead uses OpenSSL SW. Disable ENCRYPT_THEN_MAC with the flag
  `SSL_OP_NO_ENCRYPT_THEN_MAC` programmatically using SSL_CTX_set_options() to offload
  symmetric chained ciphers via QAT_HW. Please note disabling ENCRYPT_THEN_MAC has security
  implications.
* Known issue with OpenSSL 3.0 s_server using qatengine with cipher "DHE-RSA-CHACHA20-POLY1305" which
  works fine with Nginx. The issue is due to failure at EVP_PKEY_copy_parameter() in OpenSSL which is
  yet to be root caused.
* From version 4.19 of Intel&reg; QAT driver for Linux, legacy or insecure algorithms such as DES,
  3DES, MD5, SHA1, RC4 are disabled by default so there will be failures observed in the relevant
  ciphers. Driver needs to be built with flag "--enable-legacy-algorithms" to enable those algorithms
  support.

[1]:https://github.com/openssh/openssh-portable/commit/c9f7bba2e6f70b7ac1f5ea190d890cb5162ce127
