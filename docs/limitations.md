## Limitations

* When **forking** within an application it is not valid for a cryptographic
  operation to be started in the parent process, and completed in the child
  process.
* Only **one level of forking is permitted**, if a child process forks again then
  the Intel&reg; QAT OpenSSL\* Engine will not be available in that forked
  process.
* **Event driven mode** of polling operation is not supported in the FreeBSD
  Operating system or in the qatlib RPM.
* QAT Engine doesn't support **ENCRYPT_THEN_MAC**(default) mode of operation meaning
  when Encrypt then MAC is negotiated for symmetric ciphers say AES-CBC, the requests will not
  get offloaded via QAT_HW, instead uses OpenSSL SW. Disable ENCRYPT_THEN_MAC with the flag
  `SSL_OP_NO_ENCRYPT_THEN_MAC` programmatically using SSL_CTX_set_options() to offload
  symmetric chained ciphers via QAT_HW. Please note disabling ENCRYPT_THEN_MAC has security
  implications.
* OpenSSL 1.1.1n and OpenSSL 3.0.2 introduced misleading error message(undefined symbol: **EVP_PKEY_get_base_id**)
  during engine load which can be ignored as it is not a real failure. This is later fixed in
  OpenSSL\* 1.1.1o and OpenSSL\* 3.0.3 release.
* QAT Engine built for OpenSSL3.0 is only compatible with dependent libraries also linked with OpenSSL3.0
  libraries due to [OpenSSL#17112](https://github.com/openssl/openssl/pull/17112). Same applies for OpenSSL 1.1.1.
* HKDF based on SM3 is not supported in QAT_HW, The request will fallback to OpenSSL software if
  fallback been enabled otherwise failures are observed.
* There is a limitation with thread specific USDM: *memory allocated in one thread
  should be freed only by the thread which allocates it*. When the QAT driver is configured 
  with `--enable-icp-thread-specific-usdm`, and when QAT_engine is used as the default 
  OpenSSL engine, it is required that OPENSSL_init_ssl() be called from the same thread that 
  calls OPENSSL_cleanup(). Incorrect cleanup can lead to a segmentation fault (segfault). 
  Also, memory allocated in a thread is freed automatically when the thread exits/terminates, 
  even if the user does not explicitly free the memory.
* SVM mode is not supported with BoringSSL library and KPT mode.
* AES-CCM ciphers are not enabled in OpenSSL by default. Need to enable it manually using the openssl.cnf
  section as below
```
  openssl_conf = cipher_conf

  [cipher_conf]
  ssl_conf = cipher_sect

  [cipher_sect]
  system_default = system_cipher_sect

  [system_cipher_sect]
  Cipherstring = ALL
  Ciphersuites = TLS_AES_128_CCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
```
* FreeBSD qatlib Header files are not installed to the install path due to a known issue in the driver.
  Header needs to be manually copied in the default path (/usr/local) as below or to the
  install path specified during driver installation.

```
  # Create destination directory from the QATlib 23.09 top directory:
  ./install-sh -c -d '/usr/local/include/qat'

  # Install Header Files:
  /usr/bin/install -c -m 644 quickassist/include/cpa.h quickassist/include/cpa_dev.h quickassist/include/cpa_types.h quickassist/include/lac/cpa_cy_common.h quickassist/include/lac/cpa_cy_dh.h quickassist/include/lac/cpa_cy_drbg.h quickassist/include/lac/cpa_cy_dsa.h quickassist/include/lac/cpa_cy_ecdh.h quickassist/include/lac/cpa_cy_ecdsa.h quickassist/include/lac/cpa_cy_ecsm2.h quickassist/include/lac/cpa_cy_ec.h quickassist/include/lac/cpa_cy_im.h quickassist/include/lac/cpa_cy_key.h quickassist/include/lac/cpa_cy_kpt.h quickassist/include/lac/cpa_cy_ln.h quickassist/include/lac/cpa_cy_nrbg.h quickassist/include/lac/cpa_cy_prime.h quickassist/include/lac/cpa_cy_rsa.h quickassist/include/lac/cpa_cy_sym_dp.h quickassist/include/lac/cpa_cy_sym.h quickassist/include/dc/cpa_dc.h quickassist/include/dc/cpa_dc_dp.h quickassist/include/dc/cpa_dc_chain.h quickassist/lookaside/access_layer/include/icp_sal_poll.h quickassist/lookaside/access_layer/include/icp_sal_user.h quickassist/lookaside/access_layer/include/icp_sal.h quickassist/lookaside/access_layer/include/icp_sal_versions.h quickassist/utilities/libusdm_drv/qae_mem.h /usr/local/include/qat
```
* HKDF infolen > 80 is not supported due to QAT driver limitation.

## Known Issues

### Functional
* AES-CBC-HMAC-SHA chained ciphers does not support **pipeline feature** when built with
  OpenSSL 3.0 as the corresponding support is not available in OpenSSL 3.0 -
  [OpenSSL#18298](https://github.com/openssl/openssl/issues/18298)
* There is an issue in **sshd** daemon application when using the QAT for default openssl.
  sshd looks to be closing the file descriptors associated with QAT engine and driver after
  initialising openssl. Similar issue was present which prevents the ability to ssh out of
  the system using the QAT engine in versions of the ssh application before OpenSSH 8.7.
  The issue has been fixed with this commit [c9f7bba](https://github.com/openssh/openssh-portable/commit/c9f7bba2e6f70b7ac1f5ea190d890cb5162ce127)
  This update can be applied to sshd to work-around the issue.
* Known issue with QAT_SW SM2 in `ntls` mode since QAT_SW SM2 doesn't have plain sign and
  verify operation support in engine. Disable QAT_SW SM2 to workaround the issue with ntls.
  No issues with TLS mode since it uses digestsign and digestverify which is supported.
* Known issue in Software fallback with OpenSSL3.0 Engine(only) when disabled via co-existence
  algo bitmap for algorithms PRF, HKDF, SM2 & SM3. QAT_HW PRF and QAT_HW HKDF are
  not accelerated in OpenSSL 3.0 engine due to the issue [OpenSSL#21622](https://github.com/openssl/openssl/issues/21622)
### Performance
* There is known performance scaling issue (performance drop with threads >32)
  with ECDSA Ciphers in the QAT Software acceleration using multithread mode
  in the Haproxy application. This issue is not observed when using RSA ciphers
  or in multi-process mode.
* SM3 is disabled by default due to performance drop observed in **multithread scenario**
  for all ciphers suites due to the additional locks at engine_table_select introduced by
  engine digest registration in OpenSSL - [OpenSSL#18509](https://github.com/openssl/openssl/issues/18509)
* In Co-Existence mode, Performance is lower than QAT_SW only when process number >=64 due
  to known issue.
* Note regarding multithreaded performance with OpenSSL/*: In some cases, using QAT_Engine with
  OpenSSL at higher thread counts can produce *worse* performance, due to issues in the way OpenSSL
  handles higher thread counts. Check for `native_queued_spin_lock_slowpath()` consuming CPU process 
  idle time, and see the OpenSSL GitHub issues and web articles below.
  
  - Performance bottleneck with locks in engine_table_select() function - [OpenSSL#18509](https://github.com/openssl/openssl/issues/18509)
  - 3.0 performance degraded due to locking - [OpenSSL#20286](https://github.com/openssl/openssl/issues/20286)
  - https://serverfault.com/questions/919552/why-having-more-and-faster-cores-makes-my-multithreaded-software-slower
  - https://superuser.com/questions/1737747/high-system-cpu-usage-on-linux

* Nginx Handshake Performance in OpenSSL3.0 is slightly slower compared to OpenSSL 1.1.1. The same
  behaviour is observed in OpenSSL_SW as well [OpenSSL#21833](https://github.com/openssl/openssl/issues/21833)
* Performance scaling is not linear in QAT2.0 supported platforms for ECDSA and Chacha-Poly algorithms.
* Performance drop observed with ECDSAP256 algorithm in the OpenSSL speed tests with FreeBSD 14 intree driver.
