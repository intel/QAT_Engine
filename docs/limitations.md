## Limitations

* When **forking** within an application it is not valid for a cryptographic
  operation to be started in the parent process, and completed in the child
  process.
* Only **one level of forking is permitted**, if a child process forks again then
  the Intel&reg; QAT OpenSSL\* Engine will not be available in that forked
  process.
* **Event driven mode** of polling operation is not supported in the FreeBSD
  Operating system or in the qatlib RPM.
* QAT Engine does not support **ENCRYPT_THEN_MAC** (default) mode of operation, meaning
  when Encrypt-then-MAC is negotiated for symmetric ciphers such as AES-CBC, the requests will not
  be offloaded via QAT_HW; instead, OpenSSL SW is used. Disable ENCRYPT_THEN_MAC with the flag
  `SSL_OP_NO_ENCRYPT_THEN_MAC` programmatically using SSL_CTX_set_options() to offload
  symmetric chained ciphers via QAT_HW. Please note that disabling ENCRYPT_THEN_MAC has security
  implications.
* OpenSSL 3.0.2 introduced a misleading error message (undefined symbol: **EVP_PKEY_get_base_id**)
  during engine load which can be ignored as it is not a real failure. This was fixed in
  OpenSSL\* 3.0.3.
* QAT Engine built for a given OpenSSL version is only compatible with dependent libraries also linked
  with the same OpenSSL version due to [OpenSSL#17112](https://github.com/openssl/openssl/pull/17112).
  This applies to OpenSSL 3.x builds.
* HKDF based on SM3 is not supported in QAT_HW. The request will fall back to OpenSSL software if
  fallback is enabled; otherwise, failures are observed.
* There is a limitation with thread specific USDM: *memory allocated in one thread
  should be freed only by the thread which allocates it*. When the QAT driver is configured
  with `--enable-icp-thread-specific-usdm`, and when QAT_engine is used as the default
  OpenSSL engine, it is required that OPENSSL_init_ssl() be called from the same thread that
  calls OPENSSL_cleanup(). Incorrect cleanup can lead to a segmentation fault (segfault).
  Also, memory allocated in a thread is freed automatically when the thread exits/terminates,
  even if the user does not explicitly free the memory.
* SVM mode is not supported with BoringSSL library and KPT mode.
* QAT_HW and QAT_SW Co-existence mode is not supported with BoringSSL\*.
* AES-CCM ciphers are not enabled in OpenSSL by default. They must be enabled manually using the openssl.cnf
  section as below:
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
* Symmetric keys are not protected by [Key Protection Technology](#qat_hw_kpt.md).
* QAT Engine does not process the plaintext if the length is not a multiple of AES_BLOCK_SIZE for
  chained cipher AES-CBC-HMAC-SHA when built with OpenSSL v3 and above. No padding would be added
  to the plaintext as specified in RFC 5652 or RFC 5246.

## Known Issues

### Functional
* AES-CBC-HMAC-SHA chained ciphers do not support the **pipeline feature** with the QAT
  Engine on OpenSSL 3.x. This is due to the lack of required Engine framework support
  in OpenSSL 3.x. As ENGINE support is deprecated in OpenSSL 3.x and removed in
  OpenSSL 4.0, this limitation is not expected to be addressed upstream. Functionality
  is unaffected, but pipeline-related performance optimizations are unavailable -
  [OpenSSL#18298](https://github.com/openssl/openssl/issues/18298)
* Known issue with QAT_SW SM2 in `ntls` mode since QAT_SW SM2 doesn't have plain sign and
  verify operation support in engine. Disable QAT_SW SM2 to workaround the issue with ntls.
  No issues with TLS mode since it uses digestsign and digestverify which is supported.
* Known issue in Software fallback with OpenSSL 3.x Engine (only) when disabled via co-existence
  algo bitmap for algorithms PRF, HKDF, SM2 & SM3. QAT_HW PRF and QAT_HW HKDF are
  not accelerated in OpenSSL 3.x engine due to the issues
  [OpenSSL#21627](https://github.com/openssl/openssl/discussions/21627) and
  [OpenSSL#19047](https://github.com/openssl/openssl/issues/19047)
* Known issue in Co-existence mode with QAT provider on OpenSSL 3.2 and above when QAT_HW is
  unavailable at runtime (driver not loaded or all devices in the `down` state), algorithms
  that are QAT_HW-only in the co-existence build (e.g. `TLS1-PRF`) remain advertised by the
  provider and requests fail instead of being served by OpenSSL software, since no QAT_SW
  fallback exists for them. Algorithms that have a QAT_SW implementation (RSA, ECDSA, ECDH,
  X25519, AES-GCM, HKDF, etc.) correctly offload via QAT_SW in this configuration.
* Known build issue with the latest commit of BoringSSL; hence, IPP Crypto v2.1.0 should be used
  for the QAT engine with BoringSSL (use the BoringSSL commit mentioned in the Software requirements section).
* Tongsuo (BabaSSL): QAT Provider `openssl speed` fails for `aes-256-ccm` decryption (sync and async) and
  QAT Engine/QAT Provider SM2 `testapp` runs fail.
### Performance
* There is a known performance scaling issue (performance drop with threads >32)
  with ECDSA ciphers in the QAT Software acceleration using multithread mode
  in the HAProxy application. This issue is not observed when using RSA ciphers
  or in multi-process mode.
* SM3 is disabled by default due to a performance drop observed in **multithread scenarios**
  for all cipher suites due to additional locks at engine_table_select introduced by
  engine digest registration in OpenSSL - [OpenSSL#18509](https://github.com/openssl/openssl/issues/18509)
* Note regarding multithreaded performance with OpenSSL/*: In some cases, using QAT_Engine with
  OpenSSL at higher thread counts can produce *worse* performance, due to issues in the way OpenSSL
  handles higher thread counts. Check for `native_queued_spin_lock_slowpath()` consuming CPU process
  idle time, and see the OpenSSL GitHub issues and web articles below.

  - Performance bottleneck with locks in engine_table_select() function - [OpenSSL#18509](https://github.com/openssl/openssl/issues/18509)
  - 3.0 performance degraded due to locking - [OpenSSL#20286](https://github.com/openssl/openssl/issues/20286)
  - https://serverfault.com/questions/919552/why-having-more-and-faster-cores-makes-my-multithreaded-software-slower
  - https://superuser.com/questions/1737747/high-system-cpu-usage-on-linux

* Nginx Handshake Performance shows a known scaling behaviour in OpenSSL 3.x; the same
  is observed with OpenSSL SW as well [OpenSSL#21833](https://github.com/openssl/openssl/issues/21833)
* Performance scaling is not linear in QAT2.0 supported platforms for ECDSA and Chacha-Poly algorithms.
* Performance drop observed with ECDSAP256 algorithm in the OpenSSL speed tests with FreeBSD 14 intree driver.
* Performance drop observed in QAT Engine with [async-nginx](https://github.com/intel/asynch_mode_nginx/tree/master) on FreeBSD OS with asymmetric and symmetric ciphers.
* BoringSSL on FreeBSD OS is validated functionally with limited performance validation on Nginx.
* QAT_HW acceleration for **HKDF**, **ChaCha20-Poly1305**, and **AES-256-GCM** is experimental
  and not recommended for production performance use cases.
* Performance drop observed with **ECDSA P-384** in QAT_HW and co-existence offload modes when using the Engine interface
  (`qatengine`) compared to the Provider interface (`qatprovider`).
