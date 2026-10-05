## Limitations

* When **forking** within an application it is not valid for a cryptographic
  operation to be started in the parent process, and completed in the child
  process.
* Only **one level of forking is permitted**. If a child process forks again, the
  QAT Engine (`qatengine`) will not be available in that forked
  process.
* **Event-driven polling** is not supported on FreeBSD or with the QATlib RPM.
* QAT Engine does not support the default **Encrypt-then-MAC** mode. When
  Encrypt-then-MAC is negotiated for symmetric ciphers such as AES-CBC, requests
  are processed by OpenSSL software instead of being offloaded through QAT_HW.
  To offload symmetric chained ciphers through QAT_HW, disable Encrypt-then-MAC
  programmatically by passing `SSL_OP_NO_ENCRYPT_THEN_MAC` to
  `SSL_CTX_set_options()`. Disabling Encrypt-then-MAC has security implications.
* QAT Engine built for a given OpenSSL version is only compatible with dependent libraries also linked
  with the same OpenSSL version due to [OpenSSL#17112](https://github.com/openssl/openssl/pull/17112).
  This applies to OpenSSL 3.x builds.
* SM3-based HKDF is not supported in QAT_HW. The request will fall back to OpenSSL software if
  fallback is enabled; otherwise, failures are observed.
* Thread-specific USDM requires memory allocated in one thread to be freed only
  by that thread. When the QAT driver is configured
  with `--enable-icp-thread-specific-usdm`, and when QAT Engine (`qatengine`) is used as the default
  OpenSSL ENGINE, `OPENSSL_init_ssl()` must be called from the same thread that
  calls `OPENSSL_cleanup()`. Incorrect cleanup can lead to a segmentation fault.
  Memory allocated in a thread is freed automatically when the thread exits,
  even if the user does not explicitly free the memory.
* SVM mode is not supported with BoringSSL or KPT.
* QAT_HW and QAT_SW co-existence mode is not supported with BoringSSL\*.
* AES-CCM cipher suites are not enabled in OpenSSL by default. Enable them using
  settings in `openssl.cnf`, as shown below:

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

* HKDF `info` lengths greater than 80 bytes are not supported due to a QAT driver limitation.
* Symmetric keys are not protected by [Key Protection Technology](qat_hw_kpt.md).
* QAT Engine does not process plaintext whose length is not a multiple of
  `AES_BLOCK_SIZE` for the AES-CBC-HMAC-SHA chained cipher when built with
  OpenSSL 3.x. No padding is added as specified in RFC 5652 or RFC 5246.

## Known Issues

### Functional

* AES-CBC-HMAC-SHA chained ciphers do not support the **pipeline feature** with
  QAT Engine on OpenSSL 3.x. This is due to limitations in the OpenSSL ENGINE
  framework. As ENGINE support is deprecated in OpenSSL 3.x and removed in
  OpenSSL 4.0, this limitation is not expected to be addressed upstream. Functionality
  is unaffected, but pipeline-related performance optimizations are unavailable.
  See [OpenSSL#18298](https://github.com/openssl/openssl/issues/18298).
* QAT_SW SM2 in `ntls` mode does not support plain sign and verify operations
  through QAT Engine. Disable QAT_SW SM2 as a workaround. TLS mode is unaffected
  because it uses the supported DigestSign and DigestVerify operations.
* In QAT Engine (`qatengine`) builds with OpenSSL 3.x, software fallback does not
  work for PRF, HKDF, SM2, or SM3 when those algorithms are disabled through the
  co-existence algorithm bitmap. QAT_HW PRF and QAT_HW HKDF are not accelerated
  through the OpenSSL ENGINE interface due to issues
  [OpenSSL#21627](https://github.com/openssl/openssl/discussions/21627) and
  [OpenSSL#19047](https://github.com/openssl/openssl/issues/19047).
* In co-existence mode with QAT Provider (`qatprovider`) on OpenSSL 3.2 and later,
  QAT_HW-only algorithms such as `TLS1-PRF` remain advertised when QAT_HW is
  unavailable at runtime (the driver is not loaded or all devices are `down`).
  Requests to those algorithms fail instead of falling back to OpenSSL software
  because no QAT_SW implementation exists. Algorithms with a QAT_SW implementation,
  including RSA, ECDSA, ECDH, X25519, AES-GCM, and HKDF, continue to use QAT_SW.
* With QATlib 26.08 in standalone mode (without `qatmgr`),
  `icp_sal_userStop()` does not release the VFIO group file descriptor. In
  container deployments using VFIO passthrough, applications that stop a QAT
  session and reinitialise it in a forked child reserve one
  additional VF per fork. As a result, affected applications can exhaust the
  passed-through VFs, report `No devices found`, and fail QAT_HW initialisation.
  In testing with QAT Engine and Async NGINX, three passed-through VFs were
  required for QAT_HW initialisation to succeed.
* For BoringSSL builds, use IPP Crypto v2.1.0 with the BoringSSL version listed
  in [Software Requirements](software_requirements.md).
* Tongsuo (BabaSSL): QAT Provider `openssl speed` fails for `aes-256-ccm` decryption (sync and async) and
  QAT Engine and QAT Provider SM2 `testapp` runs fail.

### Performance

* There is a known performance scaling issue (performance drop with threads >32)
  with ECDSA algorithms using QAT_SW acceleration in multithreaded mode
  in the HAProxy application. This issue is not observed when using RSA ciphers
  or in multi-process mode.
* SM3 is disabled by default due to performance degradation in multithreaded
  workloads caused by additional locks in `engine_table_select()` during OpenSSL
  ENGINE digest registration. See
  [OpenSSL#18509](https://github.com/openssl/openssl/issues/18509).
* In some cases, QAT Engine (`qatengine`) performance with OpenSSL can degrade at
  higher thread counts because of OpenSSL locking behavior. Check whether
  `native_queued_spin_lock_slowpath()` consumes significant CPU time, and see
  the OpenSSL issues and articles below.

  - Performance bottleneck with locks in engine_table_select() function - [OpenSSL#18509](https://github.com/openssl/openssl/issues/18509)
  - 3.0 performance degraded due to locking - [OpenSSL#20286](https://github.com/openssl/openssl/issues/20286)
  - https://serverfault.com/questions/919552/why-having-more-and-faster-cores-makes-my-multithreaded-software-slower
  - https://superuser.com/questions/1737747/high-system-cpu-usage-on-linux
* NGINX handshake performance has a known scaling limitation with OpenSSL 3.x;
  the same behavior occurs with OpenSSL software. See
  [OpenSSL#21833](https://github.com/openssl/openssl/issues/21833).
* Performance does not scale linearly for ECDSA and ChaCha20-Poly1305 on
  QAT 2.0-supported platforms.
* ECDSA P-256 performance drops in OpenSSL speed tests with the FreeBSD 14 intree driver.
* QAT Engine performance drops with [async-nginx](https://github.com/intel/asynch_mode_nginx/tree/master)
  on FreeBSD for asymmetric and symmetric ciphers.
* BoringSSL on FreeBSD is functionally validated, with limited NGINX performance validation.
* QAT_HW acceleration for **HKDF**, **ChaCha20-Poly1305**, and **AES-256-GCM** is experimental
  and not recommended for production performance use cases.
