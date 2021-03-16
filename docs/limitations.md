## Limitations

* When forking within an application it is not valid for a cryptographic
  operation to be started in the parent process, and completed in the child
  process.
* Only one level of forking is permitted, if a child process forks again then
  the Intel&reg; QAT OpenSSL\* Engine will not be available in that forked
  process.
* The function `ASYNC_WAIT_CTX_get_changed_fds` contained in OpenSSL\* 1.1.0
  might return incorrect values in the case of failures during the submission of
  operations to the hardware accelerator. This could result in errors at the
  application level. The fix has been delivered in OpenSSL\* 1.1.0e and OpenSSL\*
  1.1.1. All previous versions of the library are affected.
  For more information, please refer to the following pull request on Github:
  [Fix waitctx fds removing the fd from the list #2581][1]
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

[1]:https://github.com/openssl/openssl/pull/2581
