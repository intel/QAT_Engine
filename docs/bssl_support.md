# Intel® QuickAssist Technology(QAT) BoringSSL* Library
Intel® QuickAssist Technology BoringSSL* Library is a prototype accelerating asymmetric cryptographic algorithms for BoringSSL*, the Google*'s OpenSSL* fork which doesn't support engine mechanism. It checks the type of user input SSL library during configuration time and builds out a traditional engine library if OpenSSL* is detected or a library fitting in with BoringSSL* private key method if BoringSSL* is applied.

This document details the capabilities, interfaces and limitations of the BoringSSL* based library. Both the hardware and software requirements are explained followed by detailed instructions on how to install and use the library.

## Features
- Asynchronous and Synchronous PKE QAT_HW Acceleration
  - RSA Support for Key Sizes 1024/2048/3072/4096.
  - ECDSA Support for NIST Prime Curves: P-256/P-384/P-521.(Disabled by default)
- Asynchronous PKE QAT_SW Acceleration
  - RSA Support for Key Sizes 2048/3072/4096.
  - ECDSA Support for NIST Prime Curves: P-256/P-384.(Disabled by default)

## Limitations
Some limitations specific for the current BoringSSL* Library:
* NIST Binary Curves and NIST Koblitz Curves are not supported by BoringSSL.
* Supports QAT_HW and QAT_SW on Linux. QAT_SW and QAT_HW FreeBSD is not supported.
* `RSA_padding_add_PKCS1_OAEP` function is exported by BoringSSL `libdecrepit.so`,
so it needs to be linked in the BoringSSL* Library. It may cause linking error while
building with the system lack of that library.

## Requirements
- [Hardware Requirements](hardware_requirements.md)
- [Software Requirements](software_requirements.md)

## Installation
### Install Prerequisites
Refer to the [Install Prerequisites](../README.md##installation-instructions)

**Note:** Replace the OpenSSL with BoringSSL installation described below.

### Build BoringSSL

Clone BoringSSL* from Github* at the following location:
```bash
git clone https://github.com/google/boringssl.git
```

Navigate to BoringSSL directory:
```bash
cd <path/to/boringssl/source/code>
mkdir -p build
cd build/
```

Note: BoringSSL* builds static library by default. To align with the QAT_Engine use case within NGINX*, an explicit option is added to build it as a dynamic library.
  ```bash
  cmake .. -DBUILD_SHARED_LIBS=1 -DCMAKE_BUILD_TYPE=Release
  make
  ```

BoringSSL* doesn't support "make install" to consolidate build output to an appropriate location. Here is a solution to integrate all output libraries into one customized path 'lib' by symbol links.
  ```bash
  cd ..
  mkdir -p lib
  ln -sf $(pwd)/build/libboringssl_gtest.so lib/
  ln -sf $(pwd)/build/crypto/libcrypto.so lib/
  ln -sf $(pwd)/build/ssl/libssl.so lib/
  ln -sf $(pwd)/build/decrepit/libdecrepit.so lib/
  ```

Note: RSA Padding schemes are handled by BoringSSL* rather than accelerated, so the engine supports the same padding schemes as BoringSSL* does natively.

### Build the Intel® QuickAssist Technology BoringSSL* Library

  The prerequisite to run autogen.sh is to have autotools (autoconf, automake, libtool and pkg-config) installed in the system.
  ```bash
  cd <path/to/qat_engine/source/code>
  ./autogen.sh
  ```
  Note: autogen.sh will regenerate autoconf tools files.

  To build and install the Intel® QAT_HW BoringSSL* Library:
  ```bash
  ./configure --with-openssl_install_dir=<path/to/boringssl/source/code> --with-qat_hw_dir=<path/to/qat/driver>
  make
  make install
  ```
  To build and install the Intel® QAT_SW BoringSSL* Library:
  ```bash
  ./configure --enable-qat_sw --with-openssl_install_dir=<path/to/boringssl/source/code>
  make
  make install
  ```
  In the above example, `--disable-qat_hw` needs to be provided if the system
  has qatlib installed.
  Note : `--enable-qat_sw` checks crypto_mb and IPSec_MB libraries in its
  respective default path (/usr/local/lib and /usr/lib) or in the path provided
  in the config flag `--with-qat_sw_crypto_mb_install_dir` (for crypto_mb) and
  `--with-qat_sw_ipsec_mb_install_dir` (for ipsec_mb). If any of the libraries
  is not installed then their corresponding algorithm support is disabled.
  By here, the QAT BoringSSL* Library `libqatengine.so` is installed to system path `/usr/local/lib`. Set the `--prefix` if specific install path is expected.

### Test the Intel® QuickAssist Technology BoringSSL* Library

The test code is under `test_bssl/` directory and will be compiled along with this library.

- Get usage help by running `qatengine_test` with `-h` option
    ```bash
    # ./qatengine_test -h
    Usage: ./qatengine_test [-h/-d/-a] <-k>
    -a :    Enable async mode
    -d :    Test on rsa private decrypt
    -h :    Print all available options
    -k :    Set private key file path for test purpose e.g. /opt/rsa_key.pmem
    Test command lines for reference:
    ./qatengine_test -k /opt/rsa_private_2k.key
    ./qatengine_test -k /opt/rsa_private_2k.key -a
    ./qatengine_test -k /opt/rsa_private_2k.key -d
    ./qatengine_test -k /opt/rsa_private_4k.key
    ./qatengine_test -k /opt/ec-secp384r1-priv-key.pem
    ./qatengine_test -k /opt/ec-secp384r1-priv-key.pem -a
  ```
`Note:` All private keys mentioned here are just for example, pls instead by your locally generated or existing one.
`Note:` Async mode can't be applied to the BoringSSL default method when QAT_HW and QAT_SW are disabled.

- Tip: to get more debug information, enable QATEngine option: --enable-qat_debug when configuring QATEngine before compiling.

All example codes provided here are __exclusively__ used for functional tests on QATEngine APIs with BoringSSL enabled.
