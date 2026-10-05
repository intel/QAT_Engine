# Intel® QuickAssist Technology (QAT) BoringSSL\* Library
Intel® QuickAssist Technology BoringSSL\* Library is a prototype accelerating asymmetric cryptographic algorithms for BoringSSL\*, the Google\*'s OpenSSL\* fork which doesn't support engine mechanism. It checks the type of user input SSL library during configuration time and builds out a traditional engine library if OpenSSL\* is detected or a library fitting in with BoringSSL\* private key method if BoringSSL\* is applied.

This document details the capabilities, interfaces and limitations of the BoringSSL\* based library. Both the hardware and software requirements are explained followed by detailed instructions on how to install and use the library.

## Features
- Asynchronous and Synchronous PKE QAT_HW Acceleration
  - RSA Support for Key Sizes 1024/2048/3072/4096.
  - ECDSA Support for NIST Prime Curves: P-256/P-384/P-521.(Disabled by default)
- Asynchronous PKE QAT_SW Acceleration
  - RSA Support for Key Sizes 2048/3072/4096.
  - ECDSA Support for NIST Prime Curves: P-256/P-384.(Disabled by default)

## Limitations
Some limitations specific for the current BoringSSL\* Library:
* NIST Binary Curves and NIST Koblitz Curves are not supported by BoringSSL\.
* `RSA_padding_add_PKCS1_OAEP` function is exported by BoringSSL\* `libdecrepit.so`,
so it needs to be linked in the BoringSSL\* Library. It may cause linking error while
building with the system lack of that library.
* The QAT Provider (`qatprovider`) is not supported with BoringSSL\*. Only QAT
Engine (`qatengine`) is available for BoringSSL\* builds.

## Requirements
- [Hardware Requirements](hardware_requirements.md)
- [Software Requirements](software_requirements.md)

## Installation
### Build BoringSSL

```
git clone https://github.com/google/boringssl.git
cd boringssl
mkdir -p build
cd build/
```

Note: BoringSSL\* builds a static library by default. To use it with QAT
acceleration in NGINX\*, explicitly build it as a dynamic library.
```
cmake .. -DBUILD_SHARED_LIBS=1 -DCMAKE_BUILD_TYPE=Release
make
```

BoringSSL\* doesn't support "make install" to consolidate build output in one location. The following commands collect the output libraries in a custom `lib` directory using symbolic links.
```
cd ..
mkdir -p lib
ln -sf $(pwd)/build/libboringssl_gtest.so lib/
ln -sf $(pwd)/build/crypto/libcrypto.so lib/
ln -sf $(pwd)/build/ssl/libssl.so lib/
ln -sf $(pwd)/build/decrepit/libdecrepit.so lib/
```

Note: RSA Padding schemes are handled by BoringSSL\* rather than accelerated, so the engine supports the same padding schemes as BoringSSL\* does natively.

### Build the Intel® QuickAssist Technology BoringSSL\* Library

The prerequisite to run autogen.sh is to have autotools (autoconf, automake, libtool and pkg-config) installed in the system.
```
cd <path/to/qat_engine/source/code>
./autogen.sh
```

To build and install the Intel® QAT_HW BoringSSL\* Library:
```
./configure --with-openssl_install_dir=<path/to/boringssl/source/code> --with-qat_hw_dir=<path/to/qat/driver>
make
install
```
To build and install the Intel® QAT_SW BoringSSL\* Library:
```
./configure --enable-qat_sw --with-openssl_install_dir=<path/to/boringssl/source/code>
make
make install
```
In the above example, `--disable-qat_hw` needs to be provided if the system
has qatlib installed.
Note: `--enable-qat_sw` checks the crypto_mb and IPsec MB libraries in their
respective default paths (`/usr/local/lib` and `/usr/lib`) or in the paths provided
in the config flag `--with-qat_sw_crypto_mb_install_dir` (for crypto_mb) and
`--with-qat_sw_ipsec_mb_install_dir` (for ipsec_mb). If any of the libraries
is not installed then their corresponding algorithm support is disabled.
At this point, the QAT BoringSSL\* Library `libqatengine.so` is installed in
the system path `/usr/local/lib`. Set `--prefix` to use a specific installation path.

### Test the Intel® QuickAssist Technology BoringSSL\* Library

The test code is under `test_bssl/` directory and will be compiled along with this library.

- Get usage help by running `qatengine_test` with `-h` option
    ```
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
`Note:` All private keys shown here are examples. Replace them with locally generated or existing keys.
`Note:` Async mode can't be applied to the BoringSSL default method when QAT_HW and QAT_SW are disabled.

- Tip: For more debug information, configure with `--enable-qat_debug` before compiling.

All example code provided here is used exclusively for functional tests of the
QAT Engine (`qatengine`) APIs with BoringSSL enabled.
