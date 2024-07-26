## Introduction

Key Protection Technology (KPT) enables customers to securely deliver their
networking security sensitive credentials to IA platforms. IA platforms with
Intel QuickAssist (QAT) IP will deliver this capability. Once, customer keys
are securely delivered to the QAT on IA platform, the customer keys are
protected within the QAT IP while in transport or in use.

The QAT_Engine with KPT feature can expose the KPT2.0 asymmetric capability
to the other applications e.g. Nginx, OpenSSL, etc.

### Supported Algorithms
* Asymmetric Cryptography:
  * RSA 512/1024/2048/4096/8192
  * ECDSA 256r1/384r1/521r1

## Requirements
### Hardware
The Key Protection Technology(KPT) feature in the Intel&reg; QAT OpenSSL\* Engine needs
QAT acceleration devices with KPT capability on platform with Intel&reg; Xeon&reg; with
QAT 4XXX Series Chipset.

### **Key Protection Technology Library**

This library provides the key protection services for applications upon various Intel&reg;
security hardware technology, like QuickAssist Technology, etc. The Intel&reg; QAT OpenSSL\*
Engine comes with the KPT library in its subdirectory `kpt/lib`.
Please refer [here](../kpt/lib/README.md) for detailed information.

## Build Instruction for enabling KPT

To build and install the Intel&reg; QAT OpenSSL\* Engine with add `--enable-qat_hw_kpt`
to enable KPT configure flag to the qat_hw target build instructions as below

```
cd QAT_Engine
./autogen.sh
./configure \
  --enable-qat_hw_kpt \
  --with-qat_hw_dir=/{driver_package_dir} \
  --with-openssl_install_dir=/{openssl_install_dir}

make clean -j
make -j && make install -j
```

### KPT Tool
Wrapped private key(WPK) file is a customized PEM file used by the KPT feature.
Sample code of KPT Tool is provided to create or parse the standard WPK file
according to WPK format definition. This tool can be built using `make kpttool`
in the top directory.
**NOTE**: Re-generate the WPK file while the platform is changed.

* KPT Tool Usage
```
Usage of kpttool:
kpttool -act [gen|par]  -alg [rsa|ecc] -in [<cpk.key>|<wpk.key>] -out <wpk.key>
                   -act (action): gen (generate wpk (wrap private key)), par (parse wpk (wrap private key))
                   -alg (algorithm): rsa (-in rsa private key file), ecc (-in ecc private key)
                   -in:  -act gen input cpk (customer private key) file
                         -act par input wpk (wrap private key) file
                   -out: -act gen output wpk (wrap private key) file
e.g. kpttool -act gen -alg ecc -in ec_secp256r1_private.key -out ec_secp256r1_wpk.key
e.g. kpttool -act par -alg ecc -in ec_secp256r1_wpk.key
e.g. kpttool -act gen -alg rsa -in rsa_2k_private.key -out rsa_2k_wpk.key
e.g. kpttool -act par -alg rsa -in rsa_2k_wpk.key
```

## Test the KPT Feature

### OpenSSL Command
  * RSA

```
RSA ENCRYPTION
# echo 123123123123 > plain.txt
# openssl rsautl --encrypt -in plain.txt -out cipher.txt -inkey rsa2k.pem

RSA DECRYPTION
# openssl rsautl --decrypt -in cipher.txt -out decrypt.txt -keyform engine -engine qatengine -inkey wpk_rsa2k.pem

RSA SIGN
# openssl dgst -sign wpk_rsa2k.pem -keyform ENGINE -engine qatengine plain.txt > digest.txt

RSA VERIFY
# openssl dgst -verify rsa2k_pub.pem -signature digest.txt verify.txt
```

  * ECDSA

```
ECDSA SIGN
# openssl dgst -sign wpk_secp521r1.pem -keyform ENGINE -engine qatengine plain.txt > digest.txt

ECDSA VERIFY
# openssl dgst -verify secp521r1_pub.pem -signature digest.txt verify.txt
```

### Nginx
In Nginx use case, `engine:qat_engine` needs to be prefixed before the WPK file
path for `ssl_certification_key`, which will tell Nginx to load the WPK file
using the QAT Engine instead of the original function.

For example:

```
server{
  ssl_certificate     cert.crt;
  ssl_certificate_key engine:qatengine:wpk_file.pem;
}
```

## Known Issues & Limitation
1. The worker-instance model is not aligned with previous usage. Since the
KPT needs to get the instance in master node to load the WPK file, the maximum
worker number will change from 64 to 63 while each worker being assigned 1
instance. If 64 workers are used, `nginx -s xxx` will fail and need
to kill all nginx processes forcedly.

2. Non-shared mode is implemented by default, and shared mode is not supported yet.

3. SWK provision number limitation for each device is 128, otherwise, the QAT Driver will return with error code -3 (CPA_CY_KPT_LOADKEY_FAIL_QUOTA_EXCEEDED).

    It means that: `num_instance * num_server_block(use WPK file) <= 128`.  
    * If 64 workers are used, the maximum number of server block that uses the WPK file is 2.  
    * In case only 1 server block used the WPK file, the maximum number of worker is 128.

4. Directive sw_fallback will not be supported while KPT capability is enabled.
