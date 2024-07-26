# Intel&reg; QuickAssist Technology(QAT) OpenSSL\* Engine
Intel&reg; QuickAssist Technology OpenSSL\* Engine (QAT_Engine) supports
acceleration through the QAT hardware (via the QAT_HW path) and through
Optimized Software using the Intel instruction set (via the QAT_SW Path
from 3rd Generation Intel&reg; Xeon&reg; Scalable Processors family).

The image below illustrates the high-level software architecture of the
QAT_Engine. Applications such as NGINX and HAProxy are common applications
which interfaces to crypto libraries like OpenSSL\* and its fork like
Tongsuo(BabaSSL)\*, BoringSSL\*, etc. OpenSSL\* is a toolkit for TLS/SSL protocols and
has developed a modular system to plugin device-specific engines and provider.
Depending on the particular use case, the QAT_Engine can be configured to accelerate
via the QAT Hardware or QAT Software or both based on the platform to meet your specific
acceleration needs.

<p align=center>
<img src="docs/images/qat_engine.png" alt="drawing" width="300"/>
</p>

## Features
Features of the QAT_Engine are described [here](docs/features.md).

## Limitations and Known Issues
Limitations and known issues for the QAT_Engine are described [here](docs/limitations.md).

## Requirements
- [Hardware Requirements](docs/hardware_requirements.md)
- [Software Requirements](docs/software_requirements.md)

## Installation Instructions
Installation instructions are described [here](docs/install.md)

## Testing
</details>
<details>
<summary>Test using OpenSSL Engine command </summary>

### Test using OpenSSL\* Engine command
Run this command to verify the Intel&reg; QAT OpenSSL\* Engine is loaded
correctly: This should not be used to determine QAT Engine capabilities as
it will not display all the algorithms that are supported in QAT Engine.

```text
cd /path/to/openssl_install/bin
./openssl engine -t -c -v qatengine
```

qat_hw target output will be:
```text
(qatengine) Reference implementation of QAT crypto engine(qat_hw) <qatengine version>
 [RSA, DSA, DH, AES-128-CBC-HMAC-SHA1, AES-128-CBC-HMAC-SHA256,
 AES-256-CBC-HMAC-SHA1, AES-256-CBC-HMAC-SHA256, TLS1-PRF, HKDF, X25519, X448]
    [ available ]
    ENABLE_EXTERNAL_POLLING, POLL, SET_INSTANCE_FOR_THREAD,
    GET_NUM_OP_RETRIES, SET_MAX_RETRY_COUNT, SET_INTERNAL_POLL_INTERVAL,
    GET_EXTERNAL_POLLING_FD, ENABLE_EVENT_DRIVEN_POLLING_MODE,
    GET_NUM_CRYPTO_INSTANCES, DISABLE_EVENT_DRIVEN_POLLING_MODE,
    SET_EPOLL_TIMEOUT, SET_CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD,
    ENABLE_INLINE_POLLING, ENABLE_HEURISTIC_POLLING,
    GET_NUM_REQUESTS_IN_FLIGHT, INIT_ENGINE, SET_CONFIGURATION_SECTION_NAME,
    ENABLE_SW_FALLBACK, HEARTBEAT_POLL, DISABLE_QAT_OFFLOAD
```

qat_sw target output will be:
```text
(qatengine) Reference implementation of QAT crypto engine(qat_sw) <qatengine version>
 [RSA, id-aes128-GCM, id-aes192-GCM, id-aes256-GCM, X25519]
     [ available ]
     ENABLE_EXTERNAL_POLLING, POLL, ENABLE_HEURISTIC_POLLING,
     GET_NUM_REQUESTS_IN_FLIGHT, INIT_ENGINE
```

Detailed information about the engine specific messages is available [here](docs/engine_specific_messages.md).
Also `./openssl engine -t -c -vvvv qatengine` gives brief description about each ctrl command.
<br>
</details>
<details>
<summary>Test using OpenSSL speed utility</summary>

### Test using OpenSSL\* speed utility

```text
cd /path/to/openssl_install/bin

qat_hw

* RSA 2K Sign/Verify
  taskset -c 1 ./openssl speed -engine qatengine -elapsed -async_jobs 72 rsa2048
* ECDH Compute Key
  taskset -c 1 ./openssl speed -engine qatengine -elapsed -async_jobs 72 ecdh
* ECDSA Sign/Verify
  taskset -c 1 ./openssl speed -engine qatengine -elapsed -async_jobs 72 ecdsa
* AES-128-CBC-HMAC-SHA256
  taskset -c 1 ./openssl speed -engine qatengine -elapsed -async_jobs 72 -evp aes-128-cbc-hmac-sha256

qat_sw

* RSA 2K Sign/Verify
  taskset -c 1 ./openssl speed -engine qatengine -elapsed -async_jobs 8 rsa2048
* ECDH X25519 Compute Key
  taskset -c 1 ./openssl speed -engine qatengine -elapsed -async_jobs 8 ecdhx25519
* ECDH P-256 Compute Key
  taskset -c 1 ./openssl speed -engine qatengine -elapsed -async_jobs 8 ecdhp256
* ECDSA P-256 Sign/Verify
  taskset -c 1 ./openssl speed -engine qatengine -elapsed -async_jobs 8 ecdsap256
* ECDH P-384 Sign/Verify
  taskset -c 1 ./openssl speed -engine qatengine -elapsed -async_jobs 8 ecdhp384
* ECDSA P-384 Sign/Verify
  taskset -c 1 ./openssl speed -engine qatengine -elapsed -async_jobs 8 ecdsap384
* AES-128-GCM
  taskset -c 1 ./openssl speed -engine qatengine -elapsed -evp aes-128-gcm
```
Note: Run the test without "-engine qatengine" for each algorithm to see the performance against OpenSSL.
This only covers key algorithms, additional algorithms can be tested by changing algo parameter.

</details>
<details>
<summary>Test using inbuilt testapp utility</summary>

## Test using inbuilt testapp utility</summary>

```text
cd /path/to/qat_engine
make test
./testapp.sh QAT_HW (For testing algorithms supported by QAT_HW)
./testapp.sh QAT_SW (For testing algorithms supported by QAT_SW)
```
The `testapp.sh` script will run the corresponding functional tests supported
by QAT_HW and QAT_SW. Please note that the QAT Engine should be built with
that support for the tests.

Additional information for testapp tests available with the help option
`./testapp -help`
</details>

## Application integration & Case studies
Links to additional content is available [here](docs/apps.md).

## Troubleshooting
Troubleshooting information is available [here](docs/troubleshooting.md).

## Licensing Information
Licensing information is available [here](docs/licensing.md).

## Legal
Legal information is available [here](docs/legal.md).

