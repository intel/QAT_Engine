# Intel&reg; QAT OpenSSL\* Engine HKDF Support

The HKDF support in the Intel&reg; QAT OpenSSL\* Engine is available only from
Version 4.8 of Intel&reg; QuickAssist Technology Driver for Linux HW Version 1.7.
By default this support is disabled as it is added as an experimental feature.
It can be enabled using the flag `--enable-qat_hw_hkdf` in the configure command
combined with modifying the Intel&reg; QuickAssist Technology Driver file's
config variable 'ServicesProfile' from its default value of 'DEFAULT' to 'CRYPTO'.

# Using the OpenSSL\* Pipelining Capability

The OpenSSL\* pipelining feature provides the capability to parallelise the
processing for a single connection. For example a big buffer to be encrypted can
be split into smaller chunks with each chunk encrypted simultaneously using
pipelining.  The Intel&reg; QAT OpenSSL\* Engine supports OpenSSL\* pipelining
capability for chained cipher encryption operations only. The engine provides a
maximum of 32 pipelines (buffer chunks) with a maximum size of 16,384 bytes for
each pipeline. When pipelines are used, they are always accelerated to the
Hardware accelerator ignoring the small packet offload threshold.  Please refer
to the OpenSSL\* manual for more information about pipelining.
<https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_set_split_send_fragment.html>

# Intel&reg; QAT OpenSSL\* Engine Software Fallback Feature

The Intel&reg; QuickAssist Heartbeat feature provides a mechanism for the
Intel&reg; QAT OpenSSL\* Engine to detect unresponsive acceleration devices and
to be notified of the start and end of any reset of the acceleration devices.
The Heartbeat feature suspends all QAT instances associated with that
acceleration device between these two reset-start and reset-end events.
An acceleration device can be configured for automatic reset by the QAT
framework upon heartbeat failure by using the `AutomaticResetOnError = 1` field
in the `[GENERAL]` section of device configuration file `/etc/<device>.conf`.
The Intel&reg; QAT OpenSSL\* Engine's software fallback feature requires this
field to be set.

The Intel&reg; QAT OpenSSL\* Engine's software fallback feature, when enabled
by the user, essentially provides continuity of crypto operations for the
application between the two above-mentioned reset-start & reset-end events.
It does this by exhibiting the following behaviour:

* Any requests that have already been submitted to the acceleration device that
goes down but have not completed will be handled as on core requests and will
complete.
* Any new requests coming in while the acceleration device is offline will either
be submitted to the other acceleration devices (if any are available) or if none
are available then the request will be handled on core.
* Once the acceleration device has come back online new requests will be able to
use instances from that acceleration device again.

This should all happen in a transparent way with the only noticeable effects being
a potential slow down in performance until the acceleration device comes back online.

### Requirements:
 1. This Intel&reg; QAT OpenSSL\* Engine supports the Intel&reg; QAT Driver
Heartbeat feature starting with QAT driver version 4.6 of the following device:
    * [Intel&reg; Xeon&reg; with Intel&reg; C62X Series Chipset][1]

[1]:https://www.intel.com/content/www/us/en/design/products-and-solutions/processors-and-chipsets/purley/intel-xeon-scalable-processors.html

 2. Intel&reg; QAT OpenSSL\* Engine needs to be configured to disable Symmetric
Chained Ciphers, PRF, HKDF & X25519/X448 acceleration by adding the below four
flags in the configure command of Intel&reg; QAT OpenSSL\* Engine build.

    ```bash
    --disable-qat_hw_ciphers --disable-qat_hw_prf --disable-qat_hw_hkdf --disable-qat_hw_ecx
    ```
3. The Heartbeat feature is not supported in the FreeBSD operating system or in the
qatlib RPM.

### Additional Information
Additional information on this Heartbeat feature can be found in:
Intel&reg; QuickAssist Technology Software for Linux\* - Programmer's Guide - HW
version 1.7 (336210) - Section 3.17 Heartbeat.

This document can be found on the 01.org website at the following hyperlink:
* [Intel&reg; QuickAssist Technology Programmer's Guide][2]

[2]:https://01.org/sites/default/files/downloads/336210qatswpg-013.pdf
