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

# Intel&reg; QAT OpenSSL\* Engine Software Fallback

The Intel&reg; QuickAssist Heartbeat feature provides a mechanism for the
Intel&reg; QAT OpenSSL\* Engine to detect unresponsive acceleration devices and
to be notified of the start and end of any reset of the acceleration devices.
The Heartbeat feature suspends all QAT instances associated with that
acceleration device between these two reset-start and reset-end events.
Application using QAT needs to have the utility/daemon that periodically checks
device which is needed as part of heartbeat functionality.
An acceleration device can be configured for automatic reset by the QAT
framework upon heartbeat failure by using the `AutomaticResetOnError = 1` field
in the `[GENERAL]` section of device configuration file `/etc/<device>.conf`.
The Intel&reg; QAT OpenSSL\* Engine's software fallback feature requires this
field to be set.

The Intel&reg; QAT OpenSSL\* Engine's software fallback feature, when enabled
by the user, essentially provides continuity of crypto operations for the
application between the two above-mentioned reset-start & reset-end events.
It does this by exhibiting the following behavior:

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
Heartbeat feature on the following QAT Enabled Devices or Platforms using
the driver Linux Hardware v1.7, v1.8, v2.0(qatlib intree) and FreeBSD Hardware
v2.0(OOT package)

    * [Intel&reg; Xeon&reg; with Intel&reg; C62X Series Chipset][1]
    * [Intel® Xeon® Scalable Processor family with Intel® QAT Gen4/Gen4m][2]

[1]:https://www.intel.com/content/www/us/en/design/products-and-solutions/processors-and-chipsets/purley/intel-xeon-scalable-processors.html
[2]:https://www.intel.com/content/www/us/en/products/docs/processors/xeon-accelerated/4th-gen-xeon-scalable-processors.html

 2. Asymmetric PKE, Key Derivation algorithms supported by QAT Engine/provider and
Symmetric algorithms like AES-GCM, AES-CCM, CHACHAPOLY, AES-CBC chained ciphers
supports software fallback on device failure. Other Hash and SMx algorithms doesnt
support software Fallback.

 3. Software fallback feature for symmetric algorithms are only supported in FreeBSD platform.

### Testing the Software Fallback using OpenSSL Speed application

Pre-Requisites:  Build QAT Driver using `./configure --enable-icp-hb-fail-sim` flag
and change the driver config files `/etc/<device>.conf` to have
`AutoResetOnError = 1` as mentioned above. Driver needs to be built with same
version of OpenSSL as the application, to meet OpenSSL's requirement of version compatibility
between OpenSSL 1.1.1 and 3.x. Set the below envs to compile Driver against same version of OpenSSL if needed.

   * `setenv LDFLAGS "-L<installed OpenSSL path>/lib"`
   * `setenv CPPFLAGS "-I<installed OpenSSL path>/include"`

 1. Manually set the `enable_sw_fallback = 1` in the e_qat.c otherwise this needs to
 be turned on with Engine Ctrl messages at runtime from the application.
 2. Build QAT Engine as per the steps mentioned in the Example build in the Installation Instructions section.
 3. Run OpenSSL speed application with qatengine from <path_to_OpenSSL_install>/bin
    e.g., `./openssl speed -engine qatengine -elapsed rsa2048`
 4. Inject device failure using the command.
       `sysctl dev.qat.0.heartbeat_sim_fail=1`
 5. Check device status(0 - device failure, 1 - device active).
       `sysctl dev.qat.0.heartbeat`
 6. On successful software fallback, there will not be any errors reported from OpenSSL speed test.

### Additional Information
Additional information on this Heartbeat feature can be found at the Heartbeat Section
of respective QAT Hardware programmer's Guide below

* [Intel QAT Software for Linux—Programmer's Guide: Hardware v1.x CE Release][3]
* [Intel QAT Software for Linux—Programmer's Guide: Hardware v2.0][4]

[3]:https://cdrdv2.intel.com/v1/dl/getContent/710060
[4]:https://cdrdv2.intel.com/v1/dl/getContent/743912

