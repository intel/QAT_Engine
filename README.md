# Intel&reg; QuickAssist Technology(QAT) OpenSSL\* Engine

## Table of Contents

- [Licensing](#licensing)
- [Features](#features)
- [Hardware Requirements](#hardware-requirements)
- [Software Requirements](#software-requirements)
- [Additional Information](#additional-information)
- [Limitations](#limitations)
- [Installation Instructions](#installation-instructions)
    - [Build Intel&reg; QuickAssist Technology Driver](#build-intel-quickassist-technology-driver)
    - [Build OpenSSL\*](#build-openssl)
    - [Clone the Intel&reg; QuickAssist Technology OpenSSL\* Engine](#clone-the-intel-quickassist-technology-openssl-engine)
    - [Build and install a contiguous memory driver](#build-and-install-a-contiguous-memory-driver)
    - [Build the Intel&reg; QuickAssist Technology OpenSSL\* Engine](#build-the-intel-quickassist-technology-openssl-engine)
    - [Copy the correct Intel&reg; QuickAssist Technology Driver config files](#copy-the-correct-intel-quickassist-technology-driver-config-files)
    - [Test the Intel&reg; QuickAssist Technology OpenSSL\* Engine](#test-the-intel-quickassist-technology-openssl-engine)
    - [Run speed with the Intel&reg; Quickassist Technology OpenSSL\* Engine](#run-speed-with-the-intel-quickassist-technology-openssl-engine)
- [Troubleshooting](#troubleshooting)
- [Intel&reg; QuickAssist Technology OpenSSL\* Engine Specific Messages](#intel-quickassist-technology-openssl-engine-specific-messages)
- [Intel&reg; QuickAssist Technology OpenSSL\* Engine Build Options](#intel-quickassist-technology-openssl-engine-build-options)
- [Using the OpenSSL\* Configuration File to Load/Initialize Engines](#using-the-openssl-configuration-file-to-loadinitialize-engines)
- [Using the OpenSSL\* Pipelining Capability](#using-the-openssl-pipelining-capability)
- [Using the OpenSSL* asynchronous mode 'ASYNC_JOB' infrastructure](#using-the-openssl-asynchronous-mode-infrastructure)
- [Functionality of the Intel&reg; QAT OpenSSL\* Engine Software Fallback Feature](#functionality-of-the-intel-qat-openssl-engine-software-fallback-feature)
- [Legal](#legal)

## Licensing

The Licensing of the files within this project is split as follows:

Intel&reg; QuickAssist Technology(QAT) OpenSSL\* Engine - BSD License.
Please see the `LICENSE` file contained in the top level folder. Some of the
engine code contains modified code from OpenSSL/BoringSSL. In both cases the
code is licensed under the OpenSSL license available at
<https://www.openssl.org/source/license.html>. Further details can be found in
the file headers of the relevant files.

Example Intel&reg; Contiguous Memory Driver contained within the folder
`qat_contig_mem` - Dual BSD/GPLv2 License.
Please see the file headers within the `qat_contig_mem` folder, and the full
GPLv2 license contained in the file `LICENSE.GPL` within the `qat_contig_mem`
folder.

Example Intel&reg; QuickAssist Technology Driver Configuration Files contained
within the folder hierarchy `qat` - Dual BSD/GPLv2 License.
Please see the file headers of the configuration files, and the full GPLv2
license contained in the file `LICENSE.GPL` within the `qat` folder.

## Features

* Synchronous and Asynchronous Operation
* Asymmetric PKE Offload
    * RSA Support for Key Sizes 1024/2048/4096.
    * DH Support for Key Sizes 768/1024/1536/2048/3072/4096.
    * DSA Support for Key Sizes 160/1024, 224/2048, 256/2048, 256/3072.
    * ECDH Support for the following curves:
        * NIST Prime Curves: P-192/P-224/P-256/P-384/P-521.
        * NIST Binary Curves: B-163/B-233/B-283/B-409/B-571.
        * NIST Koblitz Curves: K-163/K-233/K-283/K-409/K-571.
    * ECDSA Support for the following curves:
        * NIST Prime Curves: P-192/P-224/P-256/P-384/P-521.
        * NIST Binary Curves: B-163/B-233/B-283/B-409/B-571.
        * NIST Koblitz Curves: K-163/K-233/K-283/K-409/K-571.
* Symmetric Chained Cipher Offload with pipelining capability:
    * AES128-CBC-HMAC-SHA1/AES256-CBC-HMAC-SHA1.
    * AES128-CBC-HMAC-SHA256/AES256-CBC-HMAC-SHA256.
* Pseudo Random Function (PRF) offload.
* Support for the Intel&reg; QuickAssist Technology Driver Heartbeat feature.

Note: RSA Padding schemes are handled by OpenSSL rather than offloaded, so the
engine supports the same padding schemes as OpenSSL does natively.

## Hardware Requirements

This Intel&reg; QAT OpenSSL\* Engine supports crypto offload to the following
acceleration devices:

* [Intel&reg; Xeon&reg; with Intel&reg; C62X Series Chipset][1]
* [Intel&reg; Atom&trade; Processor C3000][2]
* [Intel&reg; Communications Chipset 8925 to 8955 Series][3]
* [Intel&reg; Communications Chipset 8900 to 8920 Series][4]
* [Intel&reg; Atom&trade; Processor C2000][5]

This Intel&reg; QAT OpenSSL\* Engine supports the Intel&reg; QAT Driver
Heartbeat feature from version 4.6 of the following acceleration device:

* [Intel&reg; Xeon&reg; with Intel&reg; C62X Series Chipset][1]

Note: Heartbeat feature support currently does not extend to Symmetric Chained
Cipher Offload and PRF offload.

[1]:https://www-ssl.intel.com/content/www/us/en/design/products-and-solutions/processors-and-chipsets/purley/intel-xeon-scalable-processors.html
[2]:https://www.intel.com/content/www/us/en/design/products-and-solutions/processors-and-chipsets/denverton/ns/atom-processor-c3000-series.html
[3]:https://www.intel.com/content/www/us/en/ethernet-products/gigabit-server-adapters/quickassist-adapter-8950-brief.html
[4]:https://www.intel.com/content/www/us/en/ethernet-products/gigabit-server-adapters/quickassist-adapter-8920-brief.html
[5]:https://www.intel.com/content/www/us/en/embedded/products/rangeley/overview.html

## Software Requirements

Successful operation of this release requires a software tool chain that
supports OpenSSL\* 1.1.1 or OpenSSL\* 1.1.0.
This release was validated on the following:

* Operating system: CentOS\* 7.4 64-bit version
* Kernel: GNU\*/Linux\* 3.10.0-693
* Intel&reg; Communications Chipset C62X Series Software for Linux\*, version 4.6
* OpenSSL\* 1.1.1 (Basic functionality testing done on TLS1.3)

It is recommended that the Intel&reg; QAT OpenSSL\* Engine is built against
GNU\* C Library version 2.23 or later to take advantage of AVX-512 optimizations
if supported by your processor.

## Additional Information

* [Intel&reg; QuickAssist Technology Driver][6]
* [White Paper: Intel&reg; QuickAssist Technology and OpenSSL-1.1.0:Performance][7]

Additional Information on integrating the Intel&reg QAT OpenSSL\* Engine with NGINX\*
including an asynchronous fork of NGINX\* can be found at the following Github\*
repository:

* [Intel&reg; QuickAssist Technology (QAT) Async Mode NGINX\*][8]

[6]:https://01.org/packet-processing/intel%C2%AE-quickassist-technology-drivers-and-patches
[7]:https://01.org/sites/default/files/downloads/intelr-quickassist-technology/intelquickassisttechnologyopensslperformance.pdf
[8]:https://github.com/intel/asynch_mode_nginx

## Limitations

* When using TLS 1.3 only asymmetric PKE offload is supported. TLS 1.3 uses an HKDF
  instead of a PRF which is not currently accelerated, and the set of
  symmetric ciphers currently offloaded are not compatible with the TLS 1.3
  symmetric ciphers which are AES-GCM or ChaCha-Poly based.
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
  [Fix waitctx fds removing the fd from the list #2581][9]

[9]:https://github.com/openssl/openssl/pull/2581

## Installation Instructions

### Build Intel&reg; QuickAssist Technology Driver

Please follow the instructions contained in:

**For Intel&reg; Xeon&reg; with Intel&reg; C62X Series Chipset:**
**For Intel&reg; Atom&trade; Processor:**
**For Intel&reg; Communications Chipset 8925 to 8955 Series:**
Intel&reg; QuickAssist Technology Software for Linux\* - Getting Started Guide - HW version 1.7 (336212)

**For Intel&reg; Communications Chipset 89XX Series:**
Intel&reg; Communications Chipset 89xx Series Software for Linux\* - Getting
Started Guide (330750)

**For Intel&reg; Atom&trade; Processor C2000:**
Intel&reg; Atom&trade; Processor C2000 Product Family for Communications
Infrastructure Software - Getting Started Guide (333035)

These instructions can be found on the 01.org website in the following section:

[Intel&reg; QuickAssist Technology][10]

[10]:https://01.org/packet-processing/intel%C2%AE-quickassist-technology-drivers-and-patches

### Build OpenSSL\*

Clone OpenSSL\* from Github\* at the following location:

    git clone https://github.com/openssl/openssl.git

It is recommended to checkout and build against the OpenSSL\* 1.1.1 git tag
specified in the release notes.
Versions of OpenSSL\* before OpenSSL\* 1.1.0 are not supported.

Due to the nature of the Intel&reg; QAT OpenSSL\* Engine being a dynamic engine
it can only be used with shared library builds of OpenSSL\*.

Note: The OpenSSL\* 1.1.0 and 1.1.1 baselines build as a shared library by
default now so there is no longer any need to specify the `shared` option when
running `./config`.

Note: It is not recommended to install the accelerated version of OpenSSL\* as
your default system library. If you do, you may find that acceleration is used
unexpectedly by other applications on the system resulting in
undesired/unsupported behaviour. The `--prefix` can be used with the `./config`
command to specify the location that `make install` will copy files to. Please
see the OpenSSL\* INSTALL file for full details on usage of the `--prefix`
option.

From OpenSSL\* version 1.1.0c onwards, automatic RPATH has been removed.
The reason for this is that before OpenSSL\* version 1.1.0, binaries were
installed in a non-standard location by default, and runpath driectories were
therefore added in those binaries, to make sure the executables would be able to
find the shared libraries they were linked with.  However, with OpenSSL\* version
1.1.0 and on, binaries are installed in standard directories by default, and the
addition of runpath directories is not done automatically.  If you wish
to install OpenSSL\* in a non-standard location (recommended), the runpath
directories can be specified via the OpenSSL\* Configure command, which
recognises the arguments `-rpath` and `-R` to support user-added rpaths.  For
convenience, a Makefile variable `LIBRPATH` has also been added which is defined
as the full path to a subdirectory of the installation directory. The
subdirectory is named `lib` by default.
If you do not wish to use `LIBRPATH`, the rpath can be specified directly.
The syntax for specifying a rpath is as follows:

    ./config [options] -Wl,-rpath,\${LIBRPATH}

The `-rpath` can be replaced with `-R` for brevity. If you do not wish
to use the built-in variable LIBRPATH, the syntax for specifying a rpath of
`/usr/local/ssl/lib` for example would be:

    ./config [options] -Wl,-rpath,/usr/local/ssl/lib

Alternatively, you can specify the rpath by adding it to the environment
variable `LD_LIBRARY_PATH` via the command:

    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:`RPATH`

where `RPATH` is the full path(s) to the shared libraries.  This is not the
preferred method though.

The following example is assuming:

* The OpenSSL\* source was cloned from Github\* to its own location at the root
  of the drive: `/`.
* You want OpenSSL\* to be installed to `/usr/local/ssl`.

An example build would be:
```bash
cd /openssl
./config --prefix=/usr/local/ssl -Wl,-rpath,\${LIBRPATH}
make depend (if recommended by the OpenSSL\* build system)
make
make install
```
As the Intel&reg; QAT OpenSSL\* Engine will be built as a dynamic engine it is
important to tell OpenSSL\* where to find the dynamic engines at runtime. This
is achieved by exporting the following environment variable (assuming the
example paths above):

    export OPENSSL_ENGINES=/usr/local/ssl/lib/engines-1.1

Note: This variable will need to be present in the environment whenever the
engine is used.

Further information on building OpenSSL\* can be found in the INSTALL file
distributed with the OpenSSL\* source code or on the official OpenSSL\* Wiki in
the Compilation and Installation section:
<https://wiki.openssl.org/index.php/Compilation_and_Installation>

### Clone the Intel&reg; QuickAssist Technology OpenSSL\* Engine

Clone the Github\* repository containing the Intel&reg; QAT OpenSSL\* Engine:

    git clone https://github.com/intel/QAT_Engine.git

The repository can be cloned to either a subdirectory within the OpenSSL\*
repository, for instance if the OpenSSL\* source is located at `/openssl` then
the engine could be cloned at `/openssl/engines`, or to its own unique location
on the file system, for instance within `/`. In either case the engine will not
be built as part of the OpenSSL\* build and will require building manually.

### Build and install a contiguous memory driver

The Intel&reg; QAT API requires many of the data structures (those that will be
passed to the hardware) to be allocated in contiguous pinned memory in order to
support DMA operations. You must either supply your own contiguous memory driver
and make changes to the engine to make use of it or use one of the following
drivers:

#### (Optional) Build and load the example contiguous memory driver - qat\_contig\_mem

The Intel&reg; QAT OpenSSL\* Engine comes with an example kernel space
contiguous memory driver that can be used to try out operation of the engine. It
is considered to be an example only and is not written to be a production
quality driver.

The following example is assuming:
* The Intel&reg; QAT OpenSSL\* Engine was cloned to its own location at the root
  of the drive: `/`.

To build/install the qat\_contig\_mem driver follow these steps:

```bash
cd /QAT_Engine/qat_contig_mem
make
make load
make test
```

The expected output from `make test` should be something similar to the
following:

    seg mapped to 0x7f9eedd6e000, virtualAddress in seg 0xffff880ac9c0c000,
    length 64
    Hello world!
    # PASS Verify for QAT Contig Mem Test

#### (Optional) Load the User Space DMA-able Memory (USDM) Component

As an alternative the Upstream Intel&reg; QAT Driver comes with its own
contiguous pinned memory driver that is compatible with the Intel&reg; QAT
OpenSSL\* Engine. The USDM component is of a higher quality than the
qat\_contig\_mem driver, and is the preferred option.
Unfortunately the USDM component may not be available if using older Intel&reg;
QAT Driver versions. The USDM component is used by the Upstream Intel&reg; QAT
Driver itself, and also has the following additional features:

* Support for virtualization
* Support for configurable slab sizes
* Support for configurable secure freeing of memory (overwrite with zeros)
* Support for configurable slab caching

The USDM component is located within the Upstream Intel&reg; QAT Driver source
code in the following subdirectory: `quickassist/utilities/libusdm_drv`.
As the USDM component is also used by the upstream driver itself it will have
already been built when the driver was built. It may also already be loaded as
well, and you can check by running `lsmod` and looking for usdm_drv in the list.
If not present it can be loaded as follows:

```bash
insmod ./usdm_drv.ko
```

### Build the Intel&reg; QuickAssist Technology OpenSSL\* Engine

The following example is assuming:

* The Intel&reg; QAT OpenSSL\* Engine was cloned to its own location at the root
  of the drive: `/`.
* The Intel&reg; QAT Driver was unpacked within `/QAT`.
* An Intel&reg; Communications Chipset 8925 to 8955 Series device is fitted.
* The OpenSSL\* source was cloned from Github\* to its own location at the root
  of the drive: `/`.
* OpenSSL\* was installed to `/usr/local/ssl`.
* OpenSSL\* 1.1.1 is being used.

To build and install the Intel&reg; QAT OpenSSL\* Engine:

```bash
cd /QAT_Engine
./autogen.sh
./configure \
--with-qat_dir=/QAT/QAT1.6 \
--with-openssl_dir=/openssl \
--with-openssl_install_dir=/usr/local/ssl
make
make install
```

In the above example this will create the file `qat.so` and copy it to
`/usr/local/ssl/lib/engines-1.1`.
./autogen.sh will regenerate autoconf tools files. The prerequisite to run
autogen.sh is to have autotools (autoconf, automake and libtool)
installed in the system.

Note: When building it is possible to specify command line options that can be
used to turn engine functionality on and off. Please see the Intel&reg; QAT
OpenSSL\* Engine Build Options section below for a full description of the
options that can be specified. The above options are all mandatory.

If you plan to link against the Upstream Intel&reg; QAT userspace shared library
then there are some additional options that may be required:

* The `--enable-upstream_driver` is a mandatory parameter to the `./configure`
  that tells the build that you are going to link against the upstream version
  of the Intel&reg; QAT Driver and ensures the link step is setup correctly.
* The `--enable-usdm` is an optional parameter to the `./configure` that tells
  the build that it should be compiled to use the usdm component and that the
  link should be configured to link in the userspace library of the usdm
  component.

An example to build and install the Intel&reg; QAT OpenSSL\* Engine based on the
example above, but building against the Upstream Intel&reg; QAT Driver, and
using the USDM component would be as follows:

```bash
cd /QAT_Engine
./autogen.sh
./configure \
--with-qat_dir=/QAT \
--with-openssl_dir=/openssl \
--with-openssl_install_dir=/usr/local/ssl \
--enable-upstream_driver \
--enable-usdm
make
make install
```

An example to build and install the Intel&reg; QAT OpenSSL\* Engine against a
packaged prebuilt OpenSSL\* requiring use of the optional configure parameter
`--enable-openssl_install_build_arch_path` (described in the 'Optional' configure
options section below) is as follows.  It assumes that:

* The Intel&reg; QAT OpenSSL\* Engine was cloned to its own location at the root
  of the drive: `/`.
* The Intel&reg; QAT Driver was unpacked within `/QAT`and is the
  Upstream Intel&reg; QAT Driver using the USDM component.
* The OpenSSL\* compiled code comprises a prebuilt (GNU compiled) packaged
  OpenSSL\* that either forms part of a Debian\* based distribution or else has
  been installed onto a Debian\* based distribution, of which the component
  libraries are located in directory `/usr/lib/x86_64-linux-gnu`.
* The machine processor type is `x86_64`.
* The OpenSSL\* source code was cloned from Github\* to its own location at the root
  of the drive: `/`.
* The OpenSSL\* version is in the `1.1.0` series.

To build and install the Intel&reg; QAT OpenSSL\* Engine:

```bash
cd /QAT_Engine
./autogen.sh
./configure \
--with-qat_dir=/QAT \
--with-openssl_dir=/openssl \
--with-openssl_install_dir=/usr/lib/x86_64-linux-gnu \
--enable-openssl_install_build_arch_path \
--enable-qat_for_openssl_110 \
--enable-upstream_driver \
--enable-usdm
make
make install
```

In the above example this will create the file `qat.so` and copy it to
`/usr/lib/x86_64-linux-gnu/engines-1.1`.


### Copy the correct Intel&reg; QuickAssist Technology Driver config files

The Intel&reg; QAT OpenSSL\* Engine comes with some example conf files to use
with the Intel&reg; QAT Driver.
The Intel&reg; QAT OpenSSL\* Engine will not function with the default
Intel&reg; QAT Driver conf file because the default conf does not contain a
`[SHIM]` section which the Intel&reg; QAT OpenSSL\* Engine requires by default.
The default section name in the QAT OpenSSL\* Engine can be modified if required
by either using the engine ctrl command SET_CONFIGURATION_SECTION_NAME or by
setting the environment variable "QAT_SECTION_NAME".
The conf files are located at:

    /path/to/qat_engine/qat/config

The files are grouped by acceleration device, please choose the files
appropriate to your acceleration device only.
If building to link against the Upstream Intel&reg; QAT userspace shared library
then you should use the files in `dh895xcc_upstream`, or `c6xx`.

The files are also split into `multi_process_optimized` and
`multi_thread_optimized`.

If your application runs one (or very few) processes, but has multiple threads
in each process, each accessing the acceleration device, then you should pick
the `multi_thread_optimized` config files. An example of this is a webserver
that creates a new thread for each incoming connection.

If your application scales by creating new processes, then you should pick the
`multi_process_optimized` config files. An example of this is an event driven
application that runs as a single thread in an event loop.  In this type of
application it is usual for the application to create at least one new process
for each cpu core you want to utilize.

There are also similar config files for if you are using the event driven
polling feature of the Intel&reg; QAT Driver contained in
`multi_thread_event-driven_optimized` and `multi_process_event-driven_optimized`
respectively. Once you have decided which conf file you should use,
or created your own you should follow the procedure below to install it:

1. Follow the instructions to stop the Acceleration Driver:

   **For Intel&reg; Xeon&reg; with Intel&reg; C62X Series Chipset:**
   **For Intel&reg; Atom&trade; Processor: C3000:**
   **For Intel&reg; Communications Chipset 8925 to 8955 Series:**
   Intel&reg; QuickAssist Technology Software for Linux\* - Getting Started
   Guide - HW version 1.7 (336212) - Section 3.3 Starting/Stopping the
   Acceleration.

   **For Intel&reg; Communications Chipset 89XX Series:**
   Intel&reg; Communications Chipset 89xx Series Software for Linux\* - Getting
   Started Guide (330750) - Section 3.4 Starting/Stopping the Acceleration
   Software.

   **For Intel&reg; Atom&trade; Processor C2000:**
   Intel&reg; Atom&trade; Processor C2000 Product Family for Communications
   Infrastructure Software - Getting Started Guide (333035) - Section 9.5
   Starting/Stopping the Acceleration Software.

2. Copy the appropriate `.conf` file to `/etc`

3. Follow the instructions to start the Acceleration Driver:

   **For Intel&reg; Xeon&reg; with Intel&reg; C62X Series Chipset:**
   **For Intel&reg; Atom&trade; Processor C3000:**
   **For Intel&reg; Communications Chipset 8925 to 8955 Series:**
   Intel&reg; QuickAssist Technology Software for Linux\* - Getting Started
   Guide - HW version 1.7 (336212) - Section 3.3 Starting/Stopping the
   Acceleration.

   **For Intel&reg; Communications Chipset 89XX Series:**
   Intel&reg; Communications Chipset 89xx Series Software for Linux\* - Getting
   Started Guide (330750) - Section 3.4 Starting/Stopping the Acceleration
   Software.

   **For Intel&reg; Atom&trade; Processor C2000:**
   Intel&reg; Atom&trade; Processor C2000 Product Family for Communications
   Infrastructure Software - Getting Started Guide (333035) - Section 9.5
   Starting/Stopping the Acceleration Software.

### Test the Intel&reg; QuickAssist Technology OpenSSL\* Engine

Run this command to check if the Intel&reg; QAT OpenSSL\* Engine is loaded
correctly:

```text
cd /path/to/openssl/apps
./openssl engine -t -c -vvvv qat
(qat) Reference implementation of QAT crypto engine
 [RSA, DSA, DH, AES-128-CBC-HMAC-SHA1, AES-256-CBC-HMAC-SHA1,
 AES-128-CBC-HMAC-SHA256, AES-256-CBC-HMAC-SHA256, TLS1-PRF]
     [ available ]
     ENABLE_EXTERNAL_POLLING: Enables the external polling interface to the engine.
          (input flags): NO_INPUT
     POLL: Polls the engine for any completed requests
          (input flags): NO_INPUT
     SET_INSTANCE_FOR_THREAD: Set instance to be used by this thread
          (input flags): NUMERIC
     GET_NUM_OP_RETRIES: Get number of retries
          (input flags): NO_INPUT
     SET_MAX_RETRY_COUNT: Set maximum retry count
          (input flags): NUMERIC
     SET_INTERNAL_POLL_INTERVAL: Set internal polling interval
          (input flags): NUMERIC
     GET_EXTERNAL_POLLING_FD: Returns non blocking fd for crypto engine
          (input flags): NO_INPUT
     ENABLE_EVENT_DRIVEN_POLLING_MODE: Set event driven polling mode
          (input flags): NO_INPUT
     GET_NUM_CRYPTO_INSTANCES: Get the number of crypto instances
          (input flags): NO_INPUT
     DISABLE_EVENT_DRIVEN_POLLING_MODE: Unset event driven polling mode
          (input flags): NO_INPUT
     SET_EPOLL_TIMEOUT: Set epoll_wait timeout
          (input flags): NUMERIC
     SET_CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD: Set QAT small packet threshold
          (input flags): STRING
     ENABLE_INLINE_POLLING: Enables the inline polling mode.
          (input flags): NO_INPUT
     ENABLE_HEURISTIC_POLLING: Enable the heuristic polling mode
          (input flags): NO_INPUT
     GET_NUM_REQUESTS_IN_FLIGHT: Get the number of in-flight requests
          (input flags): NUMERIC
     INIT_ENGINE: Initializes the engine if not already initialized
          (input flags): NO_INPUT
     ENABLE_SW_FALLBACK: Enables the fallback to SW if the acceleration devices go offline
          (input flags): NO_INPUT
     HEARTBEAT_POLL: Check the acceleration devices are still functioning
          (input flags): NO_INPUT
     DISABLE_QAT_OFFLOAD: Perform crypto operations on core
          (input flags): NO_INPUT

```


### Run speed with the Intel&reg; QuickAssist Technology OpenSSL\* Engine

```text
cd /path/to/openssl/apps

* RSA 2K
  * Asynchronous
  ./openssl speed -engine qat -elapsed -async_jobs 72 rsa2048
  * Synchronous
  ./openssl speed -engine qat -elapsed rsa2048
  * Software
  ./openssl speed -elapsed rsa2048
* ECDH Compute Key
  * Asynchronous
  ./openssl speed -engine qat -elapsed -async_jobs 36 ecdh
  * Synchronous
  ./openssl speed -engine qat -elapsed ecdh
  * Software
  ./openssl speed -elapsed ecdh
* Chained Cipher: aes-128-cbc-hmac-sha1
  * Asynchronous
  ./openssl speed -engine qat -elapsed -async_jobs 128 -multi 2 -evp aes-128-cbc-hmac-sha1
  * Synchronous
  ./openssl speed -engine qat -elapsed -multi 2 -evp aes-128-cbc-hmac-sha1
  * Software
  ./openssl speed -elapsed -multi 2 -evp aes-128-cbc-hmac-sha1
```

## Troubleshooting

The most likely failure point is that the Intel&reg; QAT OpenSSL\* Engine is not
loading successfully.
If this occurs some of the things to check are:

   1. Has the qat\_contig\_mem driver been loaded successfully? If not the
      engine will fail to initialise. Check by running `lsmod`, qat\_contig\_mem
      should be in the list. The same applies if using the alternative USDM
      component, but instead look for usdm_drv when running `lsmod`.
   2. Has the correct Intel&reg; QAT Driver config file been copied to `/etc`?
      Check it has a `[SHIM]` section and that the Intel&reg; QAT Driver
      software was restarted so that it picked up the new config file.
   3. Is the Intel&reg; QAT Driver up and running?
      Check by running `lsmod`, icp_qa_al should be in the list.
      Also check the Intel&reg; QAT Driver software has been started.
   4. Were the paths set correctly so that the `qat.so` engine file was copied
      to the correct location?
      Check they really are there.
   5. Has the environment variable `OPENSSL_ENGINES` been correctly defined and
      exported to the shell?
      Also check it is really pointing to the correct location.
   6. If building for OpenSSL 1.1.0 was the configure option
      `--enable-qat_for_openssl_110` specified?

If running on a Debian\* based OS (Ubuntu\* for example) it is possible that the
Intel&reg; QAT Driver userspace shared library needed by the Intel&reg; QAT
OpenSSL\* Engine may not be located even though it has been installed. To
resolve this it is recommended to add the /lib64 folder to the LD_LIBRARY_PATH
environment variable as follows:

    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/lib64

If linking against the Upstream Intel&reg; QAT Driver then ensure that the
mandatory parameter `--enable-upstream_driver` has been specified when running
`./configure`, or the link will fail.

If building against OpenSSL\* 1.1.1 or master branch , it is possible that the
OpenSSL\* Engine will fail to build with an error message `configdata.pm not
present in the @INC path`. To resolve this, it is recommended to add the
OpenSSL source path to the PERL5LIB environment variable as follows:

    export PERL5LIB=$PERL5LIB:/path/to/openssl

## Intel&reg; QuickAssist Technology OpenSSL\* Engine Specific Messages

OpenSSL\* engines support a mechanism whereby custom messages can be defined for
an application to communicate directly with the engine.  These messages are
typically used in two ways:

   1. Firstly in order to set configuration options. These messages are
      typically sent before the engine is initialized. Sending these after
      initialization will typically have no effect.
   2. Secondly in order to control the engine operation. These messages may be
      sent before initialization or after or both.

The custom message mechanism passes a string to identify the message, and uses a
number of parameters to pass information into or out of the engine. It is
defined as follows:

    ENGINE_ctrl_cmd(<Engine>, <Message String>, <Param 3>,
                    <Param 4>, NULL, 0\)

Where:

   - &lt;Engine&gt; is a pointer to the Intel&reg; QAT enabled OpenSSL\* Engine.
   - &lt;Message String&gt; is a string representing the message type.
   - &lt;Param 3&gt; is a long that can be used to pass a number, or a pointer
     can be cast to it.
   - &lt;Param 4&gt; is a void pointer used to pass data structures in.
   - The last 2 parameters are always NULL and 0 when used with the Intel&reg;
     QAT OpenSSL\* Engine.

```text
Message String: ENABLE_EXTERNAL_POLLING
Param 3:        0
Param 4:        NULL
Description:
    This message is used to enable the external polling mode of operation where
    it becomes the applications responsibility to use the POLL message below to
    check for messages that have been returned from the hardware accelerator.
    It has no parameters or return value.  If required this message must be
    sent after engine creation and before engine initialization.

Message String: POLL
Param 3:        0
Param 4:        pointer to an int
Description:
    This message is used when external polling is enabled to request poll of
    all instances. The status of the request is passed back in the variable
    passed in as Param 4. This message may be sent at any time after engine
    initialization.

Message String: INIT_ENGINE
Param 3:        0
Param 4:        NULL
Description:
    This message is not normally necessary as the engine will get initialized
    either via an ENGINE_init() call or automatically following a fork. This
    message would only be used for performance reasons with an engine compiled
    with --disable-qat_auto_engine_init_on_fork. In that case it may be
    desirable to send this engine message in the child rather than wait for the
    engine to be initialized automatically on the first offloaded crypto
    request.

Message String: SET_INTERNAL_POLL_INTERVAL
Param 3:        unsigned long cast to a long
Param 4:        NULL
Description:
    This message is used to set the interval in nano seconds between polling
    for messages coming back from the hardware accelerator. The value should be
    passed in as Param 3. The default is 10,000, the min value is 1, and
    the max value is 10,000,000. This message can be sent at any time after
    the engine has been created.

Message String: SET_EPOLL_TIMEOUT
Param 3:        unsigned long cast to a int
Param 4:        NULL
Description:
    This message is used to set the timeout in milli seconds used for
    epoll_wait() when event driven polling mode is enabled. The value should be
    passed in as Param 3. The default is 1,000, the min value is 1, and the max
    value is 10,000. This message can be sent at any time after the engine
    has been created.

Message String: ENABLE_EVENT_DRIVEN_POLLING_MODE
Param 3:        0
Param 4:        NULL
Description:
    This message changes the engines mode to use the Intel(R) QAT Drivers
    event driven polling feature. It must be sent if required after engine
    creation but before engine initialization.  It should not be sent after
    engine initialization.

Message String: DISABLE_EVENT_DRIVEN_POLLING_MODE
Param 3:        0
Param 4:        NULL
Description:
    This message changes the engines mode to use the timer based polling
    feature. It must be sent if required after engine creation but before
    engine initialization. It should not be sent after engine initialization.

Message String: GET_NUM_CRYPTO_INSTANCES
Param 3:        0
Param 4:        pointer to an int
Description:
    This message is used to retrieve the total number of crypto instances
    available as specified in the Intel(R) QAT Driver config file. The number
    of instances is assigned to the dereferenced int that is passed in as Param
    4. This message is used in conjunction with the GET_POLLING_FD message as in
    event driven polling mode with external polling there is an fd to listen to
    events on for each crypto instance. This message must be sent if required
    after the engine has been initialized.

Message String: GET_EXTERNAL_POLLING_FD
Param 3:        int cast to a long
Param 4:        pointer to an int
Description:
    This message is used to retrieve the file descriptor that can be used for
    event notification when the Intel(R) QAT Driver has had the event driven
    polling feature enabled. The value passed in as Param 3 is the instance to
    retrieve the fd for. The fd is returned by assigning to the dereferenced
    int passed as Param4. When retrieving fd's it is usual to first request how
    many instances there are with the GET_NUM_CRYPTO_INSTANCES message and then
    use a for loop to iterate through the instances starting from 0 and use
    this message to retrieve the fd for each instance. This message must be
    sent if required after the engine has been initialized.

Message String: SET_INSTANCE_FOR_THREAD
Param 3:        long
Param 4:        NULL
Description:
    This message is used to bind the thread to a specific instance number.
    Param 3 contains the instance number to bind to. If required, the message
    must be sent after the engine creation and will automatically trigger the
    engine initialization.

Message String: GET_NUM_OP_RETRIES
Param 3:        0
Param 4:        pointer to an unsigned int
Description:
    This message returns the number of retry operations.  The number is set in
    the variable passed in as Param 4.  This message may be sent at any time
    after engine initialization.

Message String: SET_MAX_RETRY_COUNT
Param 3:        int cast to a long
Param 4:        NULL
Description:
    This message is used for synchronous operations to determine how many times
    the engine should retry a message before flagging a failure. The value
    should be passed in as Param 3. Setting the value to -1 results in infinite
    retries. The default is 5 and the max value is 100,000. This message can be
    sent at any time after the engine is created.

Message String: SET_CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD
Param 3:        0
Param 4:        NULL terminated string of cipher algorithm name and threshold
                value. Maximum length is 1024 bytes including NULL terminator.
Description:
    This message is used to set the threshold that determines the size crypto
    packets need to be before they are offloaded to the acceleration device.
    It is not efficient to offload very small packets to the accelerator as to
    do so would take longer to transfer the data to and from the accelerator
    than to encrypt/decrypt using the main CPU. The threshold value can be set
    independently for each EVP_CIPHER operation supported by the engine using
    the following names:
        AES-128-CBC-HMAC-SHA1
        AES-256-CBC-HMAC-SHA1
        AES-128-CBC-HMAC-SHA256
        AES-256-CBC-HMAC-SHA256
    The input format should be a string like this in one line:
        AES-128-CBC-HMAC-SHA1:4096,AES-256-CBC-HMAC-SHA1:8192
    Using a separator ":" between cipher name and threshold value.
    Using a separator "," between different cipher configurations.
    The default threshold value is 2048 bytes, the minimum is 0 bytes and the
    maximum is 16,384.
    The threshold value includes all the bytes that make up the TLS record
    including Record Header (5 bytes), IV (16 bytes), Payload, HMAC (20/32
    bytes), Padding (variable but could be max 255 bytes), and Padding Length
    (1 byte).
    The string should be NULL terminated and not more than 1024 bytes long
    including NULL terminator.
    This message is not supported when the engine is compiled with the flag
    --enable-qat_small_pkt_offload.

Message String: ENABLE_INLINE_POLLING
Param 3:        0
Param 4:        NULL
Description:
    This message is used to enable the inline polling mode of operation where
    a busy loop is used by the Intel(R) QAT OpenSSL* Engine to check for
    messages from the hardware accelerator after requests are sent to it.
    Currently this mode is only available in the synchronous RSA computation.
    It has no parameters or return value. If required this message must be sent
    after engine creation and before engine initialization.

Message String: ENABLE_HEURISTIC_POLLING
Param 3:        0
Param 4:        NULL
Description:
    This message is used to enable the heuristic polling mode of operation where
    the application can use the GET_NUM_REQUESTS_IN_FLIGHT message below to
    retrieve the number of different kinds of in-flight requests and
    intelligently determine the proper moment to perform the polling operation.
    This mode can be regarded as an improvement of the timer-based external
    polling. The external polling mode must be enabled first before enabling
    this mode. If required this message must be sent after engine creation and
    before engine initialization.

Message String: GET_NUM_REQUESTS_IN_FLIGHT
Param 3:        int cast to a long
Param 4:        pointer to an int address
Description:
    This message is used when heuristic polling is enabled to retrieve the
    number of different kinds of in-flight requests.
    The value passed in as param 3 is the indicator for a specific kind of
    request:
        #define GET_NUM_ASYM_REQUESTS_IN_FLIGHT 1
        #define GET_NUM_PRF_REQUESTS_IN_FLIGHT 2
        #define GET_NUM_CIPHER_PIPELINE_REQUESTS_IN_FLIGHT 3
    The first (i.e, value 1) is used to retrieve the number of asymmetric-key
    in-flight requests. The second (i.e, value 2) is used to retrieve the number
    of PRF in-flight requests.  The last (i.e, value 3) is used to retrieve the
    number of cipher in-flight requests (when OpenSSL* pipelining feature is
    not used), or the number of in-flight pipelines (when OpenSSL* pipelining
    feature is used).
    The address of the variable recording the specified info is returned by
    assigning to the dereferenced int address passed as Param 4. This means the
    application can directly use this int address to retrieve the specified info
    afterwards without sending this message again.
    This message may be sent at any time after engine initialization.

Message String: SET_CONFIGURATION_SECTION_NAME
Param 3:        0
Param 4:        NULL terminated string of section name from Intel(R) QAT Driver
                config file. Maximum length is 64 bytes including
                NULL terminator.
Description:
    This message is used to configure the Intel(R) QAT OpenSSL* Engine to use
    the string passed in as parameter 4 to be the name for the Intel(R) QAT
    Driver config section rather than the default `[SHIM]`. It must be sent
    after engine creation but before engine initialization. It should not be
    sent after engine initialization.

Message String: ENABLE_SW_FALLBACK
Param 3:        0
Param 4:        NULL
Description:
    This message is used to enable fallback to software (on-core) of the crypto
    operations normally offloaded to the acceleration devices by the
    Intel&reg; QuickAssist Technology OpenSSL\* Engine.  This command enables
    the software fallback feature - crypto operations will continue to be offloaded
    but, with this feature enabled, in the event the accelerations devices
    subsequently go offline the Intel&reg; QuickAssist Technology OpenSSL\* Engine
    will automatically switch to performing crypto operations on-core.
    If required this message must be sent after engine creation and
    before engine initialization.

Message String: HEARTBEAT_POLL
Param 3:        0
Param 4:        pointer to an int
Description:
    This message is used to check the acceleration devices are still functioning.
    It is normally used in conjunction with the Software Fallback feature
    (see engine command ENABLE_SW_FALLBACK) when using External Polling Mode
    (see engine command ENABLE_EXTERNAL_POLLING). The result of this
    engine specific message (success/failure) is assigned to the dereferenced int
    that is passed in as Param 4.
    Polling using this message will result in the Intel&reg; QuickAssist Technology
    OpenSSL\* Engine being notified when instances of an acceleration device go
    offline or come back online. By sending this message more frequently you can
    decrease the time taken for the engine to become aware of instances going
    offline/coming back online at the expense of additional cpu cycles. The
    suggested polling interval would be around 0.5 seconds to 1 second.
    This message may be sent at any time after engine initialization.

Message String: DISABLE_QAT_OFFLOAD
Param 3:        0
Param 4:        NULL
Description:
    This message is used to disable offload of crypto operations to the
    acceleration devices, with the immediate effect that these operations are
    performed on-core instead.
    This message may be sent at any time after engine initialization.
```

## Intel&reg; QuickAssist Technology OpenSSL\* Engine Build Options

The following is a list of the options that can be used with the
`./configure` command when building the Intel&reg; QAT OpenSSL\* Engine:

```
Mandatory

--with-qat_dir=/path/to/qat_driver
    Specify the path to the source code of the Intel(R) QAT Driver. This path
    is needed for compilation in order to locate the Intel(R) QAT header files.
    If you do not specify this the build will fail.
    For example if using Upstream Intel&reg; QAT Driver package that was
    unpacked to `/QAT`, and you are using an Intel(R) Communications Chipset
    C62X Series device then you would use the following setting:
    --with-qat_dir=/QAT
    Another example if using the QATmux.L.2.6.0-60.tar.gz driver package that
    was unpacked to `/QAT`, and you are using an Intel(R) Communications Chipset
    8925 to 8955 Series device then you would use the following setting:
    --with-qat_dir=/QAT/QAT1.6

--with-openssl_dir=/path/to/openssl
    Specify the path to the top level of the OpenSSL* source code.  This path
    is needed so that the compilation can locate the OpenSSL header files and
    also because the mkerr.pl script is needed from the OpenSSL source files in
    order to generate the engine specific error source files. If you do not
    specify this the build will fail.
    For example if you cloned the OpenSSL* Github* repository from within `/`
    then you would use the following setting:
    --with-openssl_dir=/openssl

--with-openssl_install_dir=/path/to/openssl_install
    Specify the path to the top level where the OpenSSL* build was installed
    to. This is needed so that the qat.so engine library can be copied into the
    folder containing the other dynamic engines when you run 'make install'. If
    you do not specify this then 'make install' will fail.
    For example if you installed OpenSSL* to its default location of
    `/usr/local/ssl` then you would use the following setting:
    --with-openssl_install_dir=/usr/local/ssl

Mandatory (when using the Upstream Intel&reg; QAT Driver)

--enable-upstream_driver/--disable-upsteam_driver
    Enable/Disable linking against the Upstream Intel(R) QAT Driver. If
    linking against the Upstream Intel(R) QAT Driver then this option must be
    enabled (disabled by default).

Optional

--with-qat_install_dir=/path/to/qat_driver/build
    Specify the path to the location of the built Intel(R) QAT Driver library
    files. This path is needed in order to link to the userspace libraries of
    the Intel(R) QAT Driver.
    The default if not specified is to use the path specified by --with-qat_dir
    with '/build' appended.  You only need to specify this parameter if the
    driver library files have been built somewhere other than the default.

--enable-usdm/--disable-usdm
    Enable/Disable compiling against the USDM component and that the link should
    be configured to link in the userspace library of the USDM component. The
    USDM component is a pinned contiguous memory driver that is distributed with
    the Upstream Intel(R) QAT Driver. It can be used instead of the supplied
    qat_contig_mem memory driver (disabled by default).

--with-usdm_dir=/path/to/usdm/directory
    Specify the path to the location of the USDM component.
    The default if not specified is to use the path specified by --with-qat_dir
    with '/quickassist/utilities/libusdm_drv' appended.  You only only need to
    specify this parameter if using the USDM component, and if the path to it
    is different from the default.

--disable-qat_rsa/--enable-qat_rsa
    Disable/Enable Intel(R) QAT RSA offload (enabled by default)

--disable-qat_dsa/--enable-qat_dsa
    Disable/Enable Intel(R) QAT DSA offload (enabled by default)

--disable-qat_dh/--enable-qat_dh
    Disable/Enable Intel(R) QAT DH offload (enabled by default)

--disable-qat_ecdh/--enable-qat_ecdh
    Disable/Enable Intel(R) QAT ECDH offload (enabled by default)

--disable-qat_ecdsa/--enable-qat_ecdsa
    Disable/Enable Intel(R) QAT ECDSA offload (enabled by default)

--disable-qat_ciphers/--enable-qat_ciphers
    Disable/Enable Intel(R) QAT Chained Cipher offload (enabled by default)

--disable-qat_prf/--enable-qat_prf
    Disable/Enable Intel(R) QAT PRF offload (enabled by default)

--disable-qat_small_pkt_offload/--enable-qat_small_pkt_offload
    Enable the offload of small packet cipher operations to Intel(R) QAT. When
    disabled, these operations are performed using the CPU (disabled by
    default).

--disable-qat_warnings/--enable-qat_warnings
    Disable/Enable warnings to aid debugging. Warning: This option should never
    be left on in a production environment as it may introduce side channel
    timing attack vulnerabilities (disabled by default).

--disable-qat_debug/--enable-qat_debug
    Disable/Enable debug output to aid debugging. This will also enable the
    warning messages above. Warning: This option should never be enabled in a
    production environment as it may output private key information to the
    console/logs and may also introduce side channel timing attack
    vulnerabilities (disabled by default).

--disable-qat_mem_warnings/--enable-qat_mem_warnings
    Disable/Enable warnings from the userspace memory management code to aid
    debugging. Warning: This option should never be left on in a production
    environment as it may introduce side channel timing attack vulnerabilities
    (disabled by default).

--disable-qat_mem_debug/--enable-qat_mem_debug
    Disable/Enable debug output from the userspace memory management code to
    aid debugging. This will also enable the warning messages above. This
    option produces quite verbose output hence why it is separate to the
    standard debug. Warning: This option should never be enabled in a
    production environment as it may output private key information to the
    console/logs and may also introduce side channel timing attack
    vulnerabilities (disabled by default).

--with-qat_debug_file=/file/and/path/to/log/qat/debug/to
    This option turns on logging to a file instead of to stderr. It works with
    any combination of the following flags:
      --enable-qat_warnings
      --enable-qat_debug
      --enable-qat_mem_warnings
      --enable-qat_mem_debug
    The option should specify the full absolute path and filename that you would
    like to log to. The directory needs to be writable by the user the process
    is running as, and the log file can get very big, very quickly.
    The existing log file will be replaced rather than appended to on each run
    of the application. If the file cannot be opened for writing then the
    logging will default to output to stderr.
    As with the other logging options this option should never be enabled in a
    production environment as private key information and plaintext data will
    be logged to the file (logging to file is disabled by default).

--disable-multi_thread/--enable-multi_thread
    Disable/Enable an alternative way of managing within userspace the pinned
    contiguous memory allocated by the qat_contig_mem driver. This alternative
    method will give improved performance in a multi-threaded environment by
    making the slab pools thread local to avoid locking between threads.
    Although this can give better performance there are several drawbacks such
    as the memory slabs will be utilized less efficiently, and you cannot
    allocate in one thread and free in another thread.  Running in this mode
    also does not support processes that fork (disabled by default).

--disable-qat_mux/--enable-qat_mux
    Disable/Enable support for building using the Mux mode of the Intel(R)
    QAT Driver. Mux mode allows you to mix Intel(R) Communications Chipset
    8900 to 8920 Series hardware and Intel(R) Communications Chipset 8925
    to 8955 Series hardware within the same system using a common driver
    interface. You should only specify this option if using a mixture of
    hardware (disabled by default).

--disable-qat_lenstra_protection/--enable-qat_lenstra_protection
    Disable/Enable protection against Lenstra attack (CVE-2017-5681)
    (protection is enabled by default). The RSA-CRT implementation in the
    Intel(R) QAT OpenSSL* Engine, for OpenSSL* versions prior to v0.5.19,
    may allow remote attackers to obtain private RSA keys by conducting a
    Lenstra side-channel attack.  From version v0.5.19 onward, protection
    against this form of attack is effected by performing a Verify/Encrypt
    operation after the Sign/Decrypt operation, and if a failure is detected
    then re-running the Sign/Decrypt operation using the CPU.
    However, future releases of Intel(R) QAT driver code or firmware may
    effect this protection instead, in which case the Intel(R) QAT OpenSSL*
    Engine code-based protection would no longer be required and this
    configuration option should then be selected.
    For further information, please refer to:-
    https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00071&languageid=en-fr
    https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5681

--enable-qat_for_openssl_102
    Enable the Intel(R) QAT OpenSSL* Engine to build against OpenSSL* 1.0.2.
    Currently if using this build option, only synchronous RSA offload is
    supported (default is to build for the OpenSSL* 1.1.1/master branch).

--enable-qat_for_openssl_110
    Enable the Intel(R) QAT OpenSSL* Engine to build against OpenSSL* 1.1.0
    (default is to build for the OpenSSL* 1.1.1/master branch).

--enable-openssl_install_build_arch_path
    Enable the Intel(R) QAT OpenSSL* Engine to build against a packaged
    pre-built OpenSSL* that has either been pre-installed in your particular
    Linux distribution or else that you have installed yourself.
    For example, for a Debian* based distribution, the pre-built OpenSSL* package
    is either pre-installed or else can be installed with the command:
    `apt-get install openssl`.
    This places both static and shared libraries associated with the OpenSSL*
    package in directory /usr/lib/<architecture>, where <architecture> is a
    description of the hardware architecture the package is intended to run on
    (for example, for an Intel(R) x86-based 64-bit architecture, GNU-compiled, it
    would be 'x86_64-linux-gnu'). This directory is therefore specified via the
    `--with-openssl_install_dir` mandatory option detailed above.
    In addition, shared libraries of compiled engine code corresponding to the
    version of the pre-built OpenSSL* package are located in directory
    `usr/lib/<architecture>/engines-1.1`, the `1.1` denoting that the version is
    in the `1.1.X` series of API compatible releases. The shared library
    resulting from building and installing the Intel(R) QAT OpenSSL* Engine,
    must be placed in this directory rather than the default.  Use of this
    option, together with the correct specification of mandatory options
    `with-openssl_dir` and `with-openssl_install_dir`, ensures this.

    For this example Debian* based distribution, the OpenSSL* header files
    associated with the OpenSSL* package can also be installed by using the
    command:
    `apt-get install libssl-dev`.
    After running this command, the OpenSSL* header files are located in
    directory `/usr/include/openssl`.  However, as well as the header files,
    the build procedure for the Intel&reg; QAT OpenSSL* Engine requires use
    of an OpenSSL* supplied Perl script named `mkerr.pl`, which is not
    supplied by this command.  Therefore, rather than install the `libssl-dev`
    package, it is recommended that you install the OpenSSL* source files to
    a directory of your choice.  This is done by changing to your chosen
    directory and then cloning OpenSSL* from Github* at the following location:

    git clone https://github.com/openssl/openssl.git

    You must checkout the same version of OpenSSL* as the pre-built OpenSSL*
    package.  You can find out the version of the pre-built OpenSSL* package
    using the command:
    `apt-cache policy openssl`.
    Then checkout the git tag corresponding to the version of the pre-built
    OpenSSL* package.  At the time of writing, for a recent Debian* based
    distribution such as `Ubuntu 18.04.1 LTS`, the version of this packaged
    OpenSSL* is version `1.1.0g`.
    A list of git tags is obtained by using the git command:
    `git tag -l`.
    From this list select the tag which corresponds to the version of the
    pre-built OpenSSL* package.  For example, if the version is `1.1.0g` then
    the git checkout command would be:
    `git checkout tags/OpenSSL_1_1_0g`.
    The OpenSSL* header files and the `mkerr.pl` Perl script should now be
    available for subsequent use in the build procedure for the
    Intel&reg; QAT OpenSSL* Engine in your chosen git checkout directory.
    This directory's path should therefore be specified with the
    `--with-openssl_dir` mandatory option detailed above.

    In summary, use of the `--enable-openssl_install_build_arch_path` option
    ensures that the Intel(R) QAT OpenSSL* Engine shared library, resulting from
    carrying out the Intel(R) QAT OpenSSL* Engine build and installation
    process, is placed in the directory `usr/lib/<architecture>/engines-1.1`
    rather than the default.
    This option is disabled by default.

--disable-qat_auto_engine_init_on_fork/--enable-qat_auto_engine_init_on_fork
    Disable/Enable the engine from being initialized automatically following a
    fork operation. This is useful in a situation where you want to tightly
    control how many instances are being used for processes. For instance if an
    application forks to start a process that does not utilize QAT currently
    the default behaviour is for the engine to still automatically get started
    in the child using up an engine instance. After using this flag either the
    engine needs to be initialized manually using the engine message:
    INIT_ENGINE or will automatically get initialized on the first QAT crypto
    operation. The initialization on fork is enabled by default.

--enable-qat_skip_err_files_build
    Enable the skipping of the regeneration of the errors files during the
    QAT OpenSSL* Engine build process.  Note that if this option is selected
    then you must ensure that the files e_qat_err.c, e_qat_err.h & e_qat.txt
    are present in the QAT OpenSSL* Engine source top directory prior to
    launching the build process.  In addition, these existing files must
    have been originally generated for the OpenSSL* version you are building
    against.
    This option is disabled by default.

--with-cc-opt="parameters"
    Sets additional parameters that will be added to the CFLAGS variable at
    compile time.

--with-ld-opt="parameters"
    Sets additional parameters that will be used during linking.

```

## Using the OpenSSL\* Configuration File to Load/Initialize Engines

OpenSSL\* includes support for loading and initializing engines via the
openssl.cnf file. The openssl.cnf file is contained in the `ssl` subdirectory of
the path you install OpenSSL\* to.  By default OpenSSL\* does not load the
openssl.cnf file at initialization time. In order to load the file you need to
make the following function call from your application as the first call to the
OpenSSL\* library:

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

The second parameter determines the name of the section containing the
application specific initialization settings. If you set the parameter to NULL
as in the example above it will default to look for the `openssl_conf` section.
If you want to use your own section you should declare a structure of type
`OPENSSL_INIT_SETTINGS` and set the `appname` field to a string containing the
section name you wish to use. The example config file sections below assume you
are using the default `openssl_conf` section name.

If converting an existing application to use the Intel&reg; QAT OpenSSL\* Engine
you may find that the application instead makes the now deprecated call to:

    OPENSSL_config(NULL);

Where the parameter is a const char* pointer to the `appname` section you want
to use, or NULL to use the default `openssl_conf` section.

Currently this will give the same behaviour as the
`OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL)` call but as it is
deprecated it should not be relied upon for future use.

For further details on using the OPENSSL_init_crypto function please see the
OpenSSL\* online documentation located at:
<https://www.openssl.org/docs/man1.1.0/crypto/OPENSSL_init_crypto.html>

In order to start using the openssl.cnf file it needs some additional lines
adding. You should add the following statement in the global section (this is
the section before the first bracketed section header):

    openssl_conf = openssl_init

The string `openssl_init` is the name of the section in the configuration file
which describes the application specific settings. You do not need to stick to
the naming convention here if you prefer to use a different name.

The `openssl_init` section can be located at the end of the global section (as
the first bracketed section), or further down the configuration file. It should
have the following added:

    [ openssl_init ]
    engines = engine_section

The `engines` string is a keyword that OpenSSL\* recognises as a configuration
module. It should be set to a string which is the section name containing a list
of the engines to be loaded. So for the Intel&reg; QAT OpenSSL\* Engine the
section should contain:

    [ engine_section ]
    qat = qat_section

The `qat_section` contains all the settings relating to that particular engine.
For instance it may contain:

    [ qat_section ]
    engine_id = qat
    dynamic_path = /usr/local/ssl/lib/engines-1.1/qat.so
    # Add engine specific messages here
    default_algorithms = ALL

Where `engine_id` specifies the name of engine to load (should be `qat`).

Where `dynamic_path` is the location of the loadable shared library implementing
the engine. There is no need to specify this line if the engine is located
within the standard path that OpenSSL\* was installed to.

Where `default_algorithms` specifies which algorithms supplied by the engine
should be used by default. Specify `ALL` to make all algorithms supplied by the
engine be used by default.

In addition the `qat_section` may contain settings that call custom engine
specific messages. For instance:

    ENABLE_EVENT_DRIVEN_MODE = EMPTY

is functionally equivalent of making the following engine specific message
function call:

    ENGINE_ctrl_cmd(e, "ENABLE_EVENT_DRIVEN_MODE", 0, NULL, NULL, 0);

You should set the setting to `EMPTY` if there are no parameters to pass, or
assign the value that would be passed as the 4th parameter of the equivalent
`ENGINE_ctrl_cmd` call. It should be noted that this mechanism is only useful
for passing simple values at engine initialization time.  You cannot pass 3rd
parameter values, pass complex structures or deal with return values via this
mechanism.

Engine specific messages should be specified before the `default_algorithms`
setting or incorrect behaviour may result. The following messages are supported:

* `ENABLE_EVENT_DRIVEN_POLLING_MODE`
* `ENABLE_EXTERNAL_POLLING`
* `ENABLE_INLINE_POLLING`
* `ENABLE_SW_FALLBACK`
* `SET_INTERNAL_POLL_INTERVAL`
* `SET_EPOLL_TIMEOUT`
* `SET_MAX_RETRY_COUNT`

In case of forking, the custom values are inherited by the child process.

By default the engine will get initialized at the end of this section (after all
the custom engine specific messages have been sent). This can be controlled via
an additional `init` setting that is out of scope of the documentation here.

For further details on using the OpenSSL\* configuration file please see the
OpenSSL\* online documentation located at:
<https://www.openssl.org/docs/man1.1.0/apps/config.html>

By setting up the configuration file as above it is possible for instance to run
the OpenSSL\* speed application to use the Intel&reg; QAT OpenSSL\* Engine
without needing to specify `-engine qat` as a command line option.

## Using the OpenSSL\* Pipelining Capability

The OpenSSL\* pipelining feature provides the capability to parallelise the
processing for a single connection. For example a big buffer to be encrypted can
be split into smaller chunks with each chunk encrypted simultaneously using
pipelining.  The Intel&reg; QAT OpenSSL\* Engine supports OpenSSL\* pipelining
capability for chained cipher encryption operations only. The engine provides a
maximum of 32 pipelines (buffer chunks) with a maximum size of 16,384 bytes for
each pipeline. When pipelines are used, they are always offloaded to the
accelerator ignoring the small packet offload threshold.  Please refer to the
OpenSSL\* manual for more information about pipelining.
<https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_set_split_send_fragment.html>

## Using the OpenSSL\* asynchronous mode 'ASYNC_JOB' infrastructure

Asynchronous operation utilizes the OpenSSL\* asychronous mode (`ASYNC_JOB`
infrastructure) introduced in OpenSSL\* version 1.1.0.  In the
OpenSSL\* master branch this infrastructure was augmented to provide an
additional `callback` method by which the OpenSSL\* Engine can be notified
of crypto operation request completions by the hardware accelerator. This
additional method can be used if you think that using the alternative
`file descriptor` method descriptor is too costly in terms of CPU cycles
or in some context where a file descriptor is not appropriate.

The QAT OpenSSL\* Engine build system will automatically detect whether the
OpenSSL\* version being built against supports this additional `callback` method.
If so, the QAT OpenSSL\* Engine code will use the `callback`
mechanism for job completion rather than the `file descriptor`
mechanism if a `callback` function has been set. If a `callback` has not
been set then the `file descriptor` method will be used.

For further details on using the OpenSSL\* asynchronous mode infrastructure please
see the OpenSSL\* online documentation located at:
<https://www.openssl.org/docs/manmaster/man3/ASYNC_start_job.html>

with additional information at:
<https://www.openssl.org/docs/manmaster/man3/ASYNC_WAIT_CTX_new.html>.

## Functionality of the Intel&reg; QAT OpenSSL\* Engine Software Fallback Feature

###Requirements:
As stated in the [Hardware Requirements](#hardware-requirements) section
above,
 1. This Intel&reg; QAT OpenSSL\* Engine supports the Intel&reg; QAT Driver
Heartbeat feature only from version 4.6 of the following device:

    * [Intel&reg; Xeon&reg; with Intel&reg; C62X Series Chipset][1]

 2. Intel&reg; QAT OpenSSL\* Engine needs to be configured to disable Symmetric
Chained Cipher Offload and PRF offload by adding the below two flags in the
configure command of Intel&reg; QAT OpenSSL\* Engine build.

```bash
--disable-qat_ciphers --disable-qat_prf
```

Information on this Heartbeat feature can be found in:
Intel&reg; QuickAssist Technology Software for Linux\* - Programmer's Guide - HW
version 1.7 (336210) - Section 3.17 Heartbeat.

This document can be found on the 01.org website at the following hyperlink:

* [Intel&reg; QuickAssist Technology Programmer's Guide][11]

[11]:https://01.org/sites/default/files/downloads//336210-007qatswprogrammersguide.pdf

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
a slow down in performance until the acceleration device comes back online.


## Legal

Intel, Intel Atom, and Xeon are trademarks of
Intel Corporation in the U.S. and/or other countries.

\*Other names and brands may be claimed as the property of others.

Copyright &copy; 2016-2019, Intel Corporation. All rights reserved.
