# Installation Instructions

## Installing from packages
Distributions such as Fedora 34+, RHEL 8.4+ & 9.0+, CentOS 9 Stream,
SUSE SLES15 SP3+ and Ubuntu 24.04 each include `qatengine` package built
with QAT_HW qatlib intree driver(for 4xxx devices only) within their
repositories. Install `qatengine` package using the corresponding distro
install command. Refer qatlib [install](https://github.com/intel/qatlib/blob/main/INSTALL)
on the configuration settings.
More information about installing QAT Engine using intree driver and co-existence is
in [here](https://intel.github.io/quickassist/qatlib/index.html)

There is also pre-built binary RPM package for the distros like RHEL 9.1,
Ubuntu 22.04 and SUSE SLES15 SP3 with QAT_HW(OOT driver for 4xxx device) and QAT_SW
co-existence. Please refer [here](qat_common.md#binary-rpm-package)
for the details.

## Installing from Source code.
QAT Engine supports various crypto libraries and QAT generations with
both hardware and software based accelerations. Follow the steps below
to build qatengine for specific target.

Clone the the Intel&reg; QAT OpenSSL\* Engine Github Repo using:
```
git clone https://github.com/intel/QAT_Engine.git
```

The complete list of the build configure options to enable or disable
feature(s) is available [here](config_options.md). The prerequisite
to run `autogen.sh` is to have autotools (autoconf, automake,
libtool and pkg-config) installed in the system.

- [Install with make depend target](#install-with-make-depend-target)
- [Install Pre-requisites](#install-pre-requisites)
- [Build QAT Engine for QAT_HW](#build-qat-engine-for-qat_hw)
- [Build QAT Engine for QAT_SW](#build-qat-engine-for-qat_sw)
- [Build QAT Engine with QAT_HW & QAT_SW Co-existence ](#build-qat-engine-with-qat_hw--qat_sw-co-existence)
- [Build Instructions for BoringSSL Library](bssl_support.md)

### Install with make depend target
`make depend`  target in the QAT_Engine supports cloning and  building
the dependent libraries OpenSSL, QAT_HW(QAT1.x & QAT2.0 OOT Linux driver) and
QAT_SW(ipp-crypto & ipsec_mb automatically based on the QAT Engine configure
flags specified and platform underneath. Please follow the instructions below
to use the option.

```
cd /QAT_Engine
git submodule update --init
./configure \
--with-qat_hw_dir=/QAT \  #For QAT_HW supported platforms, Needed only if platform supports QAT_HW
--enable-qat_sw \ #For QAT_SW supported platforms, Needed only if platform supports QAT_SW
--with-openssl_install_dir=/usr/local/ssl # OpenSSL install path, if not specified will use system openssl
make depend
make
make install
```

Here `make depend` will clone the dependent libraries and install QAT_HW driver in /QAT
and QAT_SW in the default path(`/usr/local` for ipp-crypto & `/usr` for ipsec_mb).
`qatengine.so` library will be installed in `/usr/local/ssl/lib64/engines-3` where
openssl is also installed as mentioned in the openssl install flag.
Please note make depend target is not supported in FreeBSD OS, Virtualized
environment, BoringSSL, BabaSSL and qatlib dependency build.
The dependency library versions would be latest as mentioned in
[Software Requirements](software_requirements.md)

### Install Pre-requisites
Install QAT_HW and QAT_SW dependencies based on your acceleration choice the platform supports.

### Install OpenSSL or Tongsuo
This step is not required if building against system prebuilt OpenSSL\*.
When using the prebuild system OpenSSL\* the qatengine shared library will
be installed in the system OpenSSL engines directory.

```
git clone https://github.com/openssl/openssl.git
git checkout <tag> # Latest OpenSSL version tag Eg: "openssl-3.0.14"
./config --prefix=/usr/local/ssl -Wl,-rpath,/usr/local/ssl/lib64
make;
make install
```

If you prefer to use TongSuo (BabaSSL), clone using
`git clone https://github.com/Tongsuo-Project/Tongsuo.git` and use the
same install steps as mentioned above. It is recommended to checkout and build
against the OpenSSL\* or BabaSSL\* release tag specified in the
[Software Requirements](software_requirements.md) section.
The above example installs headers and libraries in the `/usr/local/ssl` dir.

`OPENSSL_ENGINES` environment variable (assuming the example paths above)
to find the dynamic engine at runtime needs to be set as below for loading engines
at OpenSSL\*

```
export OPENSSL_ENGINES=/usr/local/ssl/lib64/engines-3
```
Load/Initialize Engine using the the OpenSSL conf file is located [here](openssl_config.md)

### Install QAT_HW & QAT_SW dependencies

For **QAT_HW acceleration**, Install the QAT Hardware driver using the instructions from
Getting Starting Guide based on the QAT Hardware device for QAT1.x or QAT2.x available in the
[Intel® QuickAssist Technology](https://www.intel.com/content/www/us/en/developer/topic-technology/open/quick-assist-technology/overview.html)
page.

If **QAT_HW qatlib intree driver** over OOT driver is preferred, then configure the settings and
install the driver from [qatlib install](https://github.com/intel/qatlib/blob/main/INSTALL)

<details>
<summary>User Space DMA-able Memory (USDM) Component</summary>

The QAT_HW driver requires pinned contiguous memory allocations which is
allocated using the User Space DMA-able Memory (USDM) Component supplied within the QAT_HW
driver itself.
For Multithread use case, the USDM Component provides lockless thread specific memory
allocations which can be enabled using the below configure option while building QAT Hardware
driver. This is not needed for multiprocess use cases.

```
./configure --enable-icp-thread-specific-usdm --enable-128k-slab
```
</details>

<details>
<summary>Shared Virtual Memory</summary>

QAT gen4 devices(4xxx) supports Shared Virtual Memory (SVM) that allows the use of unpinned
user space memory avoiding the memcpy of buffers to pinned contiguous memory.
The SVM support in the driver enables passing of virtual addresses to the QAT
hardware for processing acceleration requests, i.e. addresses are the same
virtual addresses used in the calling process supporting Zero-copy. This Support
in the QAT Engine can be enabled dynamically by setting `SvmEnabled = 1` and `ATEnabled = 1`
in the QAT PF and VF device's driver config file(s) along with other prerequisites mentioned below.
This is **applicable only for OOT driver package** and not supported in qatlib intree driver.

The Following parameter needs to be enabled in BIOS and is supported only in QAT gen4 devices.

* Support for Shared Virtual Memory with Intel IOMMU
* Enable VT-d
* Enable ATS
</details>

For **QAT_SW Acceleration**, Install Intel® Crypto Multi-buffer library using the Installation instructions
from [Crypto_MB README](https://github.com/intel/ipp-crypto/tree/develop/sources/ippcp/crypto_mb)
and Intel® Multi-Buffer Crypto for IPsec Library using the instructions
from the [intel-ipsec_mb README](https://github.com/intel/intel-ipsec-mb).

### Build QAT Engine for QAT_HW

Build steps for QAT1.x or QAT2.x **OOT driver** unpacked within /QAT using OpenSSL\*
built from source and installed to `/usr/local/ssl`.  If System Openssl
is preferred then `--with-openssl_install_dir` is not needed.

```
cd /QAT_Engine
./autogen.sh
./configure \
--with-qat_hw_dir=/QAT \
--with-openssl_install_dir=/usr/local/ssl
make
make install
```

<details>
<summary>Copy the Intel® QuickAssist Technology driver config files</summary>

This step is not needed when qatlib intree driver is used which is managed by `qatmgr`
in the qatlib. QAT Engine built against OOT Driver needs Intel&reg; QAT Driver conf files
with `[SHIM]` section instead of default `[SSL]`.
The default section name in the QAT OpenSSL\* Engine can be modified if required
by either using the engine ctrl command SET_CONFIGURATION_SECTION_NAME or by
setting the environment variable "QAT_SECTION_NAME".
The example conf files with `SHIM` section are located at `/path/to/qat_engine/qat_hw_config`

The files are grouped by acceleration device(dh895xcc or c6xx or c3xxx
or 200xx or c4xxx or 4xxx), please choose the files according to the
QAT acceleration device type in the system

The files are also split into `multi_process` and `multi_thread` based use cases.

For event driven polling based application, change the parameter `Cy$nIsPolled=1`
to `Cy$nIsPolled=2` for each instances($n) in the respective config file to use
event driven polling support. Event driven config files are only supported in Linux.
Once you have decided which config file you should use, or created your own you
should follow the procedure below to install it:

1. Stop the acceleration driver as described in the Section
"Starting/Stopping the Acceleration software" from the
Getting Started Guide available in [Intel&reg; QuickAssist Technology Driver](https://developer.intel.com/quickassist)

2. Copy the appropriate `.conf` file to `/etc` for n number of QAT devices

3. Start the acceleration driver as described in the Section
"Starting/Stopping the Acceleration software" from the
Getting Started Guide available in [Intel&reg; QuickAssist Technology Driver](https://developer.intel.com/quickassist)
</details>

Build steps for **qatlib intree driver** installed from source(/usr/local)
and policies configured as in [qatlib install](https://github.com/intel/qatlib/blob/main/INSTALL)
using the system OpenSSL.

```
cd /QAT_Engine
./autogen.sh
./configure --with-qat_hw_dir=/usr/local
make
make install
```

### Build QAT Engine for QAT_SW

Build steps for crypto_mb and intel_ipsec_mb installed to its default location
`/usr/local/lib` and `/usr/lib` respectively with system OpenSSL.
If Crypto_mb and intel_ipsec_mb is installed using the prefix option then pass
the corresponding paths using the configure flags
`--with-qat_sw_crypto_mb_install_dir` and `--with-qat_sw_ipsec_mb_dir`.

```
cd /QAT_Engine
./autogen.sh
./configure --enable-qat_sw
make
make install
```
Note : If QAT_HW qatlib intree driver is installed in the system then configure `--disable-qat_hw`
to use QAT_SW only acceleration.

### Build QAT Engine with QAT_HW & QAT_SW Co-existence 

Build steps for QAT_HW & QAT_SW Co-existence with QAT_HW 1.x or 2.0 OOT
driver unpacked within `/QAT` and QAT_SW libraries installed to default path
and OpenSSL built from source is installed in `/usr/local/ssl`

```
cd /QAT_Engine
./autogen.sh
./configure \
--with-qat_hw_dir=/QAT \
--enable-qat_sw \
--with-openssl_install_dir=/usr/local/ssl
make
make install
```

The default behaviour and working mechanism of co-existence is described
[here](qat_coex.md#qat_hw-and-qat_sw-co-existence)

### Build Instructions for BoringSSL Library

Refer [BoringSSL section](bssl_support.md)
for steps to build the  Intel® QAT Engine for BoringSSL\* library
which supports RSA and ECDSA QAT Hardware and QAT Software Acceleration using BoringSSL.
