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

Also there is dockerfile available for QAT Engine with QATlib and HAproxy with QAT
which can be built into docker images.
Please refer [here](../dockerfiles/README.md) for more details.

## Installing from Source code.
QAT Engine supports various crypto libraries and QAT generations with
both hardware and software based accelerations. Follow the steps below
to build qatengine/qatprovider for specific target.

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
- [Build with QAT Provider Interface](#build-with-qat-provider-interface)
- [Build QAT Provider for QAT_HW](#build-qat-provider-for-qat_hw)
- [Build QAT Provider for QAT_SW](#build-qat-provider-for-qat_sw)
- [Build QAT Provider with QAT_HW & QAT_SW Co-existence ](#build-qat-provider-with-qat_hw--qat_sw-co-existence)
- [Build with QAT Engine Interface](#build-with-qat-engine-interface)
- [Build Instructions for BoringSSL Library](bssl_support.md)

### Install with make depend target
`make depend`  target in the QAT_Engine supports cloning and  building
the dependent libraries OpenSSL, QAT_HW(QAT1.x & QAT2.0 OOT Linux driver) and
QAT_SW(cryptography-primitives & ipsec_mb automatically based on the QAT Engine configure
flags specified and platform underneath. Please follow the instructions below
to use the option.

```
cd /QAT_Engine
git submodule update --init
./autogen.sh
./configure \
--with-qat_hw_dir=/QAT \  #For QAT_HW supported platforms, Needed only if platform supports QAT_HW
--enable-qat_sw \ #For QAT_SW supported platforms, Needed only if platform supports QAT_SW
--with-openssl_install_dir=/usr/local/ssl # OpenSSL install path, if not specified will use system openssl
make depend
make
make install
```

Here `make depend` will clone the dependent libraries and install QAT_HW driver in /QAT
and QAT_SW in the default path(`/usr/local` for cryptography-primitives & `/usr` for ipsec_mb).
By default `qatprovider.so` is installed to `/usr/local/ssl/lib64/ossl-modules`; if built
with `--enable-qat_engine`, `qatengine.so` is installed to `/usr/local/ssl/lib64/engines-3`,
openssl is also installed as mentioned in the openssl install flag.
Please note make depend target is not supported in FreeBSD OS, Virtualized
environment, BoringSSL, BabaSSL and qatlib dependency build.
The dependency library versions would be latest as mentioned in
[Software Requirements](software_requirements.md)

### Install Pre-requisites
Install QAT_HW and QAT_SW dependencies based on your acceleration choice the platform supports.

### Install OpenSSL or Tongsuo
This step is not required if building against system prebuilt OpenSSL\*.
When using the prebuild system OpenSSL\* the qatprovider shared library will be
installed in the system OpenSSL modules directory (`ossl-modules`); for
`--enable-qat_engine` builds, `qatengine.so` is installed in the system OpenSSL
engines directory (`engines-3`).

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

For the QAT Provider, the `qatprovider.so` module must be placed in the OpenSSL\*
modules directory. Set `OPENSSL_MODULES` if the module is installed outside the
default location (e.g. `<openssl-install>/lib64/ossl-modules/`):

```
export OPENSSL_MODULES=/usr/local/ssl/lib64/ossl-modules
```

Load/Initialize Engine or Provider using the OpenSSL conf file is located [here](openssl_config.md)

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
from [Crypto_MB README](https://github.com/intel/cryptography-primitives/tree/develop/sources/ippcp/crypto_mb)
and Intel® Multi-Buffer Crypto for IPsec Library using the instructions
from the [intel-ipsec_mb README](https://github.com/intel/intel-ipsec-mb).

### Build with QAT Provider Interface
The QAT Provider (`qatprovider`) is the default and recommended interface for
OpenSSL 3.x and later. `qatprovider.so` is built by default, and the
`--enable-qat_provider` configure flag is deprecated.

After installation, `qatprovider.so` is placed in the OpenSSL\* modules
directory (`<openssl-install>/lib64/ossl-modules/`). Set `OPENSSL_MODULES`
if using a non-default path:

```
export OPENSSL_MODULES=/usr/local/ssl/lib64/ossl-modules
```

Refer to [OpenSSL\* Configuration File](openssl_config.md) for loading the
provider via `openssl.cnf`, and to [QAT Provider Interface](qat_common.md#qat-provider-interface)
for test commands and further details. Note that when `qatprovider` is activated via
`openssl.cnf`, the `default` provider is not loaded automatically — ensure it is also
listed in the providers section to avoid "unknown algorithm" errors.


### Build QAT Provider for QAT_HW

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
<summary>Update the Intel® QAT driver config files</summary>

```bash
./update_config.sh <Mode> [<ServicesEnabled>] [<NumberCyInstances>] [<NumProcesses>] [<LimitDevAccess>]
```

Update the QAT device configuration file based on the provided input or default settings for either multi-process
or multi-thread mode. This step is applicable only for the Out-of-Tree (OOT) driver, as the in-tree driver
does not require configuration files and is instead managed through policy settings located in `/etc/sysconfig/qat`.

**Arguments**

- **`-h` or `-help`:**
    Print usage help.

- **`<Mode>`:**
    - `multi_process`: Configure for multi-process mode.
    - `multi_thread`: Configure for multi-thread mode.

- **`<ServicesEnabled>`:**
    - For QAT Gen4 devices (4xxx, 401x, 402x):
        `'asym;sym'`, `'asym'`, `'sym'`, `'asym;dc'`, or `'sym;dc'` (if compression co-exists).
    - For other lower QAT Gen (37c8):
        `'cy'`.

- **`<NumberCyInstances>`:**
    Number of CyInstances to configure in the driver configuration file.

- **`<NumProcesses>`:**
    Number of processes to configure in the driver configuration file.

- **`<LimitDevAccess>`:**
    LimitDevAccess configuration in the driver configuration file. Acceptable values: `[0, 1]`.

**Examples**

```bash
./update_config.sh multi_process
./update_config.sh multi_thread
./update_config.sh multi_process asym 1 64 0
```

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

### Build QAT Provider for QAT_SW

When building the QAT Provider with `crypto_mb` and `intel_ipsec_mb` installed
in their default locations (`/usr/local/lib` for `crypto_mb` and `/usr/lib`
for `intel_ipsec_mb`) and using the system OpenSSL, follow these steps:

- In newer versions of the `crypto_mb` library, the libraries are
  installed to `/usr/local/lib` by default.

If you installed `crypto_mb` and `intel_ipsec_mb` using a custom `prefix`,
provide the corresponding paths using the configure flags:
- `--with-qat_sw_crypto_mb_install_dir`
- `--with-qat_sw_ipsec_mb_dir`

For newer versions of the `crypto_mb` library, also copy the libraries
from `prefix/lib/intel64` to `prefix/lib` to ensure proper linking.

```
cd /QAT_Engine
./autogen.sh
./configure --enable-qat_sw
make
make install
```
Note : If QAT_HW qatlib intree driver is installed in the system then configure `--disable-qat_hw`
to use QAT_SW only acceleration.

### Build QAT Provider with QAT_HW & QAT_SW Co-existence

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

### Build with QAT Engine Interface
To build the legacy Engine interface, configure QAT Engine with the
`--enable-qat_engine` configure flag.
