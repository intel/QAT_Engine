# Installation Instructions

## Installing from packages
Distributions such as Fedora 34+, RHEL 8.4+ and 9.0+, CentOS Stream 9,
SUSE Linux Enterprise Server 15 SP3+, Debian 13+ and Ubuntu 24.04 include a `qatengine`
package. The included [RPM spec](../qatengine.spec) selects a QAT Provider build
by default on Fedora 41+ and RHEL 10+, installing `qatprovider.so` in OpenSSL's
modules directory. The package name remains `qatengine`; earlier Fedora builds
use the legacy Engine interface. For QAT_HW builds using the QATlib intree
driver on 4xxx devices, see the QATlib
[installation guide](https://github.com/intel/qatlib/blob/main/INSTALL) for
configuration settings. Install the distribution package using its package
manager. For more information about the intree driver and co-existence, see the
[QATlib documentation](https://intel.github.io/quickassist/qatlib/index.html).

### Binary RPM Package

The release page provides a pre-built binary RPM package for RHEL 9.2,
Ubuntu 24.04, and SUSE SLES15 SP7 using the distributions' default kernels and
dependent packages. The RPM uses the QAT 2.0 OOT driver with QAT_SW
co-existence on [Intel&reg; Xeon&reg; Scalable Processors with Intel&reg; QAT Gen4/Gen4m](https://www.intel.com/content/www/us/en/ark/products/series/228622/4th-generation-intel-xeon-scalable-processors.html).
Its default configuration builds QAT Provider (`qatprovider.so`) against
OpenSSL 3.x, accelerates asymmetric PKE through QAT_HW and AES-GCM through
QAT_SW, and installs the Provider under `ossl-modules/`.

Build the package with the `make rpm_oot` target. See
[Software Requirements](software_requirements.md) for the dependent library
versions used by the package.

Example installation and removal commands:

```text
# Install
# RHEL and SUSE
rpm -ivh QAT_Engine-<version>.x86_64.rpm --target noarch
# Ubuntu
alien -i QAT_Engine-<version>.x86_64.rpm --scripts

# Remove
# RHEL and SUSE
rpm -e QAT_Engine
# Ubuntu
apt-get remove QAT_Engine
```

The RPM installs its dependent libraries, kernel modules, and OpenSSL under
`/usr/local/ssl`. Because this OpenSSL version may differ from the system
version, set the library path before using it:

```bash
export LD_LIBRARY_PATH=/usr/local/ssl/lib64
```

Dockerfiles are also available for QAT Engine with QATlib and for HAProxy with
QAT. See the [Docker documentation](../dockerfiles/README.md) for details.

## Installing from Source code
This project supports various crypto libraries and QAT generations with
both hardware and software based accelerations. Follow the steps below
to build the QAT Engine (`qatengine`) or QAT Provider (`qatprovider`) for a specific target.

Clone the QAT_Engine GitHub repository using:
```
git clone https://github.com/intel/QAT_Engine.git
```

The complete list of build options is available in
[Configuration Options](config_options.md). To run `autogen.sh`, install
autotools (autoconf, automake, libtool, and pkg-config) on the system.

- [Install with make depend target](#install-with-make-depend-target)
- [Install Pre-requisites](#install-pre-requisites)
- [Build QAT Provider for QAT_HW](#build-qat-provider-for-qat_hw)
- [Build QAT Provider for QAT_SW](#build-qat-provider-for-qat_sw)
- [Build QAT Provider with QAT_HW & QAT_SW Co-existence](#build-qat-provider-with-qat_hw--qat_sw-co-existence)
- [Build with QAT Engine Interface](#build-with-qat-engine-interface)
- [Build Instructions for BoringSSL Library](bssl_support.md)

### Install with make depend target
The `make depend` target automatically clones and builds the OpenSSL, QAT_HW
(QAT 1.x and QAT 2.0 OOT Linux driver), and QAT_SW (cryptography-primitives and
ipsec_mb) dependencies based on the specified configure flags and platform.
Use the commands below to run this target.

```
cd /QAT_Engine
git submodule update --init
./autogen.sh \
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
When using the prebuilt system OpenSSL\*, the QAT Provider (`qatprovider`) shared library will be
installed in the system OpenSSL modules directory (`ossl-modules`); for
`--enable-qat_engine` builds, `qatengine.so` is installed in the system OpenSSL
engines directory (`engines-3`).

```
git clone https://github.com/openssl/openssl.git
git checkout <tag> # Latest OpenSSL version tag, for example, "openssl-3.0.14"
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

See [OpenSSL Configuration](openssl_config.md) to load and initialize QAT Engine
or QAT Provider through an OpenSSL configuration file.

### Install QAT_HW & QAT_SW dependencies

For **QAT_HW acceleration**, install the QAT Hardware driver using the Getting
Started Guide for the available QAT 1.x or QAT 2.x device from the
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

QAT Provider (`qatprovider`) is built by default; no enable flag is required.
See [QAT Provider Interface](qat_provider.md) for module loading, runtime
configuration, and test commands.

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

A QAT_SW build (`--enable-qat_sw`) requires both the
[`crypto_mb` library from Intel IPP Cryptography](https://github.com/intel/cryptography-primitives/tree/develop/sources/ippcp/crypto_mb)
and the
[`intel-ipsec-mb` library](https://github.com/intel/intel-ipsec-mb), regardless
of which QAT_SW algorithms are enabled.

When building the QAT Provider with `crypto_mb` and `intel_ipsec_mb` installed
in their default locations (`/usr/local/lib` for `crypto_mb` and `/usr/lib`
for `intel_ipsec_mb`) and using the system OpenSSL, follow these steps:

- In newer versions of the `crypto_mb` library, the libraries are
  installed to `/usr/local/lib` by default.

If you installed `crypto_mb` and `intel_ipsec_mb` using a custom `prefix`,
provide the corresponding paths using the configure flags:
- `--with-qat_sw_crypto_mb_install_dir`
- `--with-qat_sw_ipsec_mb_install_dir`

For newer versions of the `crypto_mb` library, also copy the libraries
from `prefix/lib/intel64` to `prefix/lib` to ensure proper linking.

```
cd /QAT_Engine
./autogen.sh
./configure --enable-qat_sw
make
make install
```

Optional for QAT Provider (`qatprovider`) with OpenSSL 3.5.0+: enable ML-KEM/ML-DSA
QAT_SW offload through IPsec MB. `crypto_mb` is still required because this is
a QAT_SW build; omit either `--with-qat_sw_*_install_dir` option when that
library is installed in its default location.

```
cd /QAT_Engine
./autogen.sh
./configure --enable-qat_sw --enable-qat_sw_ml_kem --enable-qat_sw_ml_dsa \
--with-openssl_install_dir=/path/to/openssl-3.5+ \
--with-qat_sw_crypto_mb_install_dir=/path/to/crypto_mb \
--with-qat_sw_ipsec_mb_install_dir=/path/to/ipsec_mb
make
make install
```
`--enable-qat_sw_ml_kem` and `--enable-qat_sw_ml_dsa` are provider-only options
and must not be combined with `--enable-qat_engine`.

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
To build QAT Engine (`qatengine`), configure QAT_Engine with the
`--enable-qat_engine` configure flag.
