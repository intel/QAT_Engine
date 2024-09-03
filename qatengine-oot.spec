%undefine __cmake_in_source_build
%undefine _disable_source_fetch
%global _lto_cflags %{nil}
%global debug_package %{nil}
# Dependent Library Versions
%global major        1
%global minor        5
%global rev          0
%global ipsec        intel-ipsec-mb
%global ipsecver     %{major}.%{minor}
%global ipsecfull    %{ipsec}-%{ipsecver}
%global fullversion  %{major}.%{minor}.%{rev}

%global ippcp_major        11
%global ippcp_minor        15
%global ippcp              ipp-crypto
%global ippcpver           ippcp_2021.12.1
%global ippcpfull          %{ippcp}-%{ippcpver}
%global ippcpfullversion   %{ippcp_major}.%{ippcp_minor}

%global openssl            openssl-3.0.15
%global qatdriver          QAT20.L.1.1.50-00003

%global openssl_source     %{_builddir}/%{openssl}
%global openssl_install    %{buildroot}/%{_prefix}/local/ssl

Name:       QAT_Engine
Version:    1.7.0
Release:    1%{?dist}
Summary:    Intel QuickAssist Technology(QAT) OpenSSL Engine
License:    BSD-3-Clause AND OpenSSL

Source0:    https://github.com/intel/QAT_Engine/archive/refs/tags/v%{version}.tar.gz#/%{name}-%{version}.tar.gz
Source1:    https://github.com/openssl/openssl/releases/download/%{openssl}/%{openssl}.tar.gz#/%{openssl}.tar.gz
Source2:    https://downloadmirror.intel.com/822703/%{qatdriver}.tar.gz#/%{qatdriver}.tar.gz
%if !0%{?suse_version}
Source3:    https://github.com/intel/ipp-crypto/archive/refs/tags/%{ippcpver}.tar.gz#/%{ippcp}-%{ippcpver}.tar.gz
Source4:    https://github.com/intel/intel-ipsec-mb/archive/refs/tags/v%{ipsecver}.tar.gz#/%{ipsecfull}.tar.gz
%endif

%description
This package provides the Intel QuickAssist Technology OpenSSL Engine
(an OpenSSL Plug-In Engine) which provides cryptographic acceleration
for both hardware and optimized software using Intel QuickAssist Technology
enabled Intel platforms.

%prep
%setup -b 0
%setup -b 1
%if !0%{?suse_version}
%setup -b 3
%setup -b 4
%endif
# Setup Source2 driver package manually
mkdir -p %{_builddir}/%{qatdriver}
tar -zxvf %{_sourcedir}/%{qatdriver}.tar.gz -C %{_builddir}/%{qatdriver}
cp -rf %{_builddir}/%{name}-%{version}/fips/driver_install.sh %{_builddir}

%build
cd %{_builddir}/%{openssl}
./config --prefix=%{_builddir}/openssl_install
%make_build
make install
mkdir -p %{buildroot}/%{_prefix}/local/ssl/lib64
mkdir -p %{buildroot}/%{_prefix}/local/ssl/bin
mkdir -p %{buildroot}/%{_prefix}/local/ssl/include
mkdir -p %{buildroot}/%{_prefix}/local/lib
mkdir -p %{buildroot}/%{_prefix}/lib
cp -rf %{_builddir}/openssl_install/lib64/libcrypto.so.3 %{buildroot}/%{_prefix}/local/ssl/lib64
cp -rf %{_builddir}/openssl_install/lib64/libssl.so.3 %{buildroot}/%{_prefix}/local/ssl/lib64
cp -rf %{_builddir}/openssl_install/bin %{buildroot}/%{_prefix}/local/ssl/
cp -rf %{_builddir}/openssl_install/include %{buildroot}/%{_prefix}/local/ssl/
cd %{buildroot}/%{_prefix}/local/ssl/lib64
ln -sf libcrypto.so.3 libcrypto.so
ln -sf libssl.so.3 libssl.so

cd %{_builddir}/%{qatdriver}
unset ICP_ROOT
unset ICP_BUILD_OUTPUT
./configure
%make_build

%if !0%{?suse_version}
cd %{_builddir}/%{ippcpfull}/sources/ippcp/crypto_mb
cmake . -B"build" -DOPENSSL_INCLUDE_DIR=%{openssl_install}/include -DOPENSSL_LIBRARIES=%{openssl_install} -DOPENSSL_ROOT_DIR=%{openssl_source}
cd build
%make_build

install -d %{buildroot}/%{_includedir}/crypto_mb
cp -rf   %{_builddir}/%{ippcpfull}/sources/ippcp/crypto_mb/include/crypto_mb/*.h /%{buildroot}/%{_includedir}/crypto_mb/
install -d %{buildroot}/%{_libdir}
cp %{_builddir}/%{ippcpfull}/sources/ippcp/crypto_mb/build/bin/libcrypto_mb.so.%{ippcpfullversion} %{buildroot}/%{_libdir}
cd %{buildroot}/%{_libdir}

ln -sf libcrypto_mb.so.%{ippcpfullversion} libcrypto_mb.so.%{ippcp_major}
ln -sf libcrypto_mb.so.%{ippcpfullversion} libcrypto_mb.so

cp -rf %{buildroot}/%{_libdir}/libcrypto_mb.so.%{ippcpfullversion} %{buildroot}/%{_prefix}/local/lib
cp -rf %{buildroot}/%{_libdir}/libcrypto_mb.so.%{ippcp_major} %{buildroot}/%{_prefix}/local/lib
cp -rf %{buildroot}/%{_libdir} libcrypto_mb.so %{buildroot}/%{_prefix}/local/lib

cd %{_builddir}/%{ipsecfull}
cd lib
%make_build

install -d  %{buildroot}/%{_includedir}
install -m 0644  %{_builddir}/%{ipsecfull}/lib/intel-ipsec-mb.h %{buildroot}/%{_includedir}
cp  %{buildroot}/%{_includedir}/intel-ipsec-mb.h /usr/include/
install -s -m 0755  %{_builddir}/%{ipsecfull}/lib/libIPSec_MB.so.%{fullversion}  %{buildroot}/%{_libdir}
cp -rf %{_builddir}/%{ipsecfull}/lib/libIPSec_MB.so.%{fullversion} %{buildroot}/%{_prefix}/lib
cp -rf %{_builddir}/%{ipsecfull}/lib/libIPSec_MB.so %{buildroot}/%{_prefix}/lib
cp -rf %{_builddir}/%{ipsecfull}/lib/libIPSec_MB.so.%{major} %{buildroot}/%{_prefix}/lib

cd %{buildroot}/%{_libdir}
ln -sf libIPSec_MB.so.%{fullversion} libIPSec_MB.so.%{major}
ln -sf libIPSec_MB.so.%{fullversion} libIPSec_MB.so
%endif

cd %{_builddir}/%{name}-%{version}
autoreconf -ivf

%if !0%{?suse_version}
# Enable QAT_HW & QAT_SW Co-existence acceleration
./configure --with-openssl_install_dir=%{openssl_install} --with-qat_hw_dir=%{_builddir}/%{qatdriver} --enable-qat_sw
%else
# Enable QAT_HW acceleration for SUSE
./configure --with-openssl_install_dir=%{openssl_install} --with-qat_hw_dir=%{_builddir}/%{qatdriver}
%endif
%make_build

install -d %{buildroot}/%{_prefix}/local/ssl/lib64/engines-3
cp -rf %{_builddir}/%{name}-%{version}/.libs/qatengine.so %{buildroot}/%{_prefix}/local/ssl/lib64/engines-3

install -d %{buildroot}/%{_libdir}/build
cp -rf %{_builddir}/%{name}-%{version}/qat_hw_config/4xxx/multi_process/4xxx_dev0.conf %{buildroot}/%{_libdir}/build
cp -rf %{_builddir}/%{qatdriver}/build/libusdm_drv_s.so %{buildroot}/%{_libdir}
cp -rf %{_builddir}/%{qatdriver}/build/libqat_s.so %{buildroot}/%{_libdir}
cp -rf %{_builddir}/%{qatdriver}/build %{buildroot}/%{_libdir}
cp %{_builddir}/%{name}-%{version}/fips/driver_install.sh %{buildroot}/%{_libdir}

%post
   echo "RPM is getting installed"
if (lspci | grep Co- >/dev/null )
then
   ./%{_libdir}/driver_install.sh
fi

%clean
rm -rf %{buildroot}

%files
%exclude %{_prefix}/local/lib/lib64
%{_prefix}/local/ssl/lib64/engines-3/qatengine.so
%{_prefix}/local/ssl/lib64
%{_prefix}/local/ssl/bin
%{_prefix}/local/ssl/include
%{_libdir}/libqat_s.so
%{_libdir}/libusdm_drv_s.so
%{_libdir}/build
%{_libdir}/driver_install.sh
%license LICENSE*
%doc README.md docs*

%if !0%{?suse_version}
%{_libdir}/libcrypto_mb.so.%{ippcpfullversion}
%{_libdir}/libcrypto_mb.so.%{ippcp_major}
%{_libdir}/libcrypto_mb.so

%{_libdir}/libIPSec_MB.so.%{fullversion}
%{_libdir}/libIPSec_MB.so.%{major}
%{_libdir}/libIPSec_MB.so

%{_prefix}/lib/libIPSec_MB.so.%{fullversion}
%{_prefix}/lib/libIPSec_MB.so.%{major}
%{_prefix}/lib/libIPSec_MB.so

%{_prefix}/local/lib/libcrypto_mb.so.%{ippcpfullversion}
%{_prefix}/local/lib/libcrypto_mb.so.%{ippcp_major}
%{_prefix}/local/lib/libcrypto_mb.so

%{_includedir}/crypto_mb
%{_includedir}/intel-ipsec-mb.h
%endif
