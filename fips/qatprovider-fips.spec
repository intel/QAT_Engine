%undefine __cmake_in_source_build
%global _lto_cflags %{nil}
%global debug_package %{nil}
# Versions numbers
%global major        1
%global minor        3
%global rev          0
%global ipsec        intel-ipsec-mb
%global ipsecver     %{major}.%{minor}
%global ipsecfull    %{ipsec}-%{ipsecver}
%global fullversion  %{major}.%{minor}.%{rev}


%global ippcp_major       11
%global ippcp_minor        6
%global ippcp		   ipp-crypto
%global ippcpver	   ippcp_2021.7.1
%global ippcpfull    	   %{ippcp}-%{ippcpver}
%global ippcpfullversion   %{ippcp_major}.%{ippcp_minor}

%global qatengine   QAT_Engine
%global qatdriver   QAT20.l.1.0.40-00004

%global openssl_lib_path        /root/openssl_install
%global openssl_src_path        /root/openssl

Name:		qatprovider-fips
Version:    1.2.0
Release:    1%{?dist}
Summary:    Intel QuickAssist Technology (QAT) OpenSSL Provider

License: 	BSD-3-Clause AND OpenSSL
Source0:	https://github.com/intel/%{qatengine}/archive/v%{version}/%{name}-%{version}.tar.gz 
Source1:	https://github.com/intel/%{ippcp}/archive/refs/tags/%{ippcpver}.tar.gz#/%{ippcp}-%{ippcpver}.tar.gz
Source2:	https://github.com/intel/%{ipsec}/archive/v%{ipsecver}.tar.gz#/%{ipsecfull}.tar.gz
Source3:	https://downloadmirror.intel.com/777529/QAT20.L.1.0.20-00008.tar.gz
Source4:	driver_install.tar.gz

BuildRequires:      cmake >= 3.10
BuildRequires:      gcc-c++ >= 8.2
BuildRequires:      make
BuildRequires:      nasm >= 2.14

%description
This package provides the Intel QuickAssist Technology OpenSSL Provider
(an OpenSSL Plug-In Provider) which provides cryptographic acceleration
for both hardware and optimized software using Intel QuickAssist Technology
enabled Intel platforms.

%prep
%setup -b 1
%setup -b 2
%setup -b 3
%setup -b 4

%build
cd %{_builddir}/%{qatdriver}
unset ICP_ROOT
unset ICP_BUILD_OUTPUT
%configure
make clean
%make_build
make install
rm -rf /QAT/*
cp -rf quickassist /QAT/
cp -rf build /QAT/
cp -rf /QAT/build/intel_qat.ko %{openssl_lib_path}/lib64/ossl-modules/
cp -rf /QAT/build/usdm_drv.ko %{openssl_lib_path}/lib64/ossl-modules/
cp -rf /QAT/build/qat_4xxx.ko %{openssl_lib_path}/lib64/ossl-modules/
cp -rf /QAT/build/qat_4xxx.bin %{openssl_lib_path}/lib64/ossl-modules/
cp -rf /QAT/build/qat_4xxx_mmp.bin %{openssl_lib_path}/lib64/ossl-modules/
cp -rf /QAT/build/libusdm_drv_s.so %{openssl_lib_path}/lib64/ossl-modules/
cp -rf /QAT/build/libqat_s.so %{openssl_lib_path}/lib64/ossl-modules/
cp -rf %{openssl_lib_path}/4xxx_dev0.conf /etc/
cp -rf %{openssl_lib_path}/4xxx_dev1.conf /etc/
adf_ctl restart

cd %{_builddir}/%{ippcpfull}/sources/ippcp/crypto_mb
cmake . -B"build" -DOPENSSL_INCLUDE_DIR=%{openssl_src_path}/include -DOPENSSL_LIBRARIES=%{openssl_lib_path} -DOPENSSL_ROOT_DIR=%{openssl_src_path}
cd build
make clean
make -j
make install

install -d %{buildroot}/%{_includedir}/crypto_mb
cp -rf   %{_builddir}/%{ippcpfull}/sources/ippcp/crypto_mb/include/crypto_mb/*.h /%{buildroot}/%{_includedir}/crypto_mb/
install -d %{buildroot}/%{_libdir}
cp %{_builddir}/%{ippcpfull}/sources/ippcp/crypto_mb/build/bin/libcrypto_mb.so.%{ippcpfullversion} %{buildroot}/%{_libdir}
cd %{buildroot}/%{_libdir}
ln -s libcrypto_mb.so.%{ippcpfullversion} libcrypto_mb.so.%{ippcp_major}
ln -s libcrypto_mb.so.%{ippcpfullversion} libcrypto_mb.so

cd %{_builddir}/%{ipsecfull}
cd lib
make EXTRA_CFLAGS='%{optflags}' %{?_smp_mflags}

install -d  %{buildroot}/%{_includedir}
install -m 0644  %{_builddir}/%{ipsecfull}/lib/intel-ipsec-mb.h %{buildroot}/%{_includedir}
cp  %{buildroot}/%{_includedir}/intel-ipsec-mb.h /usr/include/
install -s -m 0755  %{_builddir}/%{ipsecfull}/lib/libIPSec_MB.so.%{fullversion}  %{buildroot}/%{_libdir}
cd %{buildroot}/%{_libdir}
ln -s libIPSec_MB.so.%{fullversion} libIPSec_MB.so.%{major}
ln -s libIPSec_MB.so.%{fullversion} libIPSec_MB.so


export OPENSSL_ENGINES="/root/openssl_install/lib64/ossl-modules"
export OPENSSL_ROOT="/root/openssl"
export SYS_OPENSSL_PATH="/root/openssl_install"
export LD_LIBRARY_PATH=/root/openssl_install/lib64
export OPENSSL_LIB=/root/openssl_install
export QAT_HW_ENABLED="1"
export QAT_SW_ENABLED="1"

cd /root/rpmbuild/BUILD/%{name}-%{version}
#git checkout dev_qat_fips_drop2_release

autoreconf -ivf

cp -rf %{buildroot}/%{_libdir}/libcrypto_mb.so.%{ippcpfullversion} %{openssl_lib_path}/lib64/ossl-modules/
cp -rf %{buildroot}/%{_libdir}/libcrypto_mb.so %{openssl_lib_path}/lib64/ossl-modules/
cp -rf %{buildroot}/%{_libdir}/libIPSec_MB.so.%{fullversion}  %{openssl_lib_path}/lib64/ossl-modules/
cp -rf %{buildroot}/%{_libdir}/libIPSec_MB.so  %{openssl_lib_path}/lib64/ossl-modules/
./configure --with-openssl_install_dir=%{openssl_lib_path} --with-qat_hw_dir=/QAT --enable-qat_provider --enable-qat_hw_hkdf --enable-qat_hw_gcm --enable-qat_hw_sha3 --enable-qat_fips --enable-qat_sw --enable-qat_small_pkt_offload --enable-qat_insecure_algorithms  

make clean
%make_build
%make_install
cp -rf %{buildroot}/%{openssl_lib_path}/lib64/ossl-modules/qatprovider.so  %{openssl_lib_path}/lib64/ossl-modules/
make intkat
mv %{openssl_lib_path}/lib64/ossl-modules/qatprovider.so %{buildroot}/%{openssl_lib_path}/lib64/ossl-modules/

install -d %{buildroot}/%{_libdir}
install -d %{buildroot}/%{_libdir}/build
cp %{_libdir}/libusdm_drv_s.so %{buildroot}/%{_libdir}
cp %{_libdir}/libqat_s.so %{buildroot}/%{_libdir}
cp -rf /QAT/build/qat_4xxx.bin %{buildroot}/%{_libdir}/build
cp -rf /QAT/build/qat_4xxx_mmp.bin %{buildroot}/%{_libdir}/build
cp -rf /QAT/build/intel_qat.ko %{buildroot}/%{_libdir}/build
cp -rf /QAT/build/usdm_drv.ko %{buildroot}/%{_libdir}/build
cp -rf /QAT/build/qat_4xxx.ko %{buildroot}/%{_libdir}/build
cp -rf /QAT/build/4xxx_dev0.conf %{buildroot}/%{_libdir}/build
cp -rf %{openssl_lib_path}/4xxx_dev0.conf %{buildroot}/%{_libdir}/build
cp -rf /QAT/build/adf_ctl %{buildroot}/%{_libdir}/build
cp -rf /QAT/build/qat_service %{buildroot}/%{_libdir}/build
cp  %{_builddir}/driver_install/driver_install.sh %{buildroot}/%{_libdir}
install -d  %{buildroot}/%{_libdir}/ossl-modules
cp  %{buildroot}/%{openssl_lib_path}/lib64/ossl-modules/qatprovider.so %{buildroot}/%{_libdir}/ossl-modules/
cp  %{buildroot}/%{openssl_lib_path}/lib64/ossl-modules/qatprovider.la %{buildroot}/%{_libdir}/ossl-modules/

%post
   echo "RPM is getting installed"
if (lspci | grep Co- >/dev/null )
then
   ./%{_libdir}/driver_install.sh
fi

%clean
rm -rf %{buildroot}

%files
%exclude %{openssl_lib_path}/lib64/ossl-modules/
%exclude /usr/lib
%defattr(-,root,root,-)
%dir %attr(0755,root,root) %{openssl_lib_path}/lib64/ossl-modules/
%dir %attr(0755,root,root) /usr
%{_libdir}/ossl-modules/qatprovider.so
%{_libdir}/ossl-modules/qatprovider.la
%{_libdir}/libusdm_drv_s.so
%{_libdir}/libqat_s.so
%{_libdir}/build
%{_libdir}/driver_install.sh
%exclude %dir %{openssl_lib_path}/lib64/ossl-modules/

%license LICENSE
%{_libdir}/libcrypto_mb.so.%{ippcpfullversion}
%{_libdir}/libcrypto_mb.so.%{ippcp_major}
%{_libdir}/libcrypto_mb.so

%{_libdir}/libIPSec_MB.so.%{fullversion}
%{_libdir}/libIPSec_MB.so.%{major}
%{_libdir}/libIPSec_MB.so

%dir /usr/include/crypto_mb
%{_includedir}/crypto_mb/cpu_features.h
%{_includedir}/crypto_mb/defs.h
%{_includedir}/crypto_mb/ec_nistp256.h
%{_includedir}/crypto_mb/ec_nistp384.h
%{_includedir}/crypto_mb/ec_nistp521.h
%{_includedir}/crypto_mb/ec_sm2.h
%{_includedir}/crypto_mb/ed25519.h
%{_includedir}/crypto_mb/exp.h
%{_includedir}/crypto_mb/rsa.h
%{_includedir}/crypto_mb/sm3.h
%{_includedir}/crypto_mb/sm4.h
%{_includedir}/crypto_mb/status.h
%{_includedir}/crypto_mb/version.h
%{_includedir}/crypto_mb/x25519.h
%{_includedir}/intel-ipsec-mb.h
%{_includedir}/crypto_mb/sm4_ccm.h
%{_includedir}/crypto_mb/sm4_gcm.h

%changelog
* Mon May 29 2023 Ponnam Srinivas <ponnamsx.srinivas@intel.com>
