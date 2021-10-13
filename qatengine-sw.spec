# SPDX-License-Identifier: MIT

%global githubname QAT_Engine
%global enginesdir %(pkg-config --variable=enginesdir libcrypto)

Name:           qatengine-sw
Version:        0.6.9
Release:        1%{?dist}
Summary:        Intel QuickAssist Technology (QAT) OpenSSL Engine
# Most of the source code is BSD, with the following exceptions:
#  - e_qat.txt, e_qat_err.c, and e_qat_err.h are OpenSSL
#  - qat/config/* are (BSD or GPLv2), but are not used during compilation
#  - qat_contig_mem/* are GPLv2, but are not used during compilation
License:        BSD and OpenSSL
URL:            https://github.com/intel/%{githubname}
Source0:        https://github.com/intel/%{githubname}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  gcc make pkg-config
BuildRequires:  autoconf automake libtool
BuildRequires:  openssl-devel >= 1.1.1
BuildRequires:  intel-ipsec-mb-devel >= 0.55.0
BuildRequires:  intel-ipp-crypto-mb-devel >= 1.0.1
# https://bugzilla.redhat.com/show_bug.cgi?id=1909065
ExcludeArch:    %{arm} aarch64 %{power64} s390x i686

%description
This package provides the Intel QuickAssist Technology OpenSSL Engine
(an OpenSSL Plug-In Engine) which provides cryptographic acceleration
for optimized software using Intel QuickAssist Technology
enabled Intel platforms.

%prep
%autosetup -n %{githubname}-%{version}

%build
autoreconf -ivf

%configure --enable-qat_sw

%make_build

%install
%make_install

%files
%license LICENSE*
%doc README.md docs*
%{enginesdir}/qatengine.so
%exclude %{enginesdir}/qatengine.la

%changelog
* Mon Oct 18 2021 Yogaraj Alamenda <yogarajx.alamenda@intel.com> - 0.6.9-1
- Update to qatengine v0.6.9

* Mon Aug 23 2021 Bernard Iremonger <bernard.iremonger@intel.com> 0.6.8-1
- Initial version of rpm package
