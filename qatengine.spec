# SPDX-License-Identifier: MIT

# Define the directory where the OpenSSL engines are installed
%global enginesdir %(pkg-config --variable=enginesdir libcrypto)

Name:           qatengine
Version:        1.0.0
Release:        2%{?dist}
Summary:        Intel QuickAssist Technology (QAT) OpenSSL Engine

# Most of the source code is BSD, with the following exceptions:
#  - e_qat.txt, e_qat_err.c, and e_qat_err.h are OpenSSL
#  - qat/config/* are (BSD or GPLv2), but are not used during compilation
#  - qat_contig_mem/* are GPLv2, but are not used during compilation
License:        BSD-3-Clause AND OpenSSL
URL:            https://github.com/intel/QAT_Engine
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz

# https://bugzilla.redhat.com/show_bug.cgi?id=1909065
ExclusiveArch:  x86_64

BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  gcc
BuildRequires:  libtool
BuildRequires:  openssl-devel >= 1.1.1
BuildRequires:  qatlib-devel >= 23.02.0
%if !0%{?rhel}
BuildRequires:  intel-ipp-crypto-mb-devel >= 1.0.6
BuildRequires:  intel-ipsec-mb-devel >= 1.3.0
BuildRequires:  openssl
%endif

%description
This package provides the Intel QuickAssist Technology OpenSSL Engine
(an OpenSSL Plug-In Engine) which provides cryptographic acceleration
for both hardware and optimized software using Intel QuickAssist Technology
enabled Intel platforms.

%prep
%autosetup -n QAT_Engine-%{version}

%build
autoreconf -ivf
%if !0%{?rhel}
# Enable QAT_HW & QAT_SW Co-existence acceleration
%configure --enable-qat_sw
%else
# QAT_HW only acceleration for RHEL
%configure
%endif
%make_build

%install
%make_install

%if 0%{?rhel}
find %{buildroot} -name "*.la" -delete
%endif

%if !0%{?rhel}
%check
export OPENSSL_ENGINES=%{buildroot}%{enginesdir}
openssl engine -v %{name}
%endif

%files
%license LICENSE*
%doc README.md docs*
%{enginesdir}/%{name}.so

%changelog
* Thu Apr 13 2023 Ali Erdinc Koroglu <aekoroglu@linux.intel.com> - 1.0.0-2
- Enable QAT_HW & QAT SW Co-ex Acceleration for non RHEL distros

* Wed Mar 22 2023 Yogaraj Alamenda <yogarajx.alamenda@intel.com> - 1.0.0-1
- Update to qatengine v1.0.0

* Thu Feb 09 2023 Yogaraj Alamenda <yogarajx.alamenda@intel.com> - 0.6.19-1
- Update to qatengine v0.6.19

* Fri Jan 20 2023 Fedora Release Engineering <releng@fedoraproject.org> - 0.6.18-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_38_Mass_Rebuild

* Thu Dec 08 2022 Yogaraj Alamenda <yogarajx.alamenda@intel.com> - 0.6.18-1
- Update to qatengine v0.6.18

* Wed Nov 02 2022 Yogaraj Alamenda <yogarajx.alamenda@intel.com> - 0.6.17-1
- Update to qatengine v0.6.17

* Mon Oct 03 2022 Yogaraj Alamenda <yogarajx.alamenda@intel.com> - 0.6.16-1
- Update to qatengine v0.6.16

* Wed Aug 24 2022 Yogaraj Alamenda <yogarajx.alamenda@intel.com> - 0.6.15-1
- Update to qatengine v0.6.15

* Sat Jul 30 2022 Vladis Dronov <vdronov@redhat.com> - 0.6.14-2
- Rebuild due to qatlib so-version bump

* Wed Jul 20 2022 Yogaraj Alamenda <yogarajx.alamenda@intel.com> - 0.6.14-1
- Update to qatengine v0.6.14

* Wed Jun 22 2022 Yogaraj Alamenda <yogarajx.alamenda@intel.com> - 0.6.13-1
- Update to qatengine v0.6.13

* Fri Apr 01 2022 Yogaraj Alamenda <yogarajx.alamenda@intel.com> - 0.6.12-1
- Update to qatengine v0.6.12

* Thu Jan 27 2022 Yogaraj Alamenda <yogarajx.alamenda@intel.com> - 0.6.11-1
- Update to qatengine v0.6.11

* Fri Jan 21 2022 Fedora Release Engineering <releng@fedoraproject.org> - 0.6.10-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_36_Mass_Rebuild

* Thu Oct 28 2021 Yogaraj Alamenda <yogarajx.alamenda@intel.com> - 0.6.10-1
- Update to qatengine v0.6.10

* Mon Oct 18 2021 Yogaraj Alamenda <yogarajx.alamenda@intel.com> - 0.6.9-1
- Update to qatengine v0.6.9

* Fri Sep 10 2021 Yogaraj Alamenda <yogarajx.alamenda@intel.com> - 0.6.8-1
- Update to qatengine v0.6.8

* Thu Sep 09 2021 Yogaraj Alamenda <yogarajx.alamenda@intel.com> - 0.6.7-2
- Rebuilt for qatlib v21.08

* Fri Jul 30 2021 Yogaraj Alamenda <yogarajx.alamenda@intel.com> - 0.6.7-1
- Update to qatengine v0.6.7

* Fri Jul 23 2021 Fedora Release Engineering <releng@fedoraproject.org> - 0.6.6-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_35_Mass_Rebuild

* Thu May 20 2021 Yogaraj Alamenda <yogarajx.alamenda@intel.com> - 0.6.6-1
- Update to qatengine v0.6.6

* Thu Mar 18 2021 Yogaraj Alamenda <yogarajx.alamenda@intel.com> - 0.6.5-1
- Update to qatengine v0.6.5
- Update doc with additional docs

* Wed Jan 27 2021 Fedora Release Engineering <releng@fedoraproject.org> - 0.6.4-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_34_Mass_Rebuild

* Fri Dec 11 2020 Yogaraj Alamenda <yogarajx.alamenda@intel.com> 0.6.4-1
- Update to qatengine v0.6.4

* Mon Nov 30 2020 Yogaraj Alamenda <yogarajx.alamenda@intel.com> 0.6.3-1
- Update to qatengine v0.6.3
- Update License and library installation

* Wed Nov 18 2020 Dinesh Balakrishnan <dineshx.balakrishnan@intel.com> 0.6.2-1
- Update to qatengine v0.6.2
- Address review comments

* Tue Sep 08 2020 Dinesh Balakrishnan <dineshx.balakrishnan@intel.com> 0.6.1-1
- Initial version of rpm package
