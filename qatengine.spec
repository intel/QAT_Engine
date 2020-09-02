#======================================================================
#
#
#    BSD LICENSE
#
#    Copyright(c) 2020 Intel Corporation.
#    All rights reserved.
#
#    Redistribution and use in source and binary forms, with or without
#    modification, are permitted provided that the following conditions
#    are met:
#
#      * Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#      * Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in
#        the documentation and/or other materials provided with the
#        distribution.
#      * Neither the name of Intel Corporation nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
#    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#    OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#    LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#======================================================================

%global githubname QAT_Engine
%global soversion 0
%global enginesdir %(pkg-config --variable=enginesdir libcrypto)

Name:           qatengine
Version:        0.6.1
Release:        1%{?dist}
Summary:        Intel(R) QuickAssist Technology (QAT) OpenSSL* Engine
License:        BSD
URL:            https://github.com/intel/%{githubname}
Source0:        https://github.com/intel/%{githubname}/archive/v%{version}.tar.gz

BuildRequires:  gcc make pkg-config
BuildRequires:  openssl >= 1.1.1 openssl-devel >= 1.1.1
BuildRequires:  qatlib >= 20.08.0 qatlib-devel >= 20.08.0

%description
This package contains OpenSSL Engine providing cryptographic
hardware acceleration using Intel(R) QuickAssist Technology
which provides optimized implementations of cryptography on Intel(R) platforms.
For additional information please refer to:
https://github.com/intel/%{githubname}

%prep
%autosetup -n %{githubname}-%{version}

./autogen.sh

%build
%configure

%make_build

%install
mkdir -p %{buildroot}%{_libdir}
mkdir -p %{buildroot}%{enginesdir}

install -p -m 0755 .libs/libqatengine.so.0.0.0 %{buildroot}%{_libdir}/libqatengine.so.%{soversion}.%{version}
ln -s -f libqatengine.so.%{soversion}.%{version} %{buildroot}%{_libdir}/libqatengine.so.%{soversion}
ln -s -f ../libqatengine.so.%{soversion}.%{version} %{buildroot}%{enginesdir}/qatengine.so

%ldconfig_scriptlets

%files
%license LICENSE
%doc README.md
%{_libdir}/libqatengine.so.%{soversion}.%{version}
%{_libdir}/libqatengine.so.0
%{enginesdir}/qatengine.so

%changelog
* Tue Sep 08 2020 Dinesh Balakrishnan <dineshx.balakrishnan@intel.com> 0.6.1-1
- Initial version of rpm package
