#==========================================================================
#                                                                         \
#                                                                         \
#   BSD LICENSE                                                           \
#                                                                         \
#    opyright(c) 2024 Intel Corporation.                                  \
#   All rights reserved.                                                  \
#                                                                         \
#   Redistribution and use in source and binary forms, with or without    \
#   modification, are permitted provided that the following conditions    \
#   are met:                                                              \
#                                                                         \
#     * Redistributions of source code must retain the above copyright    \
#       notice, this list of conditions and the following disclaimer.     \
#     * Redistributions in binary form must reproduce the above copyright \
#       notice, this list of conditions and the following disclaimer in   \
#       the documentation and/or other materials provided with the        \
#       distribution.                                                     \
#     * Neither the name of Intel Corporation nor the names of its        \
#       contributors may be used to endorse or promote products derived   \
#       from this software without specific prior written permission.     \
#                                                                         \
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS   \
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT     \
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR \
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT  \
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, \
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT      \
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, \
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY \
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT   \
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE \
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.  \
#                                                                         \
#                                                                         \
#==========================================================================

ARG UBUNTU_BASE=ubuntu:22.04
FROM ${UBUNTU_BASE} AS builder

ARG OPENSSL_VERSION="openssl-3.0.14"
ARG QATLIB_VERSION="24.02.0"
ARG QAT_ENGINE_VERSION="v1.6.1"
ARG IPSEC_MB_VERSION="v1.5"
ARG IPP_CRYPTO_VERSION="ippcp_2021.12.1"
ARG GID
ENV DEBIAN_FRONTEND=noninteractive

# Install required packages including curl, telnet, and git
RUN apt-get update && \
    apt-get install -y apt-utils --no-install-recommends

# Upgrade all other packages
RUN apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    libudev-dev \
    make \
    gcc \
    g++ \
    nasm \
    pkg-config \
    libssl-dev \
    zlib1g-dev \
    git \
    nasm \
    autoconf \
    automake \
    cmake \
    ca-certificates \
    libtool && \
    git clone --depth 1 -b $OPENSSL_VERSION https://github.com/openssl/openssl.git && \
    git clone --depth 1 -b $QAT_ENGINE_VERSION https://github.com/intel/QAT_Engine && \
    git clone --depth 1 -b $IPP_CRYPTO_VERSION https://github.com/intel/ipp-crypto && \
    git clone --depth 1 -b $IPSEC_MB_VERSION https://github.com/intel/intel-ipsec-mb && \
    git clone --depth 1 -b $QATLIB_VERSION https://github.com/intel/qatlib

# Create a non-root user and group
RUN groupadd -r appuser && useradd -r -g appuser -s /bin/bash appuser

# Building OpenSSL
WORKDIR /openssl
RUN ./config && \
    make -j && \
    make install -j

# Building QATLIB
WORKDIR /qatlib
RUN ./autogen.sh && \
    ./configure --enable-systemd=no && \
    make -j && \
    make install samples-install && \
    groupadd qat -g ${GID}  && \
    usermod -a -G qat appuser

# Building Cypto_MB
WORKDIR /ipp-crypto/sources/ippcp/crypto_mb
RUN cmake . -B"../build" \
    -DOPENSSL_INCLUDE_DIR=/usr/local/include \
    -DOPENSSL_LIBRARIES=/usr/local/lib64 \
    -DOPENSSL_ROOT_DIR=/openssl

WORKDIR /ipp-crypto/sources/ippcp/build
RUN make crypto_mb -j && make install -j

# Building Ipsec_MB
WORKDIR /intel-ipsec-mb
RUN make -j && make install LIB_INSTALL_DIR=/usr/local/lib

# Building QAT Engine
WORKDIR /QAT_Engine
RUN ./autogen.sh && \
    ./configure \
    --with-openssl_install_dir=/usr/local/ \
    --with-qat-hw-dir=/usr/local/ \
    --enable-qat_sw && \
    make -j && make install -j

#Added to remobe libc library for vulnerability issue
RUN apt-get purge -y linux-libc-dev

FROM ${UBUNTU_BASE}

COPY --from=builder /usr/local/lib/libqat.so.4.2.0 /usr/lib/
COPY --from=builder /usr/local/lib/libusdm.so.0.1.0 /usr/lib/
COPY --from=builder /usr/local/lib/libIPSec_MB.so.1.5.0  /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/local/lib64/libcrypto.so.3 /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/local/lib/libcrypto_mb.so.11.15 /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/local/bin/openssl /usr/bin/
COPY --from=builder /usr/local/lib64/engines-3/qatengine.so /usr/lib/x86_64-linux-gnu/engines-3/
COPY --from=builder /etc/group /etc/group
COPY --from=builder /etc/passwd /etc/passwd
RUN ldconfig

#Expose the 8080 port
EXPOSE 8080

# Switch to non-root user
USER appuser

ENV OPENSSL_ENGINES="/usr/lib/x86_64-linux-gnu/engines-3/"
ENV LD_LIBRARY_PATH="/usr/lib/x86_64-linux-gnu/"
ENV QAT_POLICY=1

