#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([qatengine], [1.6.2], [])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_SILENT_RULES([yes])

#Libtool for generating shared library
LT_INIT
AC_PROG_LN_S
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

# Parameter parsing for enable/disable algo
AC_ARG_ENABLE(qat_hw_rsa,
              AS_HELP_STRING([--disable-qat_hw_rsa],
                             [Disable qat_hw RSA acceleration]))
AC_SUBST(enable_qat_hw_rsa)

AC_ARG_ENABLE(qat_hw_ecdh,
              AS_HELP_STRING([--disable-qat_hw_ecdh],
                             [Disable qat_hw ECDH acceleration]))
AC_SUBST(enable_qat_hw_ecdh)

AC_ARG_ENABLE(qat_hw_ecdsa,
              AS_HELP_STRING([--disable-qat_hw_ecdsa],
                             [Disable qat_hw ECDSA acceleration]))
AC_SUBST(enable_qat_hw_ecdsa)

AC_ARG_ENABLE(qat_hw_dsa,
              AS_HELP_STRING([--disable-qat_hw_dsa],
                             [Disable qat_hw DSA acceleration]))
AC_SUBST(enable_qat_hw_dsa)

AC_ARG_ENABLE(qat_hw_dh,
              AS_HELP_STRING([--disable-qat_hw_dh],
                             [Disable qat_hw DH acceleration]))
AC_SUBST(enable_qat_hw_dh)

AC_ARG_ENABLE(qat_hw_prf,
              AS_HELP_STRING([--disable-qat_hw_prf],
                             [Disable qat_hw PRF acceleration]))
AC_SUBST(enable_qat_hw_prf)

AC_ARG_ENABLE(qat_hw_hkdf,
              AS_HELP_STRING([--enable-qat_hw_hkdf],
                             [Enable qat_hw HKDF acceleration]))
AC_SUBST(enable_qat_hw_hkdf)

AC_ARG_ENABLE(qat_hw_ecx,
              AS_HELP_STRING([--disable-qat_hw_ecx],
                             [Disable qat_hw X25519/X448 acceleration]))
AC_SUBST(enable_qat_hw_ecx)

AC_ARG_ENABLE(qat_hw_ciphers,
              AS_HELP_STRING([--disable-qat_hw_ciphers],
                             [Disable qat_hw CIPHERS acceleration]))
AC_SUBST(enable_qat_hw_ciphers)

AC_ARG_ENABLE(qat_hw_gcm,
              AS_HELP_STRING([--enable-qat_hw_gcm],
                             [Enable qat_hw AES-GCM acceleration (experimental)]))
AC_SUBST(enable_qat_hw_gcm)

AC_ARG_ENABLE(qat_hw_sha3,
              AS_HELP_STRING([--enable-qat_hw_sha3],
                             [Enable qat_hw SHA3 offload]))
AC_SUBST(enable_qat_hw_sha3)

AC_ARG_ENABLE(qat_hw_chachapoly,
              AS_HELP_STRING([--enable-qat_hw_chachapoly],
                             [Enable qat_hw CHACHA-POLY acceleration]))
AC_SUBST(enable_qat_hw_chachapoly)

AC_ARG_ENABLE(qat_hw_sm4_cbc,
              AS_HELP_STRING([--enable-qat_hw_sm4_cbc],
                             [Enable qat_hw SM4-CBC acceleration]))
AC_SUBST(enable_qat_hw_sm4_cbc)

AC_ARG_ENABLE(qat_hw_sm2,
              AS_HELP_STRING([--enable-qat_hw_sm2],
                             [Enable qat_hw SM2 acceleration]))
AC_SUBST(enable_qat_hw_sm2)

AC_ARG_ENABLE(qat_hw_sm3,
              AS_HELP_STRING([--enable-qat_hw_sm3],
                             [Enable qat_hw SM3 acceleration]))
AC_SUBST(enable_qat_hw_sm3)

AC_ARG_ENABLE(qat_hw_ccm,
              AS_HELP_STRING([--disable-qat_hw_ccm],
                             [Disable qat_hw AES-CCM acceleration]))
AC_SUBST(enable_qat_hw_ccm)

AC_ARG_ENABLE(qat_sw_gcm,
              AS_HELP_STRING([--disable-qat_sw_gcm],
                             [Disable qat_sw AES-GCM acceleration]))
AC_SUBST(enable_qat_sw_gcm)

AC_ARG_ENABLE(qat_sw_sha2,
              AS_HELP_STRING([--disable-qat_sw_sha2],
                             [Disable qat_sw SHA2 acceleration]))

AC_SUBST(enable_qat_sw_sha2)

AC_ARG_ENABLE(qat_sw_rsa,
              AS_HELP_STRING([--disable-qat_sw_rsa],
                             [Disable qat_sw RSA acceleration]))
AC_SUBST(enable_qat_sw_rsa)

AC_ARG_ENABLE(qat_sw_ecx,
              AS_HELP_STRING([--disable-qat_sw_ecx],
                             [Disable qat_sw X25519 acceleration]))
AC_SUBST(enable_qat_sw_ecx)

AC_ARG_ENABLE(qat_sw_ecdsa,
              AS_HELP_STRING([--disable-qat_sw_ecdsa],
                             [Disable qat_sw ECDSA acceleration]))
AC_SUBST(enable_qat_sw_ecdsa)

AC_ARG_ENABLE(qat_sw_ecdh,
              AS_HELP_STRING([--disable-qat_sw_ecdh],
                             [Disable qat_sw ECDH acceleration]))
AC_SUBST(enable_qat_sw_ecdh)

AC_ARG_ENABLE(qat_sw_sm2,
              AS_HELP_STRING([--disable-qat_sw_sm2],
                             [Disable qat_sw SM2 acceleration]))
AC_SUBST(enable_qat_sw_sm2)

AC_ARG_ENABLE(qat_sw_sm3,
              AS_HELP_STRING([--enable-qat_sw_sm3],
                             [Enable qat_sw SM3 acceleration]))
AC_SUBST(enable_qat_sw_sm3)

AC_ARG_ENABLE(qat_sw_sm4_gcm,
              AS_HELP_STRING([--enable-qat_sw_sm4_gcm],
                             [Enable qat_sw SM4 GCM acceleration]))
AC_SUBST(enable_qat_sw_sm4_gcm)

AC_ARG_ENABLE(qat_sw_sm4_ccm,
              AS_HELP_STRING([--enable-qat_sw_sm4_ccm],
                             [Enable qat_sw SM4 CCM acceleration]))
AC_SUBST(enable_qat_sw_sm4_ccm)

AC_ARG_ENABLE(qat_sw_sm4_cbc,
              AS_HELP_STRING([--enable-qat_sw_sm4_cbc],
                             [Enable qat_sw SM4-CBC acceleration]))
AC_SUBST(enable_qat_sw_sm4_cbc)

AC_ARG_ENABLE(qat_small_pkt_offload,
              AS_HELP_STRING([--enable-qat_small_pkt_offload],
                             [Enable small packet CIPHER acceleration]))
AC_SUBST(enable_qat_small_pkt_offload)

AC_ARG_ENABLE(qat_hw,
              AS_HELP_STRING([--disable-qat_hw],
                             [Disable Intel(R) QAT Hardware acceleration]))
AC_SUBST(enable_qat_hw)

AC_ARG_ENABLE(qat_sw,
              AS_HELP_STRING([--enable-qat_sw],
                             [Enable qat_sw acceleration using Intel(R) Crypto Multi-buffer library]))
AC_SUBST(enable_qat_sw)

AC_ARG_ENABLE(qat_provider,
              AS_HELP_STRING([--enable-qat_provider],
                             [Enable Provider Support for Openssl 3.0]))
AC_SUBST(enable_qat_provider)

# Parameter parsing for self tuning of the timeout in the qat_sw polling thread
AC_ARG_ENABLE(qat_sw_heuristic_timeout,
              AS_HELP_STRING([--enable-qat_sw_heuristic_timeout],
                             [Enable self tuning of the timeout in the qat_sw polling thread]))
AC_SUBST(enable_qat_sw_heuristic_timeout)

AC_ARG_ENABLE(qat_cycle_counts,
              AS_HELP_STRING([--enable-qat_cycle_counts],
                             [Enable CPU Cycle Counts]))
AC_SUBST(enable_qat_cycle_counts)

# Parameter parsing for enable debug/warnings
AC_ARG_ENABLE(qat_debug,
              AS_HELP_STRING([--enable-qat_debug],
                             [Enable Engine Debug Messages]))
AC_SUBST(enable_qat_debug)

AC_ARG_ENABLE(qat_warnings,
              AS_HELP_STRING([--enable-qat_warnings],
                             [Enable Engine Warning Messages]))
AC_SUBST(enable_qat_warnings)

AC_ARG_ENABLE(qat_mem_debug,
              AS_HELP_STRING([--enable-qat_mem_debug],
                             [Enable Memory Driver Debug Messages]))
AC_SUBST(enable_qat_mem_debug)

AC_ARG_ENABLE(qat_mem_warnings,
              AS_HELP_STRING([--enable-qat_mem_warnings],
                             [Enable Memory Driver Warning Messages]))
AC_SUBST(enable_qat_mem_warnings)

# Mandatory QAT driver source path if building against QAT_HW Version 1.7 driver source package
AC_ARG_WITH(qat_hw_dir,
              AS_HELP_STRING([--with-qat_hw_dir],
                             [Path to the Intel Quickassist Technology Driver source code]),
	     [qat_hw_dir_prefix="$withval"],
	     [qat_hw_dir_prefix="/usr"])
AC_SUBST(with_qat_hw_dir)

# Other non mandatory parameters
AC_ARG_WITH(openssl_install_dir,
              AS_HELP_STRING([--with-openssl_install_dir],
                             [Path to where the OpenSSL libraries are installed to. The Engine will be installed to the lib/engines subdirectory of this path. If you are using BoringSSL, please use the source code dir, because BoringSSL cannot be installed.]))
AC_SUBST(with_openssl_install_dir)

AC_ARG_WITH(openssl_dir,
              AS_HELP_STRING([--with-openssl_dir],
                             [Path to the OpenSSL source code. The error files will get regenerated using the mkerr.pl script included with the OpenSSL source]))
AC_SUBST(with_openssl_dir)

AC_ARG_WITH(qat_hw_install_dir,
              AS_HELP_STRING([--with-qat_hw_install_dir],
                             [Path to the Intel Quickassist Technology Driver build output]))
AC_SUBST(with_qat_hw_install_dir)

AC_ARG_WITH(qat_sw_crypto_mb_install_dir,
              AS_HELP_STRING([--with-qat_sw_crypto_mb_install_dir],
                             [Path to the Multi-buffer based Intel(R) Crypto Multi-buffer library install location]))
AC_SUBST(with_qat_sw_crypto_mb_install_dir)

AC_ARG_WITH(qat_sw_ipsec_mb_install_dir,
              AS_HELP_STRING([--with-qat_sw_ipsec_mb_install_dir],
                             [Path to the Intel(R) Multi-Buffer Crypto for IPsec library install location]))
AC_SUBST(with_qat_sw_ipsec_mb_install_dir)

AC_ARG_ENABLE(qat_hw_contig_mem,
              AS_HELP_STRING([--enable-qat_hw_contig_mem],
                             [This should be specified to force the Engine to use the qat_contig_mem component supplied within the QAT Engine release package]))
AC_SUBST(enable_qat_hw_contig_mem)

AC_ARG_WITH(qat_hw_usdm_dir,
              AS_HELP_STRING([--with-qat_hw_usdm_dir],
                             [Path to the USDM Component source code. This should be used to specify a path to the USDM Component source other than the standard default path within the QAT1.7 Intel Quickassist Technology Driver source code]))
AC_SUBST(with_qat_hw_usdm_dir)

AC_ARG_WITH(qat_debug_file,
              AS_HELP_STRING([--with-qat_debug_file],
                             [Path and filename to log debug output to. Combine with other flags that enable the debug and warning output]))
AC_SUBST(with_qat_debug_file)

AC_ARG_WITH(qat_engine_id,
              AS_HELP_STRING([--with-qat_engine_id],
                             [This should be specified to force the Engine to use engine id other than default "qatengine"]))
AC_SUBST(with_qat_engine_id)

AC_ARG_WITH(cc_opt,
              AS_HELP_STRING([--with-cc_opt],
                             [Sets additional parameters that will be added to the CFLAGS]))
AC_SUBST(with_cc_opt)

AC_ARG_WITH(ld_opt,
              AS_HELP_STRING([--with-ld_opt],
                             [Sets additional parameters that will be used during linking]))
AC_SUBST(with_ld_opt)

AC_ARG_ENABLE(qat_hw_multi_thread,
            AS_HELP_STRING([--enable-qat_hw_multi_thread],
                           [Enable using a multi threaded version of the user space part of the supplied memory driver. Please see the documentation on limitations of using this option]))
AC_SUBST(enable_qat_hw_multi_thread)

AC_ARG_ENABLE(qat_hw_lenstra_protection,
              AS_HELP_STRING([--disable-qat_hw_lenstra_protection],
                             [Disable protection against Lenstra attack]))
AC_SUBST(enable_qat_hw_lenstra_protection)

AC_ARG_ENABLE(qat_hw_lenstra_verify_hw,
              AS_HELP_STRING([--enable-qat_hw_lenstra_verify_hw],
                             [Enable Lenstra Verify using QAT_HW instead of OpenSSL SW]))
AC_SUBST(enable_qat_hw_lenstra_verify_hw)

AC_ARG_ENABLE(qat_auto_engine_init_on_fork,
              AS_HELP_STRING([--disable-qat_auto_engine_init_on_fork],
                             [Disable auto initialization of the engine following a fork]))
AC_SUBST(enable_qat_auto_engine_init_on_fork)

AC_ARG_ENABLE(qat_plock,
              AS_HELP_STRING([--enable-qat_plock],
                             [Enable plock, an optimized read-write lock which replaces pthread read/write lock]))
AC_SUBST(enable_qat_plock)
AC_ARG_ENABLE(qat_fips,
              AS_HELP_STRING([--enable-qat_fips],
                             [Enables FIPS support]))
AC_SUBST(enable_qat_fips)

AC_ARG_ENABLE(qat_ntls,
              AS_HELP_STRING([--enable-qat_ntls],
                             [Enable ntls in engine for handing NTLS requests]))
AC_SUBST(enable_qat_ntls)

AC_ARG_ENABLE(qat_insecure_algorithms,
              AS_HELP_STRING([--enable-qat_insecure_algorithms],
                             [Enable insecure algorithms (DSA, DH, SHA1, SHA3-224, EC <256 & RSA<2048]))
AC_SUBST(enable_qat_insecure_algorithms)

AC_ARG_ENABLE(qat_hw_kpt,
              AS_HELP_STRING([--enable-qat_hw_kpt],
                             [Enable QAT HW Key Protection technology(KPT) support]))
AC_SUBST(enable_qat_hw_kpt)

#Default library name is qatengine
AC_SUBST([LIBQATNAME], "qatengine")

AC_CHECK_FILE(${qat_hw_dir_prefix}/include/qat/icp_sal_versions.h,
	      [with_icp_sal_versions_h=yes],
	      [with_icp_sal_versions_h=no])
if test "x$with_icp_sal_versions_h" = "xyes" -a "x$enable_qat_hw" != "xno"
then
  if grep "define SAL_INFO2_DRIVER_SW_VERSION_TYPE \"in-tree\"" ${qat_hw_dir_prefix}/include/qat/icp_sal_versions.h
  then
    AC_SUBST([cflags_qat_hw_intree], ["-DQAT_HW_INTREE"])
    AC_SUBST([with_qat_hw_dir], ["${qat_hw_dir_prefix}"])
    AC_MSG_NOTICE([QAT in-tree driver using QATlib in ${with_qat_hw_dir}])
  else
    AC_SUBST([cflags_qat_hw_intree], ["-DQAT_HW_FBSD_INTREE"])
    AC_SUBST([with_qat_hw_dir], ["${qat_hw_dir_prefix}"])
    AC_MSG_NOTICE([QAT in-tree driver using FBSD QATlib in ${with_qat_hw_dir}])
  fi
fi

AM_CONDITIONAL([QAT_HW_INTREE], [test "x$cflags_qat_hw_intree" != "x"])

# ERROR message if mandatory options are not provided
if test "x$cflags_qat_hw_intree" = "x"
then
  if test "x$with_qat_hw_dir" = "x" -a "x$enable_qat_sw" = "x"
  then
    AC_MSG_ERROR([qatlib library not installed or --with-qat_hw_dir or --enable-qat_sw not set, If you like to use QAT Hardware acceleration, set it to the path to the Intel Quickassist Technology Driver source code. e.g: --with-qat_hw_dir=/path/to/qat_driver or If you like to use QAT Software acceleration using Intel crypto multibuffer library and Intel IPSec (AES-GCM),  provide --enable-qat_sw after installing crypto_mb and IPSec_mb libraries as per README])
  fi
fi

#OpenSSL 3.0 uses lib location based on ARCH
AS_IF([test "$host_cpu" = "x86_64"], [AC_SUBST([openssl3_lib], "lib64")], [AC_SUBST([openssl3_lib], "lib")])

# OpenSSL/BabaSSL/BoringSSL install dir or set system default if not provided
if test "x$with_openssl_install_dir" != "x"
then
  #BoringSSL from Source
  if test -f $with_openssl_install_dir/include/openssl/base.h
  then
    if grep "define BORINGSSL_API_VERSION" $with_openssl_install_dir/include/openssl/base.h
    then
      AC_MSG_NOTICE([Build QAT Engine against BoringSSL])
      AC_SUBST([cflags_boringssl], ["-DQAT_BORINGSSL"])
      AC_CHECK_FILE(${with_openssl_install_dir}/lib/libcrypto.so,
                   [AC_SUBST([QAT_BORINGSSL_LIB], ["-Wl,-rpath,\$(with_openssl_install_dir)/lib -L\$(with_openssl_install_dir)/lib -ldecrepit -lcrypto -lssl"])],
                   [AC_MSG_ERROR([BoringSSL libraries not found in the path $(with_openssl_install_dir)/lib !])])
      AS_IF([test -d "$with_openssl_install_dir/crypto"], [AC_SUBST([cflags_boringssl], ["-DQAT_BORINGSSL -DBSSL_SOURCE"])])
      AC_SUBST([with_openssl_dir], [""]) #Err files are updated manually for BoringSSL
      AC_SUBST([LIBQATNAME], "libqatengine")
    fi
  else
    ac_default_prefix=$with_openssl_install_dir
    if grep "define OPENSSL_VERSION_NUMBER  0x1010"  $with_openssl_install_dir/include/openssl/opensslv.h
    then
      #OPENSSL 1.1.1
      AC_MSG_NOTICE([Build QAT engine against OpenSSL 1.1.1])
      libdir="\$(with_openssl_install_dir)/lib/engines-1.1"
      AC_SUBST([OPENSSL_LIB], ["-Wl,-rpath,\$(with_openssl_install_dir)/lib -L\$(with_openssl_install_dir)/lib -lcrypto"])
    else
      #OPENSSL 3.0
      if test "x$enable_qat_provider" = "xyes"
      then
        AC_MSG_NOTICE([Build QAT Provider against OpenSSL 3.0])
        libdir="\$(with_openssl_install_dir)/\$(openssl3_lib)/ossl-modules"
        AC_SUBST([cflags_openssl_3], ["-DQAT_OPENSSL_3 -DOPENSSL_SUPPRESS_DEPRECATED -DQAT_OPENSSL_PROVIDER"])
        AC_SUBST([OPENSSL_LIB], ["-Wl,-rpath,\$(with_openssl_install_dir)/\$(openssl3_lib) -L\$(with_openssl_install_dir)/\$(openssl3_lib) -lcrypto"])
        AC_SUBST([LIBQATNAME], "qatprovider")
      else
        AC_MSG_NOTICE([Build QAT Engine against OpenSSL 3.0])
        libdir="\$(with_openssl_install_dir)/\$(openssl3_lib)/engines-3"
        AC_SUBST([cflags_openssl_3], ["-DQAT_OPENSSL_3 -DOPENSSL_SUPPRESS_DEPRECATED"])
        AC_SUBST([OPENSSL_LIB], ["-Wl,-rpath,\$(with_openssl_install_dir)/\$(openssl3_lib) -L\$(with_openssl_install_dir)/\$(openssl3_lib) -lcrypto"])
      fi
    fi
  fi
  AC_SUBST([includes_openssl], ["-I\$(with_openssl_install_dir)/include"])
else
  # Default OPENSSL from the system
  AC_PATH_TOOL(PKGCONFIG, pkg-config)
  AS_IF([test "x$PKGCONFIG" = "x"], [AC_MSG_ERROR(pkg-config not found.)], )
  libdir="`pkg-config --variable=enginesdir libcrypto`"
  includes_openssl="`pkg-config --variable=includedir libcrypto`"
  if grep "define OPENSSL_VERSION_NUMBER  0x1010" $includes_openssl/openssl/opensslv.h
  then
      AC_MSG_NOTICE([Build QAT Engine against system OpenSSL 1.1.1])
  else
    if test "x$enable_qat_provider" = "xyes"
    then
      AC_MSG_NOTICE([Build QAT Provider against system OpenSSL 3.0])
      AC_SUBST([cflags_openssl_3], ["-DQAT_OPENSSL_3 -DOPENSSL_SUPPRESS_DEPRECATED -DQAT_OPENSSL_PROVIDER"])
      AC_SUBST([LIBQATNAME], "qatprovider")
      openssl3_lib="`pkg-config --variable=libdir libcrypto`"
      libdir="\$(openssl3_lib)/ossl-modules"
    else
      AC_MSG_NOTICE([Build QAT Engine against system OpenSSL 3.0])
      AC_SUBST([cflags_openssl_3], ["-DQAT_OPENSSL_3 -DOPENSSL_SUPPRESS_DEPRECATED"])
      libdir="`pkg-config --variable=enginesdir libcrypto`"
    fi
  fi
  AC_MSG_NOTICE([Install engine/provider in the system OpenSSL Path])
  AC_SUBST([includes_openssl], ["-I`pkg-config --variable=includedir libcrypto`"])
  AC_SUBST([OPENSSL_LIB], ["-lcrypto"])
  AC_SUBST([libdir])
fi
AM_CONDITIONAL([QAT_OPENSSL_3], [test "x$cflags_openssl_3" != "x"])
AM_CONDITIONAL([QAT_PROVIDER], [test "x$enable_qat_provider" = "xyes"])
AM_CONDITIONAL([QAT_BORINGSSL], [test "x$cflags_boringssl" != "x"])
AM_CONDITIONAL([ENABLE_QAT_HW_KPT], [test "x$enable_qat_hw_kpt" = "xyes"])

# qat_hw_dir configured, enable qat_hw
if test "x$with_qat_hw_dir" != "x"
then
  if test "x$enable_qat_hw" != "xno"
  then
    AC_SUBST([cflags_qat_hw], ["-DQAT_HW"])
    AC_CHECK_FILE(${with_qat_hw_dir}/quickassist/lookaside/access_layer/src/common/crypto/kpt/crypto/lac_kpt_crypto_qat_comms.c,
                  [cflags_qat_hw="${cflags_qat_hw} -DQAT20_OOT"], [])
    AC_MSG_NOTICE([QAT_HW acceleration enabled])
  else
    AC_MSG_NOTICE([QAT_HW acceleration disabled])
  fi
fi
AM_CONDITIONAL([QAT_HW], [test "x$cflags_qat_hw" != "x"])
case "$host_os" in
linux*)
    AS_IF([test `lspci -vnd 8086: | grep -c 4940` != "0"], [AC_SUBST([enable_qat20_oot], ["-DQAT20_OOT"])])
esac
AM_CONDITIONAL([QAT_4XXX], [test "x$enable_qat20_oot" != "x"])

# QAT_SW acceleration enabled
if test "x$enable_qat_sw" = "xyes"
then
#Crypto_mb install path provided
  if test "x$with_qat_sw_crypto_mb_install_dir" != "x"
  then
    AC_MSG_NOTICE([QAT_SW enabled for PKE with crypto_mb from user provided path])
    AC_SUBST([cflags_qat_sw], ["-DQAT_SW"])
    AC_SUBST([includes_qat_sw_crypto_mb], ["-I\${with_qat_sw_crypto_mb_install_dir}/include"])
    AC_CHECK_FILE(${with_qat_sw_crypto_mb_install_dir}/lib/libcrypto_mb.so,
                 [AC_SUBST([QAT_SW_CRYPTO_MB_LIB], ["-Wl,-rpath,${with_qat_sw_crypto_mb_install_dir}/lib -L\${with_qat_sw_crypto_mb_install_dir}/lib -lcrypto_mb"])],
                 [AC_MSG_ERROR([$with_qat_sw_crypto_mb_install_dir/lib/libcrypto_mb.so not found. Install it and try again.])])
  else
    AC_SUBST([cflags_qat_sw], ["-DQAT_SW"])
    AC_SUBST([includes_qat_sw_crypto_mb], ["-I/usr/local/include -I/usr/include"])
    AC_CHECK_FILE(/usr/local/lib/libcrypto_mb.so,
                 [AC_SUBST([QAT_SW_CRYPTO_MB_LIB], ["-Wl,-rpath,/usr/local/lib -L/usr/local/lib -lcrypto_mb"])],
                 [AC_SUBST([QAT_SW_CRYPTO_MB_LIB], ["-lcrypto_mb"])])
  fi

#IPSEC_MB install path provided
  if test "x$with_qat_sw_ipsec_mb_install_dir" != "x"
  then
    AC_MSG_NOTICE([QAT_SW for AES-GCM enabled with IPsec_mb library from the path provided])
    AC_SUBST([cflags_qat_sw_ipsec], ["-DQAT_SW_IPSEC"])
    AC_SUBST([includes_qat_sw_ipsec_mb], ["-I\${with_qat_sw_ipsec_mb_install_dir}/include"])
    AC_CHECK_FILE(${with_qat_sw_ipsec_mb_install_dir}/lib/libIPSec_MB.so,
                 [AC_SUBST([QAT_SW_IPSEC_MB_LIB], ["-Wl,-rpath,${with_qat_sw_ipsec_mb_install_dir}/lib -L\${with_qat_sw_ipsec_mb_install_dir}/lib -lIPSec_MB"])],
                 [AC_MSG_ERROR([$with_qat_sw_ipsec_mb_install_dir/lib/libIPSec_MB.so not found. Install it and try again.])])
  else
    AC_SUBST([cflags_qat_sw_ipsec], ["-DQAT_SW_IPSEC"])
    AC_SUBST([includes_qat_sw_ipsec_mb], ["-I/usr/include"])
    AC_SUBST([QAT_SW_IPSEC_MB_LIB], ["-lIPSec_MB"])
  fi
fi
AM_CONDITIONAL([QAT_SW], [test "x$cflags_qat_sw" != "x"])
AM_CONDITIONAL([QAT_SW_IPSEC], [test "x$cflags_qat_sw_ipsec" != "x"])

# OpenSSL source dir to regenerate err files if any changes in err messages
if test "x$with_openssl_dir" = "x"
then
  if test "x$cflags_boringssl" != "x"
  then
    AC_MSG_NOTICE([Build with existing error files for BoringSSL])
  else
    AC_MSG_NOTICE([Build with existing error files without regenerating from OpenSSL source])
  fi
fi
AM_CONDITIONAL([QAT_ERR_FILES_BUILD], [test "x$with_openssl_dir" != "x"])

# Disable unsupported algorithms with BoringSSl enabled
if test "x$cflags_boringssl" != "x"
then
  if test "x$cflags_qat_hw" != "x"
  then
    AC_SUBST([enable_qat_hw_ciphers], ["no"])
    AC_SUBST([enable_qat_hw_sm4_cbc], ["no"])
    AC_SUBST([enable_qat_hw_ecdh], ["no"])
    AC_SUBST([enable_qat_hw_dsa], ["no"])
    AC_SUBST([enable_qat_hw_dh], ["no"])
    AC_SUBST([enable_qat_hw_prf], ["no"])
    AC_SUBST([enable_qat_hw_hkdf], ["no"])
    AC_SUBST([enable_qat_hw_ecx], ["no"])
    AC_SUBST([enable_qat_hw_gcm], ["no"])
    AC_SUBST([enable_qat_hw_sm2], ["no"])
    AC_SUBST([enable_qat_hw_ccm], ["no"])
  fi
  if test "x$cflags_qat_sw" != "x"
  then
    AC_SUBST([enable_qat_sw_ciphers], ["no"])
    AC_SUBST([enable_qat_sw_ecdh], ["no"])
    AC_SUBST([enable_qat_sw_ecx], ["no"])
    AC_SUBST([enable_qat_sw_gcm], ["no"])
    AC_SUBST([enable_qat_sw_sm2], ["no"])
    AC_SUBST([enable_qat_sw_sm4_cbc], ["no"])
    AC_SUBST([enable_qat_sw_heuristic_timeout], ["no"])
    AC_SUBST([enable_qat_sw_sha2], ["no"])
  fi
fi

if test "x$enable_qat_hw_kpt" = "xyes" -a "x$cflags_qat_hw" != "x"
then
  AC_SUBST([includes_kpt_lib], ["-Ikpt/lib"])
fi

# Compiler security flags
AC_SUBST([cflags_common], ["-Wall -Wformat -Wformat-security -D_FORTIFY_SOURCE=2 -fno-delete-null-pointer-checks -fwrapv -fstack-protector-strong"])

# Disable insecure algorithms by default
if test "x$enable_qat_insecure_algorithms" = "xyes"
then
  AC_MSG_NOTICE([Insecure Algorithms enabled])
  cflags_common="${cflags_common} -DQAT_INSECURE_ALGO"
else
  AC_MSG_NOTICE([Insecure Algorithms disabled])
  AC_SUBST([enable_qat_hw_dsa], ["no"])
  AC_SUBST([enable_qat_hw_dh], ["no"])
fi
AM_CONDITIONAL([QAT_INSECURE_ALGO], [test "enable_qat_insecure_algorithms" = "xyes"])

# Enable QAT_HW Algorithms based on enable/disable Flags
if test "x$cflags_qat_hw" != "x"
then
  AS_IF([test "x$enable_qat_hw_rsa" != "xno"],
        [cflags_qat_hw="${cflags_qat_hw} -DENABLE_QAT_HW_RSA"; AC_MSG_NOTICE([Accelerating RSA to Hardware])])
  AS_IF([test "x$enable_qat_hw_ecdsa" != "xno"],
        [cflags_qat_hw="${cflags_qat_hw} -DENABLE_QAT_HW_ECDSA"; AC_MSG_NOTICE([Accelerating ECDSA to Hardware])])
  AS_IF([test "x$enable_qat_hw_ecdh" != "xno"],
        [cflags_qat_hw="${cflags_qat_hw} -DENABLE_QAT_HW_ECDH"; AC_MSG_NOTICE([Accelerating ECDH to Hardware])])
  AS_IF([test "x$enable_qat_hw_ecx" != "xno"],
        [cflags_qat_hw="${cflags_qat_hw} -DENABLE_QAT_HW_ECX"; AC_MSG_NOTICE([Accelerating X25519/X448 to Hardware])])
  AS_IF([test "x$enable_qat_hw_dsa" != "xno"],
        [cflags_qat_hw="${cflags_qat_hw} -DENABLE_QAT_HW_DSA"; AC_MSG_NOTICE([Accelerating DSA to Hardware])])
  AS_IF([test "x$enable_qat_hw_dh" != "xno"],
        [cflags_qat_hw="${cflags_qat_hw} -DENABLE_QAT_HW_DH"; AC_MSG_NOTICE([Accelerating DH to Hardware])])
  AS_IF([test "x$enable_qat_hw_prf" != "xno"],
        [cflags_qat_hw="${cflags_qat_hw} -DENABLE_QAT_HW_PRF"; AC_MSG_NOTICE([Accelerating PRF to Hardware])])
  AS_IF([test "x$enable_qat_hw_hkdf" = "xyes"],
        [cflags_qat_hw="${cflags_qat_hw} -DENABLE_QAT_HW_HKDF"; AC_MSG_NOTICE([Accelerating HKDF to Hardware])])
  AS_IF([test "x$enable_qat_hw_sha3" = "xyes"], 
        [cflags_qat_hw="${cflags_qat_hw} -DENABLE_QAT_HW_SHA3"; AC_MSG_NOTICE([Accelerating SHA3 to Hardware])])
  AS_IF([test "x$enable_qat_hw_sm3" = "xyes"],
        [cflags_qat_hw="${cflags_qat_hw} -DENABLE_QAT_HW_SM3"; AC_MSG_NOTICE([Accelerating SM3 to Hardware])])
  AS_IF([test "x$enable_qat_hw_ciphers" != "xno"],
        [cflags_qat_hw="${cflags_qat_hw} -DENABLE_QAT_HW_CIPHERS"; AC_MSG_NOTICE([Accelerating CIPHERS to Hardware])])
  AS_IF([test "x$enable_qat_hw_gcm" = "xyes"],
        [cflags_qat_hw="${cflags_qat_hw} -DENABLE_QAT_HW_GCM"; AC_MSG_NOTICE([Accelerating GCM to Hardware (experimental)])])
  AS_IF([test "x$enable_qat_hw_chachapoly" = "xyes"],
        [cflags_qat_hw="${cflags_qat_hw} -DENABLE_QAT_HW_CHACHAPOLY"; AC_MSG_NOTICE([Accelerating CHACHA-POLY to Hardware])])
  AS_IF([test "x$enable_qat_hw_sm4_cbc" = "xyes"], 
        [cflags_qat_hw="${cflags_qat_hw} -DENABLE_QAT_HW_SM4_CBC"; AC_MSG_NOTICE([Accelerating SM4-CBC to Hardware])])
  AS_IF([test "x$enable_qat_hw_sm2" = "xyes"],
        [cflags_qat_hw="${cflags_qat_hw} -DENABLE_QAT_HW_SM2"; AC_MSG_NOTICE([Accelerating SM2 to Hardware])])
  AS_IF([test "x$enable_qat_hw_ccm" != "xno"],
        [cflags_qat_hw="${cflags_qat_hw} -DENABLE_QAT_HW_CCM"; AC_MSG_NOTICE([Accelerating AES-CCM to Hardware])])
  AS_IF([test "x$enable_qat_hw_kpt" = "xyes"],
        [cflags_qat_hw="${cflags_qat_hw} -DENABLE_QAT_HW_KPT"; AC_MSG_NOTICE([QAT_HW KPT Support enabled])])
fi

# Enable QAT_SW Algorithms based on enable/disable Flags
if test "x$cflags_qat_sw" != "x"
then
  AS_IF([test "x$enable_qat_sw_rsa" != "xno"],
        [cflags_qat_sw="${cflags_qat_sw} -DENABLE_QAT_SW_RSA"; AC_MSG_NOTICE([Accelerating RSA to Software (Multi-buffer)])])
  AS_IF([test "x$enable_qat_sw_ecdsa" != "xno"],
        [cflags_qat_sw="${cflags_qat_sw} -DENABLE_QAT_SW_ECDSA"; AC_MSG_NOTICE([Accelerating ECDSA to Software (Multi-buffer)])])
  AS_IF([test "x$enable_qat_sw_ecdh" != "xno"],
        [cflags_qat_sw="${cflags_qat_sw} -DENABLE_QAT_SW_ECDH"; AC_MSG_NOTICE([Accelerating ECDH to Software (Multi-buffer)])])
  AS_IF([test "x$enable_qat_sw_ecx" != "xno"],
        [cflags_qat_sw="${cflags_qat_sw} -DENABLE_QAT_SW_ECX"; AC_MSG_NOTICE([Accelerating X25519/X448 to Software (Multi-buffer)])])
  AS_IF([test "x$enable_qat_sw_sm2" != "xno"], 
        [cflags_qat_sw="${cflags_qat_sw} -DENABLE_QAT_SW_SM2"; AC_MSG_NOTICE([Accelerating SM2 to Software (Multi-buffer)])])
  AS_IF([test "x$enable_qat_sw_sm3" = "xyes"],
        [cflags_qat_sw="${cflags_qat_sw} -DENABLE_QAT_SW_SM3"; AC_MSG_NOTICE([Accelerating SM3 to Software (Multi-buffer)])])
  AS_IF([test "x$enable_qat_sw_sm4_cbc" = "xyes"], 
        [cflags_qat_sw="${cflags_qat_sw} -DENABLE_QAT_SW_SM4_CBC"; AC_MSG_NOTICE([Accelerating SM4-CBC to Software (Multi-buffer)])])
  AS_IF([test "x$enable_qat_sw_sm4_gcm" = "xyes"], 
        [cflags_qat_sw="${cflags_qat_sw} -DENABLE_QAT_SW_SM4_GCM"; AC_MSG_NOTICE([Accelerating SM4-GCM to Software (Multi-buffer)])])
  AS_IF([test "x$enable_qat_sw_sm4_ccm" = "xyes"], 
        [cflags_qat_sw="${cflags_qat_sw} -DENABLE_QAT_SW_SM4_CCM"; AC_MSG_NOTICE([Accelerating SM4-CCM to Software (Multi-buffer)])])
fi

if test "x$cflags_qat_sw_ipsec" != "x"
then
  AS_IF([test "x$enable_qat_sw_gcm" != "xno"],
        [cflags_qat_sw_ipsec+=" -DENABLE_QAT_SW_GCM"; AC_MSG_NOTICE([Accelerating GCM to Software (IPSec_mb)])])
  AS_IF([test "x$enable_qat_sw_sha2" != "xno"],
        [cflags_qat_sw_ipsec+=" -DENABLE_QAT_SW_SHA2"; AC_MSG_NOTICE([Accelerating SHA2 to Software (IPSec_mb)])])
fi    

if test "x$cflags_qat_hw" != "x" -a  "x$cflags_qat_sw" != "x"
then
    AC_MSG_NOTICE([QAT_HW & QAT_SW Co-existence])

    if test "x$enable_qat_hw_sm3" != "x" -a "x$enable_qat_sw_sm3" != "x"
    then
      AC_MSG_ERROR(Co-existence not supported by SM3)
    fi
fi

if test "x$cflags_qat_hw" != "x"
then
    AC_CHECK_FILE(${with_openssl_install_dir}/include/openssl/ossl_typ.h,
              [with_kdf_support_h=yes],
              [with_kdf_support_h=no])
    if test "x$with_kdf_support_h" = "xyes"
    then
        if grep "struct evp_kdf_ctx_st EVP_KDF_CTX" $with_openssl_install_dir/include/openssl/ossl_typ.h
        then
          AC_SUBST([cflags_qat_hw], ["${cflags_qat_hw} -DQAT_KDF_SUPPORT"])
          AC_MSG_NOTICE([KDF structure support available])
        fi
    fi
fi
#System OpenSSL
if test "x$with_openssl_install_dir" = "x"
then
  AC_CHECK_LIB([crypto],[EVP_sm3],[with_sm3_support_h=yes],[with_sm3_support_h=no])
  if test "x$with_sm3_support_h" = "xno"
  then
    AC_SUBST([cflags_qat_hw], ["${cflags_qat_hw} -DOPENSSL_NO_SM2_SM3"])
    AC_MSG_NOTICE([SM3 support not available in system OpenSSL])
  fi
fi

#Enable additional QAT_HW & QAT_SW flags
AS_IF([test "x$enable_qat_debug" = "xyes"], 
      [cflags_common="${cflags_common} -DQAT_DEBUG"; AC_MSG_NOTICE([Debug messages enabled])])

AS_IF([test "x$enable_qat_warnings" = "xyes"],
      [cflags_common="${cflags_common} -DQAT_WARN"; AC_MSG_NOTICE([Warning messages enabled])])

AS_IF([test "x$enable_qat_mem_debug" = "xyes"], 
      [cflags_common="${cflags_common} -DQAT_MEM_DEBUG"; AC_MSG_NOTICE([Memory driver debug messages enabled])])

AS_IF([test "x$enable_qat_mem_warnings" = "xyes"],
      [cflags_common="${cflags_common} -DQAT_MEM_WARN"; AC_MSG_NOTICE([Memory driver warning messages enabled])])

AS_IF([test "x$enable_qat_cycle_counts" = "xyes"],
      [cflags_common="${cflags_common} -DQAT_CPU_CYCLES_COUNT"; AC_MSG_NOTICE([CPU Cycle Counts enabled])])

AS_IF([test "x$enable_qat_auto_engine_init_on_fork" = "xno"],
      [cflags_common="${cflags_common} -DDISABLE_QAT_AUTO_ENGINE_INIT_ON_FORK" ; AC_MSG_NOTICE([Auto engine init on fork disabled])])

AS_IF([test "x$enable_qat_small_pkt_offload" = "xyes"],
      [cflags_common="${cflags_common} -DENABLE_QAT_SMALL_PKT_OFFLOAD"; AC_MSG_NOTICE([Accelerating symmetric small packets enabled])])

AS_IF([test "x$enable_qat_plock" = "xyes"],
      [cflags_common="${cflags_common} -DQAT_PLOCK"; AC_MSG_NOTICE([plock enabled])])
AM_CONDITIONAL([QAT_PLOCK], [test "x$enable_qat_plock" != "x"])

AS_IF([test "x$enable_qat_fips" = "xyes"],
      [cflags_common="${cflags_common} -DENABLE_QAT_FIPS"; AC_MSG_NOTICE([FIPS Support enabled])])
AM_CONDITIONAL([QAT_FIPS], [test "x$enable_qat_fips" != "x"])

AS_IF([test "x$enable_qat_sw_heuristic_timeout" = "xyes" -a "x$cflags_qat_sw" != "x"],
      [cflags_common="${cflags_common} -DQAT_SW_HEURISTIC_TIMEOUT"; AC_MSG_NOTICE([QAT_SW Heuristic Timeout enabled])])

AS_IF([test "x$with_qat_engine_id" != "x"],
      [cflags_common="${cflags_common} -DQAT_ENGINE_ID=\$(with_qat_engine_id)"; AC_MSG_NOTICE([Using engine id other than default])])

AS_IF([test "x$enable_qat_ntls" = "xyes"],
      [cflags_common="${cflags_common} -DQAT_NTLS";  AC_MSG_NOTICE([Enabling NTLS for Engine])])

# Enable Additional QAT_HW Flags
if test "x$cflags_qat_hw" != "x"
then
  AS_IF([test "x$enable_qat_hw_lenstra_protection" = "xno"],
        [cflags_common="${cflags_common} -DDISABLE_QAT_HW_LENSTRA_PROTECTION"; AC_MSG_NOTICE([Lenstra attack protection disabled])])
  AS_IF([test "x$enable_qat_hw_lenstra_verify_hw" = "xyes" -a "x$enable_qat_hw_lenstra_protection" != "xno"],
        [cflags_common="${cflags_common} -DENABLE_QAT_HW_LENSTRA_VERIFY_HW"; AC_MSG_NOTICE([Lenstra check via QAT_HW enabled])])
  AS_IF([test "x$enable_qat_hw_set_inst_thread" = "xyes"],
        [cflags_common="${cflags_common} -DQAT_HW_SET_INSTANCE_THREAD"; AC_MSG_NOTICE([QAT_HW set instance for thread enabled])])
fi

# Additional cflags if any to be passed
if test "x$with_cc_opt" != "x"
then
  AC_SUBST([cflags_cc_opt], ["\$(with_cc_opt)"])
fi

# Additional LD_flags if any to be passed
if test "x$with_ld_opt" != "x"
then
  AC_SUBST([QAT_LD_LIB], ["\$(with_ld_opt)"])
fi

# Write logs to a debug file
if test "x$with_qat_debug_file" != "x"
then
  AC_SUBST([cflags_qat_debug], ["-DQAT_DEBUG_FILE_PATH=\$(with_qat_debug_file)"])
  AC_MSG_NOTICE([Debugs to file enabled])
fi

#QAT_HW Memory Driver
if test "x$cflags_qat_hw" != "x"
then
  if test "x$enable_qat_hw_contig_mem" = "xyes" -a "x$enable_qat_hw_multi_thread" != "xyes"
  then
    AC_SUBST([cflags_mem_driver], ["-DUSE_QAT_CONTIG_MEM -Iqat_contig_mem"])
    AC_MSG_NOTICE([qat_contig_mem enabled])
  else if test "x$enable_qat_hw_multi_thread" = "xyes"
  then
    AC_SUBST([cflags_mem_driver], ["-DUSE_QAT_CONTIG_MEM -Iqat_contig_mem"])
    AC_MSG_NOTICE([qat_contig_mem (multi-thread) enabled])
  else
    AC_SUBST([cflags_mem_driver], ["-DUSE_USDM_MEM"])
    AC_MSG_NOTICE([USDM enabled])
  fi
  fi
fi
AM_CONDITIONAL([QAT_HW_CONTIG_MEM], [test "x$enable_qat_hw_contig_mem" = "xyes" -a "x$enable_qat_hw_multi_thread" != "xyes"])
AM_CONDITIONAL([QAT_HW_MULTI_THREAD], [test "x$enable_qat_hw_multi_thread" = "xyes"])
AM_CONDITIONAL([QAT_HW_USDM], [test "x$enable_qat_hw_contig_mem" != "xyes" -a "x$enable_qat_hw_multi_thread" != "xyes"])

#glibc detection for AVX512 memcpy optimization (not related to QAT_SW AVX512)
case "$host_os" in
linux*)
  AC_CHECK_PROG(USE_LDD, ldd, yes, no)
  AC_CHECK_PROG(USE_HEAD, head, yes, no)
  if test $USE_LDD == "yes" -a $USE_HEAD
  then
    if test "`ldd --version | head -1 | awk '{print ($4>=2.23)?"1":"0"}' 2>/dev/null`" = "1"
    then
      AC_MSG_NOTICE([glibc version >= 2.23. glibc AVX-512 memcpy optimisation supported.])
    else
      AC_MSG_NOTICE([glibc version < 2.23. glibc AVX-512 memcpy optimisation not supported.])
    fi
    if test "`ldd --version | head -1 | awk '{print ($4<2.17)?"1":"0"}' 2>/dev/null`" = "1"
    then
      AC_ARG_WITH(LIBS, AS_HELP_STRING(), , LIBS+="-lrt")
      AC_SUBST(LIBS)
    fi
  else
    AC_MSG_NOTICE([glibc version could not be auto detected. Check manually using 'ldd --version'])
    AC_MSG_NOTICE([glibc AVX-512 memcpy optimisation supported only from glibc version 2.23])
    AC_ARG_WITH(LIBS, AS_HELP_STRING(), , LIBS+="-lrt")
    AC_SUBST(LIBS)
  fi
  ;;
  *)
esac

# Driver headers include path
if test "x$cflags_qat_hw" != "x"
then
  if test "x$cflags_qat_hw_intree" != "x"
  then
    AC_SUBST([includes_qat_hw], ["-I\${with_qat_hw_dir}/include/qat"])
  else
    AC_SUBST([with_ICP_API_DIR], ["\$(with_qat_hw_dir)/quickassist/include"])
    AC_SUBST([with_ICP_SAL_API_DIR], ["\$(with_qat_hw_dir)/quickassist/lookaside/access_layer/include"])
    AC_SUBST([with_ICP_LAC_API_DIR], ["\$(with_ICP_API_DIR)/lac"])
    AC_SUBST([with_ICP_DC_DIR], ["\$(with_qat_hw_dir)/quickassist/include/dc"])
    AC_SUBST([includes_qat_hw], ["-I\$(with_ICP_API_DIR) -I\$(with_ICP_LAC_API_DIR) -I\$(with_ICP_SAL_API_DIR) -I\$(with_ICP_DC_DIR)"])
  fi
fi

# qatlib Intree uses different library name
if test "x$cflags_qat_hw_intree" != "x"
then
  case "$host_os" in
  freebsd*)
      AC_SUBST([DRIVER], ["qat_s"])
      AC_SUBST([USDM], ["usdm_drv_s"])
      ;;
  *)
      AC_SUBST([DRIVER], ["qat"])
      AC_SUBST([USDM], ["usdm"])
      ;;
  esac
else
  AC_SUBST([DRIVER], ["qat_s"])
  AC_SUBST([USDM], ["usdm_drv_s"])
fi

if test "x$cflags_qat_hw" != "x"
then
  if test "x$cflags_qat_hw_intree" != "x"
  then
    AC_SUBST([QAT_HW_DRIVER_LIB], ["-L\$(with_qat_hw_dir)/lib -l\$(DRIVER)"])
  else
    if test "x$with_qat_hw_install_dir" = "x"
    then
      with_qat_hw_install_dir="\$(with_qat_hw_dir)/build"
    fi
    AC_SUBST([QAT_HW_DRIVER_LIB], ["-Wl,-rpath,\$(with_qat_hw_install_dir) -L\$(with_qat_hw_install_dir) -l\$(DRIVER)"])
  fi
fi

if test "x$cflags_qat_hw" != "x"
then
  if test "x$enable_qat_hw_contig_mem" != "xyes" -a "x$enable_qat_hw_multi_thread" != "xyes"
  then
    if test "x$cflags_qat_hw_intree" != "x"
    then
      AC_SUBST([QAT_HW_MEM_LIB], ["-l\$(USDM)"])
    else
      if test "x$with_qat_hw_usdm_dir" = "x"
      then
       with_qat_hw_usdm_dir="\$(with_qat_hw_dir)/quickassist/utilities/libusdm_drv"
      fi
      AC_SUBST([QAT_HW_MEM_LIB], ["-Wl,-rpath,\$(with_qat_hw_usdm_dir) -L\$(with_qat_hw_usdm_dir) -l\$(USDM)"])
      AC_SUBST([includes_qat_hw_usdm], ["-I\$(with_qat_hw_usdm_dir)"])
    fi
  fi
fi

echo "==============================================================================="
echo "Enabled Algorithms and Additional Flags"
echo "==============================================================================="
echo "QAT_HW ALGORITHMS :" [$cflags_qat_hw]
echo "QAT_SW ALGORITHMS :" [$cflags_qat_sw]
echo "ADDITIONAL FLAGS  :" [$cflags_common $cflags_openssl_3 $cflags_boringssl]
if test "x$cflags_qat_hw" != "x"
then
  if test "x$cflags_qat_hw_intree" = "x"
  then
  AC_CHECK_FILE(${with_qat_hw_dir}/build/libqat_s.so, [],
                [echo "QAT_HW Driver library not found in $with_qat_hw_dir/build. Install it & try again or proceed with 'make depend' target to install dependencies"])
  fi
fi
if test "x$cflags_qat_sw" != "x"
then
  if test "x$with_qat_sw_crypto_mb_install_dir" = "x"
  then
    AC_CHECK_LIB(crypto_mb, mbx_getversion)
    AC_CHECK_FILE(/usr/local/lib/libcrypto_mb.so)
    if test "x$ac_cv_file__usr_local_lib_libcrypto_mb_so" != "xyes" -a "x$ac_cv_lib_crypto_mb_mbx_getversion" != "xyes"
    then
      echo "libcrypto_mb.so not found in /usr/local/lib or in system default. Install it & try again or proceed with 'make depend' target to install dependencies"
      # Setting it for make depend target
      AC_SUBST([QAT_SW_CRYPTO_MB_LIB], ["-Wl,-rpath,/usr/local/lib -L/usr/local/lib -lcrypto_mb"])
    fi
  fi
  if test "x$with_qat_sw_ipsec_mb_install_dir" = "x"
  then
    AC_CHECK_LIB(IPSec_MB, imb_get_version, [], [echo "libIPsec_MB.so not found in default path. Install it & try again or proceed with 'make depend' target to install dependencies"])
  fi
fi
echo "==============================================================================="

# Output files from the configure
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
