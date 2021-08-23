#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([qatengine], [0.6.8], [])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE([foreign subdir-objects])

#Libtool for generating shared library
LT_INIT
AC_PROG_LN_S
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

# Parameter parsing for disabling the feature
AC_ARG_ENABLE(qat_hw_rsa,
              AS_HELP_STRING([--disable-qat_hw_rsa],
                             [Disable qat_hw RSA acceleration]))
AC_SUBST(enable_qat_hw_rsa)

AC_ARG_ENABLE(qat_hw_ciphers,
              AS_HELP_STRING([--disable-qat_hw_ciphers],
                             [Disable qat_hw CIPHERS acceleration]))
AC_SUBST(enable_qat_hw_ciphers)

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

AC_ARG_ENABLE(qat_hw_gcm,
              AS_HELP_STRING([--enable-qat_hw_gcm],
                             [Enable qat_hw AES-GCM acceleration (experimental)]))
AC_SUBST(enable_qat_hw_gcm)

AC_ARG_ENABLE(qat_sw_gcm,
              AS_HELP_STRING([--disable-qat_sw_gcm],
                             [Disable qat_sw AES-GCM acceleration]))
AC_SUBST(enable_qat_sw_gcm)

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

AC_ARG_ENABLE(qat_hw_small_pkt_offload,
              AS_HELP_STRING([--enable-qat_hw_small_pkt_offload],
                             [Enable small packet CIPHER acceleration]))
AC_SUBST(enable_qat_hw_small_pkt_offload)

AC_ARG_ENABLE(qat_hw,
              AS_HELP_STRING([--disable-qat_hw],
                             [Disable Intel(R) QAT Hardware acceleration]))
AC_SUBST(enable_qat_hw)

AC_ARG_ENABLE(qat_sw,
              AS_HELP_STRING([--enable-qat_sw],
                             [Enable qat_sw acceleration using Intel(R) Crypto Multi-buffer library]))
AC_SUBST(enable_qat_sw)

# Parameter parsing for self tuning of the timeout in the qat_sw polling thread
AC_ARG_ENABLE(qat_sw_heuristic_timeout,
              AS_HELP_STRING([--enable-qat_sw_heuristic_timeout],
                             [Enable self tuning of the timeout in the qat_sw polling thread]))
AC_SUBST(enable_qat_sw_heuristic_timeout)

AC_ARG_ENABLE(qat_cycle_counts,
              AS_HELP_STRING([--enable-qat_cycle_counts],
                             [Enable CPU Cycle Counts]))
AC_SUBST(enable_qat_cycle_counts)

# Parameter parsing for enabling debug/warnings
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

# Mandatory QAT driver source path if building against QAT HW Version 1.7 driver source package
AC_ARG_WITH(qat_hw_dir,
              AS_HELP_STRING([--with-qat_hw_dir],
                             [Path to the Intel Quickassist Technology Driver source code]),
	     [qat_hw_dir_prefix="$withval"],
	     [qat_hw_dir_prefix="/usr"])
AC_SUBST(with_qat_hw_dir)

# Other non mandatory parameters
AC_ARG_WITH(openssl_install_dir,
              AS_HELP_STRING([--with-openssl_install_dir],
                             [Path to where the OpenSSL libraries are installed to. The Engine will be installed to the lib/engines subdirectory of this path]))
AC_SUBST(with_openssl_install_dir)

AC_ARG_WITH(openssl_dir,
              AS_HELP_STRING([--with-openssl_dir],
                             [Path to the OpenSSL source code. The error files will get regenerated using the mkerr.pl script included with the OpenSSL source]))
AC_SUBST(with_openssl_dir)

AC_ARG_WITH(qat_hw_install_dir,
              AS_HELP_STRING([--with-qat_hw_install_dir],
                             [Path to the Intel Quickassist Technology Driver build output]))
AC_SUBST(with_qat_hw_install_dir)

AC_ARG_WITH(qat_sw_install_dir,
              AS_HELP_STRING([--with-qat_sw_install_dir],
                             [Path to the Multi-buffer based Intel(R) Crypto Multi-buffer library and Intel(R) IPSec library build output]))
AC_SUBST(with_qat_sw_install_dir)

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
                             [Enable Lenstra Verify using QAT HW instead of OpenSSL SW]))
AC_SUBST(enable_qat_hw_lenstra_verify_hw)

AC_ARG_ENABLE(qat_auto_engine_init_on_fork,
              AS_HELP_STRING([--disable-qat_auto_engine_init_on_fork],
                             [Disable auto initialization of the engine following a fork]))
AC_SUBST(enable_qat_auto_engine_init_on_fork)

AC_CHECK_FILE(${qat_hw_dir_prefix}/include/qat/icp_sal_versions.h,
	      [with_icp_sal_versions_h=yes],
	      [with_icp_sal_versions_h=no])
if test "x$with_icp_sal_versions_h" = "xyes" -a "x$enable_qat_sw" = "x"
then
  if test `grep "define SAL_INFO2_DRIVER_SW_VERSION_TYPE \"in-tree\"" ${qat_hw_dir_prefix}/include/qat/icp_sal_versions.h | wc -l` = "1"
  then
    AC_SUBST([cflags_qat_hw_intree], ["-DQAT_HW_INTREE -DQAT_HW_DISABLE_NONZERO_MEMFREE"])
    AC_SUBST([with_qat_hw_dir], ["${qat_hw_dir_prefix}"])
    AC_MSG_NOTICE([QAT intree driver using QATlib in ${with_qat_hw_dir}])
  fi
fi

# ERROR message if mandatory options are not provided
if test "x$cflags_qat_hw_intree" = "x"
then
  if test "x$with_qat_hw_dir" = "x" -a "x$enable_qat_sw" = "x"
  then
    AC_MSG_ERROR([--with-qat_hw_dir or --enable-qat_sw not set, If you like to use QAT Hardware acceleration, set it to the path to the Intel Quickassist Technology Driver source code. e.g: --with-qat_hw_dir=/path/to/qat_driver or If you like to use QAT Software acceleration using Intel crypto multibuffer library and Intel IPSec (AES-GCM),  provide --enable-qat_sw after installing crypto_mb and IPSec_mb libraries as per README])
  fi
fi

# OpenSSL install dir or set system openssl install dir if not provided
if test "x$with_openssl_install_dir" != "x"
then
  ac_default_prefix=$with_openssl_install_dir
  if test "`grep "define OPENSSL_VERSION_MAJOR" $with_openssl_install_dir/include/openssl/opensslv.h | awk '{print $4}'`" = "3"
  then
    AC_MSG_NOTICE([Build QAT engine against OpenSSL 3.0])
    AC_SUBST([cflags_openssl_3], ["-DQAT_OPENSSL_3 -DOPENSSL_SUPPRESS_DEPRECATED"])
    libdir="\$(with_openssl_install_dir)/lib/engines-3"
    AC_SUBST([openssl_version], ["3"])
  else
    AC_MSG_NOTICE([Build QAT engine against OpenSSL 1.1.x])
    libdir="\$(with_openssl_install_dir)/lib/engines-1.1"
    if test "`grep "define OPENSSL_VERSION_NUMBER  0x101000" $with_openssl_install_dir/include/openssl/opensslv.h | wc -l`" = "1"
    then
      if test "x$with_openssl_dir" = "x"
      then
        AC_MSG_ERROR([OpenSSL version 1.1.0! Additional flag "--with-openssl_dir" pointing to the OpenSSL source dir needs to be configured for OpenSSL 1.1.0 to regenerate err files])
      fi
      AC_SUBST([cflags_openssl_110], ["-DQAT_OPENSSL_110"])
    fi
  fi
  AC_SUBST([includes_openssl], ["-I\$(with_openssl_install_dir)/include"])
  AC_SUBST([OPENSSL_LIB], ["-Wl,-rpath,\$(with_openssl_install_dir)/lib -L\$(with_openssl_install_dir)/lib -lcrypto"])
else
  AC_PATH_TOOL(PKGCONFIG, pkg-config)
  AS_IF([test "x$PKGCONFIG" = "x"], [AC_MSG_ERROR(pkg-config not found.)], )
  libdir="`pkg-config --variable=enginesdir libcrypto`"
  includes_openssl="`pkg-config --variable=includedir libcrypto`"
  if test "`grep "define OPENSSL_VERSION_MAJOR" $includes_openssl/openssl/opensslv.h | awk '{print $4}'`" = "3"
  then
    AC_MSG_NOTICE([Build QAT engine against OpenSSL 3.0])
    AC_SUBST([cflags_openssl_3], ["-DQAT_OPENSSL_3 -DOPENSSL_SUPPRESS_DEPRECATED"])
  else
    if test "`grep "define OPENSSL_VERSION_NUMBER  0x10100" $includes_openssl/openssl/opensslv.h | wc -l`" = "1"
    then
      AC_MSG_ERROR([OpenSSL version in the system is less than 1.1.1. Either update system OpenSSL to 1.1.1 or Use "--with-openssl_install_dir" pointing to the path where OpenSSL downloaded from source is installed. Additional flag "--with-openssl_dir" pointing to the OpenSSL source dir needs to be configured for OpenSSL 1.1.0])
    fi
  fi
  AC_MSG_NOTICE([Install engine in the system OpenSSL enginesdir Path])
  AC_SUBST([includes_openssl], ["-I`pkg-config --variable=includedir libcrypto`"])
  AC_SUBST([OPENSSL_LIB], ["-lcrypto"])
  AC_SUBST([libdir])
fi
AM_CONDITIONAL([QAT_OPENSSL_110], [test "x$cflags_openssl_110" != "x"])
AM_CONDITIONAL([QAT_OPENSSL_3], [test "x$cflags_openssl_3" != "x"])

# If both QAT HW and QAT SW configured, then check the libraries from standard location and use accordingly.
if test "x$cflags_qat_hw_intree" = "x"
then
  if test "x$with_qat_hw_dir" != "x" -a "x$enable_qat_sw" = "xyes"
  then
    AC_CHECK_LIB(qat_s, cpaCyRsaDecrypt, [AC_MSG_NOTICE([QAT libraries found in the system])], [AC_MSG_NOTICE([QAT Library not found in the standard location])], [])
    # Check if QAT HW is installed, otherwise use QAT SW
    if test "x$ac_cv_lib_qat_s_cpaCyRsaDecrypt" = "xno"
    then
      AC_CHECK_LIB(crypto_mb, mbx_getversion, [AC_SUBST([cflags_qat_sw], ["-DQAT_SW"])], [AC_MSG_ERROR([Both QAT HW and QAT SW Crypto Multi-buffer library not found in the standard path. Install either QAT or Crypto Multi-buffer library])], [])
      AM_CONDITIONAL([QAT_SW], [test "x$ac_cv_lib_crypto_mb_mbx_getversion" = "xyes"])
    fi
  fi
fi

# qat_hw_dir configured, enable qat_hw
if test "x$with_qat_hw_dir" != "x"
then
  if test "x$enable_qat_hw" != "xno"
  then
    AC_SUBST([cflags_qat_hw], ["-DQAT_HW"])
    AC_MSG_NOTICE([Enabling build for QAT HW acceleration])
  else
    AC_MSG_NOTICE([Disabling build for QAT HW acceleration])
  fi
fi
AM_CONDITIONAL([QAT_HW], [test "x$cflags_qat_hw" != "x"])

# QAT SW acceleration enabled
if test "x$enable_qat_sw" = "xyes"
then
  if test "x$cflags_qat_hw" = "x"
  then
    if test "x$with_qat_sw_install_dir" != "x"
    then
      AC_MSG_NOTICE([Enabling build for QAT SW and QAT SW IPSEC, library from the path provided in qat_sw_install_dir])
      AC_SUBST([cflags_qat_sw], ["-DQAT_SW"])
      AC_SUBST([cflags_qat_sw_ipsec], ["-DQAT_SW_IPSEC"])
      AC_SUBST([includes_qat_sw], ["-I\$(with_qat_sw_install_dir)/include"])
      AC_SUBST([QAT_SW_CRYPTO_MB_LIB], ["-Wl,-rpath,\$(with_qat_sw_install_dir)/lib -L\$(with_qat_sw_install_dir)/lib -lcrypto_mb -lIPSec_MB"])
    else
      AC_CHECK_LIB(crypto_mb, mbx_getversion, [AC_MSG_NOTICE([Enabling build for QAT SW])], [AC_MSG_NOTICE([crypto_mb Library not found, Disabling QAT SW])], [])
      AC_CHECK_LIB(IPSec_MB, imb_get_version, [AC_MSG_NOTICE([Enabling build for QAT SW IPSEC])], [AC_MSG_NOTICE([IPSec_MB Library not found, Disabling QAT_SW GCM])], [])
      AC_SUBST([includes_qat_sw], ["-I/usr/local/include -I/usr/include"])
      if test "x$ac_cv_lib_crypto_mb_mbx_getversion" = "xyes"
      then
        AC_CHECK_FILE(/usr/local/lib/libcrypto_mb.so,
                     [AC_SUBST([QAT_SW_CRYPTO_MB_LIB], ["-Wl,-rpath,/usr/local/lib -L/usr/loca/lib -lcrypto_mb"])],
                     [AC_SUBST([QAT_SW_CRYPTO_MB_LIB], ["-lcrypto_mb"])])
        AC_SUBST([cflags_qat_sw], ["-DQAT_SW"])
      fi
      if test "x$ac_cv_lib_IPSec_MB_imb_get_version" = "xyes"
      then
        AC_SUBST([cflags_qat_sw_ipsec], ["-DQAT_SW_IPSEC"])
        AC_SUBST([QAT_SW_IPSEC_MB_LIB], ["-lIPSec_MB"])
      fi
      if test "x$ac_cv_lib_crypto_mb_mbx_getversion" != "xyes" -a "x$ac_cv_lib_IPSec_MB_imb_get_version" != "xyes"
      then
        AC_MSG_ERROR([Both crypto_mb & IPSec_MB libraries not found in the default install dir, Install the dependant libraries or provide path via --with-qat_sw_install_dir if installed other than the default location])
      fi
    fi
  # QAT SW GCM with QAT HW
  else if test "x$cflags_qat_hw" != "x"
  then
    AC_CHECK_LIB(IPSec_MB, imb_get_version, [AC_MSG_NOTICE([Enabling build for QAT SW IPSEC with QAT HW])], [AC_MSG_NOTICE([IPSec_MB library not found, Disabling QAT_SW GCM])],[])
    if test "x$ac_cv_lib_IPSec_MB_imb_get_version" = "xyes"
    then
        AC_SUBST([cflags_qat_sw_ipsec], ["-DQAT_SW_IPSEC"])
        AC_SUBST([QAT_SW_IPSEC_MB_LIB], ["-lIPSec_MB"])
    fi
  fi
  fi
else
  if test "x$cflags_qat_hw" = "x" -a "x$cflags_qat_hw_intree" = "x"
  then
    AC_MSG_ERROR([qatlib library not installed or --with-qat_hw_dir or --enable-qat_sw not set, If you like to use QAT Hardware acceleration, set it to the path to the Intel Quickassist Technology Driver source code. e.g: --with-qat_hw_dir=/path/to/qat_driver or If you like to use QAT Software acceleration using Intel crypto multibuffer library and Intel IPSec (VAES-GCM),  provide --enable-qat_sw after installing crypto_mb and IPSec_mb libraries as per README])
  fi
fi
AM_CONDITIONAL([QAT_SW], [test "x$cflags_qat_sw" != "x"])
AM_CONDITIONAL([QAT_SW_IPSEC], [test "x$cflags_qat_sw_ipsec" != "x"])

# OpenSSL source dir to regenerate err file for OpenSSL 1.1.0
if test "x$with_openssl_dir" = "x"
then
  AC_MSG_NOTICE([Build with existing error files without regenerating from OpenSSL source])
else if test "x$with_openssl_dir" = "xno"
then
  AC_MSG_ERROR([--without-openssl_dir is invalid, set using --with-openssl_dir to the path to the OpenSSL source code. e.g: --with-openssl_dir=/path/to/openssl])
fi
fi
AM_CONDITIONAL([QAT_ERR_FILES_BUILD], [test "x$with_openssl_dir" != "x"])

# Checking the parameters given and parsing the relevant flags
if test "x$enable_qat_hw_rsa" != "xno" -a "x$cflags_qat_hw" != "x"
then
  enable_qat_hw_rsa="-DENABLE_QAT_HW_RSA"
  AC_MSG_NOTICE([Accelerating RSA to Hardware])
else
  enable_qat_hw_rsa="-DDISABLE_QAT_HW_RSA"
  AC_MSG_NOTICE([Not Accelerating RSA to Hardware])
fi

if test "x$enable_qat_hw_ciphers" != "xno" -a "x$cflags_qat_hw" != "x" -a "x$cflags_openssl_3" = "x"
then
  enable_qat_hw_ciphers="-DENABLE_QAT_HW_CIPHERS"
  AC_MSG_NOTICE([Accelerating CIPHERS to Hardware])
else
  enable_qat_hw_ciphers="-DDISABLE_QAT_HW_CIPHERS"
  AC_MSG_NOTICE([Not Accelerating CIPHERS to Hardware])
fi

if test "x$enable_qat_hw_ecdh" != "xno" -a "x$cflags_qat_hw" != "x"
then
  enable_qat_hw_ecdh="-DENABLE_QAT_HW_ECDH"
  AC_MSG_NOTICE([Accelerating ECDH to Hardware])
else
  enable_qat_hw_ecdh="-DDISABLE_QAT_HW_ECDH"
  AC_MSG_NOTICE([Not Accelerating ECDH to Hardware])
fi

if test "x$enable_qat_hw_ecdsa" != "xno" -a "x$cflags_qat_hw" != "x"
then
  enable_qat_hw_ecdsa="-DENABLE_QAT_HW_ECDSA"
  AC_MSG_NOTICE([Accelerating ECDSA to Hardware])
else
  enable_qat_hw_ecdsa="-DDISABLE_QAT_HW_ECDSA"
  AC_MSG_NOTICE([Not Accelerating ECDSA to Hardware])
fi

if test "x$enable_qat_hw_dsa" != "xno" -a "x$cflags_qat_hw" != "x"
then
  enable_qat_hw_dsa="-DENABLE_QAT_HW_DSA"
  AC_MSG_NOTICE([Accelerating DSA to Hardware])
else
  enable_qat_hw_dsa="-DDISABLE_QAT_HW_DSA"
  AC_MSG_NOTICE([Not Accelerating DSA to Hardware])
fi

if test "x$enable_qat_hw_dh" != "xno" -a "x$cflags_qat_hw" != "x"
then
  enable_qat_hw_dh="-DENABLE_QAT_HW_DH"
  AC_MSG_NOTICE([Accelerating DH to Hardware])
else
  enable_qat_hw_dh="-DDISABLE_QAT_HW_DH"
  AC_MSG_NOTICE([Not Accelerating DH to Hardware])
fi

if test "x$enable_qat_hw_prf" != "xno" -a "x$cflags_qat_hw" != "x" -a "x$cflags_openssl_3" = "x"
then
  enable_qat_hw_prf="-DENABLE_QAT_HW_PRF"
  AC_MSG_NOTICE([Accelerating PRF to Hardware])
else
  enable_qat_hw_prf="-DDISABLE_QAT_HW_PRF"
  AC_MSG_NOTICE([Not Accelerating PRF to Hardware])
fi

if test "x$enable_qat_hw_hkdf" = "xyes" -a "x$cflags_qat_hw" != "x" -a "x$cflags_openssl_3" = "x"
then
  enable_qat_hw_hkdf="-DENABLE_QAT_HW_HKDF"
  AC_MSG_NOTICE([Accelerating HKDF to Hardware])
else
  enable_qat_hw_hkdf="-DDISABLE_QAT_HW_HKDF"
  AC_MSG_NOTICE([Not Accelerating HKDF to Hardware])
fi

if test "x$enable_qat_hw_ecx" != "xno" -a "x$cflags_qat_hw" != "x" -a "x$cflags_openssl_3" = "x"
then
  enable_qat_hw_ecx="-DENABLE_QAT_HW_ECX"
  AC_MSG_NOTICE([Accelerating X25519/X448 to Hardware])
else
  enable_qat_hw_ecx="-DDISABLE_QAT_HW_ECX"
  AC_MSG_NOTICE([Not Accelerating X25519/X448 to Hardware])
fi

if test "x$enable_qat_hw_gcm" = "xyes" -a "x$cflags_qat_hw" != "x"
then
  enable_qat_hw_gcm="-DENABLE_QAT_HW_GCM"
  AC_MSG_NOTICE([Accelerating AES-GCM to Hardware (experimental)])
else
  enable_qat_hw_gcm="-DDISABLE_QAT_HW_GCM"
  AC_MSG_NOTICE([Not Accelerating AES-GCM to Hardware])
fi

if test "x$enable_qat_sw_gcm" != "xno" -a "x$cflags_qat_sw_ipsec" != "x"
then
  enable_qat_sw_gcm="-DENABLE_QAT_SW_GCM"
  AC_MSG_NOTICE([Accelerating AES-GCM to Software (IPSec_mb)])
else
  enable_qat_sw_gcm="-DDISABLE_QAT_SW_GCM"
  AC_MSG_NOTICE([Not Accelerating AES-GCM to Software (IPSec_mb)])
fi

if test "x$enable_qat_sw_rsa" != "xno" -a "x$cflags_qat_sw" != "x"
then
  enable_qat_sw_rsa="-DENABLE_QAT_SW_RSA"
  AC_MSG_NOTICE([Accelerating RSA to Software (Multi-buffer)])
else
  enable_qat_sw_rsa="-DDISABLE_QAT_SW_RSA"
  AC_MSG_NOTICE([Not Accelerating RSA to Software (Multi-buffer)])
fi

if test "x$enable_qat_sw_ecx" != "xno" -a "x$cflags_qat_sw" != "x" -a "x$cflags_openssl_3" = "x"
then
    enable_qat_sw_ecx="-DENABLE_QAT_SW_ECX"
    AC_MSG_NOTICE([Accelerating X25519 to Software (Multi-buffer)])
else
    enable_qat_sw_ecx="-DDISABLE_QAT_SW_ECX"
    AC_MSG_NOTICE([Not Accelerating X25519 to Software (Multi-buffer)])
fi

if test "x$enable_qat_sw_ecdsa" != "xno" -a "x$cflags_qat_sw" != "x"
then
    enable_qat_sw_ecdsa="-DENABLE_QAT_SW_ECDSA"
    AC_MSG_NOTICE([Accelerating ECDSA P256 & P384 to Software (Multi-buffer)])
else
    enable_qat_sw_ecdsa="-DDISABLE_QAT_SW_ECDSA"
    AC_MSG_NOTICE([Not Accelerating ECDSA P256 & P384 to Software (Multi-buffer)])
fi

if test "x$enable_qat_sw_ecdh" != "xno" -a "x$cflags_qat_sw" != "x"
then
    enable_qat_sw_ecdh="-DENABLE_QAT_SW_ECDH"
    AC_MSG_NOTICE([Accelerating ECDH P256 &P384 to Software (Multi-buffer)])
else
    enable_qat_sw_ecdh="-DDISABLE_QAT_SW_ECDH"
    AC_MSG_NOTICE([Not Accelerating ECDH P256 & P384 to Software (Multi-buffer)])
fi

if test "x$enable_qat_hw_small_pkt_offload" = "xyes" -a "x$cflags_qat_hw" != "x"
then
  enable_qat_hw_small_pkt_offload="-DENABLE_QAT_HW_SMALL_PKT_OFFLOAD"
  AC_MSG_NOTICE([Accelerating small packet CIPHERS to Hardware])
else
  enable_qat_hw_small_pkt_offload=""
  AC_MSG_NOTICE([Not Accelerating small packet CIPHERS to Hardware])
fi

if test "x$enable_qat_hw_lenstra_protection" = "xno" -a "x$cflags_qat_hw" != "x"
then
  enable_qat_hw_lenstra_protection="-DDISABLE_QAT_HW_LENSTRA_PROTECTION"
  AC_MSG_NOTICE([Lenstra attack protection disabled.])
else
  enable_qat_hw_lenstra_protection=""
  AC_MSG_NOTICE([Lenstra attack protection enabled (default).])
fi

if test "x$enable_qat_hw_lenstra_verify_hw" = "xyes" -a "x$cflags_qat_hw" != "x"
then
    if test "x$enable_qat_hw_lenstra_protection" != "xno"
    then
      enable_qat_hw_lenstra_verify_hw="-DENABLE_QAT_HW_LENSTRA_VERIFY_HW"
      AC_MSG_NOTICE([Lenstra check via QAT HW enabled.])
    fi
fi

if test "x$enable_qat_debug" = "xyes"
then
  enable_qat_debug="-DQAT_DEBUG"
  AC_MSG_NOTICE([Enabling Engine Debug Messages])
else
  enable_qat_debug=""
  AC_MSG_NOTICE([Disabling Engine Debug Messages])
fi

if test "x$enable_qat_warnings" = "xyes"
then
  enable_qat_warnings="-DQAT_WARN"
  AC_MSG_NOTICE([Enabling Engine Warning Messages])
else
  enable_qat_warnings=""
  AC_MSG_NOTICE([Disabling Engine Warning Messages])
fi

if test "x$enable_qat_mem_debug" = "xyes"
then
  enable_qat_mem_debug="-DQAT_MEM_DEBUG"
  AC_MSG_NOTICE([Enabling Memory Driver Debug Messages])
else
  enable_qat_mem_debug=""
  AC_MSG_NOTICE([Disabling Memory Driver Debug Messages])
fi

if test "x$enable_qat_mem_warnings" = "xyes"
then
  enable_qat_mem_warnings="-DQAT_MEM_WARN"
  AC_MSG_NOTICE([Enabling Memory Driver Warning Messages])
else
  enable_qat_mem_warnings=""
  AC_MSG_NOTICE([Disabling Memory Driver Warning Messages])
fi

if test "x$enable_qat_auto_engine_init_on_fork" = "xno"
then
  enable_qat_auto_engine_init_on_fork="-DDISABLE_QAT_AUTO_ENGINE_INIT_ON_FORK"
  AC_MSG_NOTICE([Auto engine init on fork disabled.])
else
  enable_qat_auto_engine_init_on_fork=""
  AC_MSG_NOTICE([Auto Engine init on fork enabled (default).])
fi

if test "x$enable_qat_sw_heuristic_timeout" = "xyes" -a "x$cflags_qat_sw" != "x"
then
  enable_qat_sw_heuristic_timeout="-DQAT_SW_HEURISTIC_TIMEOUT"
  AC_MSG_NOTICE([Enabling QAT SW Heuristic Timeout])
else
  enable_qat_sw_heuristic_timeout=""
  AC_MSG_NOTICE([Disabling QAT SW Heuristic Timeout (default)])
fi

if test "x$enable_qat_cycle_counts" = "xyes"
then
  enable_qat_cycle_counts="-DQAT_CPU_CYCLES_COUNT"
  AC_MSG_NOTICE([Enabling CPU Cycle Counts])
else
  enable_qat_cycle_counts=""
  AC_MSG_NOTICE([Disabling CPU Cycle Counts])
fi

# Compiler security flags
case "$host_os" in
*linux*)
  if test "`cc --version | head -1 | awk '{print $3>=4.9}' 2>/dev/null`" = "1"
  then
    AC_SUBST([cflags], ["-shared -fPIC -Wall -Wformat -Wformat-security -O2 -D_FORTIFY_SOURCE=2 -fno-delete-null-pointer-checks -fwrapv -fstack-protector-strong -fno-strict-overflow"])
  else
    AC_SUBST([cflags], ["-shared -fPIC -Wall -Wformat -Wformat-security -O2 -D_FORTIFY_SOURCE=2 -fno-delete-null-pointer-checks -fwrapv -fstack-protector -fno-strict-overflow"])
  fi
;;
*freebsd*)
    AC_SUBST([cflags], ["-shared -fPIC -Wall -Wformat -Wformat-security -O2 -D_FORTIFY_SOURCE=2 -fno-delete-null-pointer-checks -fwrapv -fstack-protector-strong"])
;;
*) ;;
esac

if test "x$with_cc_opt" != "x"
then
  AC_SUBST([cflags_cc_opt], ["\$(with_cc_opt)"])
fi

if test "x$cflags_qat_hw" != "x"
then
  if test "x$enable_qat_hw_contig_mem" = "xyes" -a "x$enable_qat_hw_multi_thread" != "xyes"
  then
    AC_SUBST([cflags_mem_driver], ["-DUSE_QAT_CONTIG_MEM -Iqat_contig_mem"])
    AC_MSG_NOTICE([Compiling for qat_contig_mem])
  else if test "x$enable_qat_hw_multi_thread" = "xyes"
  then
    AC_SUBST([cflags_mem_driver], ["-DUSE_QAT_CONTIG_MEM -Iqat_contig_mem"])
    AC_MSG_NOTICE([Compiling for multi_thread using qat_contig_mem])
  else
    AC_SUBST([cflags_mem_driver], ["-DUSE_USDM_MEM"])
    AC_MSG_NOTICE([Compiling for USDM])
  fi
  fi
fi
AM_CONDITIONAL([QAT_HW_CONTIG_MEM], [test "x$enable_qat_hw_contig_mem" = "xyes" -a "x$enable_qat_hw_multi_thread" != "xyes"])
AM_CONDITIONAL([QAT_HW_MULTI_THREAD], [test "x$enable_qat_hw_multi_thread" = "xyes"])
AM_CONDITIONAL([QAT_HW_USDM], [test "x$enable_qat_hw_contig_mem" != "xyes" -a "x$enable_qat_hw_multi_thread" != "xyes"])

if test "x$with_qat_debug_file" != "x"
then
  AC_SUBST([cflags_qat_debug_file], ["-DQAT_DEBUG_FILE_PATH=\$(with_qat_debug_file)"])
  AC_MSG_NOTICE([Enabling writing debug to file])
fi

if test "x$with_qat_engine_id" != "x"
then
  AC_SUBST([cflags_qat_engine_id], ["-DQAT_ENGINE_ID=\$(with_qat_engine_id)"])
  AC_MSG_NOTICE([Using engine id other than default])
else
  AC_MSG_NOTICE([Using default engine id "qatengine"])
fi

case "$host_os" in
linux*)
  AC_CHECK_PROG(USE_LDD, ldd, yes, no)
  AC_CHECK_PROG(USE_HEAD, head, yes, no)
  if test $USE_LDD == "yes" -a $USE_HEAD
  then
    if test "`ldd --version | head -1 | awk '{print $4>=2.23?"1":"0"}' 2>/dev/null`" = "1"
    then
      AC_MSG_NOTICE([glibc version >= 2.23. glibc AVX-512 optimisation supported.])
    else
      AC_MSG_NOTICE([glibc version < 2.23. glibc AVX-512 optimisation not supported.])
    fi
    if test "`ldd --version | head -1 | awk '{print $4<2.17?"1":"0"}' 2>/dev/null`" = "1"
    then
      AC_ARG_WITH(LIBS, AS_HELP_STRING(), , LIBS+="-lrt")
      AC_SUBST(LIBS)
    fi
  else
    AC_MSG_NOTICE([glibc version could not be auto detected. Check manually using 'ldd --version'])
    AC_MSG_NOTICE([glibc AVX-512 optimisation supported only from glibc version 2.23])
    AC_ARG_WITH(LIBS, AS_HELP_STRING(), , LIBS+="-lrt")
    AC_SUBST(LIBS)

  fi
  ;;
  *)
esac

# Setting driver headers include path
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

if test "x$cflags_qat_hw_intree" != "x"
then
  AC_SUBST([DRIVER], ["qat"])
  AC_SUBST([USDM], ["usdm"])
else
  AC_SUBST([DRIVER], ["qat_s"])
  AC_SUBST([USDM], ["usdm_drv_s"])
fi

if test "x$with_ld_opt" != "x"
then
  AC_SUBST([QAT_LD_LIB], ["\$(with_ld_opt)"])
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

# Output files from the configure
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
