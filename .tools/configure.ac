#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([libqat], [1.0], [])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE([foreign])

#Libtool for generating shared library

LT_INIT
AC_PROG_LIBTOOL
AC_PROG_LN_S
AC_CONFIG_MACRO_DIR([m4])

# Parameter parsing for disabling the feature

AC_ARG_ENABLE(qat_rsa,
              AS_HELP_STRING([--disable-qat_rsa],
                             [Disable accelerated RSA offload]))
AC_SUBST(enable_qat_rsa)


AC_ARG_ENABLE(qat_ciphers,
              AS_HELP_STRING([--disable-qat_ciphers],
                             [Disable accelerated CIPHERS offload]))
AC_SUBST(enable_qat_ciphers)


AC_ARG_ENABLE(qat_ecdh,
              AS_HELP_STRING([--disable-qat_ecdh],
                             [Disable accelerated ECDH offload]))
AC_SUBST(enable_qat_ecdh)


AC_ARG_ENABLE(qat_ecdsa,
              AS_HELP_STRING([--disable-qat_ecdsa],
                             [Disable accelerated ECDSA offload]))
AC_SUBST(enable_qat_ecdsa)


AC_ARG_ENABLE(qat_dsa,
              AS_HELP_STRING([--disable-qat_dsa],
                             [Disable accelerated DSA offload]))
AC_SUBST(enable_qat_dsa)


AC_ARG_ENABLE(qat_dh,
              AS_HELP_STRING([--disable-qat_dh],
                             [Disable accelerated DH offload]))
AC_SUBST(enable_qat_dh)

AC_ARG_ENABLE(qat_prf,
              AS_HELP_STRING([--disable-qat_prf],
                             [Disable accelerated PRF offload]))
AC_SUBST(enable_qat_prf)

AC_ARG_ENABLE(qat_hkdf,
              AS_HELP_STRING([--disable-qat_hkdf],
                             [Disable accelerated HKDF offload]))
AC_SUBST(enable_qat_hkdf)

AC_ARG_ENABLE(qat_small_pkt_offload,
              AS_HELP_STRING([--enable-qat_small_pkt_offload],
                             [Enable accelerated small packet CIPHER offload]))
AC_SUBST(enable_qat_small_pkt_offload)

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

# Environment setting : Required for building the library

AC_ARG_WITH(qat_dir,
              AS_HELP_STRING([--with-qat_dir],
                             [Path to the Intel Quickassist Technology Driver source code]))
AC_SUBST(with_qat_dir)

AC_ARG_WITH(openssl_install_dir,
              AS_HELP_STRING([--with-openssl_install_dir],
                             [Path to where the OpenSSL libraries are installed to. The Engine will be installed to the lib/engines subdirectory of this path]))
AC_SUBST(with_openssl_install_dir)

# Other non mandatory parameters

AC_ARG_WITH(openssl_dir,
              AS_HELP_STRING([--with-openssl_dir],
                             [Path to the OpenSSL source code. The error files will get regenerated using the mkerr.pl script included with the OpenSSL source]))
AC_SUBST(with_openssl_dir)

AC_ARG_WITH(qat_install_dir,
              AS_HELP_STRING([--with-qat_install_dir],
                             [Path to the Intel Quickassist Technology Driver build output]))
AC_SUBST(with_qat_install_dir)

AC_ARG_ENABLE(qat16_driver,
              AS_HELP_STRING([--enable_qat16_driver],
                             [Enable using the QAT1.6 Intel Quickassist Technology Driver]))
AC_SUBST(enable_qat16_driver)

AC_ARG_ENABLE(qat_contig_mem,
              AS_HELP_STRING([--enable-qat_contig_mem],
                             [This should be specified to force the Engine to use the qat_contig_mem component supplied within the QAT Engine release package]))
AC_SUBST(enable_qat_contig_mem)

AC_ARG_WITH(usdm_dir,
              AS_HELP_STRING([--with-usdm_dir],
                             [Path to the USDM Component source code. This should be used to specify a path to the USDM Component source other than the standard default path within the QAT1.7 Intel Quickassist Technology Driver source code]))
AC_SUBST(with_usdm_dir)

AC_ARG_WITH(qat_debug_file,
              AS_HELP_STRING([--with-qat_debug_file],
                             [Path and filename to log debug output to. Combine with other flags that enable the debug and warning output]))
AC_SUBST(with_qat_debug_file)

AC_ARG_WITH(cc_opt,
              AS_HELP_STRING([--with-cc_opt],
                             [Sets additional parameters that will be added to the CFLAGS]))
AC_SUBST(with_cc_opt)

AC_ARG_WITH(ld_opt,
              AS_HELP_STRING([--with-ld_opt],
                             [Sets additional parameters that will be used during linking]))
AC_SUBST(with_ld_opt)

AC_ARG_ENABLE(multi_thread,
            AS_HELP_STRING([--enable-multi_thread],
                           [Enable using a multi threaded version of the user space part of the supplied memory driver. Please see the documentation on limitations of using this option]))
AC_SUBST(enable_multi_thread)

AC_ARG_ENABLE(qat_mux,
            AS_HELP_STRING([--enable-qat_mux],
                           [Enable linking against a build of the Intel Quickassist Technology Driver that supports multiple accelerator hardware versions. Please see the documentation for more details]))
AC_SUBST(enable_qat_mux)

AC_ARG_ENABLE(qat_lenstra_protection,
              AS_HELP_STRING([--disable-qat_lenstra_protection],
                             [Disable protection against Lenstra attack]))
AC_SUBST(enable_qat_lenstra_protection)

AC_ARG_ENABLE(qat_for_openssl_102,
              AS_HELP_STRING([--enable-qat_for_openssl_102],
                             [Enable building QAT engine against OpenSSL 1.0.2 with only RSA sync offloading]))
AC_SUBST(enable_qat_for_openssl_102)

AC_ARG_ENABLE(qat_for_openssl_110,
              AS_HELP_STRING([--enable-qat_for_openssl_110],
                             [Enable building QAT engine against OpenSSL 1.1.0 branch]))
AC_SUBST(enable_qat_for_openssl_110)

AC_ARG_ENABLE(openssl_install_build_arch_path,
              AS_HELP_STRING([--enable-openssl_install_build_arch_path],
                             [Enable building QAT engine against packaged OpenSSL on, for example, a Debian system]))
AC_SUBST(enable_openssl_install_build_arch_path)

AC_ARG_ENABLE(qat_auto_engine_init_on_fork,
              AS_HELP_STRING([--disable-qat_auto_engine_init_on_fork],
                             [Disable auto initialization of the engine following a fork]))
AC_SUBST(enable_qat_auto_engine_init_on_fork)

# ERROR message if mandatory options are not provided


if test "x$with_qat_dir" = "x"
then
  AC_MSG_ERROR([--with-qat_dir is not set, set it to the path to the Intel Quickassist Technology Driver source code. e.g: --with-qat_dir=/path/to/qat_driver])
else if test "x$with_qat_dir" = "xno"
then
  AC_MSG_ERROR([--without-qat_dir is invalid, set using --with-qat_dir to the path to the Intel Quickassist Technology Driver source code. e.g: --with-qat_dir=/path/to/qat_driver])
fi
fi

if test "x$with_openssl_install_dir" = "x"
then
  AC_MSG_ERROR([--with-openssl_install_dir is not set, set it to the path to where the OpenSSL libraries are installed. e.g: --with-openssl_install_dir=/path/to/openssl_install])
else if test "x$with_openssl_install_dir" = "xno"
then
  AC_MSG_ERROR([--without-openssl_install_dir is invalid, set using --with-openssl_install_dir to the path to where the OpenSSL libraries are installed. e.g: --with-openssl_install_dir=/path/to/openssl_install])
fi
fi

ac_default_prefix=$with_openssl_install_dir

# Default non mandatory paths if not provided

if test "x$with_openssl_dir" = "x"
then
  AC_MSG_NOTICE([Build with existing error files without regenerating from OpenSSL source])
else if test "x$with_openssl_dir" = "xno"
then
  AC_MSG_ERROR([--without-openssl_dir is invalid, set using --with-openssl_dir to the path to the OpenSSL source code. e.g: --with-openssl_dir=/path/to/openssl])
fi
fi
AM_CONDITIONAL([QAT_ERR_FILES_BUILD], [test "x$with_openssl_dir" != "x"])

if test "x$with_qat_install_dir" = "x"
then
  with_qat_install_dir="\$(with_qat_dir)/build"
fi

if test "x$with_usdm_dir" = "x"
then
  with_usdm_dir="\$(with_qat_dir)/quickassist/utilities/libusdm_drv"
fi

# Checking the parameters given and parsing the relevant flags

if test "x$enable_qat_rsa" != "xno"
then
  enable_qat_rsa="-DOPENSSL_ENABLE_QAT_RSA"
  AC_MSG_NOTICE([Offloading RSA to Hardware])
else
  enable_qat_rsa="-DOPENSSL_DISABLE_QAT_RSA"
  AC_MSG_NOTICE([Not Offloading RSA to Hardware])
fi

if test "x$enable_qat_ciphers" != "xno"
then
  enable_qat_ciphers="-DOPENSSL_ENABLE_QAT_CIPHERS"
  AC_MSG_NOTICE([Offloading CIPHERS to Hardware])
else
  enable_qat_ciphers="-DOPENSSL_DISABLE_QAT_CIPHERS"
  AC_MSG_NOTICE([Not Offloading CIPHERS to Hardware])
fi

if test "x$enable_qat_ecdh" != "xno"
then
  enable_qat_ecdh="-DOPENSSL_ENABLE_QAT_ECDH"
  AC_MSG_NOTICE([Offloading ECDH to Hardware])
else
  enable_qat_ecdh="-DOPENSSL_DISABLE_QAT_ECDH"
  AC_MSG_NOTICE([Not Offloading ECDH to Hardware])
fi

if test "x$enable_qat_ecdsa" != "xno"
then
  enable_qat_ecdsa="-DOPENSSL_ENABLE_QAT_ECDSA"
  AC_MSG_NOTICE([Offloading ECDSA to Hardware])
else
  enable_qat_ecdsa="-DOPENSSL_DISABLE_QAT_ECDSA"
  AC_MSG_NOTICE([Not Offloading ECDSA to Hardware])
fi

if test "x$enable_qat_dsa" != "xno"
then
  enable_qat_dsa="-DOPENSSL_ENABLE_QAT_DSA"
  AC_MSG_NOTICE([Offloading DSA to Hardware])
else
  enable_qat_dsa="-DOPENSSL_DISABLE_QAT_DSA"
  AC_MSG_NOTICE([Not Offloading DSA to Hardware])
fi

if test "x$enable_qat_dh" != "xno"
then
  enable_qat_dh="-DOPENSSL_ENABLE_QAT_DH"
  AC_MSG_NOTICE([Offloading DH to Hardware])
else
  enable_qat_dh="-DOPENSSL_DISABLE_QAT_DH"
  AC_MSG_NOTICE([Not Offloading DH to Hardware])
fi

if test "x$enable_qat_prf" != "xno"
then
  enable_qat_prf="-DOPENSSL_ENABLE_QAT_PRF"
  AC_MSG_NOTICE([Offloading PRF to Hardware])
else
  enable_qat_prf="-DOPENSSL_DISABLE_QAT_PRF"
  AC_MSG_NOTICE([Not Offloading PRF to Hardware])
fi

if test "x$enable_qat_hkdf" != "xno"
then
  enable_qat_hkdf="-DOPENSSL_ENABLE_QAT_HKDF"
  AC_MSG_NOTICE([Offloading HKDF to Hardware])
else
  enable_qat_hkdf="-DOPENSSL_DISABLE_QAT_HKDF"
  AC_MSG_NOTICE([Not Offloading HKDF to Hardware])
fi

if test "x$enable_qat_small_pkt_offload" = "xyes"
then
  enable_qat_small_pkt_offload="-DOPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS"
  AC_MSG_NOTICE([Offloading small packet CIPHERS to Hardware])
else
  enable_qat_small_pkt_offload=""
  AC_MSG_NOTICE([Not Offloading small packet CIPHERS to Hardware])
fi

if test "x$enable_qat_lenstra_protection" = "xno"
then
  enable_qat_lenstra_protection="-DOPENSSL_DISABLE_QAT_LENSTRA_PROTECTION"
  AC_MSG_NOTICE([Lenstra attack protection disabled.])
else
  enable_qat_lenstra_protection=""
  AC_MSG_NOTICE([Lenstra attack protection enabled (default).])
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
  enable_qat_auto_engine_init_on_fork="-DOPENSSL_DISABLE_QAT_AUTO_ENGINE_INIT_ON_FORK"
  AC_MSG_NOTICE([Auto engine init on fork disabled.])
else
  enable_qat_auto_engine_init_on_fork=""
  AC_MSG_NOTICE([Auto Engine init on fork enabled (default).])
fi

# Check for memory driver and parse the CFLAGS for building library

AC_ARG_WITH(includes, AS_HELP_STRING(), , includes="-I\$(with_openssl_install_dir)/include")
AC_SUBST(includes)

case `($CC --version) 2>/dev/null` in
    'gcc (GCC) '[[0-3]].* | \
    'gcc (GCC) '4.[[0-8]].*)
         AC_ARG_WITH(cflags, AS_HELP_STRING(), , cflags="-shared -fPIC -Wall -Wformat -Wformat-security -O2 -D_FORTIFY_SOURCE=2 -fstack-protector -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv")
         AC_SUBST(cflags)
         ;;
    *)
         AC_ARG_WITH(cflags, AS_HELP_STRING(), , cflags="-shared -fPIC -Wall -Wformat -Wformat-security -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv")
         AC_SUBST(cflags)
         ;;
esac

if test "x$with_cc_opt" != "x"
then
  AC_ARG_WITH(cflags_cc_opt, AS_HELP_STRING(), , cflags_cc_opt="\$(with_cc_opt)")
  AC_SUBST(cflags_cc_opt)
fi


if test "x$enable_qat_contig_mem" = "xyes" -a "x$enable_multi_thread" != "xyes"
then
  AC_MSG_NOTICE([Compiling for qat_contig_mem])
  AC_ARG_WITH(cflags_mem_driver, AS_HELP_STRING(), , cflags_mem_driver="-DUSE_QAT_CONTIG_MEM -Iqat_contig_mem")
  AC_SUBST(cflags_mem_driver)
else if test "x$enable_multi_thread" = "xyes"
then
  AC_MSG_NOTICE([Compiling for multi_thread])
  AC_ARG_WITH(cflags_mem_driver, AS_HELP_STRING(), , cflags_mem_driver="-DUSE_QAT_CONTIG_MEM -Iqat_contig_mem")
  AC_SUBST(cflags_mem_driver)
else
  AC_MSG_NOTICE([Compiling for USDM])
  AC_ARG_WITH(cflags_mem_driver, AS_HELP_STRING(), , cflags_mem_driver="-DUSE_QAE_MEM")
  AC_SUBST(cflags_mem_driver)
  AC_ARG_WITH(include_enable_usdm, AS_HELP_STRING(), , include_enable_usdm="-I\$(with_usdm_dir)")
  AC_SUBST(include_enable_usdm)
fi
fi

AM_CONDITIONAL([QAT_CONTIG_MEM], [test "x$enable_qat_contig_mem" = "xyes" -a "x$enable_multi_thread" != "xyes"])
AM_CONDITIONAL([QAT_MULTI_THREAD], [test "x$enable_multi_thread" = "xyes"])
AM_CONDITIONAL([QAE_MEM], [test "x$enable_qat_contig_mem" != "xyes" -a "x$enable_multi_thread" != "xyes"])

if test "x$with_qat_debug_file" != "x"
then
  AC_ARG_WITH(cflags_qat_debug_file, AS_HELP_STRING(), , cflags_qat_debug_file="-DQAT_DEBUG_FILE_PATH=\$(with_qat_debug_file)")
  AC_SUBST(cflags_qat_debug_file)
  AC_MSG_NOTICE([Enabling writing debug to file])
fi


AC_CHECK_PROG(USE_GETCONF, getconf, yes, no)
AC_PROG_AWK
if test $AWK == "gawk" -a $USE_GETCONF == "yes"
then
 AC_MSG_NOTICE([Getting glibc version ...])
 if test `getconf GNU_LIBC_VERSION | gawk '{print $2>=2.23?"1":"0"}' 2>/dev/null` == 1
 then
  AC_MSG_NOTICE([glibc version is greater or equal to 2.23 so AVX-512 optimisations are supported.])
 else
  AC_MSG_NOTICE([glibc version is less than 2.23 - no AVX-512 optimisation supported.])
 fi
 if test `getconf GNU_LIBC_VERSION | gawk '{print $2<2.17?"1":"0"}' 2>/dev/null` == 1
 then
  AC_ARG_WITH(LIBS, AS_HELP_STRING(), , LIBS+="-lrt")
  AC_SUBST(LIBS)
 fi
else
 AC_MSG_NOTICE([Version of glibc could not be obtained automatically.  Please check manually by running:-])
 AC_MSG_NOTICE(['getconf GNU_LIBC_VERSION' or 'ldd --version'.])
 AC_MSG_NOTICE([If version of glibc returned is greater or equal to 2.23 then glibc AVX-512 optimisation is supported.])
 AC_ARG_WITH(LIBS, AS_HELP_STRING(), , LIBS+="-lrt")
 AC_SUBST(LIBS)
fi

if test "x$enable_qat_for_openssl_102" = "xyes"
then
  AC_MSG_NOTICE([Build QAT engine against OpenSSL 1.0.2 with only RSA sync offloading])
# always set enable_qat_rsa to -DOPENSSL_ENABLE_QAT_RSA
  enable_qat_rsa="-DOPENSSL_ENABLE_QAT_RSA"
# this is a trick to bypass code for small packet cipher offloading
  enable_qat_small_pkt_offload="-DOPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS"
fi

AM_CONDITIONAL([QAT_OPENSSL_102], [test "x$enable_qat_for_openssl_102" = "xyes"])

if test "x$enable_qat_for_openssl_110" = "xyes"
then
  AC_MSG_NOTICE([Build QAT engine against OpenSSL 1.1.0])
fi
AM_CONDITIONAL([QAT_OPENSSL_110], [test "x$enable_qat_for_openssl_110" = "xyes"])

if test "x$enable_openssl_install_build_arch_path" = "xyes"
then
  AC_MSG_NOTICE([Build QAT engine against packaged OpenSSL on, for example, a Debian system])
fi
AM_CONDITIONAL([QAT_OPENSSL_PACKAGE_BUILD_ARCH_PATH], [test "x$enable_openssl_install_build_arch_path" = "xyes"])

if test "`grep "define OPENSSL_VERSION_MAJOR" $with_openssl_install_dir/include/openssl/opensslv.h | gawk '{print $4}'`" = "3"
then
  AC_MSG_NOTICE([Build QAT engine against OpenSSL 3.0.0])
fi
AM_CONDITIONAL([QAT_OPENSSL_300], [ test "`grep "define OPENSSL_VERSION_MAJOR" $with_openssl_install_dir/include/openssl/opensslv.h | gawk '{print $4}'`" = "3"])

# Adding driver source for building and linking the library

AC_ARG_WITH(ICP_API_DIR, AS_HELP_STRING(), ,with_ICP_API_DIR="\$(with_qat_dir)/quickassist/include")
AC_SUBST(with_ICP_API_DIR)

AC_ARG_WITH(ICP_SAL_API_DIR, AS_HELP_STRING(), ,with_ICP_SAL_API_DIR="\$(with_qat_dir)/quickassist/lookaside/access_layer/include")
AC_SUBST(with_ICP_SAL_API_DIR)

AC_ARG_WITH(ICP_LAC_API_DIR, AS_HELP_STRING(), ,with_ICP_LAC_API_DIR="\$(with_ICP_API_DIR)/lac")
AC_SUBST(with_ICP_LAC_API_DIR)

AC_ARG_WITH(includes_driver, AS_HELP_STRING(), , includes_driver="-I\$(with_ICP_API_DIR) -I\$(with_ICP_LAC_API_DIR) -I\$(with_ICP_SAL_API_DIR)")
AC_SUBST(includes_driver)

AC_ARG_WITH(DRIVER, AS_HELP_STRING(), , DRIVER="qat")
AC_SUBST(DRIVER)

if test "x$enable_qat_mux" = "xyes"
then
  AC_ARG_WITH(DRIVER, AS_HELP_STRING(), , DRIVER="qat_mux")
  AC_SUBST(DRIVER)
  AC_ARG_WITH(cflags_upstream_driver, AS_HELP_STRING(), , cflags_upstream_driver="")
  AC_SUBST(cflags_upstream_driver)
  AC_MSG_NOTICE([Enabling build for Mux Driver])
else if test "x$enable_qat16_driver" = "xyes"
then
  AC_ARG_WITH(DRIVER, AS_HELP_STRING(), , DRIVER="icp_qa_al")
  AC_SUBST(DRIVER)
  AC_ARG_WITH(cflags_upstream_driver, AS_HELP_STRING(), , cflags_upstream_driver="")
  AC_SUBST(cflags_upstream_driver)
  AC_MSG_NOTICE([Enabling build for QAT1.6 Driver])
else
  AC_ARG_WITH(cflags_upstream_driver, AS_HELP_STRING(), , cflags_upstream_driver="-DOPENSSL_ENABLE_QAT_UPSTREAM_DRIVER")
  AC_SUBST(cflags_upstream_driver)
  AC_MSG_NOTICE([Enabling build for Upstream Driver])
fi
fi

AM_CONDITIONAL([OPENSSL_ENABLE_QAT_UPSTREAM_DRIVER], [test "x$enable_qat16_driver" != "xyes"])

if test "x$enable_qat_mux" = "xyes"
then
AC_ARG_WITH(ICP_MUX_DIR, AS_HELP_STRING(), , with_ICP_MUX_DIR="\$(with_qat_dir)/../QAT1.5/quickassist/include")
AC_SUBST(with_ICP_MUX_DIR)
AC_ARG_WITH(ICP_DC_DIR, AS_HELP_STRING(), , with_ICP_DC_DIR="\$(with_ICP_API_DIR)/dc")
AC_SUBST(with_ICP_DC_DIR)
AC_ARG_WITH(cflags_mux, AS_HELP_STRING(), , cflags_mux="-DWITH_CPA_MUX")
AC_SUBST(cflags_mux)
AC_ARG_WITH(includes_enable_qat_mux, AS_HELP_STRING(), , includes_enable_qat_mux="-I\$(with_ICP_MUX_DIR) -I\$(with_ICP_DC_DIR)")
AC_SUBST(includes_enable_qat_mux)
fi

if test "x$with_ld_opt" != "x"
then
  AC_ARG_WITH(QAT_SHARED_LIB_DEPS_LD, AS_HELP_STRING(), , QAT_SHARED_LIB_DEPS_LD=["\$(with_ld_opt)"])
  AC_SUBST(QAT_SHARED_LIB_DEPS_LD)
fi

if test "x$with_qat_install_dir" != "x"
then
  AC_ARG_WITH(QAT_SHARED_LIB_DEPS_DRIVER, AS_HELP_STRING(), , QAT_SHARED_LIB_DEPS_DRIVER=["-Wl,-rpath,\$(with_qat_install_dir) -L\$(with_qat_install_dir) -l\$(DRIVER)_s"])
  AC_SUBST(QAT_SHARED_LIB_DEPS_DRIVER)
fi

if test "x$enable_qat_contig_mem" != "xyes" -a "x$enable_multi_thread" != "xyes" -a "$enable_qat16_driver" = "xyes"
then
  AC_ARG_WITH(QAT_SHARED_LIB_DEPS_QAE_MEM, AS_HELP_STRING(), , QAT_SHARED_LIB_DEPS_QAE_MEM=["-Wl,-rpath,\$(with_usdm_dir) -L\$(with_usdm_dir) -lusdm_drv_s"])
  AC_SUBST(QAT_SHARED_LIB_DEPS_QAE_MEM)
fi

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

# Output files from the configure
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
