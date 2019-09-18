
ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libqat.la

if QAT_CONTIG_MEM
 MEM_LIB_SRC = qae_mem_utils.c \
               qat_sys_call.c
 MEM_LIB_HEADER = qae_mem_utils.h \
                  qat_sys_call.h
endif

if QAT_MULTI_THREAD
 MEM_LIB_SRC = multi_thread_qaememutils.c \
               qat_sys_call.c
endif

if QAE_MEM
 MEM_LIB_SRC = cmn_mem_drv_inf.c
 MEM_LIB_HEADER = cmn_mem_drv_inf.h
endif

OPENSSL_COMMON_SRC = e_qat.c \
                     qat_fork.c \
                     qat_events.c \
                     qat_callback.c \
                     qat_polling.c \
                     qat_asym_common.c \
                     qat_utils.c \
                     qat_rsa.c \
                     qat_rsa_crt.c

OPENSSL_COMMON_HDR = e_qat.h \
                     qat_fork.h \
                     qat_events.h \
                     qat_callback.h \
                     qat_polling.h \
                     qat_asym_common.h \
                     qat_utils.h \
                     qat_rsa.h \
                     qat_rsa_crt.h

if QAT_OPENSSL_102
 OPENSSL_VERSION_SPECIFIC_SRC = qat_aux.c \
                                qat_rsa_aux.c

 OPENSSL_VERSION_SPECIFIC_HDR = qat_aux.h \
                                qat_rsa_aux.h

else
 OPENSSL_VERSION_SPECIFIC_SRC = qat_ciphers.c \
                                qat_dh.c \
                                qat_dsa.c \
                                qat_ec.c \
                                qat_prf.c \
                                qat_hkdf.c \
                                qat_evp.c

 OPENSSL_VERSION_SPECIFIC_HDR = qat_ciphers.h \
                                qat_dh.h \
                                qat_dsa.h \
                                qat_ec.h \
                                qat_evp.h
endif

if !OPENSSL_ENABLE_QAT_UPSTREAM_DRIVER
 PARSE_CONFIG_FILES_SRC = qat_parseconf.c
 PARSE_CONFIG_FILES_HDR = qat_parseconf.h
endif

libqat_la_SOURCES = ${OPENSSL_COMMON_SRC} \
                    ${OPENSSL_VERSION_SPECIFIC_SRC} \
                    ${PARSE_CONFIG_FILES_SRC} \
                    ${MEM_LIB_SRC} \
                    e_qat_err.c

include_HEADERS = ${OPENSSL_COMMON_HDR} \
                  ${OPENSSL_VERSION_SPECIFIC_HDR} \
                  ${PARSE_CONFIG_FILES_HDR} \
                  ${MEM_LIB_HEADER} \
                  e_qat_err.h


CC = cc
AM_CPPFLAGS = $(includes) $(include_enable_usdm) $(includes_driver) \
              $(includes_enable_qat_mux)

AM_CFLAGS = $(cflags) $(cflags_cc_opt) $(cflags_enable_upstream_driver) \
            $(cflags_qat_contig_mem) $(cflags_enable_multi_thread) \
            $(cflags_enable_usdm) $(cflags_mux) $(enable_qat_rsa) \
            $(enable_qat_ciphers) $(enable_qat_ecdh) $(enable_qat_ecdsa) \
            $(enable_qat_dsa) $(enable_qat_dh) $(enable_qat_prf) \
            $(enable_qat_hkdf) \
            $(enable_qat_small_pkt_offload) \
            $(enable_qat_lenstra_protection) \
            $(enable_qat_debug) $(enable_qat_warnings) \
            $(enable_qat_mem_debug) $(enable_qat_mem_warnings) \
            $(enable_qat_auto_engine_init_on_fork) \
            $(cflags_qat_debug_file)\
            $(cflags_SSL_QAT_use_async_callback)

libqat_la_LDFLAGS = $(QAT_SHARED_LIB_DEPS_LD) \
                    $(QAT_SHARED_LIB_DEPS_UPSTREAM_DRIVER) \
                    $(QAT_SHARED_LIB_DEPS_DRIVER) \
                    $(QAT_SHARED_LIB_DEPS_QAE_MEM)

if QAT_OPENSSL_102
 ENGINE_LIB = $(with_openssl_install_dir)/lib/engines/libqat.so
else
if QAT_OPENSSL_PACKAGE_BUILD_ARCH_PATH
if QAT_OPENSSL_300
 ENGINE_LIB = $(with_openssl_install_dir)/engines-3/qat.so
else
 ENGINE_LIB = $(with_openssl_install_dir)/engines-1.1/qat.so
endif
else
if QAT_OPENSSL_300
 ENGINE_LIB = $(with_openssl_install_dir)/lib/engines-3/qat.so
else
 ENGINE_LIB = $(with_openssl_install_dir)/lib/engines-1.1/qat.so
endif
endif
endif

mostlyclean-generic:
	-rm -f *.obj lib tags core .pure .nfs* \
	*.old *.bak fluff *.so *.sl *.dll

	-rm -f $(ENGINE_LIB)

if !QAT_SKIP_ERR_FILES_BUILD
MAKE = make err-files && make
endif

install-data-am:
	-cp -f $(prefix)/lib/libqat.so $(ENGINE_LIB)

err-files:
if QAT_OPENSSL_102
	rm -rf e_qat_err* && perl $(with_openssl_dir)/util/mkerr.pl -conf e_qat.ec \
       -rebuild -reindex -nostatic -write $(libqat_la_SOURCES)

else
if QAT_OPENSSL_110
	rm -rf e_qat_err* && perl $(with_openssl_dir)/util/mkerr.pl -conf e_qat.ec \
       -rebuild -reindex -nostatic -write $(libqat_la_SOURCES)

else
	rm -f e_qat_err.c e_qat.txt && perl $(with_openssl_dir)/util/mkerr.pl -conf e_qat.ec \
       -rebuild -reindex $(libqat_la_SOURCES)
endif
endif
