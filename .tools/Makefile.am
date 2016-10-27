
ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libqat.la

if QAT_CONTIG_MEM
 MEM_LIB_SRC = qae_mem_utils.c
 MEM_LIB_HEADER = qae_mem_utils.h
endif

if QAT_MULTI_THREAD
 MEM_LIB_SRC = multi_thread_qaememutils.c
endif

if QAE_MEM
 MEM_LIB_SRC = cmn_mem_drv_inf.c
 MEM_LIB_HEADER = cmn_mem_drv_inf.h
endif

libqat_la_SOURCES = e_qat.c \
				qat_asym_common.c \
				qat_ciphers.c \
				qat_dh.c \
				qat_dsa.c \
				qat_ec.c \
				qat_parseconf.c \
				qat_prf.c \
				qat_utils.c \
				qat_rsa.c \
				e_qat_err.c \
				${MEM_LIB_SRC}

include_HEADERS = e_qat.h \
					qat_asym_common.h \
					qat_ciphers.h \
					qat_dh.h \
					qat_dsa.h \
					qat_ec.h \
					qat_parseconf.h \
					qat_prf.h \
					qat_utils.h \
					qat_rsa.h \
					${MEM_LIB_HEADER}

CC = cc
INCLUDES = $(includes) $(include_enable_usdm) $(includes_driver) \
			$(includes_enable_qat_mux)

CFLAGS = $(cflags) $(cflags_cc_opt) $(cflags_enable_upstream_driver) \
		$(cflags_qat_contig_mem) $(cflags_enable_multi_thread) \
		$(cflags_enable_usdm) $(cflags_mux) $(disable_qat_rsa) \
		$(disable_qat_ciphers) $(disable_qat_ecdh) $(disable_qat_ecdsa) \
		$(disable_qat_dsa) $(disable_qat_dh) $(disable_qat_prf) \
		$(enable_qat_small_pkt_offload) \
		$(enable_qat_debug) $(enable_qat_warnings) \
		$(enable_qat_mem_debug) $(enable_qat_mem_warnings)

libqat_la_LDFLAGS = $(QAT_SHARED_LIB_DEPS_LD) \
					$(QAT_SHARED_LIB_DEPS_UPSTREAM_DRIVER) \
					$(QAT_SHARED_LIB_DEPS_DRIVER) \
					$(QAT_SHARED_LIB_DEPS_QAE_MEM)

mostlyclean-generic:
	-rm -f *.obj lib tags core .pure .nfs* \
	*.old *.bak fluff *.so *.sl *.dll e_qat_err*

	-rm -f $(with_openssl_install_dir)/lib/engines-1.1/qat.so

MAKE = perl $(with_openssl_dir)/util/mkerr.pl -conf e_qat.ec \
		-nostatic -write $(libqat_la_SOURCES) && make

install-data-am:
	-cp -f $(prefix)/lib/libqat.so \
	$(with_openssl_install_dir)/lib/engines-1.1/qat.so
