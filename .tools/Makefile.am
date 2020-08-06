
ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libqatengine.la

if OPENSSL_QAT_OFFLOAD
if QAT_CONTIG_MEM
 MEM_LIB_SRC = qae_mem_utils.c \
               qat_sys_call.c
 MEM_LIB_HDR = qae_mem_utils.h \
               qat_sys_call.h
endif

if QAT_MULTI_THREAD
 MEM_LIB_SRC = multi_thread_qaememutils.c \
               qat_sys_call.c
endif

if QAE_MEM
 MEM_LIB_SRC = cmn_mem_drv_inf.c
 MEM_LIB_HDR = cmn_mem_drv_inf.h
endif
endif

OPENSSL_COMMON_SRC = e_qat.c        \
                     e_qat_err.c    \
                     qat_fork.c     \
                     qat_events.c   \
                     qat_utils.c    \
                     qat_evp.c

OPENSSL_COMMON_HDR = e_qat.h        \
                     e_qat_err.h    \
                     qat_fork.h     \
                     qat_events.h   \
                     qat_utils.h    \
                     qat_evp.h


if OPENSSL_MULTIBUFF_OFFLOAD
 OPENSSL_MULTIBUFF_SRC = multibuff_init.c     \
                         multibuff_polling.c  \
                         multibuff_freelist.c \
                         multibuff_queue.c    \
                         multibuff_rsa.c      \
                         multibuff_ecx.c

 OPENSSL_MULTIBUFF_HDR = multibuff_polling.h  \
                         multibuff_freelist.h \
                         multibuff_queue.h    \
                         multibuff_rsa.h      \
                         multibuff_ecx.h
endif

if OPENSSL_QAT_OFFLOAD
 OPENSSL_QAT_SRC = qat_init.c        \
                   qat_asym_common.c \
                   qat_polling.c     \
                   qat_callback.c    \
                   qat_rsa.c         \
                   qat_rsa_crt.c     \
                   qat_ciphers.c     \
                   qat_dh.c          \
                   qat_dsa.c         \
                   qat_ec.c          \
                   qat_prf.c

if !QAT_OPENSSL_110
 OPENSSL_111_SRC = qat_hkdf.c        \
                   qat_ecx.c
endif

 OPENSSL_QAT_HDR = qat_asym_common.h \
                   qat_polling.h     \
                   qat_callback.h    \
                   qat_rsa.h         \
                   qat_rsa_crt.h     \
                   qat_ciphers.h     \
                   qat_dh.h          \
                   qat_dsa.h         \
                   qat_ec.h
endif

if OPENSSL_IPSEC_OFFLOAD
  OPENSSL_VAES_SRC = vaes_gcm.c      \
                     vaes_ipsec_inf.c
  OPENSSL_VAES_HDR = vaes_gcm.h
endif

if !OPENSSL_ENABLE_QAT_UPSTREAM_DRIVER
 PARSE_CONFIG_FILES_SRC = qat_parseconf.c
 PARSE_CONFIG_FILES_HDR = qat_parseconf.h
endif

libqatengine_la_SOURCES = ${OPENSSL_COMMON_SRC}     \
                          ${OPENSSL_QAT_SRC}        \
                          ${OPENSSL_111_SRC}        \
                          ${OPENSSL_MULTIBUFF_SRC}  \
                          ${PARSE_CONFIG_FILES_SRC} \
                          ${MEM_LIB_SRC}            \
                          ${OPENSSL_VAES_SRC}

include_HEADERS = ${OPENSSL_COMMON_HDR}     \
                  ${OPENSSL_QAT_HDR}        \
                  ${OPENSSL_MULTIBUFF_HDR}  \
                  ${PARSE_CONFIG_FILES_HDR} \
                  ${MEM_LIB_HDR}            \
                  ${OPENSSL_VAES_HDR}

CC = gcc

AM_CPPFLAGS = $(includes_openssl) $(include_enable_usdm) $(includes_driver) \
              $(includes_qat_mux) $(includes_multibuff) $(includes_ipsec)

AM_CFLAGS = $(cflags) $(cflags_cc_opt) $(cflags_upstream_driver)             \
            $(cflags_mem_driver) $(cflags_mux) $(cflags_qat_debug_file)      \
            $(cflags_openssl_300) $(cflags_multibuff_offload)                \
            $(cflags_qat_offload) $(cflags_ipsec_offload)                    \
            $(enable_qat_rsa) $(enable_qat_ciphers) $(enable_qat_ecdh)       \
            $(enable_qat_ecdsa) $(enable_qat_dsa) $(enable_qat_dh)           \
            $(enable_qat_prf) $(enable_qat_hkdf) $(enable_qat_ecx)           \
            $(enable_vaes_gcm) $(enable_qat_small_pkt_offload)               \
            $(enable_qat_auto_engine_init_on_fork)                           \
            $(enable_qat_lenstra_protection) $(cflags_qat_engine_id)         \
            $(cflags_qat_intree) $(enable_qat_debug) $(enable_qat_warnings)  \
            $(enable_qat_mem_debug) $(enable_qat_mem_warnings)               \
            $(enable_qat_cycle_counts) $(enable_multibuff_rsa)               \
            $(enable_multibuff_ecx) $(enable_multibuff_heuristic_timeout)


libqatengine_la_LDFLAGS = $(QAT_SHARED_LIB_DEPS_LD)        \
                          $(QAT_SHARED_LIB_DEPS_DRIVER)    \
                          $(QAT_SHARED_LIB_DEPS_QAE_MEM)   \
                          $(QAT_SHARED_LIB_DEPS_MULTIBUFF) \
                          $(QAT_SHARED_LIB_DEPS_IPSEC)

mostlyclean-generic:
	-rm -f *.obj lib tags core .pure .nfs* \
	*.old *.bak fluff *.so *.sl *.dll

	-rm -f $(engine_install_dir)/$(with_qat_engine_id).so

if QAT_ERR_FILES_BUILD
MAKE = make err-files && make
endif

install-data-am:
	cp -f .libs/libqatengine.so $(engine_install_dir)/$(with_qat_engine_id).so

err-files:
if QAT_OPENSSL_110
	rm -rf e_qat_err* && perl $(with_openssl_dir)/util/mkerr.pl -conf e_qat.ec \
       -rebuild -reindex -nostatic -write *.c

else
	rm -f e_qat_err.c e_qat.txt && perl $(with_openssl_dir)/util/mkerr.pl -conf e_qat.ec \
       -rebuild -reindex *.c
endif
