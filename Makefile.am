ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = qatengine.la

if OPENSSL_QAT_OFFLOAD
if QAT_CONTIG_MEM
 MEM_LIB_SRC = qae_mem_utils.c \
               qat_sys_call.c
endif

if QAT_MULTI_THREAD
 MEM_LIB_SRC = multi_thread_qaememutils.c \
               qat_sys_call.c
endif

if QAE_MEM
 MEM_LIB_SRC = cmn_mem_drv_inf.c
endif
endif

OPENSSL_COMMON_SRC = e_qat.c        \
                     e_qat_err.c    \
                     qat_fork.c     \
                     qat_events.c   \
                     qat_utils.c    \
                     qat_evp.c

if OPENSSL_MULTIBUFF_OFFLOAD
 OPENSSL_MULTIBUFF_SRC = multibuff_init.c     \
                         multibuff_polling.c  \
                         multibuff_freelist.c \
                         multibuff_queue.c    \
                         multibuff_rsa.c      \
                         multibuff_ecx.c
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
                   qat_prf.c         \
                   qat_gcm.c

if !QAT_OPENSSL_110
 OPENSSL_111_SRC = qat_hkdf.c        \
                   qat_ecx.c
endif
endif

if OPENSSL_IPSEC_OFFLOAD
  OPENSSL_VAES_SRC = vaes_gcm.c      \
                     vaes_ipsec_inf.c
endif

qatengine_la_SOURCES = ${OPENSSL_COMMON_SRC}    \
                       ${OPENSSL_QAT_SRC}       \
                       ${OPENSSL_111_SRC}       \
                       ${OPENSSL_MULTIBUFF_SRC} \
                       ${MEM_LIB_SRC}           \
                       ${OPENSSL_VAES_SRC}

AM_CPPFLAGS = $(includes_openssl) $(includes_usdm) $(includes_driver) \
              $(includes_multibuff) $(includes_ipsec)

AM_CFLAGS = $(cflags) $(cflags_cc_opt) $(cflags_qat_intree)           \
            $(cflags_mem_driver) $(cflags_openssl_300)                \
            $(cflags_qat_offload) $(cflags_multibuff_offload)         \
            $(cflags_ipsec_offload) $(enable_qat_rsa)                 \
            $(enable_qat_ciphers) $(enable_qat_gcm) $(enable_qat_dh)  \
            $(enable_qat_ecdsa) $(enable_qat_dsa) $(enable_qat_ecdh)  \
            $(enable_qat_prf) $(enable_qat_hkdf) $(enable_qat_ecx)    \
            $(enable_vaes_gcm) $(enable_multibuff_rsa)                \
            $(enable_multibuff_ecx) $(enable_qat_small_pkt_offload)   \
            $(enable_qat_auto_engine_init_on_fork)                    \
            $(enable_qat_lenstra_protection) $(cflags_qat_engine_id)  \
            $(enable_qat_debug) $(enable_qat_warnings)                \
            $(enable_qat_mem_debug) $(enable_qat_mem_warnings)        \
            $(cflags_qat_debug_file) $(enable_qat_cycle_counts)       \
            $(enable_multibuff_heuristic_timeout)


qatengine_la_LDFLAGS = -module -no-undefined -avoid-version \
                       -shared $(QAT_SHARED_LIB_DEPS_LD)    \
                       $(QAT_SHARED_LIB_DEPS_DRIVER)        \
                       $(QAT_SHARED_LIB_DEPS_QAE_MEM)       \
                       $(QAT_SHARED_LIB_DEPS_MULTIBUFF)     \
                       $(QAT_SHARED_LIB_DEPS_IPSEC)

mostlyclean-generic:
	-rm -f *.obj lib tags core .pure .nfs* \
	*.old *.bak fluff *.so *.sl *.dll

if QAT_ERR_FILES_BUILD
MAKE = make err-files && make
endif

err-files:
if QAT_OPENSSL_110
	rm -rf e_qat_err* && perl $(with_openssl_dir)/util/mkerr.pl -conf e_qat.ec \
       -rebuild -reindex -nostatic -write *.c

else
	rm -f e_qat_err.c e_qat.txt && perl $(with_openssl_dir)/util/mkerr.pl -conf e_qat.ec \
       -rebuild -reindex *.c
endif
