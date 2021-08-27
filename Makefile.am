ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = qatengine.la

if QAT_HW
if QAT_HW_CONTIG_MEM
 QAT_HW_MEM_SRC = qae_mem_utils.c \
                  qat_sys_call.c
endif

if QAT_HW_MULTI_THREAD
 QAT_HW_MEM_SRC = qat_hw_multi_thread_inf.c \
                  qat_sys_call.c
endif

if QAT_HW_USDM
 QAT_HW_MEM_SRC = qat_hw_usdm_inf.c
endif
endif

QAT_COMMON_SRC = e_qat.c      \
                 qat_fork.c   \
                 qat_events.c \
                 qat_utils.c  \
                 qat_evp.c

if QAT_OPENSSL_3
QAT_ERR_SRC = qat_prov_err.c
else
QAT_ERR_SRC = e_qat_err.c
endif

if QAT_HW
 QAT_HW_SRC = qat_hw_init.c        \
              qat_hw_asym_common.c \
              qat_hw_polling.c     \
              qat_hw_callback.c    \
              qat_hw_rsa.c         \
              qat_hw_rsa_crt.c     \
              qat_hw_ciphers.c     \
              qat_hw_dh.c          \
              qat_hw_dsa.c         \
              qat_hw_ec.c          \
              qat_hw_prf.c         \
              qat_hw_gcm.c

if !QAT_OPENSSL_110
 QAT_HW_111_SRC = qat_hw_hkdf.c       \
                  qat_hw_ecx.c        \
                  qat_hw_sha3.c       \
                  qat_hw_chachapoly.c
endif
endif

if QAT_SW
 QAT_SW_SRC = qat_sw_init.c     \
              qat_sw_polling.c  \
              qat_sw_freelist.c \
              qat_sw_queue.c    \
              qat_sw_rsa.c      \
              qat_sw_ecx.c      \
              qat_sw_ec.c
endif

if QAT_SW_IPSEC
  QAT_SW_IPSEC_SRC = qat_sw_gcm.c       \
                     qat_sw_ipsec_inf.c
endif

qatengine_la_SOURCES = ${QAT_COMMON_SRC}   \
                       ${QAT_ERR_SRC}      \
                       ${QAT_HW_SRC}       \
                       ${QAT_HW_111_SRC}   \
                       ${QAT_HW_MEM_SRC}   \
                       ${QAT_SW_SRC}       \
                       ${QAT_SW_IPSEC_SRC}

AM_CPPFLAGS = $(includes_openssl) $(includes_qat_hw_usdm)  \
              $(includes_qat_hw) $(includes_qat_sw)

AM_CFLAGS = $(cflags) $(cflags_cc_opt) $(cflags_qat_debug_file)      \
            $(cflags_mem_driver) $(cflags_openssl_3)                 \
            $(cflags_qat_engine_id) $(cflags_qat_hw_intree)          \
            $(cflags_qat_hw) $(cflags_qat_sw) $(cflags_qat_sw_ipsec) \
            $(cflags_qat_rsa) $(cflags_qat_ecx) $(cflags_qat_ecdsa)  \
            $(cflags_qat_ecdh) $(cflags_qat_gcm) $(enable_qat_hw_dh) \
            $(enable_qat_hw_dsa) $(enable_qat_hw_ciphers)            \
            $(enable_qat_hw_prf) $(enable_qat_hw_hkdf)               \
            $(enable_qat_hw_sha3) $(enable_qat_hw_chachapoly)        \
            $(enable_qat_hw_small_pkt_offload)                       \
            $(enable_qat_hw_lenstra_protection)                      \
            $(enable_qat_hw_lenstra_verify_hw)                       \
            $(enable_qat_sw_heuristic_timeout)                       \
            $(enable_qat_auto_engine_init_on_fork)                   \
            $(enable_qat_debug) $(enable_qat_warnings)               \
            $(enable_qat_mem_debug) $(enable_qat_mem_warnings)       \
            $(enable_qat_cycle_counts)


qatengine_la_LDFLAGS = -module -no-undefined -avoid-version       \
                       -shared $(QAT_LD_LIB) $(QAT_HW_DRIVER_LIB) \
                       $(QAT_HW_MEM_LIB) $(QAT_SW_CRYPTO_MB_LIB)  \
                       $(QAT_SW_IPSEC_MB_LIB)

mostlyclean-generic:
	-rm -f *.obj lib tags core .pure .nfs* \
	*.old *.bak fluff *.so *.sl *.dll test/*.obj testapp

if QAT_ERR_FILES_BUILD
MAKE = make err-files && make
endif

err-files:
if QAT_OPENSSL_110
	rm -rf e_qat_err* && perl -I$(with_openssl_dir) \
       $(with_openssl_dir)/util/mkerr.pl -conf e_qat.ec \
       -rebuild -reindex -nostatic -write *.c
else
if QAT_OPENSSL_3
	perl -I$(with_openssl_dir) $(with_openssl_dir)/util/mkerr.pl -conf qat_prov.ec \
       -rebuild -reindex *.c
else
	rm -f e_qat_err.c e_qat.txt && perl -I$(with_openssl_dir) \
	   $(with_openssl_dir)/util/mkerr.pl -conf e_qat.ec \
	   -rebuild -reindex *.c
endif
endif

include test.am
