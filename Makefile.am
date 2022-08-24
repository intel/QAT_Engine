ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = subdir-objects

lib_LTLIBRARIES = @LIBQATNAME@.la
if QAT_BORINGSSL
bin_PROGRAMS = qatengine_test
endif

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

if !QAT_BORINGSSL
 QAT_COMMON_SRC = e_qat.c     \
                 qat_fork.c   \
                 qat_events.c \
                 qat_utils.c  \
                 qat_evp.c

if QAT_PROVIDER
 QAT_PROV_SRC = qat_prov_init.c           \
                qat_prov_kmgmt_rsa.c      \
                qat_prov_sign_rsa.c       \
                qat_prov_rsa.c            \
                qat_prov_kmgmt_ecx.c      \
                qat_prov_exch_ecx.c       \
                qat_prov_hw_ecx.c         \
                qat_prov_sw_ecx.c         \
                qat_prov_ciphers.c        \
                qat_prov_kmgmt_ec.c       \
                qat_prov_ecdsa.c          \
                qat_prov_ecdh.c           \
                qat_prov_dsa.c            \
                qat_prov_kmgmt_dsa.c      \
                qat_prov_dh.c             \
                qat_prov_kmgmt_dh.c       \
                qat_prov_hkdf.c           \
                qat_prov_prf.c            \
                qat_prov_cbc.c            \
                qat_prov_sha3.c           \
                qat_prov_bio.c            \
                qat_prov_capabilities.c   \
                qat_prov_chachapoly.c     \
                qat_prov_sign_sm2.c
endif

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
              qat_hw_gcm.c         \
              qat_hw_hkdf.c        \
              qat_hw_ecx.c         \
              qat_hw_sha3.c        \
              qat_hw_chachapoly.c
endif

if QAT_SW
 QAT_SW_SRC = qat_sw_init.c     \
              qat_sw_polling.c  \
              qat_sw_freelist.c \
              qat_sw_queue.c    \
              qat_sw_rsa.c      \
              qat_sw_ecx.c      \
              qat_sw_ec.c       \
              qat_sw_sm2.c      \
              qat_sw_sm3.c
endif

if QAT_SW_IPSEC
  QAT_SW_IPSEC_SRC = qat_sw_gcm.c       \
                     qat_sw_ipsec_inf.c
endif
endif

if QAT_BORINGSSL
 QAT_COMMON_SRC = e_qat.c      \
                  qat_utils.c  \
                  qat_fork.c   \
                  qat_events.c \
                  qat_evp.c    \
                  qat_bssl.c

QAT_ERR_SRC = qat_bssl_err.c

if QAT_HW
 QAT_HW_SRC = qat_hw_init.c        \
              qat_hw_asym_common.c \
              qat_hw_polling.c     \
              qat_hw_callback.c    \
              qat_hw_rsa.c         \
              qat_hw_rsa_crt.c     \
              qat_hw_ec.c
endif
endif

@LIBQATNAME@_la_SOURCES = ${QAT_COMMON_SRC}   \
                          ${QAT_PROV_SRC}     \
                          ${QAT_ERR_SRC}      \
                          ${QAT_HW_SRC}       \
                          ${QAT_HW_MEM_SRC}   \
                          ${QAT_SW_SRC}       \
                          ${QAT_SW_IPSEC_SRC}

AM_CPPFLAGS = $(includes_openssl) $(includes_qat_hw_usdm)     \
              $(includes_qat_hw) $(includes_qat_sw_crypto_mb) \
              $(includes_qat_sw_ipsec_mb)

AM_CFLAGS = $(cflags) $(cflags_cc_opt) $(cflags_qat_debug_file)      \
            $(cflags_mem_driver) $(cflags_openssl_3)                 \
            $(cflags_boringssl)                                      \
            $(cflags_qat_engine_id) $(cflags_qat_hw_intree)          \
            $(cflags_qat_hw) $(cflags_qat_sw) $(cflags_qat_sw_ipsec) \
            $(cflags_qat_rsa) $(cflags_qat_ecx) $(cflags_qat_ecdsa)  \
            $(cflags_qat_ecdh) $(cflags_qat_gcm) $(enable_qat_hw_dh) \
            $(enable_qat_hw_dsa) $(enable_qat_hw_ciphers)            \
            $(enable_qat_hw_prf) $(enable_qat_hw_hkdf)               \
            $(enable_qat_hw_sha3) $(enable_qat_hw_chachapoly)        \
            $(enable_qat_sw_sm2) $(enable_qat_sw_sm3)                \
            $(enable_qat_hw_small_pkt_offload)                       \
            $(enable_qat_hw_lenstra_protection)                      \
            $(enable_qat_hw_lenstra_verify_hw)                       \
            $(enable_qat_sw_heuristic_timeout)                       \
            $(enable_qat_auto_engine_init_on_fork)                   \
            $(enable_qat_debug) $(enable_qat_warnings)               \
            $(enable_qat_mem_debug) $(enable_qat_mem_warnings)       \
            $(enable_qat_cycle_counts) $(enable_qat_hw_set_inst_thread)


@LIBQATNAME@_la_LDFLAGS = -module -no-undefined -avoid-version       \
                          -shared $(QAT_LD_LIB) $(QAT_HW_DRIVER_LIB) \
                          $(QAT_HW_MEM_LIB) $(QAT_SW_CRYPTO_MB_LIB)  \
                          $(QAT_SW_IPSEC_MB_LIB)
if QAT_BORINGSSL
override @LIBQATNAME@_la_LDFLAGS := $(subst -module, ,${@LIBQATNAME@_la_LDFLAGS}) $(QAT_BORINGSSL_LIB)
override @LIBQATNAME@_la_LDFLAGS := $(subst -shared, ,${@LIBQATNAME@_la_LDFLAGS}) $(QAT_BORINGSSL_LIB)
endif

if QAT_BORINGSSL
qatengine_test_LDFLAGS = $(QAT_LD_LIB) $(QAT_HW_DRIVER_LIB) \
                        $(QAT_HW_MEM_LIB) $(QAT_SW_CRYPTO_MB_LIB)  \
                        $(QAT_SW_IPSEC_MB_LIB) $(QAT_BORINGSSL_LIB)
qatengine_test_SOURCES = test_bssl/main.c test_bssl/test_bssl_rsa.c \
                         test_bssl/test_bssl_ecdsa.c test_bssl/test_bssl_utils.c
qatengine_test_LDADD = $(lib_LTLIBRARIES) -lpthread
endif

mostlyclean-generic:
	-rm -rf *.obj bin lib tags core .pure .nfs* \
	*.old *.bak fluff *.so *.sl *.dll test/*.obj testapp \
	test/.dirstamp test/*.o test_bssl/*obj test_bssl/.dirstamp \
       test_bssl/*.o qatengine_test

if QAT_ERR_FILES_BUILD
err_files_str != ls *.c | sed "s/qat_bssl_err.c//"
MAKE = make err-files && make
endif

err-files:
if QAT_OPENSSL_3
	perl -I$(with_openssl_dir) $(with_openssl_dir)/util/mkerr.pl -conf qat_prov.ec \
       -rebuild -reindex $(err_files_str)
else
	perl -I$(with_openssl_dir) $(with_openssl_dir)/util/mkerr.pl -conf e_qat.ec \
	   -rebuild -reindex $(err_files_str)
endif

include test.am
