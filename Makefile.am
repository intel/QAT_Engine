ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = subdir-objects

lib_LTLIBRARIES = @LIBQATNAME@.la
bin_PROGRAMS =

if !QAT_BORINGSSL
 QAT_COMMON_SRC = e_qat.c      \
                  qat_fork.c   \
                  qat_events.c \
                  qat_utils.c  \
                  qat_evp.c    \
                  qat_err.c

if QAT_PROVIDER
 QAT_PROV_SRC = qat_prov_init.c           \
                qat_prov_kmgmt_rsa.c      \
                qat_prov_sign_rsa.c       \
                qat_prov_rsa.c            \
                qat_prov_rsa_enc_dec.c    \
                qat_prov_kmgmt_ecx.c      \
                qat_prov_exch_ecx.c       \
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
                qat_prov_sign_sm2.c       \
                qat_prov_hkdf_packet.c    \
                qat_prov_sm4_gcm.c        \
                qat_prov_sm4_ccm.c        \
                qat_prov_sm4_cbc.c        \
                qat_prov_sm3.c            \
                qat_prov_aes_ccm.c


if QAT_FIPS
 QAT_FIPS_SRC = qat_fips.c                \
                qat_self_test_kats.c      \
                qat_self_test_tls_prf.c   \
                qat_prov_cmvp.c           \
                qat_prov_sha2.c           \
                qat_sw_sha2.c
endif
endif

if QAT_HW
 QAT_HW_SRC = qat_hw_init.c        \
              qat_hw_asym_common.c \
              qat_hw_polling.c     \
              qat_hw_callback.c    \
              qat_hw_usdm_inf.c    \
              qat_hw_rsa.c         \
              qat_hw_ciphers.c     \
              qat_hw_dh.c          \
              qat_hw_dsa.c         \
              qat_hw_ec.c          \
              qat_hw_prf.c         \
              qat_hw_gcm.c         \
              qat_hw_hkdf.c        \
              qat_hw_ecx.c         \
              qat_hw_sha3.c        \
              qat_hw_chachapoly.c  \
              qat_hw_sm4_cbc.c     \
              qat_hw_sm3.c         \
              qat_hw_sm2.c         \
              qat_hw_ccm.c

if ENABLE_QAT_HW_KPT
 QAT_HW_KPT_SRC = qat_hw_kpt.c
endif
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
              qat_sw_sm3.c      \
              qat_sw_sm4_cbc.c  \
              qat_sw_sm4_gcm.c  \
              qat_sw_sm4_ccm.c
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
                  qat_bssl.c   \
                  qat_bssl_err.c

if QAT_HW
 QAT_HW_SRC = qat_hw_init.c        \
              qat_hw_asym_common.c \
              qat_hw_usdm_inf.c    \
              qat_hw_polling.c     \
              qat_hw_callback.c    \
              qat_hw_rsa.c         \
              qat_hw_ec.c
endif

if QAT_SW
 QAT_SW_SRC = qat_sw_init.c     \
              qat_sw_polling.c  \
              qat_sw_freelist.c \
              qat_sw_queue.c    \
              qat_sw_rsa.c      \
              qat_sw_ec.c
endif

endif

@LIBQATNAME@_la_SOURCES = ${QAT_COMMON_SRC}   \
                          ${QAT_PROV_SRC}     \
                          ${QAT_FIPS_SRC}     \
                          ${QAT_HW_SRC}       \
                          ${QAT_SW_SRC}       \
                          ${QAT_SW_IPSEC_SRC} \
                          ${QAT_HW_KPT_SRC}

AM_CPPFLAGS = $(includes_openssl) $(includes_qat_hw) $(includes_qat_sw_crypto_mb) \
              $(includes_qat_sw_ipsec_mb) $(includes_kpt_lib)

AM_CFLAGS = $(cflags_cc_opt) $(cflags_qat_hw_intree) \
            $(cflags_openssl_3) $(cflags_boringssl)  \
            $(cflags_qat_hw) $(cflags_qat_sw)        \
            $(cflags_qat_sw_ipsec) $(cflags_common)  \
            $(cflags_qat_debug)

if QAT_BORINGSSL
bin_PROGRAMS += qatengine_test
@LIBQATNAME@_la_LDFLAGS = -no-undefined -avoid-version                \
                          $(QAT_LD_LIB) $(QAT_HW_DRIVER_LIB)          \
                          $(QAT_SW_CRYPTO_MB_LIB)                     \
                          $(QAT_SW_IPSEC_MB_LIB) $(QAT_BORINGSSL_LIB)
qatengine_test_LDFLAGS = $(QAT_LD_LIB) $(QAT_HW_DRIVER_LIB)           \
                         $(QAT_SW_CRYPTO_MB_LIB)                      \
                         $(QAT_SW_IPSEC_MB_LIB) $(QAT_BORINGSSL_LIB)
qatengine_test_SOURCES = test_bssl/main.c                             \
                         test_bssl/test_bssl_rsa.c                    \
                         test_bssl/test_bssl_ecdsa.c                  \
                         test_bssl/test_bssl_utils.c
qatengine_test_LDADD = $(lib_LTLIBRARIES) -lpthread
else
@LIBQATNAME@_la_LDFLAGS = -module -no-undefined -avoid-version        \
                          -shared $(QAT_LD_LIB) $(QAT_HW_DRIVER_LIB)  \
                          $(QAT_SW_CRYPTO_MB_LIB) $(QAT_SW_IPSEC_MB_LIB)
endif

if QAT_PLOCK
lib_LTLIBRARIES += libplock.la
libplock_la_LDFLAGS = --shared -fPIC -Wextra -Wundef                           \
                      -Wdeclaration-after-statement -Wfatal-errors             \
                      -Wtype-limits -Wshift-negative-value -Wshift-overflow=2  \
                      -Wduplicated-cond -Wnull-dereference                     \
                      -Wno-address-of-packed-member -Wno-unused-label          \
                      -Wno-sign-compare -Wno-unused-parameter -Wno-clobbered   \
                      -Wno-missing-field-initializers -Wno-cast-function-type  \
                      -Wno-string-plus-int -Wno-atomic-alignment
libplock_la_SOURCES = plock.c
endif

if ENABLE_QAT_HW_KPT
noinst_LTLIBRARIES = libkpt.la
libkpt_la_SOURCES = kpt/lib/kpt.c
libkpt_la_CFLAGS = $(includes_qat_hw) $(includes_openssl) \
                   $(cflags) $(cflags_openssl_3)          \
                   $(cflags_common)
libkpt_la_LDFLAGS = $(QAT_LD_LIB) $(QAT_HW_DRIVER_LIB)    \
                    $(OPENSSL_LIB) -ldl -lrt -lpthread

EXTRA_PROGRAMS = kpttool testapp
kpttool_SOURCES = kpt/apps/main.c        \
                  kpt/apps/kpt_swk.c     \
                  kpt/apps/kpt_rsa_key.c \
                  kpt/apps/kpt_ecc_key.c \
                  kpt/apps/kpt_dev_pp.c
kpttool_CFLAGS = $(includes_qat_hw) $(includes_openssl) \
                 $(cflags_openssl_3)                    \
                 -fPIE -pie -g -static -z relro -z now
kpttool_LDFLAGS = $(QAT_LD_LIB) $(QAT_HW_DRIVER_LIB)
kpttool_LDADD = $(OPENSSL_LIB) -lpthread -ldl -lrt
@LIBQATNAME@_la_LIBADD = libkpt.la
endif

mostlyclean-generic:
	-rm -rf *.obj bin lib tags core .pure .nfs* \
	*.old *.bak fluff *.so *.sl *.dll test/*.obj testapp \
	test/.dirstamp test/*.o test_bssl/*obj test_bssl/.dirstamp \
	test_bssl/*.o qatengine_test rpmbuild kpttool

if QAT_ERR_FILES_BUILD
MAKE = make err-files && make
endif

err-files:
	perl -I$(with_openssl_dir) $(with_openssl_dir)/util/mkerr.pl -conf qat.ec \
         -rebuild -reindex `ls *.c`

if QAT_FIPS
intkat:
	$(shell ./intkat.sh)
endif

if QAT_HW
depend: OpenSSL qat_hw_driver
endif
if QAT_SW
depend: OpenSSL ipsec_mb crypto_mb
endif
OpenSSL:
	cd openssl && ./config -Wl,-rpath,$(with_openssl_install_dir)/lib64 --prefix=$(with_openssl_install_dir) && make clean && make -j$(nproc) && make install -j$(nproc)

if QAT_HW
qat_hw_driver:
	bash ./driver_install.sh $(with_qat_hw_dir)
if QAT_4XXX
if !QAT_HW_INTREE
cflags_qat_hw += "-DQAT20_OOT"
endif
endif
endif

if QAT_SW
ipsec_mb:
	cd intel-ipsec-mb && make uninstall && make clean && make -j$(nproc) && make install -j$(nproc)

crypto_mb:
	cd cryptography-primitives/sources/ippcp/crypto_mb && rm -rf build && cmake . -B"build" -DOPENSSL_INCLUDE_DIR=$(with_openssl_install_dir)/include -DOPENSSL_LIBRARIES=$(with_openssl_install_dir) -DOPENSSL_ROOT_DIR=$(PWD)/openssl && cd build && make clean && make -j$(nproc) && make install -j$(nproc)
endif

if QAT_4XXX
rpm_oot:
	mkdir -p rpmbuild/BUILD rpmbuild/RPMS rpmbuild/SOURCES rpmbuild/SPECS rpmbuild/SRPMS
	cp qatengine-oot.spec rpmbuild/SPECS/
	rpmbuild --undefine=_disable_source_fetch --define "_topdir $(abs_srcdir)/rpmbuild" -ba rpmbuild/SPECS/qatengine-oot.spec
endif

rpm_intree:
	mkdir -p rpmbuild/BUILD rpmbuild/RPMS rpmbuild/SOURCES rpmbuild/SPECS rpmbuild/SRPMS
	rpmbuild --undefine=_disable_source_fetch --define "_topdir $(abs_srcdir)/rpmbuild" -ba qatengine.spec
include test.am
