# CC contains the current compiler
CC = cc

# ICP_ROOT (mandatory) contains the path of the QAT package
ifndef ICP_ROOT
 $(error Env variable ICP_ROOT must be set)
endif

# OPENSSL_ENGINES (mandatory) contains the path of where
# OpenSSL engines were installed to
ifndef OPENSSL_ENGINES
 $(error Env variable OPENSSL_ENGINES must be set)
endif

# OPENSSL_ROOT (optional) contains the path of OpenSSL
# If the variable is not set, we assume the QAT engine is built
# from ./engines/qat_engine
ifdef OPENSSL_ROOT
 TOP = $(OPENSSL_ROOT)
else
 TOP = ../..
endif

INCLUDES = -I$(TOP)/include -I$(TOP)

# -fPIC is required to build as shared lib
CFLAG = -fPIC

ifeq ($(MAKEFILE),)
 MAKEFILE := Makefile
endif

# CFLAGS contains flags and include paths for the compiler
CFLAGS += $(INCLUDES) $(CFLAG)


# QAT_FLAGS is an optional variable used for QAT specific build flags
ifdef QAT_FLAGS
 CFLAGS += $(QAT_FLAGS)
endif

ifdef UPSTREAM_DRIVER_CMN_ROOT
 CFLAGS += -DOPENSSL_ENABLE_QAT_UPSTREAM_DRIVER
endif

ifdef CMN_ROOT
 CRYPTO_MEMORY_DRIVER = qae_mem
 CFLAGS += -DUSE_QAE_MEM
 INCLUDES += -I./
 INCLUDES += -I$(CMN_ROOT)
else
 ifdef MULTI_THREAD_MEMUTILS
  CRYPTO_MEMORY_DRIVER = multi_thread
  CFLAGS += -DUSE_QAT_CONTIG_MEM -Iqat_contig_mem
 else
  CRYPTO_MEMORY_DRIVER = qat_contig_mem
  CFLAGS += -DUSE_QAT_CONTIG_MEM -Iqat_contig_mem
 endif
endif

# Include path for Intel QAT API
ifdef ICP_API_PATH
 ICP_API_DIR = $(ICP_API_PATH)
else
 ICP_API_DIR = ${ICP_ROOT}/quickassist/include
endif

ifdef ICP_SAL_API_PATH
 ICP_SAL_API_DIR = $(ICP_SAL_API_PATH)
else
 ICP_SAL_API_DIR = $(ICP_ROOT)/quickassist/lookaside/access_layer/include
endif

ICP_LAC_API_DIR = $(ICP_API_DIR)/lac

# QAT Driver
INCLUDES += -I$(ICP_API_DIR) -I$(ICP_LAC_API_DIR) -I$(ICP_SAL_API_DIR)
DRIVER = icp_qa_al
ifdef WITH_CPA_MUX
 ICP_MUX_DIR = $(ICP_ROOT)/../QAT1.5/quickassist/include
 ICP_DC_DIR = $(ICP_API_DIR)/dc
 CFLAGS += -DWITH_CPA_MUX
 INCLUDES += -I$(ICP_MUX_DIR) -I$(ICP_DC_DIR)
 DRIVER = qat_mux
endif

# Source files that are shared between the 2 mem drivers
QAT_LIB_SRC_COMMON = e_qat.c\
	 qat_utils.c\
	 qat_ciphers.c\
	 qat_rsa.c\
	 qat_dsa.c\
	 qat_dh.c\
	 qat_ec.c\
	 qat_asym_common.c\
	 e_qat_err.c\
	 qat_parseconf.c\
	 qat_prf.c

QAT_LIB_OBJ_COMMON = e_qat.o\
	 qat_utils.o\
	 qat_ciphers.o\
	 qat_rsa.o\
	 qat_dsa.o\
	 qat_dh.o\
	 qat_ec.o\
	 qat_asym_common.o\
	 e_qat_err.o\
	 qat_parseconf.o\
	 qat_prf.o

ifeq ($(CRYPTO_MEMORY_DRIVER),qat_contig_mem)
 QAT_LIB_SRC = $(QAT_LIB_SRC_COMMON)  qae_mem_utils.c
 QAT_LIB_OBJ = $(QAT_LIB_OBJ_COMMON)  qae_mem_utils.o
 QAT_MEMLIB_OBJ = qae_mem_utils.o
 QAT_MEMLIB_NAME = libqae_mem_utils
 QAT_MEMLIB_DEPS =
endif
ifeq ($(CRYPTO_MEMORY_DRIVER),multi_thread)
 QAT_LIB_SRC = $(QAT_LIB_SRC_COMMON)  multi_thread_qaememutils.c
 QAT_LIB_OBJ = $(QAT_LIB_OBJ_COMMON)  multi_thread_qaememutils.o
 QAT_MEMLIB_OBJ = multi_thread_qaememutils.o
 QAT_MEMLIB_NAME = libmulti_thread_qaememutils
 QAT_MEMLIB_DEPS =
endif
ifeq ($(CRYPTO_MEMORY_DRIVER),qae_mem)
 QAT_LIB_SRC = $(QAT_LIB_SRC_COMMON) cmn_mem_drv_inf.c
 QAT_LIB_OBJ = $(QAT_LIB_OBJ_COMMON) cmn_mem_drv_inf.o
 QAT_MEMLIB_OBJ = cmn_mem_drv_inf.o
 QAT_MEMLIB_NAME = libcmn_mem_drv_inf
 QAT_MEMLIB_DEPS =
endif

SRC = $(QAT_LIB_SRC)
QAT_LIB_TARGET = $(TOP)/libcrypto.a

ifdef ICP_BUILD_OUTPUT
 ifdef UPSTREAM_DRIVER_CMN_ROOT
  QAT_SHARED_LIB_DEPS =-Wl,-rpath,$(UPSTREAM_DRIVER_CMN_ROOT) -L$(UPSTREAM_DRIVER_CMN_ROOT) -lqae_mem_s
  QAT_SHARED_LIB_DEPS +=-Wl,-rpath,$(ICP_BUILD_OUTPUT) -L$(ICP_BUILD_OUTPUT) -l$(DRIVER)_s -ludev
 else
  QAT_SHARED_LIB_DEPS =-Wl,-rpath,$(ICP_BUILD_OUTPUT) -L$(ICP_BUILD_OUTPUT) -l$(DRIVER)_s
 endif
else
 ifdef UPSTREAM_DRIVER_CMN_ROOT
  QAT_SHARED_LIB_DEPS =-Wl,-rpath,$(UPSTREAM_DRIVER_CMN_ROOT) -L$(UPSTREAM_DRIVER_CMN_ROOT) -lqae_mem_s
  QAT_SHARED_LIB_DEPS +=-l$(DRIVER)_s -ludev
 else
  QAT_SHARED_LIB_DEPS =-l$(DRIVER)_s
 endif
endif

ifeq ($(CRYPTO_MEMORY_DRIVER),qat_contig_mem)
 QAT_SHARED_LIB_DEPS += -L. -lqae_mem_utils
endif
ifeq ($(CRYPTO_MEMORY_DRIVER),multi_thread)
 QAT_SHARED_LIB_DEPS += -L. -lmulti_thread_qaememutils
endif
ifeq ($(CRYPTO_MEMORY_DRIVER),qae_mem)
 ifndef UPSTREAM_DRIVER_CMN_ROOT
  QAT_SHARED_LIB_DEPS += -Wl,-rpath,$(CMN_ROOT) -L$(CMN_ROOT) -lqae_mem_s
 endif
 QAT_SHARED_LIB_DEPS += -L. -lcmn_mem_drv_inf
endif

QAT_LIB_NAME = qat

.PHONEY: all lib


all: errors lib

tags:
	ctags $(SRC)

errors:
	perl $(TOP)/util/mkerr.pl -conf e_qat.ec -nostatic -write $(SRC)


SHLIB_TARGET = gnu

lib: $(QAT_LIB_OBJ) $(QAT_MEMLIB_OBJ)
	$(MAKE) -f $(TOP)/Makefile.shared -e \
					LIBNAME=$(QAT_MEMLIB_NAME) \
					LIBEXTRAS='$(QAT_MEMLIB_OBJ)' \
					LIBDEPS='$(QAT_MEMLIB_DEPS)' \
					link_dso.$(SHLIB_TARGET); \
	$(MAKE) -f $(TOP)/Makefile.shared -e \
					LIBNAME=$(QAT_LIB_NAME) \
					LIBEXTRAS='$(QAT_LIB_OBJ_COMMON)' \
					LIBDEPS='$(QAT_SHARED_LIB_DEPS)' \
					link_dso.$(SHLIB_TARGET); \



install:
	set -e; \
	echo Installing $(QAT_LIB_NAME); \
	cp $(QAT_LIB_NAME).so $(OPENSSL_ENGINES)/$(QAT_LIB_NAME).so; \
	cp $(QAT_MEMLIB_NAME).so $(OPENSSL_ENGINES)/../$(QAT_MEMLIB_NAME).so; \
	chmod 555 $(OPENSSL_ENGINES)/$(QAT_LIB_NAME).so; \
	chmod 555 $(OPENSSL_ENGINES)/../$(QAT_MEMLIB_NAME).so 

qae_mem_utils.o: qae_mem_utils.c
	$(CC) $(CFLAGS) -c -o qae_mem_utils.o qae_mem_utils.c

cmn_mem_drv_inf.o: cmn_mem_drv_inf.c
	$(CC) $(CFLAGS) -c -o cmn_mem_drv_inf.o cmn_mem_drv_inf.c


links:


tests:


# This variables are copied from the Makefile of OpenSSL
MAKEDEPPROG = gcc
MAKEDEPEND = $(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
DEPFLAG =

# The script /util/domd requires a valid value for the env variable PERL
depend: errors
	export PERL=perl; \
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(QAT_LIB_SRC);


files:



lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff


dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff *.so *.sl *.dll e_qat_err.*

# DO NOT DELETE THIS LINE -- make depend depends on it.

e_qat.o: e_qat.c e_qat.h e_qat_err.h qat_ciphers.h qat_dh.h 
e_qat.o: qat_dsa.h qat_ec.h qat_parseconf.h qat_rsa.h qat_prf.h 
e_qat.o: qat_utils.h
e_qat_err.o: e_qat_err.c e_qat_err.h
qae_mem_utils.o: qae_mem_utils.c qae_mem_utils.h
qat_asym_common.o: e_qat.h qat_asym_common.c qat_asym_common.h qat_ciphers.h
qat_asym_common.o: qat_utils.h
qat_ciphers.o: e_qat.h e_qat_err.h qat_ciphers.c qat_ciphers.h
qat_ciphers.o: qat_utils.h
qat_dh.o: e_qat.h e_qat_err.h qat_asym_common.h qat_ciphers.h qat_dh.c qat_dh.h
qat_dh.o: qat_utils.h
qat_dsa.o: e_qat.h e_qat_err.h qat_asym_common.h qat_ciphers.h qat_dsa.c
qat_dsa.o: qat_dsa.h qat_utils.h
qat_ec.o: e_qat.h e_qat_err.h qat_asym_common.h qat_ciphers.h qat_ec.c qat_ec.h
qat_ec.o: qat_utils.h
qat_parseconf.o: qat_parseconf.c qat_parseconf.h qat_utils.h
qat_rsa.o: e_qat.h e_qat_err.h qat_asym_common.h qat_ciphers.h qat_rsa.c
qat_rsa.o: qat_rsa.h qat_utils.h
qat_prf.o: e_qat.h e_qat_err.h qat_asym_common.h qat_prf.c
qat_prf.o: qat_prf.h qat_utils.h
qat_utils.o: e_qat.h qat_ciphers.h qat_utils.c qat_utils.h
