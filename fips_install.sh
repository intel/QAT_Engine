#!/bin/sh
./autogen.sh
if [ "$QAT_HW_ENABLED" = "1" ] && [ "$QAT_SW_ENABLED" = "1" ]
then
cp -f /usr/lib64/build/qat_4xxx.ko $OPENSSL_ENGINES/
cp -f /usr/lib64/build/usdm_drv.ko $OPENSSL_ENGINES/
cp -f /usr/lib64/build/intel_qat.ko $OPENSSL_ENGINES/
cp -f /usr/lib64/libusdm_drv_s.so $OPENSSL_ENGINES/
cp -f /usr/lib64/libqat_s.so $OPENSSL_ENGINES/
cp -f /lib/firmware/qat_4xxx.bin $OPENSSL_ENGINES/
cp -f /lib/firmware/qat_4xxx_mmp.bin $OPENSSL_ENGINES/
cp -f /usr/lib64/libIPSec_MB.so $OPENSSL_ENGINES/
cp -f /usr/lib64/libcrypto_mb.so $OPENSSL_ENGINES/
./configure --with-qat_hw_dir=$ICP_ROOT --with-openssl_install_dir=$OPENSSL_LIB --enable-qat_sw --enable-qat_provider --enable-qat_hw_sha3 --enable-qat_hw_gcm --enable-qat_hw_hkdf --enable-qat_fips --enable-qat_insecure_algorithms
make clean
make -j 30
make install
make intkat
cp -f $OPENSSL_ENGINES/qatprovider.so /usr/lib64/ossl-modules/
echo "=================================================================================="
echo "* Note:
* Before running the script, Please ensure below files are available in below paths.
* If not, Please Copy them Manually.
* qat_4xxx.ko, usdm_drv.ko, intel_qat.ko files to '/usr/lib64/build/'
* qat_4xxx.bin, qat_4xxx_mmp.bin to '/lib/firmware/'
* libusdm_drv_s.so, libqat_s.so, libIPSec_MB.so, libcrypto_mb.so files to '/usr/lib64/'
* export 'SYS_OPENSSL_PATH' as openssl install path which contains bin.
* eg. SYS_OPENSSL_PATH=/root/openssl_install/ "
else
if [ "$QAT_HW_ENABLED" = "1" ]
then
cp -f /usr/lib64/build/qat_4xxx.ko $OPENSSL_ENGINES/
cp -f /usr/lib64/build/usdm_drv.ko $OPENSSL_ENGINES/
cp -f /usr/lib64/build/intel_qat.ko $OPENSSL_ENGINES/
cp -f /usr/lib64/libusdm_drv_s.so $OPENSSL_ENGINES/
cp -f /usr/lib64/libqat_s.so $OPENSSL_ENGINES/
cp -f /lib/firmware/qat_4xxx.bin $OPENSSL_ENGINES/
cp -f /lib/firmware/qat_4xxx_mmp.bin $OPENSSL_ENGINES/
./configure --with-qat_hw_dir=$ICP_ROOT --with-openssl_install_dir=$OPENSSL_LIB --enable-qat_provider --enable-qat_hw_sha3 --enable-qat_hw_gcm --enable-qat_hw_hkdf --enable-qat_fips --enable-qat_insecure_algorithms
else
cp -f /usr/lib64/libIPSec_MB.so $OPENSSL_ENGINES/
cp -f /usr/lib64/libcrypto_mb.so $OPENSSL_ENGINES/
./configure --with-openssl_install_dir=$OPENSSL_LIB --enable-qat_sw --enable-qat_provider --enable-qat_fips
fi
make clean
make -j 30
make install
make intkat
cp -f $OPENSSL_ENGINES/qatprovider.so /usr/lib64/ossl-modules/
echo "=================================================================================="
if [ "$QAT_HW_ENABLED" = "1" ]
then
echo "* Note:
* Before running the script, Please ensure below files are available in below paths.
* If not, Please Copy them Manually.
* qat_4xxx.ko, usdm_drv.ko, intel_qat.ko files to '/usr/lib64/build/'
* libusdm_drv_s.so, libqat_s.so to '/usr/lib64/'
* qat_4xxx.bin, qat_4xxx_mmp.bin to '/lib/firmware/'
* export 'SYS_OPENSSL_PATH' as openssl install path which contains bin.
* eg. SYS_OPENSSL_PATH=/root/openssl_install/ "
else
echo "* Note:
* Before running the script, Please ensure below files are available in below path.
* If not, Please Copy them Manually.
* libIPSec_MB.so, libcrypto_mb.so files to '/usr/lib64/'
* export 'SYS_OPENSSL_PATH' as openssl install path which contains bin.
* eg. SYS_OPENSSL_PATH=/root/openssl_install/ "
fi
fi

