#!/bin/sh
$SYS_OPENSSL_PATH/bin/openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
if [ "$QAT_HW_ENABLED" = "1" ] && [ "$QAT_SW_ENABLED" = "1" ]
then
$SYS_OPENSSL_PATH/bin/openssl dgst -sha256 -sign private-key.pem $OPENSSL_ENGINES/qatprovider.so &> qat_signature.bin
$SYS_OPENSSL_PATH/bin/openssl dgst -sha256 -sign private-key.pem $OPENSSL_ENGINES/intel_qat.ko &> intel_qat_signature.bin
$SYS_OPENSSL_PATH/bin/openssl dgst -sha256 -sign private-key.pem $OPENSSL_ENGINES/libusdm_drv_s.so &> usdm_signature.bin
$SYS_OPENSSL_PATH/bin/openssl dgst -sha256 -sign private-key.pem $OPENSSL_ENGINES/libqat_s.so &> libqat_signature.bin
$SYS_OPENSSL_PATH/bin/openssl dgst -sha256 -sign private-key.pem $OPENSSL_ENGINES/qat_4xxx.ko &> qat_4xxx_signature.bin
$SYS_OPENSSL_PATH/bin/openssl dgst -sha256 -sign private-key.pem $OPENSSL_ENGINES/usdm_drv.ko &> usdm_drv_signature.bin
$SYS_OPENSSL_PATH/bin/openssl dgst -sha256 -sign private-key.pem $OPENSSL_ENGINES/qat_4xxx.bin &> qat_4xxx_bin_signature.bin
$SYS_OPENSSL_PATH/bin/openssl dgst -sha256 -sign private-key.pem $OPENSSL_ENGINES/qat_4xxx_mmp.bin &> qat_4xxx_mmp_signature.bin
$SYS_OPENSSL_PATH/bin/openssl dgst -sha256 -sign private-key.pem $OPENSSL_ENGINES/libIPSec_MB.so &> ipsec_mb_signature.bin
$SYS_OPENSSL_PATH/bin/openssl dgst -sha256 -sign private-key.pem $OPENSSL_ENGINES/libcrypto_mb.so &> libcrypto_mb_signature.bin

$SYS_OPENSSL_PATH/bin/openssl ec -in private-key.pem -text -noout &> ec_key.txt
sed -n 7,14p ec_key.txt &> pub_key.txt

objcopy --add-section .qat_sig=qat_signature.bin --set-section-flags .qat_sig=noload,readonly $OPENSSL_ENGINES/qatprovider.so
objcopy --add-section .iqat_sig=intel_qat_signature.bin --set-section-flags .iqat_sig=noload,readonly $OPENSSL_ENGINES/qatprovider.so
objcopy --add-section .usdm_sig=usdm_signature.bin --set-section-flags .usdm_sig=noload,readonly $OPENSSL_ENGINES/qatprovider.so
objcopy --add-section .libqat_sig=libqat_signature.bin --set-section-flags .libqat_sig=noload,readonly $OPENSSL_ENGINES/qatprovider.so
objcopy --add-section .qat_4xxx_sig=qat_4xxx_signature.bin --set-section-flags .qat_4xxx_sig=noload,readonly $OPENSSL_ENGINES/qatprovider.so
objcopy --add-section .usdm_drv_sig=usdm_drv_signature.bin --set-section-flags .usdm_drv_sig=noload,readonly $OPENSSL_ENGINES/qatprovider.so
objcopy --add-section .qat_4xxx_bin_sig=qat_4xxx_bin_signature.bin --set-section-flags .qat_4xxx_bin_sig=noload,readonly $OPENSSL_ENGINES/qatprovider.so
objcopy --add-section .qat_4xxx_mmp_sig=qat_4xxx_mmp_signature.bin --set-section-flags .qat_4xxx_mmp_sig=noload,readonly $OPENSSL_ENGINES/qatprovider.so
objcopy --add-section .ipsec_mb_sig=ipsec_mb_signature.bin --set-section-flags .ipsec_mb_sig=noload,readonly $OPENSSL_ENGINES/qatprovider.so
objcopy --add-section .libcrypto_mb_sig=libcrypto_mb_signature.bin --set-section-flags .libcrypto_mb_sig=noload,readonly $OPENSSL_ENGINES/qatprovider.so
objcopy --add-section .pub_key=pub_key.txt --set-section-flags .pub_key=noload,readonly $OPENSSL_ENGINES/qatprovider.so

rm -f qat_signature.bin
rm -f intel_qat_signature.bin
rm -f usdm_signature.bin
rm -f libqat_signature.bin
rm -f qat_4xxx_signature.bin
rm -f usdm_drv_signature.bin
rm -f qat_4xxx_bin_signature.bin
rm -f qat_4xxx_mmp_signature.bin
rm -f ipsec_mb_signature.bin
rm -f libcrypto_mb_signature.bin
rm -f pub_key.txt
rm -f ec_key.txt
rm -f private-key.pem

else
if [ "$QAT_HW_ENABLED" = "1" ]
then
$SYS_OPENSSL_PATH/bin/openssl dgst -sha3-256 -sign private-key.pem $OPENSSL_ENGINES/qatprovider.so &> qat_signature.bin
$SYS_OPENSSL_PATH/bin/openssl dgst -sha3-256 -sign private-key.pem $OPENSSL_ENGINES/intel_qat.ko &> intel_qat_signature.bin
$SYS_OPENSSL_PATH/bin/openssl dgst -sha3-256 -sign private-key.pem $OPENSSL_ENGINES/libusdm_drv_s.so &> usdm_signature.bin
$SYS_OPENSSL_PATH/bin/openssl dgst -sha3-256 -sign private-key.pem $OPENSSL_ENGINES/libqat_s.so &> libqat_signature.bin
$SYS_OPENSSL_PATH/bin/openssl dgst -sha3-256 -sign private-key.pem $OPENSSL_ENGINES/qat_4xxx.ko &> qat_4xxx_signature.bin
$SYS_OPENSSL_PATH/bin/openssl dgst -sha3-256 -sign private-key.pem $OPENSSL_ENGINES/usdm_drv.ko &> usdm_drv_signature.bin
$SYS_OPENSSL_PATH/bin/openssl dgst -sha3-256 -sign private-key.pem $OPENSSL_ENGINES/qat_4xxx.bin &> qat_4xxx_bin_signature.bin
$SYS_OPENSSL_PATH/bin/openssl dgst -sha3-256 -sign private-key.pem $OPENSSL_ENGINES/qat_4xxx_mmp.bin &> qat_4xxx_mmp_signature.bin
else
$SYS_OPENSSL_PATH/bin/openssl dgst -sha256 -sign private-key.pem $OPENSSL_ENGINES/qatprovider.so &> qat_signature.bin
$SYS_OPENSSL_PATH/bin/openssl dgst -sha256 -sign private-key.pem $OPENSSL_ENGINES/libIPSec_MB.so &> ipsec_mb_signature.bin
$SYS_OPENSSL_PATH/bin/openssl dgst -sha256 -sign private-key.pem $OPENSSL_ENGINES/libcrypto_mb.so &> libcrypto_mb_signature.bin
fi

$SYS_OPENSSL_PATH/bin/openssl ec -in private-key.pem -text -noout &> ec_key.txt
sed -n 7,14p ec_key.txt &> pub_key.txt
objcopy --add-section .qat_sig=qat_signature.bin --set-section-flags .qat_sig=noload,readonly $OPENSSL_ENGINES/qatprovider.so
if [ "$QAT_HW_ENABLED" = "1" ]
then
objcopy --add-section .iqat_sig=intel_qat_signature.bin --set-section-flags .iqat_sig=noload,readonly $OPENSSL_ENGINES/qatprovider.so
objcopy --add-section .usdm_sig=usdm_signature.bin --set-section-flags .usdm_sig=noload,readonly $OPENSSL_ENGINES/qatprovider.so
objcopy --add-section .libqat_sig=libqat_signature.bin --set-section-flags .libqat_sig=noload,readonly $OPENSSL_ENGINES/qatprovider.so
objcopy --add-section .qat_4xxx_sig=qat_4xxx_signature.bin --set-section-flags .qat_4xxx_sig=noload,readonly $OPENSSL_ENGINES/qatprovider.so
objcopy --add-section .usdm_drv_sig=usdm_drv_signature.bin --set-section-flags .usdm_drv_sig=noload,readonly $OPENSSL_ENGINES/qatprovider.so
objcopy --add-section .qat_4xxx_bin_sig=qat_4xxx_bin_signature.bin --set-section-flags .qat_4xxx_bin_sig=noload,readonly $OPENSSL_ENGINES/qatprovider.so
objcopy --add-section .qat_4xxx_mmp_sig=qat_4xxx_mmp_signature.bin --set-section-flags .qat_4xxx_mmp_sig=noload,readonly $OPENSSL_ENGINES/qatprovider.so
else
objcopy --add-section .ipsec_mb_sig=ipsec_mb_signature.bin --set-section-flags .ipsec_mb_sig=noload,readonly $OPENSSL_ENGINES/qatprovider.so
objcopy --add-section .libcrypto_mb_sig=libcrypto_mb_signature.bin --set-section-flags .libcrypto_mb_sig=noload,readonly $OPENSSL_ENGINES/qatprovider.so
fi
objcopy --add-section .pub_key=pub_key.txt --set-section-flags .pub_key=noload,readonly $OPENSSL_ENGINES/qatprovider.so
rm -f qat_signature.bin
if [ "$QAT_HW_ENABLED" = "1" ]
then
rm -f intel_qat_signature.bin
rm -f usdm_signature.bin
rm -f libqat_signature.bin
rm -f qat_4xxx_signature.bin
rm -f usdm_drv_signature.bin
rm -f qat_4xxx_bin_signature.bin
rm -f qat_4xxx_mmp_signature.bin
else
rm -f ipsec_mb_signature.bin
rm -f libcrypto_mb_signature.bin
fi
rm -f pub_key.txt
rm -f ec_key.txt
rm -f private-key.pem
fi
