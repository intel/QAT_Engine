#!/bin/bash
# Script to install driver modules during the RPM installation
set -e

if ( lsmod | grep qat >/dev/null ); then
   echo "QAT driver already installed and removing existing modules ......."
   if (lsmod | grep usdm >/dev/null); then
      rmmod usdm_drv
      rmmod qat_4xxx
      rmmod intel_qat
      echo "Removed existing driver"
   elif (lsmod | grep intel_qat >/dev/null); then
      rmmod qat_4xxx
      rmmod intel_qat
      echo "Removed existing driver"
   fi
else
   echo "Shutdown qat services"
   cd /usr/lib64/build
   ./qat_service shutdown
fi


if [ $? -ne 0 ]; then
   sudo	insmod /usr/lib64/build/intel_qat.ko
fi
sudo modprobe authenc
sudo modprobe mdev
sudo modprobe uio

cp -rf /usr/lib64/build/qat_4xxx.bin /lib/firmware/
cp -rf /usr/lib64/build/qat_4xxx_mmp.bin /lib/firmware/

echo "Installing QAT Kernel Modules"

sudo insmod /usr/lib64/build/intel_qat.ko
sudo insmod /usr/lib64/build/usdm_drv.ko
sudo insmod /usr/lib64/build/qat_4xxx.ko

for(( i=0; i< 8; i++ ))
do
    cp -rf /usr/lib64/build/4xxx_dev0.conf /etc/4xxx_dev$i.conf
done

cp -rf /usr/lib64/build/4xxx_dev* /etc/
cp /usr/lib64/build/adf_ctl /usr/local/bin
cp /usr/lib64/build/adf_ctl /usr/bin

cd /usr/lib64/build

sudo adf_ctl restart
