#!/bin/sh

#QAT_HW OOT driver Location
QAT17_DRIVER=https://downloadmirror.intel.com/838409/QAT.L.4.27.0-00006.tar.gz
QAT20_DRIVER=https://downloadmirror.intel.com/843052/QAT20.L.1.2.30-00078.tar.gz

#Supported Devices
numC62xDevice=`lspci -vnd 8086: | grep -c "37c8\|37c9"`
numDh895xDevice=`lspci -vnd 8086: | grep -c "0435\|0443"`
numC3xxxDevice=`lspci -vnd 8086: | grep -c "19e2\|19e3"`
num200xxDevice=`lspci -vnd 8086: | grep -c "18ee\|18ef"`
numC4xxxDevice=`lspci -vnd 8086: | grep -c "18a0\|18a1"`
num4xxxDevice=`lspci -vnd 8086: | grep -c "4940\|4942"`

QAT_ENGINE_ROOT=$PWD

#Install QAT_HW OOT Driver and copy config files
if [ "$numC62xDevice" -gt 0 -o "$numDh895xDevice" -gt 0 -o "$numC3xxxDevice" -gt 0 -o "$numC4xxxDevice" -gt 0 -o "$num200xxDevice" -gt 0 -o "$num4xxxDevice" -gt 0 ]
then
    if [ "$num4xxxDevice" -gt 0 ]
    then
        echo "QAT2.0 Driver"
        wget -O QAT_HW.tar.gz $QAT20_DRIVER
    else
        echo "QAT1.7 Driver"
        wget -O QAT_HW.tar.gz $QAT17_DRIVER
    fi
    mkdir -p $1
    tar -zxvf QAT_HW.tar.gz -C $1
    unset ICP_ROOT
    unset ICP_BUILD_OUTPUT
    cd $1
    ./configure
    make uninstall; make clean; make install -j
    if [ "$numC62xDevice" -gt 0 ]
    then
        for(( i=0; i<$numC62xDevice; i++ ))
        do
           sudo cp -rf $QAT_ENGINE_ROOT/qat_hw_config/c6xx/multi_process/c6xx_dev0.conf /etc/c6xx_dev$i.conf
        done
    elif [ "$numDh895xDevice" -gt 0 ]
    then
        for(( i=0; i<"$numDh895xDevice"; i++ ))
        do
           sudo cp -rf $QAT_ENGINE_ROOT/qat_hw_config/dh895xcc/multi_process/dh895xcc_dev0.conf /etc/dh895xcc_dev$i.conf
        done
    elif [ "$numC3xxxDevice" -gt 0 ]
    then
        for(( i=0; i<"$numC3xxxDevice"; i++ ))
        do
           sudo cp -rf $QAT_ENGINE_ROOT/qat_hw_config/c3xxx/multi_process/c3xxx_dev0.conf /etc/c3xxx_dev$i.conf
        done
    elif [ "$numC4xxxDevice" -gt 0 ]
    then
        for(( i=0; i<"$numC4xxxDevice"; i++ ))
        do
           sudo cp -rf $QAT_ENGINE_ROOT/qat_hw_config/c4xxx/multi_process/c4xxx_dev0.conf /etc/c4xxx_dev$i.conf
        done
    elif [ "$num200xxDevice" -gt 0 ]
    then
        for(( i=0; i<"$num200xxDevice"; i++ ))
        do
           sudo cp -rf $QAT_ENGINE_ROOT/qat_hw_config/200xx/multi_process/200xx_dev0.conf /etc/200xx_dev$i.conf
        done
    elif [ "$num4xxxDevice" -gt 0 ]
    then
        for(( i=0; i<$num4xxxDevice; i++ ))
        do
           sudo cp -rf $QAT_ENGINE_ROOT/qat_hw_config/4xxx/multi_process/4xxx_dev0.conf /etc/4xxx_dev$i.conf
        done
    fi
    adf_ctl restart
    echo "QAT_HW Driver installed successfully!"
else
    echo "QAT_HW Device not supported to install from make depend ! Install driver manually"
fi
