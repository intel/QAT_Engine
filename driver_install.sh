#!/bin/sh

#QAT_HW OOT driver Location
QAT17_DRIVER=https://downloadmirror.intel.com/852035/QAT.L.4.28.0-00004.tar.gz
QAT20_DRIVER=https://downloadmirror.intel.com/852759/QAT20.L.1.2.30-00090.tar.gz

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
    echo "QAT_HW Driver installed successfully!"
else
    echo "QAT_HW Device not supported to install from make depend ! Install driver manually"
fi
