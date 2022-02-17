#!/usr/bin/env bash
#run testapp
date > testapp.log

echo $1
if [ -z $1 ]
then
	echo "Parameter QAT_SW or QAT_HW required."
	echo "usage : ./testapp.sh QAT_HW | QAT_SW"
	exit 1
fi

if [ ! -f "testapp" ]; then
    echo "testapp does not exist. make test"
    make test
fi

./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v rsa2048 -sign >> testapp.log
./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v rsa2048 -verify >> testapp.log
./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v rsa2048 -encrypt >> testapp.log
./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v rsa2048 -decrypt >> testapp.log
./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v rsa3072 -sign >> testapp.log
./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v rsa3072 -verify >> testapp.log
./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v rsa3072 -encrypt >> testapp.log
./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v rsa3072 -decrypt >> testapp.log
./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v rsa4096 -sign >> testapp.log
./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v rsa4096 -verify >> testapp.log
./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v rsa4096 -encrypt >> testapp.log
./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v rsa4096 -decrypt >> testapp.log
./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v ecdhp256 >> testapp.log
./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v ecdhp384 >> testapp.log
./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v ecdhx25519 >> testapp.log
./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v ecdhx448 >> testapp.log
./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v ecdsap256 >> testapp.log
./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v ecdsap384 >> testapp.log
if [ $1 = QAT_SW ]
then
  ./testapp -engine qatengine -c 1 -n 1 -nc 1 -v aes128gcm >> testapp.log
  ./testapp -engine qatengine -c 1 -n 1 -nc 1 -v aes256gcm >> testapp.log
fi

if [ $1 = QAT_HW ]
then
  ./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v ecdhp521 >> testapp.log
  ./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v ecdsap521 >> testapp.log
  ./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v dsa1024 -sign >> testapp.log
  ./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v dsa2048 -verify >> testapp.log
  ./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v dsa4096 -verify >> testapp.log
  ./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v dh >> testapp.log
  ./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v prf >> testapp.log
  ./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v aes128_cbc_hmac_sha1 >> testapp.log
  ./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v aes256_cbc_hmac_sha1 >> testapp.log
  ./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v aes128_cbc_hmac_sha256 >> testapp.log
  ./testapp -engine qatengine -async_jobs 8 -c 1 -n 1 -nc 1 -v aes256_cbc_hmac_sha256 >> testapp.log
fi
