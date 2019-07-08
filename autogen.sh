#!/usr/bin/env bash

# Change directory to .tools as this script is location dependent

tools_dir=$(cd `dirname $0` && pwd)/.tools
cd $tools_dir

if [ ! -d "m4" ]
then
    mkdir m4
fi

autoreconf -ivf

rm -f ../configure
sed 's/^srcdir\=$/srcdir\=\"\.tools\"/g' < $tools_dir/configure > ../configure
chmod +x ../configure
