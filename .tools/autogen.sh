#!/bin/bash

# Change directory to .tools as this script is location dependent
cd "$(dirname "$0")"

autoreconf -ivf

rm -f ../configure
sed 's/^srcdir\=$/srcdir\=\"\.tools\"/g' < configure > ../configure
chmod +x ../configure
