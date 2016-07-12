#!/bin/bash

autoreconf -ivf

rm -f ../configure
sed 's/^srcdir\=$/srcdir\=\"\.tools\"/g' < configure > ../configure
chmod +x ../configure
