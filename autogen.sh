#!/usr/bin/env bash

if [ ! -d "m4" ]
then
    mkdir m4
fi

autoreconf -ivf

chmod +x configure
