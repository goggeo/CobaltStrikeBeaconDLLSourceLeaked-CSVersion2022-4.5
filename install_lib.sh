#!/usr/bin/env bash
#1.安装必要静态库：libtommath
git clone https://github.com/libtom/libtommath.git
mkdir -p libtommath/build
cd libtommath/build
cmake ..
make -j$(nproc)

#2.安装必要静态库：libtomcrypt
git clone https://github.com/libtom/libtomcrypt.git
mkdir -p libtomcrypt/build
cd libtomcrypt/build
cmake ..
make -j$(nproc)