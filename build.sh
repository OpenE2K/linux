#!/bin/bash
export ARCH=e2k
export CROSS_COMPILE="/opt/mcst/bin.toolchain/e2k-linux-"
export CROSS_ROOT="/opt/mcst/crossfs-3.0-rc5.e2k-8c"

# make mrproper
# make defconfig

# make bootimage CC=/opt/mcst/bin.toolchain/e2k-linux-gcc -j5
rm scripts/mod/.devicetable-offsets.h.cmd
make modules CC=/opt/mcst/bin.toolchain/e2k-linux-gcc -j5
make modules_install INSTALL_MOD_PATH=../modules_3.14_103 
