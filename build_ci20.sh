#!/bin/sh

A=CONF
if [ "$1" = "fast" ]; then
    A=FAST
fi

export MAKEOBJDIRPREFIX=/home/br/obj/

export CROSS_BINUTILS_PREFIX=/usr/local/bin/mips-unknown-freebsd11.1-
export XCC=${CROSS_BINUTILS_PREFIX}gcc
export XCXX=${CROSS_BINUTILS_PREFIX}c++
export XCPP=${CROSS_BINUTILS_PREFIX}cpp

export CROSS_BINUTILS_PREFIX=/usr/local/bin/mips-unknown-freebsd11.1-
export STRIPBIN=${CROSS_BINUTILS_PREFIX}strip

export WITHOUT_CLANG=yes
export WITHOUT_CLANG_BOOTSTRAP=yes
export WITHOUT_CLANG_FULL=yes
export WITHOUT_CLANG_IS_CC=yes
export X_COMPILER_TYPE=gcc

make TARGET=mips TARGET_ARCH=mipsel KERN${A}=CI20 buildkernel || exit 1

HOSTNAME=`hostname -s`

if [ "$HOSTNAME" == "vica" ]; then
	scp /home/rb743/obj/mips.mipsel/home/rb743/dev/freebsd-head/sys/CI20/kernel \
	    br@128.232.18.121:~/bsdpad/trunk/build/ci20/ || exit 1
	ssh br@128.232.18.121 sh /home/br/bsdpad/trunk/build/ci20/ci20.sh
fi

if [ "$HOSTNAME" == "pie" ]; then
	cp /home/br/obj/usr/home/br/dev/freebsd-head/mips.mipsel/sys/CI20/kernel /home/br/bsdpad/trunk/build/ci20/
	sh /home/br/bsdpad/trunk/build/ci20/ci20.sh
fi
