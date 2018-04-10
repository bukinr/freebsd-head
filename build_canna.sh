#!/bin/sh

A=CONF
if [ "$1" = "fast" ]; then
    A=FAST
fi

make -j8 TARGET=mips TARGET_ARCH=mipsel KERN${A}=CANNA buildkernel &&
scp /home/rb743/obj/mips.mipsel/home/rb743/dev/freebsd-head/sys/CANNA/kernel br@128.232.18.121:~/bsdpad/trunk/build/canna/

ssh br@128.232.18.121 sh /home/br/bsdpad/trunk/build/canna/canna.sh
