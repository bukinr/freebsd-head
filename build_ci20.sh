#!/bin/sh

A=CONF
if [ "$1" = "fast" ]; then
    A=FAST
fi

make TARGET=mips TARGET_ARCH=mipsel KERN${A}=CI20 buildkernel || exit 1

HOSTNAME=`hostname -s`

if [ "$HOSTNAME" == "vica" ]; then
	scp /home/rb743/obj/mips.mipsel/home/rb743/dev/freebsd-head/sys/CI20/kernel \
	    br@128.232.18.121:~/bsdpad/trunk/build/ci20/ || exit 1
	ssh br@128.232.18.121 sh /home/br/bsdpad/trunk/build/ci20/ci20.sh
fi

if [ "$HOSTNAME" == "pie" ]; then
	cp ~/obj/mips.mipsel/usr/home/br/dev/freebsd-head/sys/CI20/kernel /home/br/bsdpad/trunk/build/ci20/
	sh /home/br/bsdpad/trunk/build/ci20/ci20.sh
fi
