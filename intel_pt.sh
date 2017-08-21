#!/bin/sh

A=CONF
if [ "$1" = "fast" ]; then
    A=FAST
fi

make -j8 KERN${A}=PT buildkernel || exit 1

scp /home/br/obj/usr/home/br/dev/freebsd-head/sys/PT/modules/usr/home/br/dev/freebsd-head/sys/modules/pt/pt.ko 10.5.0.86:~/
