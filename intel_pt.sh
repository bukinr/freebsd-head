#!/bin/sh

A=CONF
if [ "$1" = "fast" ]; then
    A=FAST
fi

make -j8 KERN${A}=PT buildkernel || exit 1

VARS=`make buildenvvars`
eval $VARS make -C lib/libipt || exit 1
eval $VARS make -C lib/libpmc || exit 1
eval $VARS make -C usr.sbin/pmcstat || exit 1
#eval $VARS make -C usr.sbin/mtrace clean all || exit 1

scp \
 /home/br/obj/usr/home/br/dev/freebsd-head/usr.sbin/pmcstat/pmcstat \
 /home/br/obj/usr/home/br/dev/freebsd-head/usr.sbin/mtrace/mtrace \
 /home/br/obj/usr/home/br/dev/freebsd-head/lib/libpmc/libpmc.so.5 \
 /home/br/obj/usr/home/br/dev/freebsd-head/lib/libipt/libipt.so.0 \
 /home/br/obj/usr/home/br/dev/freebsd-head/lib/libpmcstat/libpmcstat.so.5 \
 /home/br/obj/usr/home/br/dev/freebsd-head/sys/PT/modules/usr/home/br/dev/freebsd-head/sys/modules/hwpmc/hwpmc.ko \
 /home/br/obj/usr/home/br/dev/freebsd-head/sys/PT/modules/usr/home/br/dev/freebsd-head/sys/modules/pt/pt.ko \
 /home/br/obj/usr/home/br/dev/freebsd-head/sys/PT/kernel \
 10.5.0.86:~/

