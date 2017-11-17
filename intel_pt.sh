#!/bin/sh

A=CONF
if [ "$1" = "fast" ]; then
    A=FAST
fi

#cp lib/libpmc/pmc.h /home/br/obj/usr/home/br/dev/freebsd-head/tmp/usr/include/pmc.h
#cp sys/dev/hwpmc/hwpmc_pt.h /home/br/obj/usr/home/br/dev/freebsd-head/tmp/usr/include/dev/hwpmc/hwpmc_pt.h

make -j8 KERN${A}=PT buildkernel || exit 1

VARS=`make buildenvvars`
eval $VARS make -C lib/libipt || exit 1
eval $VARS make -C lib/libpmc || exit 1

#cp /home/br/obj/usr/home/br/dev/freebsd-head/lib/libpmc/libpmc.so.5 /home/br/obj/usr/home/br/dev/freebsd-head/lib32/usr/lib32/libpmc.so.5
#cp /home/br/obj/usr/home/br/dev/freebsd-head/lib/libpmc/libpmc.so.5 /home/br/obj/usr/home/br/dev/freebsd-head/tmp/usr/lib/libpmc.so.5
#cp /home/br/obj/usr/home/br/dev/freebsd-head/lib/libpmc/libpmc.so.5 /home/br/obj/usr/home/br/dev/freebsd-head/world32/usr/home/br/dev/freebsd-head/lib/libpmc/libpmc.so.5

eval $VARS make -C usr.sbin/pmcstat || exit 1

eval $VARS make -C usr.sbin/pmctrace clean all || exit 1
#eval $VARS make -C usr.sbin/mtrace clean all || exit 1

# /home/br/obj/usr/home/br/dev/freebsd-head/usr.sbin/mtrace/mtrace

scp \
 /home/br/obj/usr/home/br/dev/freebsd-head/amd64.amd64/usr.sbin/pmcstat/pmcstat \
 /home/br/obj/usr/home/br/dev/freebsd-head/amd64.amd64/usr.sbin/pmctrace/pmctrace \
 /home/br/obj/usr/home/br/dev/freebsd-head/amd64.amd64/lib/libpmc/libpmc.so.5 \
 /home/br/obj/usr/home/br/dev/freebsd-head/amd64.amd64/lib/libipt/libipt.so.0 \
 /home/br/obj/usr/home/br/dev/freebsd-head/amd64.amd64/sys/PT/modules/usr/home/br/dev/freebsd-head/sys/modules/hwpmc/hwpmc.ko \
 /home/br/obj/usr/home/br/dev/freebsd-head/amd64.amd64/sys/PT/kernel \
 10.5.0.86:~/

