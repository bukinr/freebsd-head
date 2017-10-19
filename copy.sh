#!/bin/sh

VARS=`make buildenvvars`
eval $VARS make -C lib/libpmc clean all || exit 1
eval $VARS make -C lib/libpmcstat clean all || exit 1

cp lib/libpmc/pmc.h /home/br/obj/usr/home/br/dev/freebsd-head/tmp/usr/include/pmc.h

cp lib/libpmcstat/libpmcstat.h /home/br/obj/usr/home/br/dev/freebsd-head/lib32/usr/include/libpmcstat.h
cp lib/libpmcstat/libpmcstat.h /home/br/obj/usr/home/br/dev/freebsd-head/tmp/usr/include/libpmcstat.h
cp /home/br/obj/usr/home/br/dev/freebsd-head/lib/libpmcstat/libpmcstat.so.5 /home/br/obj/usr/home/br/dev/freebsd-head/lib32/usr/lib32/libpmcstat.so.5
cp /home/br/obj/usr/home/br/dev/freebsd-head/lib/libpmcstat/libpmcstat.so.5 /home/br/obj/usr/home/br/dev/freebsd-head/tmp/usr/lib/libpmcstat.so.5
cp /home/br/obj/usr/home/br/dev/freebsd-head/lib/libpmcstat/libpmcstat.so.5 /home/br/obj/usr/home/br/dev/freebsd-head/world32/usr/home/br/dev/freebsd-head/lib/libpmcstat/libpmcstat.so.5

eval $VARS make -C usr.sbin/pmcstat
