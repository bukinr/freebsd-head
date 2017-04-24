#!/bin/sh

A=CONF
if [ "$1" = "fast" ]; then
	A=FAST
fi

export DESTDIR=/home/br/world-amd64

make -j8 KERN${A}=SGX buildkernel || exit 1

#make -j8 -DNO_ROOT KERN${A}=SGX installkernel || exit 1
cp /home/br/obj/usr/home/br/dev/freebsd-head/sys/SGX/kernel $DESTDIR/boot/kernel/kernel

rm -f disk_amd64_.img disk_amd64_.img.gz
tools/tools/makeroot/makeroot.sh -s 60m -f amd64_disk/basic.files -e amd64_disk/extras.mtree amd64.img /home/br/world-amd64/ && \
sudo dd if=amd64.img of=/dev/md0p2 bs=1m || exit 1
cp disk_amd64.img disk_amd64_.img
gzip disk_amd64_.img
scp disk_amd64_.img.gz 10.5.0.85:~/
