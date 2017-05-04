#!/bin/sh

A=CONF
if [ "$1" = "fast" ]; then
	A=FAST
fi

VARS=`make buildenvvars`

cp sys/x86/sgx/sgx_user.h usr.bin/secure_app/

make -C app clean all || exit 1
make -C usr.bin/secure_app || exit 1

cp usr.bin/secure_app/secure_app amd64_disk/usr/bin/
cp app/app amd64_disk/usr/bin/

cp /home/br/dev/sgx/app amd64_disk/usr/bin/sgx_app
cp /home/br/dev/sgx/libsgx_urts amd64_disk/usr/bin/
cp /home/br/dev/sgx/libenclave1.so amd64_disk/usr/bin/

cp /home/br/dev/sgx/le_prod_css.bin amd64_disk/opt/intel/sgxpsw/aesm/
cp /home/br/dev/sgx/libsgx_le.signed.so amd64_disk/opt/intel/sgxpsw/aesm/
cp /home/br/dev/sgx/aesm_service amd64_disk/usr/bin/

export DESTDIR=/home/br/world-amd64

make -j8 KERN${A}=SGX buildkernel || exit 1

#make -j8 -DNO_ROOT KERN${A}=SGX installkernel || exit 1
cp -f /home/br/obj/usr/home/br/dev/freebsd-head/sys/SGX/kernel $DESTDIR/boot/kernel/kernel
cp -f /home/br/obj/usr/home/br/dev/freebsd-head/sys/SGX/modules/usr/home/br/dev/freebsd-head/sys/modules/sgx_linux/sgx_linux.ko $DESTDIR/boot/kernel/
cp -f /home/br/obj/usr/home/br/dev/freebsd-head/sys/SGX/modules/usr/home/br/dev/freebsd-head/sys/modules/linux/linux.ko $DESTDIR/boot/kernel/
cp -f /home/br/obj/usr/home/br/dev/freebsd-head/sys/SGX/modules/usr/home/br/dev/freebsd-head/sys/modules/linux_common/linux_common.ko $DESTDIR/boot/kernel/
cp -f /home/br/obj/usr/home/br/dev/freebsd-head/sys/SGX/modules/usr/home/br/dev/freebsd-head/sys/modules/linux64/linux64.ko $DESTDIR/boot/kernel/

rm -f disk_amd64_.img disk_amd64_.img.gz
tools/tools/makeroot/makeroot.sh -s 120m -f amd64_disk/basic.files -e amd64_disk/extras.mtree amd64.img /home/br/world-amd64/ && \
sudo dd if=amd64.img of=/dev/md0p2 bs=1m || exit 1
cp disk_amd64.img disk_amd64_.img
gzip disk_amd64_.img
scp disk_amd64_.img.gz 10.5.0.85:~/
