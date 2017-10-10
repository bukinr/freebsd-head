#!/bin/sh

A=CONF
if [ "$1" = "fast" ]; then
	A=FAST
fi

VARS=`make buildenvvars`

##cp sys/amd64/sgx/sgx_user.h usr.bin/secure_app/

make -C app clean all || exit 1
cp app/app amd64_disk/usr/bin/

make -C usr.bin/secure_app || exit 1
cp usr.bin/secure_app/secure_app amd64_disk/usr/bin/

##cp /home/br/dev/sgx/libsgx_urts amd64_disk/usr/bin/

if [ "$2" = "linux" ]; then
	cp /home/br/dev/sgx/app amd64_disk/usr/bin/sgx_app
	cp /home/br/dev/sgx/libenclave1.so amd64_disk/usr/bin/
	cp /home/br/dev/sgx/libenclave2.so amd64_disk/usr/bin/
	cp /home/br/dev/sgx/libenclave3.so amd64_disk/usr/bin/

	cp /home/br/dev/sgx/sample_enclave/* amd64_disk/usr/bin/

	cp /home/br/dev/sgx/le_prod_css.bin amd64_disk/opt/intel/sgxpsw/aesm/
	cp /home/br/dev/sgx/libsgx_le.signed.so amd64_disk/opt/intel/sgxpsw/aesm/
	cp /home/br/dev/sgx/aesm_service amd64_disk/usr/bin/
fi

if [ "$2" = "" ]; then
	cp /home/br/dev/freebsd-sgx/psw/ae/aesm_service/aesm_service amd64_disk/usr/bin/
	cp /home/br/dev/freebsd-sgx/SampleCode/LocalAttestation/app amd64_disk/usr/bin/sgx_app
	cp /home/br/dev/freebsd-sgx/SampleCode/LocalAttestation/libenclave1.so amd64_disk/usr/bin/
	cp /home/br/dev/freebsd-sgx/SampleCode/LocalAttestation/libenclave2.so amd64_disk/usr/bin/
	cp /home/br/dev/freebsd-sgx/SampleCode/LocalAttestation/libenclave3.so amd64_disk/usr/bin/
	cp /home/br/dev/freebsd-sgx/psw/uae_service/linux/libsgx_uae_service.so amd64_disk/usr/local/lib/
	cp /home/br/dev/freebsd-sgx/psw/urts/linux/libsgx_urts.so amd64_disk/usr/local/lib/

	# cp /home/br/dev/freebsd-sgx/psw/ae/data/prebuilt/le_prod_css.bin amd64_disk/opt/intel/sgxpsw/aesm/
	# cp /home/br/dev/freebsd-sgx/psw/ae/data/prebuilt/libsgx_le.signed.so amd64_disk/opt/intel/sgxpsw/aesm/
	cp /home/br/dev/freebsd-sgx/psw/ae/data/prebuilt/le_prod_css.bin amd64_disk/usr/bin/
	cp /home/br/dev/freebsd-sgx/psw/ae/data/prebuilt/libsgx_le.signed.so amd64_disk/usr/bin/

	cp /usr/local/lib/libcurl.so.4 amd64_disk/usr/local/lib/
	cp /usr/local/lib/libprotobuf.so.13 amd64_disk/usr/local/lib/
	cp /usr/local/lib/gcc46/libstdc++.so.6 amd64_disk/usr/local/lib/
	cp /usr/local/lib/libnghttp2.so.14 amd64_disk/usr/local/lib/


	cp /home/br/dev/freebsd-sgx/SampleCode/hello-enclave/app amd64_disk/usr/bin/sgx_hello_app
	cp /home/br/dev/freebsd-sgx/SampleCode/hello-enclave/enclave.signed.so amd64_disk/usr/bin/
	cp /home/br/dev/freebsd-sgx/SampleCode/hello-enclave/enclave.so amd64_disk/usr/bin/
fi

export DESTDIR=/home/br/world-amd64

make -j8 KERN${A}=SGX buildkernel || exit 1

#VARS=`make buildenvvars`
#eval $VARS make -C sys/modules/sgx || exit 1
#make -j8 -DNO_ROOT KERN${A}=SGX installkernel || exit 1

cp -f /home/br/obj/usr/home/br/dev/freebsd-head/sys/SGX/kernel $DESTDIR/boot/kernel/kernel

# modules
cp -f /home/br/obj/usr/home/br/dev/freebsd-head/sys/SGX/modules/usr/home/br/dev/freebsd-head/sys/modules/sgx_linux/sgx_linux.ko $DESTDIR/boot/kernel/
cp -f /home/br/obj/usr/home/br/dev/freebsd-head/sys/SGX/modules/usr/home/br/dev/freebsd-head/sys/modules/sgx/sgx.ko $DESTDIR/boot/kernel/
cp -f /home/br/obj/usr/home/br/dev/freebsd-head/sys/SGX/modules/usr/home/br/dev/freebsd-head/sys/modules/linux_common/linux_common.ko $DESTDIR/boot/kernel/
cp -f /home/br/obj/usr/home/br/dev/freebsd-head/sys/SGX/modules/usr/home/br/dev/freebsd-head/sys/modules/linux64/linux64.ko $DESTDIR/boot/kernel/

# pt modules
cp -f /home/br/obj/usr/home/br/dev/freebsd-head/sys/SGX/modules/usr/home/br/dev/freebsd-head/sys/modules/pt/pt.ko $DESTDIR/boot/kernel/

MD=`sudo mdconfig -n disk_amd64.img`

rm -f disk_amd64_.img disk_amd64_.img.gz
tools/tools/makeroot/makeroot.sh -s 120m -f amd64_disk/basic.files -e amd64_disk/extras.mtree amd64.img /home/br/world-amd64/ && \
sudo dd if=amd64.img of=/dev/md${MD}p2 bs=1m || exit 1
cp disk_amd64.img disk_amd64_.img
gzip disk_amd64_.img
scp disk_amd64_.img.gz 10.5.0.85:~/

sudo mdconfig -d -u ${MD}
