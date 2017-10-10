A=CONF
if [ "$1" = "fast" ]; then
    A=FAST
fi

KERNEL=BERI_DE4_USBROOT

if [ "$2" = "dma" ]; then
	KERNEL=BERI_DE4_USBROOT_DMA
fi

#make -j8 TARGET=mips TARGET_ARCH=mips64 -DNO_ROOT DESTDIR=/home/br/world-mips64 installworld

make -j8 TARGET=mips TARGET_ARCH=mips64 KERN${A}=${KERNEL} buildkernel || exit 1

ssh -K rb743@woc-base-05.cl.cam.ac.uk uname || exit 1

hostname=`uname -n`
if [ $hostname == 'pie' ]; then
	rm -f /home/br/obj/mips.mips64/usr/home/br/dev/freebsd-head/sys/${KERNEL}/kernel.bz2 && \
	bzip2 /home/br/obj/mips.mips64/usr/home/br/dev/freebsd-head/sys/${KERNEL}/kernel && \
	scp /home/br/obj/mips.mips64/usr/home/br/dev/freebsd-head/sys/${KERNEL}/kernel.bz2 \
		rb743@woc-base-05.cl.cam.ac.uk:~/
fi

if [ $hostname == 'vica.cl.cam.ac.uk' ]; then
	rm -f /home/rb743/obj/mips.mips64/home/rb743/dev/freebsd-head/sys/${KERNEL}/kernel.bz2 && \
	bzip2 /home/rb743/obj/mips.mips64/home/rb743/dev/freebsd-head/sys/${KERNEL}/kernel && \
	scp /home/rb743/obj/mips.mips64/home/rb743/dev/freebsd-head/sys/${KERNEL}/kernel.bz2 woc-base-05:~/
fi

#http://www-dyns.cl.cam.ac.uk/cgi/raven/boot-mc.cgi?machine=woc-base-05&debug=off&method=&op=&server=

# echo sysctl kern.ipc.nmbufs
