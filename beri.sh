A=CONF
if [ "$1" = "fast" ]; then
    A=FAST
fi

export MAKEOBJDIRPREFIX=/xhome/obj/

KERNEL=BERI_DE4_USBROOT
KERNEL_PATH=/xhome/obj/usr/home/br/dev/freebsd-head/mips.mips64/sys/${KERNEL}

if [ "$2" = "dma" ]; then
	KERNEL=BERI_DE4_USBROOT_DMA
fi

#make -j4 TARGET=mips TARGET_ARCH=mips64 -DNO_ROOT DESTDIR=/home/br/world-mips64 installworld

make -j4 TARGET=mips TARGET_ARCH=mips64 KERN${A}=${KERNEL} buildkernel || exit 1

ssh -K rb743@woc-base-05.cl.cam.ac.uk uname || exit 1

hostname=`uname -n`
if [ $hostname == 'pie' ]; then
    rm -f ${KERNEL_PATH}/kernel.bz2 && \
    sh ./sys/tools/embed_mfs.sh ${KERNEL_PATH}/kernel mips.img && \
    bzip2 -k ${KERNEL_PATH}/kernel && \
    scp -o GSSAPIAuthentication=yes ${KERNEL_PATH}/kernel.bz2 \
	rb743@woc-base-05.cl.cam.ac.uk:~/
fi

#http://www-dyns.cl.cam.ac.uk/cgi/raven/boot-mc.cgi?machine=woc-base-05&debug=off&method=&op=&server=

# echo sysctl kern.ipc.nmbufs
