A=CONF
if [ "$1" = "fast" ]; then
    A=FAST
fi

make -j16 TARGET=mips TARGET_ARCH=mips64 KERN${A}=BERI_DE4_USBROOT buildkernel || exit 1

rm -f /home/rb743/obj/mips.mips64/home/rb743/dev/freebsd-head/sys/BERI_DE4_USBROOT/kernel.bz2 && \
bzip2 /home/rb743/obj/mips.mips64/home/rb743/dev/freebsd-head/sys/BERI_DE4_USBROOT/kernel

ssh -K woc-base-05 uname && \
scp /home/rb743/obj/mips.mips64/home/rb743/dev/freebsd-head/sys/BERI_DE4_USBROOT/kernel.bz2 woc-base-05:~/

#http://www-dyns.cl.cam.ac.uk/cgi/raven/boot-mc.cgi?machine=woc-base-05&debug=off&method=&op=&server=
