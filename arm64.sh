A=CONF
if [ "$1" = "fast" ]; then
    A=FAST
fi

make -j6 TARGET=arm64 KERN${A}=GENERIC buildkernel || exit 1
cp /home/br/obj/usr/home/br/dev/freebsd-head/arm64.aarch64/sys/GENERIC/kernel /tftpboot/

echo "setenv serverip 10.5.0.1 ; setenv ipaddr 10.5.0.44; usb start; tftpboot kernel; fatwrite mmc 1 0x81000000 kernel \$filesize; tftpboot 0x81000000 loader.efi; tftpboot 0x83000000 dragonboard410c.dtb; usb stop; bootefi 0x81000000 0x83000000"

echo "load /kernel"
echo "boot"

# dtc -o - -O dts -I dtb /tftpboot/dragonboard410c.dtb | less

exit 0
scp	\
	/home/br/obj/usr/home/br/dev/freebsd-head/arm64.aarch64/sys/GENERIC/modules/usr/home/br/dev/freebsd-head/sys/modules/hwpmc/hwpmc.ko \
	/home/br/obj/usr/home/br/dev/freebsd-head/arm64.aarch64/sys/GENERIC/kernel 10.5.0.45:~/
