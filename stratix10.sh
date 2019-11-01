A=CONF
if [ "$1" = "fast" ]; then
    A=FAST
fi

# make -j6 TARGET=arm64 NO_ROOT=1 DESTDIR=/home/br/world-arm64 installworld

make -j6 TARGET=arm64 KERN${A}=GENERIC buildkernel

# cp /xhome/obj/usr/home/br/dev/freebsd-head/arm64.aarch64/sys/GENERIC/kernel /tftpboot/stratix10/
cp /home/br/obj/usr/home/br/dev/freebsd-head/arm64.aarch64/sys/GENERIC/kernel /tftpboot/stratix10/

#echo 'setenv serverip 10.5.0.1; setenv ipaddr 10.5.0.33; setenv netmask 255.255.255.0; tftpboot stratix10/kernel'

echo 'tftpboot 0x2000000 stratix10/kernel; fatwrite mmc 0:1 0x2000000 kernel $filesize'

#echo 'tftpboot 0x2000000 stratix10/loader_lua.efi; bootefi 0x2000000'
#echo 'fatwrite mmc 0:1 0x2000000 kernel $filesize'
#echo 'tftpboot 0x2000000 stratix10/loader_lua.efi'
#echo 'tftpboot 0x3000000 stratix10/socfpga_stratix10_de10_pro.dtb'
#echo 'bootefi 0x2000000 0x3000000'
#echo 'load disk0s1:kernel'

echo 'tftpboot 0x2000000 stratix10/loader_lua.efi'
echo 'tftpboot 0x8000000 stratix10/socfpga_stratix10_de10_pro.dtb'
echo 'bootefi 0x2000000 0x8000000'
echo 'load disk0s1:kernel'
echo 'fdt ls'
echo 'boot'

# echo 'dd if=/root/DE10_Pro-hps.core.rbf of=/dev/fpga0 bs=4m'

echo 'cp /root/DE10_Pro-hps.core.rbf /var && dd if=/var/DE10_Pro-hps.core.rbf of=/dev/fpga0 bs=4m'
