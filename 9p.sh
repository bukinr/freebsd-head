#./tools/tools/makeroot/makeroot.sh -s 32m -f basic.files riscv.img /home/br/world-riscv/

make -j8 TARGET=riscv KERNCONF=GENERIC buildkernel

#sh ./sys/tools/embed_mfs.sh /usr/obj/usr/home/br/dev/freebsd-head/riscv.riscv64/sys/GENERIC/kernel ./riscv.img

scp /usr/obj/usr/home/br/dev/freebsd-head/riscv.riscv64/sys/GENERIC/kernel 10.4.0.2:~/9p_kernel
