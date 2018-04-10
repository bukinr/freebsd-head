#!/bin/sh

#./x86_64-softmmu/qemu-system-x86_64 -drive file=/home/br/FreeBSD-11.0-STABLE-amd64.raw,if=virtio -serial telnet:10.5.0.85:4444,server -enable-kvm -cpu host -epc 32M -sdl

test -f ~/disk_amd64_.img.gz && gunzip -f ~/disk_amd64_.img.gz
test -f ~/disk_amd64_.img || exit 1

#./x86_64-softmmu/qemu-system-x86_64 -drive file=/home/br/disk_amd64_.img,if=virtio -serial telnet:10.5.0.85:4444,server -enable-kvm -cpu host -epc 32M -sdl

./x86_64-softmmu/qemu-system-x86_64 -drive file=/home/br/disk_amd64_.img,if=virtio -enable-kvm -cpu host -epc 32M -device isa-serial,chardev=test0 -chardev stdio,server,nowait,id=test0 -nographic -serial mon:null
