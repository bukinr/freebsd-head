PREFIX = mips64-unknown-freebsd11.1-

CC = ${PREFIX}gcc
LD = ${PREFIX}ld

CFLAGS = -march=mips64r2 -EB -nostdlib -mno-abicalls -msoft-float

all:
	${CC} ${CFLAGS} -c -o start.o ${.CURDIR}/start.S
	${CC} ${CFLAGS} -c -o main.o ${.CURDIR}/main.c
	${LD} -T ${.CURDIR}/ldscript start.o main.o -o dm
	${OBJCOPY} -O binary dm dm.bin
	scp -o GSSAPIAuthentication=yes /home/br/obj/usr/home/br/dev/freebsd-head/amd64.amd64/device-model/dm.bin \
		rb743@woc-base-05.cl.cam.ac.uk:~/
