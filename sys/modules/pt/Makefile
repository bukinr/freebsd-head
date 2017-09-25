# $FreeBSD$

.PATH: ${SRCTOP}/sys/amd64/pt

KMOD=	pt
SRCS=	pt.c ptvar.h assym.s device_if.h bus_if.h
#pt_support.S

pt_support.o:  assym.s
	${CC} -c -x assembler-with-cpp -DLOCORE ${CFLAGS} \
	    ${.IMPSRC} -o ${.TARGET}

.include <bsd.kmod.mk>
