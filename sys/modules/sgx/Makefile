# $FreeBSD$

.PATH: ${SRCTOP}/sys/amd64/sgx

KMOD=	sgx
SRCS=	sgx.c
SRCS+=	sgx.h sgx_user.h
SRCS+=	bus_if.h device_if.h

.include <bsd.kmod.mk>
