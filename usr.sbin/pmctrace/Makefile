#	@(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD$

PROG=	pmctrace
SRCS=	pmctrace.c
MAN=

LIBADD= elf pmc pmcstat

.if ${MACHINE_CPUARCH} == "amd64"
SRCS+=	pmctrace_pt.c	\
	pmctrace_pt.h
LIBADD+= ipt
.endif

.include <bsd.prog.mk>
