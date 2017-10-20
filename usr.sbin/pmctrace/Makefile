#	@(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD$

PROG=	pmctrace
SRCS=	pmctrace.c pmctrace_pt.c pmctrace_pt.h

CFLAGS+=-I${SRCTOP}/lib/libpmcstat

LIBADD=	elf ipt pmc pmcstat

# NO_SHARED=	yes

.include <bsd.prog.mk>
