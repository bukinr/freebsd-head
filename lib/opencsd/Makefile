# $FreeBSD$

PACKAGE=lib${LIB}
SHLIBDIR?=	/lib

.include <src.opts.mk>

OPENCSDSRC=	${SRCTOP}/contrib/opencsd

.PATH:	${OPENCSDSRC}/decoder/source/etmv4/	\
	${OPENCSDSRC}/decoder/include/opencsd/etmv4/

LIB=	opencsd
SHLIB_MAJOR=0

SRCS=	\
	trc_cmp_cfg_etmv4.cpp			\
	trc_etmv4_stack_elem.cpp		\
	trc_pkt_decode_etmv4i.cpp		\
	trc_pkt_elem_etmv4d.cpp			\
	trc_pkt_elem_etmv4i.cpp			\
	trc_pkt_proc_etmv4.cpp			\
	trc_pkt_proc_etmv4i_impl.cpp

CFLAGS+=	\
	-I${OPENCSDSRC}/decoder/include/	\
	-I${.CURDIR}

INCS=	\
	etmv4_decoder.h

INCSDIR=${INCLUDEDIR}/opencsd

LIBADD=	

WARNS?= 1

HAS_TESTS=

.include <bsd.lib.mk>
