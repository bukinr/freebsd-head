#
# $FreeBSD$
#

PROG=	pmcstat
MAN=	pmcstat.8

LIBADD=	elf kvm pmc m ncursesw pmcstat ipt

SRCS=	pmcstat.c pmcstat.h pmcstat_log.c \
pmcpl_callgraph.c pmcpl_gprof.c pmcpl_annotate.c \
pmcpl_annotate_cg.c pmcpl_calltree.c pmcstat_pt.c

.include <bsd.prog.mk>
