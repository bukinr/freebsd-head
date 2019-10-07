#!/bin/sh

# 1 - core
git diff -U99999999 origin/master sys/kern sys/sys		\
	sys/dev/hwpmc/hwpmc_mod.c > patch.hwpmc1

# 2 - vm
git diff -U99999999 origin/master sys/conf/files		\
	sys/dev/hwpmc/hwpmc_vm.c				\
	sys/dev/hwpmc/hwpmc_vm.h				\
	sys/modules/hwpmc/Makefile > patch.hwpmc2

# 3 -- libpmc
git diff -U99999999 origin/master lib/libpmc			\
	sys/dev/hwpmc/pmc_events.h > patch.hwpmc3

# 4 -- coresight kernel
git diff -U99999999 origin/master sys/arm64/include/pmc_mdep.h	\
	sys/conf/files.arm64 sys/dev/hwpmc/hwpmc_arm64.c	\
	sys/dev/hwpmc/hwpmc_cs.c				\
	sys/dev/hwpmc/hwpmc_cs.h > patch.hwpmc4

# 5 -- intel pt
git diff -U99999999 origin/master sys/amd64/include/pmc_mdep.h	\
	sys/conf/files.amd64 sys/dev/hwpmc/hwpmc_core.c		\
	sys/dev/hwpmc/hwpmc_intel.c sys/dev/hwpmc/hwpmc_pt.c	\
	sys/dev/hwpmc/hwpmc_pt.h				\
	sys/x86/include/specialreg.h > patch.hwpmc5

# 6 - pmctrace
git diff -U99999999 origin/master usr.sbin/Makefile		\
	lib/libipt						\
	usr.sbin/pmctrace/Makefile usr.sbin/pmctrace/pmctrace.c	\
	usr.sbin/pmctrace/pmctrace.h > patch.hwpmc6

# 7 - pmctrace PT
git diff -U99999999 origin/master				\
	usr.sbin/pmctrace/pmctrace_pt.* > patch.hwpmc7

# 8 - pmctrace CS
git diff -U99999999 origin/master				\
	usr.sbin/pmctrace/pmctrace_cs.* > patch.hwpmc8

# 9 - pmcstat libpmcstat
git diff -U99999999 origin/master				\
	lib/libpmcstat usr.sbin/pmcstat > patch.hwpmc9
