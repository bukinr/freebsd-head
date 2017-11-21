/*-
 * Copyright (c) 2017 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/pmckern.h>
#include <sys/conf.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>

#define	PMC_VM_DEBUG
#undef	PMC_VM_DEBUG

#ifdef	PMC_VM_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

#include "hwpmc_vm.h"

struct cdev *pmc_cdev[MAXCPU];

extern TAILQ_HEAD(, pmc_vm_map) pmc_maplist;

static int
pmc_mmap_single(struct cdev *cdev, vm_ooffset_t *offset,
    vm_size_t mapsize, struct vm_object **objp, int nprot)
{
	struct pmc_vm_map *map, *map_tmp;
	struct cdev_cpu *cc;

	cc = cdev->si_drv1;

	TAILQ_FOREACH_SAFE(map, &pmc_maplist, map_next, map_tmp) {
		if (map->cpu == cc->cpu && map->t == curthread) {
			*objp = map->obj;
			return (0);
		}
	}

	return (ENXIO);
}

static struct cdevsw pmc_cdevsw = {
	.d_version =		D_VERSION,
	.d_mmap_single =	pmc_mmap_single,
	.d_name =		"HWPMC",
};

int
pmc_vm_initialize(struct pmc_mdep *md)
{
	unsigned int maxcpu;
	struct cdev_cpu *cc;
	int cpu;

	maxcpu = pmc_cpu_max();

	for (cpu = 0; cpu < maxcpu; cpu++) {
		cc = malloc(sizeof(struct cdev_cpu), M_PMC, M_WAITOK | M_ZERO);
		cc->cpu = cpu;
		cc->md = md;

		pmc_cdev[cpu] = make_dev(&pmc_cdevsw, 0, UID_ROOT, GID_WHEEL,
		    0666, "pmc%d", cpu);
		pmc_cdev[cpu]->si_drv1 = cc;
	}

	return (0);
}

int
pmc_vm_finalize(void)
{
	unsigned int maxcpu;
	struct cdev_cpu *cc;
	int cpu;

	maxcpu = pmc_cpu_max();

	for (cpu = 0; cpu < maxcpu; cpu++) {
		cc = pmc_cdev[cpu]->si_drv1;
		free(cc, M_PMC);
		destroy_dev(pmc_cdev[cpu]);
	}

	return (0);
}
