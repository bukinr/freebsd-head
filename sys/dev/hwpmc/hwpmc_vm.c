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

struct cdev_cpu {
	int cpu;
	struct pmc_mdep *md;
};

struct pmc_vm_handle {
	vm_object_t		mem;
	vm_size_t		size;
	void *			base;
	struct cdev_cpu		*cc;
};

struct pmc_vm_handle *vmh;
struct cdev *pmc_cdev[MAXCPU];

static int
pmc_pg_ctor(void *handle, vm_ooffset_t size, vm_prot_t prot,
    vm_ooffset_t foff, struct ucred *cred, u_short *color)
{

	return (0);
}

static void
pmc_pg_dtor(void *handle)
{
	struct pmc_vm_handle *vmh;

	vmh = handle;

	free(vmh, M_PMC);
}

static int
pmc_pg_fault(vm_object_t object, vm_ooffset_t offset,
    int prot, vm_page_t *mres)
{
	struct pmc_vm_handle *vmh;
	struct pmc_mdep *md;
	struct cdev_cpu *cc;
	vm_paddr_t paddr;
	vm_pindex_t pidx;
	vm_page_t page;
	int error;

	vmh = object->handle;
	if (vmh == NULL) {
		dprintf("%s: offset 0x%lx, VM_PAGER_FAIL: vmh is null\n",
		    __func__, offset);
		return (VM_PAGER_FAIL);
	}

	cc = vmh->cc;
	md = cc->md;

	dprintf("%s%d: offset %lx\n", __func__, cc->cpu, offset);

	pidx = OFF_TO_IDX(offset);

	if (md->pmd_get_page == NULL)
		return (VM_PAGER_FAIL);

	error = (*md->pmd_get_page)(cc->cpu, offset, &paddr);
	if (error != 0)
		return (VM_PAGER_FAIL);

	if (((*mres)->flags & PG_FICTITIOUS) != 0) {
		/*
		 * If the passed in result page is a fake page, update it with
		 * the new physical address.
		 */
		page = *mres;
		vm_page_updatefake(page, paddr, object->memattr);
	} else {
		/*
		 * Replace the passed in reqpage page with our own fake page and
		 * free up the all of the original pages.
		 */

		VM_OBJECT_WUNLOCK(object);
		page = vm_page_getfake(paddr, object->memattr);
		VM_OBJECT_WLOCK(object);
		vm_page_lock(*mres);
		vm_page_free(*mres);
		vm_page_unlock(*mres);
		*mres = page;
		vm_page_insert(page, object, pidx);
	}

	page->valid = VM_PAGE_BITS_ALL;

	return (VM_PAGER_OK);
}

static struct cdev_pager_ops pmc_pg_ops = {
	.cdev_pg_ctor = pmc_pg_ctor,
	.cdev_pg_dtor = pmc_pg_dtor,
	.cdev_pg_fault = pmc_pg_fault,
};

static int
pmc_mmap_single(struct cdev *cdev, vm_ooffset_t *offset,
    vm_size_t mapsize, struct vm_object **objp, int nprot)
{

	vmh = malloc(sizeof(struct pmc_vm_handle),
	    M_PMC, M_WAITOK | M_ZERO);

	vmh->cc = cdev->si_drv1;
	vmh->mem = cdev_pager_allocate(vmh, OBJT_DEVICE, &pmc_pg_ops,
	    mapsize, nprot, *offset, NULL);
	if (vmh->mem == NULL)
		return (ENXIO);

	*objp = vmh->mem;

	return (0);
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
		    0600, "pmc%d", cpu);
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
