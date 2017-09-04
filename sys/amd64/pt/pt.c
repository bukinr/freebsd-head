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
#include <sys/systm.h>
#include <sys/ioccom.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/conf.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/vmem.h>
#include <sys/vmmeter.h>
#include <sys/bus.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_pager.h>
#include <vm/vm_phys.h>
#include <vm/vm_radix.h>
#include <vm/pmap.h>

#include <machine/intr_machdep.h>
#include <x86/apicvar.h>
#include <machine/cpu.h>
#include <machine/cpufunc.h>
#include <machine/md_var.h>
#include <machine/specialreg.h>
#include <machine/pt.h>
#include <machine/ptreg.h>
#include <machine/pcb.h>

#include <amd64/pt/ptvar.h>

#define	PT_DEBUG
#undef	PT_DEBUG

#ifdef	PT_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

static struct cdev_pager_ops pt_pg_ops;
struct pt_softc pt_sc;

static int
pt_pg_ctor(void *handle, vm_ooffset_t size, vm_prot_t prot,
    vm_ooffset_t foff, struct ucred *cred, u_short *color)
{

	return (0);
}

static void
pt_pg_dtor(void *handle)
{
	struct pt_vm_handle *vmh;
	struct pt_softc *sc;

	vmh = handle;
	if (vmh == NULL) {
		dprintf("%s: vmh not found.\n", __func__);
		return;
	}

	sc = vmh->sc;
	if (sc == NULL) {
		dprintf("%s: sc is NULL\n", __func__);
		return;
	}

	uint64_t *addr;
	addr = (uint64_t *)vmh->base;
	printf("%lx %lx\n", addr[0], addr[1]);

	printf("output base %lx\n", rdmsr(MSR_IA32_RTIT_OUTPUT_BASE));
	printf("output base ptr %lx\n", rdmsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS));

	contigfree(vmh->base, vmh->size, M_PT);
	free(vmh, M_PT);
}

static int
pt_pg_fault(vm_object_t object, vm_ooffset_t offset,
    int prot, vm_page_t *mres)
{
	vm_pindex_t pidx;
	struct pt_vm_handle *vmh;
	vm_page_t page;
	vm_offset_t paddr;
	struct pt_softc *sc;

	sc = &pt_sc;

	printf("%s: offset 0x%lx\n", __func__, offset);

	vmh = object->handle;
	if (vmh == NULL)
		return (VM_PAGER_FAIL);

	pidx = OFF_TO_IDX(offset);

	paddr = vtophys(vmh->base) + offset;
	paddr = vtophys(sc->topa) + offset;

	if (((*mres)->flags & PG_FICTITIOUS) != 0) {
		printf("PG_FICTITIOUS\n");
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

static struct cdev_pager_ops pt_pg_ops __unused = {
	.cdev_pg_ctor = pt_pg_ctor,
	.cdev_pg_dtor = pt_pg_dtor,
	.cdev_pg_fault = pt_pg_fault,
};

#if 0
static void
pt_intr(void)
{

	printf("pt intr\n");
}
#endif

static int
pt_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{
	pmap_t pmap;
	uint64_t cr3;
	struct pt_softc *sc;
	uint64_t reg;

	sc = &pt_sc;

	pmap = vmspace_pmap(td->td_proc->p_vmspace);
	cr3 = pmap->pm_cr3;

	lapic_enable_pmc();

	wrmsr(MSR_IA32_RTIT_CTL, 0);

	printf("cr3 %lx\n", cr3);
	wrmsr(MSR_IA32_RTIT_CR3_MATCH, cr3);
	//wrmsr(MSR_IA32_RTIT_OUTPUT_BASE, sc->base);
	wrmsr(MSR_IA32_RTIT_OUTPUT_BASE, (uint64_t)vtophys(sc->topa));

	reg = (sc->size - 1);
	printf("Writing reg %lx\n", reg);

	//topa
	reg = 0x7f;
	wrmsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, reg);

	/* Enable tracing */

	printf("Enabling trace\n");
	reg = RTIT_CTL_TRACEEN;
	reg |= RTIT_CTL_USER;
	reg |= RTIT_CTL_CR3FILTER;
	reg |= RTIT_CTL_BRANCHEN;
	reg |= RTIT_CTL_TSCEN;
	reg |= RTIT_CTL_TOPA;
	//reg |= RTIT_CTL_MTCEN;
	wrmsr(MSR_IA32_RTIT_CTL, reg);

	return (0);
}

static int
pt_mmap_single(struct cdev *cdev, vm_ooffset_t *offset,
    vm_size_t mapsize, struct vm_object **objp, int nprot)
{
	struct pt_vm_handle *vmh;
	struct pt_softc *sc;

	sc = &pt_sc;

	printf("%s: mapsize 0x%lx, offset %lx\n",
	    __func__, mapsize, *offset);

	vmh = malloc(sizeof(struct pt_vm_handle),
	    M_PT, M_WAITOK | M_ZERO);
	vmh->sc = sc;
	vmh->size = mapsize;
	vmh->base = contigmalloc(mapsize, M_PT, M_NOWAIT | M_ZERO,
	    0,		/* low */
	    ~0,		/* high */
	    PAGE_SIZE,	/* alignment */
	    0		/* boundary */);
	if (vmh->base == NULL) {
		printf("Can't alloc phys mem\n");
		free(vmh, M_PT);
		return (EINVAL);
	}

	sc->base = (uint64_t)vtophys(vmh->base); /* TEST */
	sc->size = vmh->size; /* TEST */

	vmh->mem = cdev_pager_allocate(vmh, OBJT_DEVICE, &pt_pg_ops,
	    mapsize, nprot, *offset, NULL);
	if (vmh->mem == NULL) {
		printf("cdev_pager_allocate failed\n");
		contigfree(vmh->base, vmh->size, M_PT);
		free(vmh, M_PT);
		return (ENOMEM);
	}

#if 0
	vm_object_t object;
	object = vmh->mem;

	int req;
	req = VM_ALLOC_NORMAL; //| VM_ALLOC_NOOBJ;

	VM_OBJECT_WLOCK(vmh->mem);
	sc->page = vm_page_alloc_contig(vmh->mem, 0, req, mapsize/PAGE_SIZE,
	    0, VM_MAX_ADDRESS,
	    PAGE_SIZE, 0,
	    VM_MEMATTR_UNCACHEABLE);
	VM_OBJECT_WUNLOCK(vmh->mem);

	printf("%s: page is %lx\n", __func__, (uint64_t)sc->page);
#endif

	*objp = vmh->mem;

	return (0);
}

static struct cdevsw pt_cdevsw = {
	.d_version =		D_VERSION,
	.d_ioctl =		pt_ioctl,
	.d_mmap_single =	pt_mmap_single,
	.d_name =		"Intel PT",
};

static int
pt_enumerate(struct pt_softc *sc)
{
	u_int cp[4];
	u_int *eax;
	u_int *ebx;
	u_int *ecx;

	eax = &cp[0];
	ebx = &cp[1];
	ecx = &cp[2];

	printf("Enumerating part 1\n");
	cpuid_count(PT_CPUID, 0, cp);
	printf("Maximum valid sub-leaf Index: %x\n", cp[0]);
	printf("ebx %x\n", cp[1]);
	printf("ecx %x\n", cp[2]);

	printf("Enumerating part 2\n");
	cpuid_count(PT_CPUID, 1, cp);
	printf("eax %x\n", cp[0]);
	printf("ebx %x\n", cp[1]);

	return (0);
}

static int
pt_load(void)
{
	struct pt_softc *sc;
	int error;

	sc = &pt_sc;

	printf("%s, cpu_stdext_feature %x\n", __func__, cpu_stdext_feature);
	if ((cpu_stdext_feature & CPUID_STDEXT_PROCTRACE) == 0)
		return (ENXIO);

	printf("%s\n", __func__);
	mtx_init(&sc->mtx, "PT driver", NULL, MTX_DEF);

	error = pt_enumerate(sc);
	if (error) {
		printf("%s: Failed to enumerate PT features.\n",
		    __func__);
		return (ENXIO);
	}

	printf("%s\n", __func__);
	sc->pt_cdev = make_dev(&pt_cdevsw, 0, UID_ROOT, GID_WHEEL,
	    0600, "ipt");

	sc->state |= PT_STATE_RUNNING;

	printf("%s\n", __func__);
	printf("PT initialized\n");

	wrmsr(MSR_IA32_RTIT_CTL, 0);
	wrmsr(MSR_IA32_RTIT_STATUS, 0);

	uint64_t *topa;
	void *buf;
	int i;

	//uint64_t *topa_entry;

	topa = malloc(PAGE_SIZE, M_PT, M_ZERO);

	for (i = 0; i < 1; i++) {
		buf = contigmalloc(2 * 1024 * 1024, M_PT, M_NOWAIT | M_ZERO,
		    0,		/* low */
		    ~0,		/* high */
		    PAGE_SIZE,	/* alignment */
		    0		/* boundary */);
		if (buf == NULL) {
			printf("Can't allocate topa\n");
			return (1);
		}
		topa[i] = (uint64_t)vtophys(buf) | TOPA_SIZE_2M | TOPA_INT;
	}
	topa[1] = vtophys(topa) | TOPA_END;

	sc->topa = topa;

#if 0
	uint64_t base;
	uint64_t base1;

	//base = (intptr_t)kmem_alloc_contig(kmem_arena,
	//	2048 * 1024 * 1024, M_ZERO, 0, ~0, PAGE_SIZE, 0, VM_MEMATTR_DEFAULT);

	uint64_t sz;

	sz = (5UL * 1024 * 1024 * 1024);
	base = (uint64_t)contigmalloc(sz, M_PT, M_WAITOK,
	    0 /* low */, ~0 /* high */,
	    0 /* alignment */, 0 /* boundary */);
	base1 = (uint64_t)contigmalloc(sz, M_PT, M_WAITOK,
	    0 /* low */, ~0 /* high */,
	    0 /* alignment */, 0 /* boundary */);

	printf("base %lx\n", base);
	printf("base1 %lx\n", base1);
	if (base)
		contigfree((void *)base, sz, M_PT);
	if (base1)
		contigfree((void *)base1, sz, M_PT);
#endif

	return (0);
}

static int
pt_unload(void)
{
	struct pt_softc *sc;

	sc = &pt_sc;

	printf("%s\n", __func__);

	if ((sc->state & PT_STATE_RUNNING) == 0)
		return (0);

	printf("%s\n", __func__);

	mtx_lock(&sc->mtx);
	sc->state &= ~PT_STATE_RUNNING;
	mtx_unlock(&sc->mtx);

	printf("%s\n", __func__);

	destroy_dev(sc->pt_cdev);
	mtx_destroy(&sc->mtx);

	printf("%s\n", __func__);

	return (0);
}

static int
pt_handler(module_t mod, int what, void *arg)
{
	int error;

	switch (what) {
	case MOD_LOAD:
		error = pt_load();
		break;
	case MOD_UNLOAD:
		error = pt_unload();
		break;
	default:
		error = 0;
		break;
	}

	return (error);
}

static moduledata_t pt_kmod = {
	"pt",
	pt_handler,
	NULL
};

DECLARE_MODULE(pt, pt_kmod, SI_SUB_LAST, SI_ORDER_ANY);
MODULE_VERSION(pt, 1);
