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
#include <sys/bus.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/conf.h>
#include <sys/module.h>
#include <sys/proc.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_pager.h>
#include <vm/pmap.h>

#include <machine/md_var.h>
#include <machine/specialreg.h>
#include <machine/bus.h>

#include "sgx.h"

#define	SGX_CPUID			0x12
#define	SGX_PAGE_SIZE			4096
#define	SGX_VA_PAGE_SLOTS		512

#define	DEBUG
#undef	DEBUG

#ifdef	DEBUG
#define	debug_printf(dev, fmt, ...) \
    device_printf(dev, fmt, ##__VA_ARGS__)
#else
#define	debug_printf(dev, fmt, ...)
#endif

MALLOC_DEFINE(M_SGX, "sgx", "SGX driver");

/* EPC (Enclave Page Cache) page */
struct epc_page {
	uint64_t		base;
	uint64_t		phys;
	uint8_t			used;
};

/* Version Array page */
struct va_page {
	struct epc_page		*epc_page;
	TAILQ_ENTRY(va_page)	va_next;
	bool			slots[SGX_VA_PAGE_SLOTS];
};

struct sgx_enclave_page {
	struct epc_page			*epc_page;
	struct va_page			*va_page;
	int				va_slot;
	uint64_t			addr;
	TAILQ_ENTRY(sgx_enclave_page)	next;
};

struct sgx_enclave {
	uint64_t			base;
	uint64_t			size;
	struct sgx_enclave_page		secs_page;
	struct sgx_vm_handle		*vmh;
	struct mtx			mtx;
	TAILQ_ENTRY(sgx_enclave)	next;
	TAILQ_HEAD(, sgx_enclave_page)	pages;
	TAILQ_HEAD(, va_page)		va_pages;
};

struct sgx_softc {
	struct cdev			*sgx_cdev;
	device_t			dev;
	struct mtx			mtx_epc;
	struct mtx			mtx;
	struct epc_page			*epc_pages;
	uint32_t			npages;
	TAILQ_HEAD(, sgx_enclave)	enclaves;
};

struct sgx_vm_handle {
	struct sgx_softc	*sc;
	vm_object_t		mem;
	uint64_t		base;
	vm_size_t		size;
	struct sgx_enclave	*enclave;
};

static struct epc_page *
sgx_epc_page_get(struct sgx_softc *sc)
{
	struct epc_page *epc;
	int i;

	mtx_lock(&sc->mtx_epc);

	for (i = 0; i < sc->npages; i++) {
		epc = &sc->epc_pages[i];
		if (epc->used == 0) {
			epc->used = 1;
			mtx_unlock(&sc->mtx_epc);
			return (epc);
		}
	}

	mtx_unlock(&sc->mtx_epc);

	return (NULL);
}

static void
sgx_epc_page_put(struct sgx_softc *sc, struct epc_page *epc)
{

	epc->used = 0;
}

static int
sgx_epc_page_count(struct sgx_softc *sc)
{
	struct epc_page *epc;
	int cnt;
	int i;

	cnt = 0;

	for (i = 0; i < sc->npages; i++) {
		epc = &sc->epc_pages[i];
		if (epc->used == 0) {
			cnt++;
		}
	}

	return (cnt);
}

static int
sgx_va_slot_alloc(struct va_page *va_page)
{
	int i;

	for (i = 0; i < SGX_VA_PAGE_SLOTS; i++) {
		if (va_page->slots[i] == 0) {
			va_page->slots[i] = 1;
			return (i);
		}
	}

	return (-1);
}

static int
sgx_va_slot_free(struct sgx_softc *sc,
    struct sgx_enclave *enclave,
    struct sgx_enclave_page *enclave_page)
{
	struct va_page *va_page;
	struct epc_page *epc;
	int va_slot;
	int found;
	int i;

	found = 0;

	va_page = enclave_page->va_page;
	va_slot = enclave_page->va_slot;

	KASSERT(va_page->slots[va_slot] == 1, ("freeing unused page"));

	va_page->slots[va_slot] = 0;

	/* Now check if we need to remove va_page. */
	for (i = 0; i < SGX_VA_PAGE_SLOTS; i++) {
		if (va_page->slots[i] == 1) {
			found = 1;
			break;
		}
	}

	if (found == 0) {
		mtx_lock(&enclave->mtx);
		TAILQ_REMOVE(&enclave->va_pages, va_page, va_next);
		mtx_unlock(&enclave->mtx);

		epc = va_page->epc_page;
		__eremove((void *)epc->base);
		sgx_epc_page_put(sc, epc);
		free(enclave_page->va_page, M_SGX);
	}

	return (0);
}

static int
sgx_enclave_page_remove(struct sgx_softc *sc,
    struct sgx_enclave *enclave,
    struct sgx_enclave_page *enclave_page)
{
	struct epc_page *epc;

	sgx_va_slot_free(sc, enclave, enclave_page);

	epc = enclave_page->epc_page;
	__eremove((void *)epc->base);
	sgx_epc_page_put(sc, epc);

	return (0);
}

static int
sgx_enclave_page_construct(struct sgx_softc *sc,
    struct sgx_enclave *enclave,
    struct sgx_enclave_page *enclave_page)
{
	struct va_page *va_page;
	struct va_page *va_page_tmp;
	struct epc_page *epc;
	int va_slot;

	va_slot = -1;

	mtx_lock(&enclave->mtx);
	TAILQ_FOREACH_SAFE(va_page, &enclave->va_pages, va_next,
	    va_page_tmp) {
		va_slot = sgx_va_slot_alloc(va_page);
		if (va_slot >= 0) {
			break;
		}
	}
	mtx_unlock(&enclave->mtx);

	if (va_slot < 0) {
		epc = sgx_epc_page_get(sc);
		if (epc == NULL) {
			device_printf(sc->dev,
			    "%s: No free epc pages available\n", __func__);
			return (-1);
		}

		va_page = malloc(sizeof(struct va_page), M_SGX, M_WAITOK | M_ZERO);
		if (va_page == NULL) {
			device_printf(sc->dev,
			    "%s: Can't alloc va_page\n", __func__);
			sgx_epc_page_put(sc, epc);
			return (-1);
		}

		va_slot = sgx_va_slot_alloc(va_page);
		va_page->epc_page = epc;
		__epa((void *)epc->base);

		mtx_lock(&enclave->mtx);
		TAILQ_INSERT_TAIL(&enclave->va_pages, va_page, va_next);
		mtx_unlock(&enclave->mtx);
	}

	enclave_page->va_page = va_page;
	enclave_page->va_slot = va_slot;

	return (0);
}

static int
sgx_mem_find(struct sgx_softc *sc, uint64_t addr,
    vm_map_entry_t *entry0, vm_object_t *mem0)
{
	struct proc *proc;
	vm_map_t map;
	vm_map_entry_t entry;
	vm_object_t mem;
	vm_pindex_t pindex;
	vm_prot_t prot;
	boolean_t wired;
	int error;

	proc = curthread->td_proc;

	map = &proc->p_vmspace->vm_map;
	error = vm_map_lookup(&map, addr, VM_PROT_NONE, &entry,
	    &mem, &pindex, &prot, &wired);
	vm_map_lookup_done(map, entry);
	if (error != 0) {
		device_printf(sc->dev,
		    "%s: can't find enclave\n", __func__);
		return (-1);
	}

	*mem0 = mem;
	*entry0 = entry;

	return (0);
}

static int
sgx_enclave_find(struct sgx_softc *sc, uint64_t addr,
    struct sgx_enclave **encl)
{
	struct sgx_vm_handle *vmh;
	vm_map_entry_t entry;
	vm_object_t mem;
	int ret;

	ret = sgx_mem_find(sc, addr, &entry, &mem);
	if (ret != 0) {
		return (-1);
	}

	vmh = mem->handle;
	*encl = vmh->enclave;

	return (0);
}

static struct sgx_enclave *
sgx_enclave_alloc(struct sgx_softc *sc, struct secs *secs)
{
	struct sgx_enclave *enclave;
	struct sgx_vm_handle *vmh;
	vm_map_entry_t entry;
	vm_object_t mem;
	int ret;

	ret = sgx_mem_find(sc, secs->base, &entry, &mem);
	if (ret != 0) {
		device_printf(sc->dev, "Can't find vm_map\n");
		return (NULL);
	}

	vmh = mem->handle;
	vmh->base = (entry->start - entry->offset);

	enclave = malloc(sizeof(struct sgx_enclave), M_SGX, M_WAITOK | M_ZERO);
	if (enclave == NULL) {
		device_printf(sc->dev, "Can't alloc memory for enclave\n");
		return (NULL);
	}

	TAILQ_INIT(&enclave->pages);
	TAILQ_INIT(&enclave->va_pages);

	mtx_init(&enclave->mtx, "SGX enclave", NULL, MTX_DEF);

	enclave->base = secs->base;
	enclave->size = secs->size;

	enclave->vmh = vmh;
	vmh->enclave = enclave;

	return (enclave);
}

static int
sgx_enclave_free(struct sgx_softc *sc,
    struct sgx_enclave *enclave)
{
	struct sgx_enclave_page *enclave_page_tmp;
	struct sgx_enclave_page *enclave_page;

	mtx_lock(&sc->mtx);
	TAILQ_REMOVE(&sc->enclaves, enclave, next);
	mtx_unlock(&sc->mtx);

	/* Remove all the enclave pages */
	TAILQ_FOREACH_SAFE(enclave_page, &enclave->pages, next,
	    enclave_page_tmp) {
		TAILQ_REMOVE(&enclave->pages, enclave_page, next);
		sgx_enclave_page_remove(sc, enclave, enclave_page);
		free(enclave_page, M_SGX);
	}

	/* Remove SECS page */
	enclave_page = &enclave->secs_page;
	sgx_enclave_page_remove(sc, enclave, enclave_page);

	free(enclave, M_SGX);

	return (0);
}

static void
sgx_measure_page(struct epc_page *secs, struct epc_page *epc,
    uint16_t mrmask)
{
	int i, j;

	for (i = 0, j = 1; i < PAGE_SIZE; i += 0x100, j <<= 1) {
		if (!(j & mrmask)) {
			continue;
		}

		__eextend((void *)secs->base,
		    (void *)((uint64_t)epc->base + i));
	}
}

static int
sgx_tcs_validate(struct tcs *tcs)
{
	int i;

	if ((tcs->flags != 0) ||
	    (tcs->ossa & (PAGE_SIZE - 1)) ||
	    (tcs->ofsbasgx & (PAGE_SIZE - 1)) ||
	    (tcs->ogsbasgx & (PAGE_SIZE - 1)) ||
	    ((tcs->fslimit & 0xfff) != 0xfff) ||
	    ((tcs->gslimit & 0xfff) != 0xfff)) {
		return (-1);
	}

	for (i = 0; i < sizeof(tcs->reserved)/sizeof(uint64_t); i++) {
		if (tcs->reserved[i]) {
			return (-1);
		}
	}

	return (0);
}

static void
sgx_tcs_dump(struct sgx_softc *sc, struct tcs *t)
{

	debug_printf(sc->dev, "t->state %lx\n", t->state);
	debug_printf(sc->dev, "t->flags %lx\n", t->flags);
	debug_printf(sc->dev, "t->ossa %lx\n", t->ossa);
	debug_printf(sc->dev, "t->cssa %x\n", t->cssa);
	debug_printf(sc->dev, "t->nssa %x\n", t->nssa);
	debug_printf(sc->dev, "t->oentry %lx\n", t->oentry);
	debug_printf(sc->dev, "t->aep %lx\n", t->aep);
	debug_printf(sc->dev, "t->ofsbasgx %lx\n", t->ofsbasgx);
	debug_printf(sc->dev, "t->ogsbasgx %lx\n", t->ogsbasgx);
	debug_printf(sc->dev, "t->fslimit %x\n", t->fslimit);
	debug_printf(sc->dev, "t->gslimit %x\n", t->gslimit);
}

static int
sgx_pg_ctor(void *handle, vm_ooffset_t size, vm_prot_t prot,
    vm_ooffset_t foff, struct ucred *cred, u_short *color)
{
	struct sgx_vm_handle *vmh;
	struct sgx_softc *sc;

	if (handle == NULL) {
		printf("%s: vmh not found\n", __func__);
		return (0);
	}

	vmh = handle;
	sc = vmh->sc;

	debug_printf(sc->dev,
	    "%s: vmh->base %lx foff 0x%lx size 0x%lx\n",
	    __func__, vmh->base, foff, size);

	return (0);
}

static void
sgx_pg_dtor(void *handle)
{
	struct sgx_vm_handle *vmh;
	struct sgx_softc *sc;

	if (handle == NULL) {
		printf("%s: vmh not found\n", __func__);
		return;
	}

	vmh = handle;
	sc = vmh->sc;

	if (vmh->enclave == NULL) {
		device_printf(sc->dev,
		    "%s: enclave not found\n", __func__);
		return;
	}
	sgx_enclave_free(sc, vmh->enclave);
	free(vmh, M_SGX);

	debug_printf(sc->dev, "count free epc pages: %d\n",
	    sgx_epc_page_count(sc));
}

static int
sgx_pg_fault(vm_object_t object, vm_ooffset_t offset,
    int prot, vm_page_t *mres)
{
	struct sgx_enclave *enclave;
	struct sgx_vm_handle *vmh;
	struct sgx_softc *sc;
	vm_page_t page;
	vm_memattr_t memattr;
	vm_pindex_t pidx;
	vm_paddr_t paddr;
	struct sgx_enclave_page *enclave_page_tmp;
	struct sgx_enclave_page *enclave_page;
	struct epc_page *epc;
	int found;

	vmh = object->handle;
	if (vmh == NULL) {
		return (VM_PAGER_FAIL);
	}

	enclave = vmh->enclave;
	if (enclave == NULL) {
		return (VM_PAGER_FAIL);
	}

	sc = vmh->sc;

	debug_printf(sc->dev, "%s: offset 0x%lx\n", __func__, offset);

	memattr = object->memattr;
	pidx = OFF_TO_IDX(offset);

	found = 0;
	mtx_lock(&enclave->mtx);
	TAILQ_FOREACH_SAFE(enclave_page, &enclave->pages, next,
	    enclave_page_tmp) {
		if ((vmh->base + offset) == enclave_page->addr) {
			found = 1;
			break;
		}
	}
	mtx_unlock(&enclave->mtx);
	if (found == 0) {
		device_printf(sc->dev,
		    "%s: page not found\n", __func__);
		return (VM_PAGER_FAIL);
	}

	epc = enclave_page->epc_page;
	paddr = epc->phys;

	if (((*mres)->flags & PG_FICTITIOUS) != 0) {
		page = *mres;
		vm_page_updatefake(page, paddr, memattr);
	} else {
		VM_OBJECT_WUNLOCK(object);
		page = vm_page_getfake(paddr, memattr);
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

static struct cdev_pager_ops sgx_pg_ops = {
	.cdev_pg_ctor = sgx_pg_ctor,
	.cdev_pg_dtor = sgx_pg_dtor,
	.cdev_pg_fault = sgx_pg_fault,
};

static int
sgx_create(struct sgx_softc *sc, struct sgx_enclave_create *param)
{
	struct sgx_enclave_page *secs_page;
	struct page_info pginfo;
	struct secinfo secinfo;
	struct sgx_enclave *enclave;
	struct epc_page *epc;
	struct secs *m_secs;
	int ret;

	epc = NULL;
	m_secs = NULL;
	enclave = NULL;

	/* SGX Enclave Control Structure (SECS) */
	m_secs = (struct secs *)kmem_alloc_contig(kmem_arena, PAGE_SIZE,
	    0/*flags*/, 0, BUS_SPACE_MAXADDR_32BIT,
	    PAGE_SIZE, 0, VM_MEMATTR_DEFAULT);
	if (m_secs == NULL) {
		device_printf(sc->dev, "Can't allocate memory.\n");
		goto error;
	}

	ret = copyin((void *)param->src, m_secs, sizeof(struct secs));
	if (ret != 0) {
		device_printf(sc->dev, "Can't copy SECS\n");
		goto error;
	}

	enclave = sgx_enclave_alloc(sc, m_secs);
	if (enclave == NULL) {
		device_printf(sc->dev, "Can't copy SECS\n");
		goto error;
	}

	memset(&secinfo, 0, sizeof(struct secinfo));
	memset(&pginfo, 0, sizeof(struct page_info));
	pginfo.linaddr = 0;
	pginfo.srcpge = (uint64_t)m_secs;
	pginfo.secinfo = (uint64_t)&secinfo;
	pginfo.secs = 0;

	epc = sgx_epc_page_get(sc);
	if (epc == NULL) {
		device_printf(sc->dev,
		    "%s: failed to get epc page\n", __func__);
		goto error;
	}

	ret = sgx_enclave_page_construct(sc, enclave, &enclave->secs_page);
	if (ret != 0) {
		device_printf(sc->dev, "can't construct page\n");
		goto error;
	}

	secs_page = &enclave->secs_page;
	secs_page->epc_page = epc;

	__ecreate(&pginfo, (void *)epc->base);

	mtx_lock(&sc->mtx);
	TAILQ_INSERT_TAIL(&sc->enclaves, enclave, next);
	mtx_unlock(&sc->mtx);

	kmem_free(kmem_arena, (vm_offset_t)m_secs, PAGE_SIZE);

	return (0);

error:
	if (m_secs != NULL) {
		kmem_free(kmem_arena, (vm_offset_t)m_secs, PAGE_SIZE);
	}
	if (enclave != NULL) {
		free(enclave, M_SGX);
	}
	if (epc != NULL) {
		sgx_epc_page_put(sc, epc);
	}

	return (-1);
}

static int
sgx_add_page(struct sgx_softc *sc, struct sgx_enclave_add_page *addp)
{
	struct sgx_enclave_page *enclave_page;
	struct epc_page *secs_epc_page;
	struct sgx_enclave *enclave;
	struct epc_page *epc;
	struct page_info pginfo;
	struct secinfo secinfo;
	void *tmp_vaddr;
	uint64_t page_type;
	struct proc *proc;
	struct tcs *t;
	pmap_t pmap;
	int ret;

	tmp_vaddr = NULL;
	enclave_page = NULL;
	epc = NULL;

	ret = sgx_enclave_find(sc, addp->addr, &enclave);
	if (ret != 0) {
		device_printf(sc->dev, "Failed to find enclave\n");
		return (-1);
	}

	proc = curthread->td_proc;
	pmap = vm_map_pmap(&proc->p_vmspace->vm_map);

	memset(&secinfo, 0, sizeof(struct secinfo));
	ret = copyin((void *)addp->secinfo, &secinfo, sizeof(struct secinfo));
	if (ret != 0) {
		device_printf(sc->dev,
		    "%s: Failed to copy secinfo\n", __func__);
		return (-1);
	}

	tmp_vaddr = (void *)kmem_alloc_contig(kmem_arena, PAGE_SIZE,
	    0/*flags*/, 0, BUS_SPACE_MAXADDR_32BIT,
	    PAGE_SIZE, 0, VM_MEMATTR_DEFAULT);
	if (tmp_vaddr == NULL) {
		device_printf(sc->dev,
		    "%s: failed to alloc memory\n", __func__);
		goto error;
	}

	ret = copyin((void *)addp->src, tmp_vaddr, PAGE_SIZE);
	if (ret != 0) {
		device_printf(sc->dev,
		    "%s: Failed to copy page\n", __func__);
		goto error;
	}

	page_type = (secinfo.flags >> 8) & 0xff;
	if (page_type == PT_TCS) {
		t = (struct tcs *)tmp_vaddr;
		if (sgx_tcs_validate(t) != 0) {
			device_printf(sc->dev,
			    "%s: TCS page validation failed\n", __func__);
			return (-1);
		}
		sgx_tcs_dump(sc, t);
	}

	enclave_page = malloc(sizeof(struct sgx_enclave_page),
	    M_SGX, M_WAITOK | M_ZERO);
	if (enclave_page == NULL) {
		device_printf(sc->dev,
		    "%s: Can't allocate enclave page.\n", __func__);
		goto error;
	}

	epc = sgx_epc_page_get(sc);
	if (epc == NULL) {
		device_printf(sc->dev,
		    "%s: failed to get epc page\n", __func__);
		goto error;
	}

	ret = sgx_enclave_page_construct(sc, enclave, enclave_page);
	if (ret != 0) {
		device_printf(sc->dev, "Can't construct page\n");
		goto error;
	}

	enclave_page->epc_page = epc;
	enclave_page->addr = addp->addr;
	secs_epc_page = enclave->secs_page.epc_page;

	memset(&pginfo, 0, sizeof(struct page_info));
	pginfo.linaddr = (uint64_t)addp->addr;
	pginfo.srcpge = (uint64_t)tmp_vaddr;
	pginfo.secinfo = (uint64_t)&secinfo;
	pginfo.secs = (uint64_t)secs_epc_page->base;
	__eadd(&pginfo, (void *)epc->base);
	kmem_free(kmem_arena, (vm_offset_t)tmp_vaddr, PAGE_SIZE);

	sgx_measure_page(enclave->secs_page.epc_page, epc, addp->mrmask);

	mtx_lock(&enclave->mtx);
	TAILQ_INSERT_TAIL(&enclave->pages, enclave_page, next);
	mtx_unlock(&enclave->mtx);

	return (0);

error:
	if (tmp_vaddr != NULL) {
		kmem_free(kmem_arena, (vm_offset_t)tmp_vaddr, PAGE_SIZE);
	}
	if (epc != NULL) {
		sgx_epc_page_put(sc, epc);
	}
	if (enclave_page != NULL) {
		/* TODO */
	}

	return (-1);
}

static int
sgx_init(struct sgx_softc *sc, struct sgx_enclave_init *initp)
{
	struct epc_page *secs_epc_page;
	struct sgx_enclave *enclave;
	void *tmp_vaddr;
	void *einittoken;
	void *sigstruct;
	int retry;
	int ret;

	tmp_vaddr = NULL;

	debug_printf(sc->dev, "%s: addr %lx, sigstruct %lx,"
	    "einittoken %lx\n", __func__, initp->addr,
	    initp->sigstruct, initp->einittoken);

	ret = sgx_enclave_find(sc, initp->addr, &enclave);
	if (ret != 0) {
		device_printf(sc->dev, "Failed to get enclave\n");
		goto error;
	}

	secs_epc_page = enclave->secs_page.epc_page;

	tmp_vaddr = (void *)kmem_alloc_contig(kmem_arena, PAGE_SIZE,
	    0/*flags*/, 0, BUS_SPACE_MAXADDR_32BIT,
	    PAGE_SIZE, 0, VM_MEMATTR_DEFAULT);
	if (tmp_vaddr == NULL) {
		device_printf(sc->dev,
		    "%s: failed to alloc memory\n", __func__);
		goto error;
	}
	sigstruct = tmp_vaddr;
	einittoken = (void *)((uint64_t)sigstruct + PAGE_SIZE / 2);

	ret = copyin((void *)initp->sigstruct, sigstruct,
	    SIGSTRUCT_SIZE);
	if (ret != 0) {
		device_printf(sc->dev,
		    "%s: Failed to copy SIGSTRUCT page\n", __func__);
		goto error;
	}

	ret = copyin((void *)initp->einittoken, einittoken,
	    EINITTOKEN_SIZE);
	if (ret != 0) {
		device_printf(sc->dev,
		    "%s: Failed to copy EINITTOKEN page\n", __func__);
		goto error;
	}

	retry = 16;
	do {
		ret = __einit(sigstruct, (void *)secs_epc_page->base,
		    einittoken);
		debug_printf(sc->dev,
		    "%s: __einit returned %d\n", __func__, ret);
	} while (ret == SGX_UNMASKED_EVENT && retry--);

	if (ret != 0) {
		debug_printf(sc->dev,
		    "%s: Failed to init enclave: %d\n", __func__, ret);
		goto error;
	}

error:
	if (tmp_vaddr != NULL) {
		kmem_free(kmem_arena, (vm_offset_t)tmp_vaddr, PAGE_SIZE);
	}
	
	return (ret);
}

static int
sgx_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{
	struct sgx_enclave_add_page *addp;
	struct sgx_enclave_create *param;
	struct sgx_enclave_init *initp;
	struct sgx_softc *sc;
	int ret;

	sc = dev->si_drv1;
	cmd &= 0xffff;

	debug_printf(sc->dev, "%s: cmd %lx\n", __func__, cmd);

	ret = 0;

	switch (cmd) {
	case SGX_IOC_ENCLAVE_CREATE:
		param = (struct sgx_enclave_create *)addr;
		ret = sgx_create(sc, param);
		break;
	case SGX_IOC_ENCLAVE_ADD_PAGE:
		addp = (struct sgx_enclave_add_page *)addr;
		ret = sgx_add_page(sc, addp);
		break;
	case SGX_IOC_ENCLAVE_INIT:
		initp = (struct sgx_enclave_init *)addr;
		ret = sgx_init(sc, initp);
		break;
	default:
		return (EINVAL);
	}

	if (ret == -1) {
		ret = EINVAL;
	}

	return (ret);
}

static int
sgx_mmap_single(struct cdev *cdev, vm_ooffset_t *offset,
    vm_size_t mapsize, struct vm_object **objp, int nprot)
{
	struct sgx_vm_handle *vmh;
	struct sgx_softc *sc;

	sc = cdev->si_drv1;

	debug_printf(sc->dev, "%s: mapsize 0x%lx, offset %lx\n",
	    __func__, mapsize, *offset);

	vmh = malloc(sizeof(struct sgx_vm_handle),
	    M_SGX, M_WAITOK | M_ZERO);
	if (vmh == NULL) {
		device_printf(sc->dev,
		    "%s: Can't alloc memory\n", __func__);
		return (ENOMEM);
	}

	vmh->sc = sc;
	vmh->size = mapsize;
	vmh->mem = cdev_pager_allocate(vmh, OBJT_DEVICE, &sgx_pg_ops,
	    mapsize, nprot, *offset, NULL);
	if (vmh->mem == NULL) {
		free(vmh, M_SGX);
		return (ENOMEM);
	}

	*objp = vmh->mem;

	return (0);
}

static struct cdevsw sgx_cdevsw = {
	.d_version =		D_VERSION,
	.d_ioctl =		sgx_ioctl,
	.d_mmap_single =	sgx_mmap_single,
	.d_name =		"Intel SGX",
};

static int
sgx_get_epc_area(struct sgx_softc *sc)
{
	vm_offset_t epc_base_vaddr;
	uint64_t epc_base;
	uint64_t epc_size;
	u_int cp[4];
	int i;

	cpuid_count(SGX_CPUID, 0x2, cp);

	epc_base = ((uint64_t)(cp[1] & 0xfffff) << 32) + \
	    (cp[0] & 0xfffff000);
	epc_size = ((uint64_t)(cp[3] & 0xfffff) << 32) + \
	    (cp[2] & 0xfffff000);
	sc->npages = epc_size / SGX_PAGE_SIZE;

	device_printf(sc->dev, "%s: epc_base %lx size %lx (%d pages)\n",
	    __func__, epc_base, epc_size, sc->npages);

	epc_base_vaddr = (vm_offset_t)pmap_mapdev(epc_base, epc_size);

	sc->epc_pages = malloc(sizeof(struct epc_page) * sc->npages,
	    M_DEVBUF, M_WAITOK | M_ZERO);
	if (sc->epc_pages == NULL) {
		device_printf(sc->dev,
		    "%s: can't alloc memory\n", __func__);
		return (ENOMEM);
	}

	for (i = 0; i < sc->npages; i++) {
		sc->epc_pages[i].base = epc_base_vaddr + SGX_PAGE_SIZE * i;
		sc->epc_pages[i].phys = epc_base + SGX_PAGE_SIZE * i;
		sc->epc_pages[i].used = 0;
	}

	debug_printf(sc->dev, "npages %d\n", sc->npages);

	return (0);
}

static void
sgx_identify(driver_t *driver, device_t parent)
{
	u_int regs[4];

	if ((cpu_stdext_feature & CPUID_STDEXT_SGX) == 0)
		return;

	do_cpuid(1, regs);

	if ((regs[2] & CPUID2_OSXSAVE) == 0) {
		device_printf(parent, "OSXSAVE not found\n");
		return;
	}

	if ((rcr4() & CR4_XSAVE) == 0) {
		device_printf(parent, "CR4_XSAVE not found\n");
		return;
	}

	if ((rcr4() & CR4_FXSR) == 0) {
		device_printf(parent, "CR4_FXSR not found\n");
		return;
	}

	/* Make sure we're not being doubly invoked. */
	if (device_find_child(parent, "sgx", -1) != NULL)
		return;

	/* We attach a sgx child for every CPU */
	if (BUS_ADD_CHILD(parent, 10, "sgx", -1) == NULL)
		device_printf(parent, "add sgx child failed\n");
}

static int
sgx_probe(device_t dev)
{

	device_set_desc(dev, "Intel SGX");

	return (BUS_PROBE_DEFAULT);
}

static int
sgx_attach(device_t dev)
{
	struct sgx_softc *sc;
	int ret;

	sc = device_get_softc(dev);
	sc->dev = dev;

	mtx_init(&sc->mtx, "SGX", NULL, MTX_DEF);
	mtx_init(&sc->mtx_epc, "SGX EPC area", NULL, MTX_DEF);

	ret = sgx_get_epc_area(sc);
	if (ret != 0) {
		device_printf(sc->dev,
		    "%s: Failed to get Processor Reserved Memory area\n",
		    __func__);
		return (ENXIO);
	}

	sc->sgx_cdev = make_dev(&sgx_cdevsw, 0, UID_ROOT, GID_WHEEL,
	    0600, "isgx");
	if (sc->sgx_cdev == NULL) {
		device_printf(dev,
		    "%s: Failed to create character device.\n", __func__);
		return (ENXIO);
	}
	sc->sgx_cdev->si_drv1 = sc;

	TAILQ_INIT(&sc->enclaves);

	return (0);
}

static device_method_t sgx_methods[] = {
	DEVMETHOD(device_identify,	sgx_identify),
	DEVMETHOD(device_probe,		sgx_probe),
	DEVMETHOD(device_attach,	sgx_attach),
	{ 0, 0 }
};

static driver_t sgx_driver = {
	"sgx",
	sgx_methods,
	sizeof(struct sgx_softc),
};

static devclass_t sgx_devclass;

DRIVER_MODULE(sgx, nexus, sgx_driver, sgx_devclass, 0, 0);
