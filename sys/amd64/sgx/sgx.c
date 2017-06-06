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

#include <machine/md_var.h>
#include <machine/specialreg.h>
#include <machine/bus.h>

#include "sgx.h"

#define	SGX_CPUID			0x12
#define	SGX_PAGE_SIZE			4096
#define	SGX_VA_PAGE_SLOTS		512

MALLOC_DEFINE(M_SGX, "sgx", "SGX driver");

/* Enclave Page Cache */
struct epc_page {
	uint64_t		base;
	uint64_t		phys;
	uint8_t			used;
};

/* Version-Array page */
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
	struct privcmd_map		*map;
	TAILQ_ENTRY(sgx_enclave)	next;
	TAILQ_HEAD(, sgx_enclave_page)	pages;
	TAILQ_HEAD(, va_page)		va_pages;
};

struct sgx_softc {
	struct cdev			*sgx_cdev;
	device_t			dev;
	struct epc_page			*epc_pages;
	uint32_t			npages;
	TAILQ_HEAD(, sgx_enclave)	enclaves;
};

struct privcmd_map {
	struct sgx_softc	*sc;
	vm_object_t		mem;
	uint64_t		base;
	vm_size_t		size;
	struct sgx_enclave	*enclave;
};

static int
get_va_slot(struct va_page *va_page)
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
free_va_slot(struct sgx_enclave *enclave,
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

	if (va_page->slots[va_slot] == 0) {
		/* Error */
	}

	va_page->slots[va_slot] = 0;
	for (i = 0; i < SGX_VA_PAGE_SLOTS; i++) {
		if (va_page->slots[i] == 1) {
			found = 1;
			break;
		}
	}

	if (found == 0) {
		TAILQ_REMOVE(&enclave->va_pages, va_page, va_next);
		epc = va_page->epc_page;
		__eremove((void *)epc->base);
		epc->used = 0;
		free(enclave_page->va_page, M_SGX);
	}

	return (0);
}

static int
enclave_remove(struct sgx_enclave *enclave)
{
	struct sgx_enclave_page *enclave_page_tmp;
	struct sgx_enclave_page *enclave_page;
	struct epc_page *epc;

	TAILQ_FOREACH_SAFE(enclave_page, &enclave->pages, next, enclave_page_tmp) {
		TAILQ_REMOVE(&enclave->pages, enclave_page, next);
		free_va_slot(enclave, enclave_page);

		epc = enclave_page->epc_page;
		__eremove((void *)epc->base);
		epc->used = 0;
		free(enclave_page, M_SGX);
	}

	enclave_page = &enclave->secs_page;
	free_va_slot(enclave, enclave_page);

	epc = enclave_page->epc_page;
	__eremove((void *)epc->base);
	epc->used = 0;
	free(enclave, M_SGX);

	return (0);
}

static struct epc_page *
get_epc_page(struct sgx_softc *sc)
{
	struct epc_page *epc;
	int i;

	for (i = 0; i < sc->npages; i++) {
		epc = &sc->epc_pages[i];
		if (epc->used == 0) {
			epc->used = 1;
			return (epc);
		}
	}

	return (NULL);
}

static int
privcmd_pg_ctor(void *handle, vm_ooffset_t size, vm_prot_t prot,
    vm_ooffset_t foff, struct ucred *cred, u_short *color)
{
	struct privcmd_map *map;

	printf("%s: foff 0x%lx size 0x%lx\n", __func__, foff, size);

	map = handle;

	return (0);
}

static void
privcmd_pg_dtor(void *handle)
{
	struct privcmd_map *map;
	struct sgx_softc *sc;
	struct sgx_enclave *enclave;

	if (handle == NULL) {
		printf("%s: map not found\n", __func__);
		return;
	}

	map = handle;
	sc = map->sc;

	if (map->enclave == NULL) {
		printf("%s: enclave not found\n", __func__);
		return;
	}

	enclave = map->enclave;

	TAILQ_REMOVE(&sc->enclaves, enclave, next);
	enclave_remove(enclave);
}

static int
privcmd_pg_fault(vm_object_t object, vm_ooffset_t offset,
    int prot, vm_page_t *mres)
{
	struct sgx_enclave *enclave;
	struct privcmd_map *map;
	struct sgx_softc *sc;
	vm_page_t page;
	vm_memattr_t memattr;
	vm_pindex_t pidx;
	vm_paddr_t paddr;
	struct sgx_enclave_page *enclave_page_tmp;
	struct sgx_enclave_page *enclave_page;
	struct epc_page *epc;
	int found;

	map = object->handle;
	if (map == NULL) {
		return VM_PAGER_FAIL;
	}
	sc = map->sc;
	enclave = map->enclave;

	if (enclave == NULL) {
		return VM_PAGER_FAIL;
	}

	//printf("%s: offset 0x%lx\n", __func__, offset);

	memattr = object->memattr;
	pidx = OFF_TO_IDX(offset);

	found = 0;
	TAILQ_FOREACH_SAFE(enclave_page, &enclave->pages, next, enclave_page_tmp) {
		//printf("%s: page addr %lx\n", __func__, enclave_page->addr);
		if ((map->base + offset) == enclave_page->addr) {
			//printf("page found\n");
			found = 1;
			break;
		}
	}
	if (found == 0) {
		printf("Error: page not found\n");
		return VM_PAGER_FAIL;
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

static struct cdev_pager_ops privcmd_pg_ops = {
	.cdev_pg_fault = privcmd_pg_fault,
	.cdev_pg_ctor = privcmd_pg_ctor,
	.cdev_pg_dtor = privcmd_pg_dtor,
};

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
		printf("Can't find enclave\n");
		return (-1);
	}

	*mem0 = mem;
	*entry0 = entry;

	return (0);
}

static int
sgx_construct_page(struct sgx_softc *sc,
    struct sgx_enclave *enclave,
    struct sgx_enclave_page *enclave_page)
{
	struct va_page *va_page;
	struct va_page *va_page_tmp;
	struct epc_page *epc;
	int va_slot;

	va_slot = -1;

	TAILQ_FOREACH_SAFE(va_page, &enclave->va_pages, va_next, va_page_tmp) {
		va_slot = get_va_slot(va_page);
		if (va_slot >= 0) {
			break;
		}
	}

	if (va_slot < 0) {
		epc = get_epc_page(sc);
		if (epc == NULL) {
			printf("No free epc pages available\n");
			return (-1);
		}

		va_page = malloc(sizeof(struct va_page), M_SGX, M_WAITOK | M_ZERO);
		if (va_page == NULL) {
			printf("Can't alloc va_page\n");
			return (ENOMEM);
		}

		va_slot = get_va_slot(va_page);
		va_page->epc_page = epc;
		__epa((void *)epc->base);
		TAILQ_INSERT_TAIL(&enclave->va_pages, va_page, va_next);
	}

	enclave_page->va_page = va_page;
	enclave_page->va_slot = va_slot;

	return (0);
}

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

	/* SGX Enclave Control Structure (SECS) */
	m_secs = (struct secs *)kmem_alloc_contig(kmem_arena, PAGE_SIZE,
	    0/*flags*/, 0, BUS_SPACE_MAXADDR_32BIT,
	    PAGE_SIZE, 0, VM_MEMATTR_DEFAULT);

	ret = copyin((void *)param->src, m_secs, sizeof(struct secs));
	if (ret != 0) {
		printf("Can't copy SECS\n");
		return (-1);
	}

	enclave = malloc(sizeof(struct sgx_enclave), M_SGX, M_WAITOK | M_ZERO);
	if (enclave == NULL) {
		printf("Can't alloc memory for enclave\n");
		return (ENOMEM);
	}

	TAILQ_INIT(&enclave->pages);
	TAILQ_INIT(&enclave->va_pages);
	enclave->base = m_secs->base;
	enclave->size = m_secs->size;

	memset(&secinfo, 0, sizeof(struct secinfo));

	//printf("enclave->base phys %lx\n", vtophys(enclave->base));

	struct privcmd_map *priv_map;
	vm_map_entry_t entry;
	vm_object_t mem;

	ret = sgx_mem_find(sc, m_secs->base, &entry, &mem);
	if (ret != 0) {
		printf("Can't find vm_map\n");
		return (-1);
	}

	priv_map = mem->handle;
	printf("vm_map found, size 0x%lx\n", priv_map->size);
	enclave->map = priv_map;
	priv_map->enclave = enclave;
	priv_map->base = (entry->start - entry->offset);

	memset(&pginfo, 0, sizeof(struct page_info));
	pginfo.linaddr = 0;
	pginfo.srcpge = (uint64_t)m_secs;
	pginfo.secinfo = (uint64_t)&secinfo;
	pginfo.secs = 0;

#if 0
	printf("%s: secs->base 0x%lx, secs->size 0x%lx\n", __func__, m_secs->base, m_secs->size);
#endif

	epc = get_epc_page(sc);
	if (epc == NULL) {
		printf("%s: failed to get epc page\n", __func__);
		return (-1);
	}

	ret = sgx_construct_page(sc, enclave, &enclave->secs_page);
	if (ret != 0) {
		printf("can't construct page\n");
		return (-1);
	}

	secs_page = &enclave->secs_page;
	secs_page->epc_page = epc;

	__ecreate(&pginfo, (void *)epc->base);

	TAILQ_INSERT_TAIL(&sc->enclaves, enclave, next);

	return (0);
}

static int
enclave_get(struct sgx_softc *sc, uint64_t addr,
    struct sgx_enclave **encl)
{
	struct privcmd_map *priv_map;
	vm_map_entry_t entry;
	vm_object_t mem;
	int ret;

	ret = sgx_mem_find(sc, addr, &entry, &mem);
	if (ret != 0) {
		return (-1);
	}

	priv_map = mem->handle;
	*encl = priv_map->enclave;

	return (0);
}

static int
sgx_measure_page(struct epc_page *secs, struct epc_page *epc,
    uint16_t mrmask)
{
	int i, j;

	for (i = 0, j = 1; i < PAGE_SIZE; i += 0x100, j <<= 1) {
		if (!(j & mrmask)) {
			continue;
		}

		__eextend((void *)secs->base, (void *)((uint64_t)epc->base + i));
	}

	return (0);
}

static int
validate_tcs(struct tcs *tcs)
{
	int i;

	if ((tcs->flags != 0) ||
	    (tcs->ossa & (PAGE_SIZE - 1)) ||
	    (tcs->ofsbasgx & (PAGE_SIZE - 1)) ||
	    (tcs->ogsbasgx & (PAGE_SIZE - 1)) ||
	    ((tcs->fslimit & 0xFFF) != 0xFFF) ||
	    ((tcs->gslimit & 0xFFF) != 0xFFF)) {
		return (-1);
	}

	for (i = 0; i < sizeof(tcs->reserved)/sizeof(uint64_t); i++) {
		if (tcs->reserved[i]) {
			return (-1);
		}
	}

	return (0);
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
	vm_offset_t tmp_vaddr;
	uint64_t page_type;
	struct proc *proc;
	pmap_t pmap;
	int ret;

	ret = enclave_get(sc, addp->addr, &enclave);
	if (ret != 0) {
		printf("Failed to get enclave\n");
		return (-1);
	}

	proc = curthread->td_proc;
	pmap = vm_map_pmap(&proc->p_vmspace->vm_map);

	//printf("addp->addr phys %lx\n", pmap_extract(pmap, addp->addr));
	//printf("%s\n", __func__);
	//printf("%s: add page addr %lx src %lx secinfo %lx mrmask %x\n", __func__,
	//    addp->addr, addp->src, addp->secinfo, addp->mrmask);

	memset(&secinfo, 0, sizeof(struct secinfo));
	ret = copyin((void *)addp->secinfo, &secinfo, sizeof(struct secinfo));
	if (ret != 0) {
		printf("%s: Failed to copy secinfo\n", __func__);
		return (-1);
	}

	tmp_vaddr = kmem_alloc_contig(kmem_arena, PAGE_SIZE,
	    0/*flags*/, 0, BUS_SPACE_MAXADDR_32BIT,
	    PAGE_SIZE, 0, VM_MEMATTR_DEFAULT);

	ret = copyin((void *)addp->src, (void *)tmp_vaddr, PAGE_SIZE);
	if (ret != 0) {
		printf("%s: Failed to copy page\n", __func__);
		kmem_free(kmem_arena, tmp_vaddr, PAGE_SIZE);
		return (-1);
	}

	page_type = (secinfo.flags >> 8) & 0xff;
	//printf("page_type %ld\n", page_type);

	struct tcs *t;
	if (page_type == PT_TCS) {

		t = (struct tcs *)tmp_vaddr;
		if (validate_tcs(t) != 0) {
			printf("TCS validation failed\n");
			return (-1);
		}
#if 0
		printf("t->state %lx\n", t->state);
		printf("t->flags %lx\n", t->flags);
		printf("t->ossa %lx\n", t->ossa);
		printf("t->cssa %x\n", t->cssa);
		printf("t->nssa %x\n", t->nssa);
		printf("t->oentry %lx\n", t->oentry);
		printf("t->aep %lx\n", t->aep);
		printf("t->ofsbasgx %lx\n", t->ofsbasgx);
		printf("t->ogsbasgx %lx\n", t->ogsbasgx);
		printf("t->fslimit %x\n", t->fslimit);
		printf("t->gslimit %x\n", t->gslimit);
#endif
	}

	enclave_page = malloc(sizeof(struct sgx_enclave_page), M_SGX, M_WAITOK | M_ZERO);
	if (enclave_page == NULL) {
		printf("Can't allocate enclave page\n");
		return (-1);
	}

	epc = get_epc_page(sc);
	if (epc == NULL) {
		printf("%s: failed to get epc page\n", __func__);
		return (-1);
	}

	ret = sgx_construct_page(sc, enclave, enclave_page);
	if (ret != 0) {
		printf("can't construct page\n");
		return (-1);
	}
	enclave_page->epc_page = epc;
	enclave_page->addr = addp->addr;

	secs_epc_page = enclave->secs_page.epc_page;

	memset(&pginfo, 0, sizeof(struct page_info));
	pginfo.linaddr = (uint64_t)addp->addr;
	pginfo.srcpge = (uint64_t)tmp_vaddr;
	pginfo.secinfo = (uint64_t)&secinfo;
	pginfo.secs = (uint64_t)secs_epc_page->base;

#if 0
	printf("pginfo %lx epc %lx\n", (uint64_t)&pginfo, (uint64_t)epc->base);
	printf("%s: __eadd\n", __func__);
#endif

	__eadd(&pginfo, (void *)epc->base);

#if 0
	printf("%s: sgx_measure_page\n", __func__);
#endif
	ret = sgx_measure_page(enclave->secs_page.epc_page, epc, addp->mrmask);
	if (ret != 0) {
		printf("sgx_measure_page returned %d\n", ret);
		return (-1);
	}

	kmem_free(kmem_arena, tmp_vaddr, PAGE_SIZE);

	TAILQ_INSERT_TAIL(&enclave->pages, enclave_page, next);

	return (0);
}

static int
sgx_init(struct sgx_softc *sc, struct sgx_enclave_init *initp)
{
	struct epc_page *secs_epc_page;
	struct sgx_enclave *enclave;
	vm_offset_t tmp_vaddr;
	void *einittoken;
	void *sigstruct;
	int retry;
	int ret;

	printf("%s: addr %lx\n", __func__, initp->addr);
	printf("%s: sigstruct %lx\n", __func__, initp->sigstruct);
	printf("%s: einittoken %lx\n", __func__, initp->einittoken);

	ret = enclave_get(sc, initp->addr, &enclave);
	if (ret != 0) {
		printf("Failed to get enclave\n");
		return (-1);
	}

	secs_epc_page = enclave->secs_page.epc_page;

	tmp_vaddr = kmem_alloc_contig(kmem_arena, PAGE_SIZE,
	    0/*flags*/, 0, BUS_SPACE_MAXADDR_32BIT,
	    PAGE_SIZE, 0, VM_MEMATTR_DEFAULT);
	sigstruct = (void *)tmp_vaddr;
	einittoken = (void *)((uint64_t)sigstruct + PAGE_SIZE / 2);

	ret = copyin((void *)initp->sigstruct, sigstruct,
	    SIGSTRUCT_SIZE);
	if (ret != 0) {
		printf("%s: Failed to copy SIGSTRUCT page\n", __func__);
		return (-1);
	}

	ret = copyin((void *)initp->einittoken, einittoken,
	    EINITTOKEN_SIZE);
	if (ret != 0) {
		printf("%s: Failed to copy EINITTOKEN page\n", __func__);
		return (-1);
	}

	retry = 16;
	do {
		ret = __einit(sigstruct, (void *)secs_epc_page->base, einittoken);
		printf("__einit returned %d\n", ret);
	} while (ret == SGX_UNMASKED_EVENT && retry--);

	if (ret != 0) {
		printf("Failed to init enclave: %d\n", ret);
	}

#if 0
	switch (ret) {
	case SGX_INVALID_MEASUREMENT:
		printf("Invalid measurement\n");
		break;
	case SGX_UNMASKED_EVENT:
		printf("Unmasked event\n");
		break;
	case SGX_INVALID_ATTRIBUTE:
		printf("Invalid attr\n");
		break;
	default:
		printf("%s: err %d\n", __func__, ret);
		break;
	};
#endif

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

	//printf("%s: %ld\n", __func__, cmd);

	ret = 0;

	switch (cmd & 0xffff) {
	case SGX_IOC_ENCLAVE_CREATE:
		//printf("%s: enclave_create: addr %lx flags %d\n", __func__, (uint64_t)addr, flags);

		param = (struct sgx_enclave_create *)addr;
		ret = sgx_create(sc, param);

		break;
	case SGX_IOC_ENCLAVE_ADD_PAGE:
		//printf("%s: enclave_add_page\n", __func__);

		addp = (struct sgx_enclave_add_page *)addr;
		ret = sgx_add_page(sc, addp);

		break;
	case SGX_IOC_ENCLAVE_INIT:
		//printf("%s: enclave_init\n", __func__);

		initp = (struct sgx_enclave_init *)addr;
		ret = sgx_init(sc, initp);

		break;
	default:
		return -EINVAL;
	}

	if (ret == -1) {
		ret = EINVAL;
	}
	//printf("%s: %ld ret %d\n", __func__, cmd, ret);
	return (ret);
}

static int
sgx_mmap_single(struct cdev *cdev, vm_ooffset_t *offset, vm_size_t mapsize,
    struct vm_object **objp, int nprot)
{
	struct privcmd_map *map;
	struct sgx_softc *sc;

	map = malloc(sizeof(struct privcmd_map), M_SGX, M_WAITOK | M_ZERO);
	if (map == NULL) {
		printf("%s: Can't alloc memory\n", __func__);
		return (ENOMEM);
	}

	sc = cdev->si_drv1;

	map->sc = sc;
	map->size = mapsize;
	map->mem = cdev_pager_allocate(map, OBJT_DEVICE, &privcmd_pg_ops,
	    mapsize, nprot, *offset, NULL);
	if (map->mem == NULL) {
		free(map, M_SGX);
		return (ENOMEM);
	}

	*objp = map->mem;

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

	printf("%s: epc_base %lx size %lx\n", __func__, epc_base, epc_size);

	epc_base_vaddr = (vm_offset_t)pmap_mapdev(epc_base, epc_size);

	sc->npages = epc_size / SGX_PAGE_SIZE;

	sc->epc_pages = malloc(sizeof(struct epc_page) * sc->npages,
	    M_DEVBUF, M_WAITOK | M_ZERO);
	if (sc->epc_pages == NULL) {
		printf("%s: can't alloc memory\n", __func__);
		return (ENOMEM);
	}

	for (i = 0; i < sc->npages; i++) {
		sc->epc_pages[i].base = epc_base_vaddr + SGX_PAGE_SIZE * i;
		sc->epc_pages[i].phys = epc_base + SGX_PAGE_SIZE * i;
		sc->epc_pages[i].used = 0;
	}

	return (0);
}

static void
sgx_identify(driver_t *driver, device_t parent)
{
	unsigned regs[4];

	if ((cpu_stdext_feature & CPUID_STDEXT_SGX) == 0)
		return;

	do_cpuid(1, regs);

	if ((regs[2] & CPUID2_OSXSAVE) == 0) {
		printf("OSXSAVE not found\n");
		return;
	}

	if ((rcr4() & CR4_XSAVE) == 0) {
		printf("CR4_XSAVE not found\n");
		return;
	}

	if ((rcr4() & CR4_FXSR) == 0) {
		printf("CR4_FXSR not found\n");
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

	ret = sgx_get_epc_area(sc);
	if (ret != 0) {
		printf("Failed to get EPC area\n");
		return (ENXIO);
	}

	sc->sgx_cdev = make_dev(&sgx_cdevsw, 0, UID_ROOT, GID_WHEEL,
	    0600, "isgx");
	if (sc->sgx_cdev == NULL) {
		device_printf(dev, "Failed to create character device.\n");
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
