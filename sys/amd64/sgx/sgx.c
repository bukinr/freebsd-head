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
#include <sys/vmmeter.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_pager.h>
#include <vm/vm_phys.h>
#include <vm/pmap.h>

#include <machine/md_var.h>
#include <machine/specialreg.h>
#include <machine/bus.h>
#include <machine/cpufunc.h>
#include <machine/sgx.h>
#include <machine/sgxvar.h>

#include <amd64/sgx/sgx.h>

#define	DEBUG
#undef	DEBUG

#ifdef	DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

struct sgx_softc sgx_sc;

#ifdef	DEBUG
static int
sgx_count_epc_pages(struct sgx_softc *sc)
{
	struct epc_page *epc;
	int cnt;
	int i;

	cnt = 0;

	for (i = 0; i < sc->npages; i++) {
		epc = &sc->epc_pages[i];
		if (epc->used == 0)
			cnt++;
	}

	return (cnt);
}
#endif

static int
sgx_get_epc_page(struct sgx_softc *sc, struct epc_page **epc0)
{
	struct epc_page *epc;
	int i;

	mtx_lock(&sc->mtx_epc);

	for (i = 0; i < sc->npages; i++) {
		epc = &sc->epc_pages[i];
		if (epc->used == 0) {
			epc->used = 1;
			mtx_unlock(&sc->mtx_epc);
			*epc0 = epc;
			return (0);
		}
	}

	mtx_unlock(&sc->mtx_epc);

	return (ENOMEM);
}

static void
sgx_put_epc_page(struct sgx_softc *sc, struct epc_page *epc)
{

	if (epc == NULL)
		return;

	KASSERT(epc->used == 1, ("Freeing unused page."));
	epc->used = 0;
}

static int
sgx_va_slot_alloc(struct sgx_enclave *enclave,
    struct va_page *va_page)
{
	int i;

	mtx_assert(&enclave->mtx, MA_OWNED);

	for (i = 0; i < SGX_VA_PAGE_SLOTS; i++)
		if (va_page->slots[i] == 0) {
			va_page->slots[i] = 1;
			return (i);
		}

	return (-1);
}

static void
sgx_va_slot_free(struct sgx_softc *sc,
    struct sgx_enclave *enclave,
    struct sgx_enclave_page *enclave_page)
{
	struct va_page *va_page;
	struct epc_page *epc;
	int va_slot;
	int i;

	va_page = enclave_page->va_page;
	va_slot = enclave_page->va_slot;

	KASSERT(va_page->slots[va_slot] == 1,
	    ("Freeing unused slot."));

	va_page->slots[va_slot] = 0;

	/* Now check if we need to remove va_page. */
	mtx_lock(&enclave->mtx);
	for (i = 0; i < SGX_VA_PAGE_SLOTS; i++)
		if (va_page->slots[i] == 1) {
			mtx_unlock(&enclave->mtx);
			return;
		}

	TAILQ_REMOVE(&enclave->va_pages, va_page, va_next);
	mtx_unlock(&enclave->mtx);

	epc = va_page->epc_page;
	mtx_lock(&sc->mtx);
	sgx_eremove((void *)epc->base);
	mtx_unlock(&sc->mtx);
	sgx_put_epc_page(sc, epc);
	free(enclave_page->va_page, M_SGX);
}

static void
sgx_enclave_page_remove(struct sgx_softc *sc,
    struct sgx_enclave *enclave,
    struct sgx_enclave_page *enclave_page)
{
	struct epc_page *epc;

	sgx_va_slot_free(sc, enclave, enclave_page);

	epc = enclave_page->epc_page;
	mtx_lock(&sc->mtx);
	sgx_eremove((void *)epc->base);
	mtx_unlock(&sc->mtx);
	sgx_put_epc_page(sc, epc);
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
	int ret;

	va_slot = -1;

	mtx_lock(&enclave->mtx);
	TAILQ_FOREACH_SAFE(va_page, &enclave->va_pages, va_next,
	    va_page_tmp) {
		va_slot = sgx_va_slot_alloc(enclave, va_page);
		if (va_slot >= 0)
			break;
	}
	mtx_unlock(&enclave->mtx);

	if (va_slot < 0) {
		ret = sgx_get_epc_page(sc, &epc);
		if (ret) {
			dprintf("%s: No free EPC pages available.\n",
			    __func__);
			return (ret);
		}

		va_page = malloc(sizeof(struct va_page),
		    M_SGX, M_WAITOK | M_ZERO);
		if (va_page == NULL) {
			dprintf("%s: Can't alloc va_page.\n", __func__);
			sgx_put_epc_page(sc, epc);
			return (ENOMEM);
		}

		mtx_lock(&enclave->mtx);
		va_slot = sgx_va_slot_alloc(enclave, va_page);
		mtx_unlock(&enclave->mtx);

		va_page->epc_page = epc;
		mtx_lock(&sc->mtx);
		sgx_epa((void *)epc->base);
		mtx_unlock(&sc->mtx);

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

	proc = curthread->td_proc;
	map = &proc->p_vmspace->vm_map;

	vm_map_lock_read(map);
	if (!vm_map_lookup_entry(map, addr, &entry)) {
		vm_map_unlock_read(map);
		dprintf("%s: Can't find enclave.\n", __func__);
		return (EINVAL);
	}
	vm_map_unlock_read(map);

	*mem0 = entry->object.vm_object;
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
	if (ret)
		return (ret);

	vmh = mem->handle;
	if (vmh == NULL)
		return (ENXIO);

	*encl = vmh->enclave;

	return (0);
}

static int
sgx_enclave_alloc(struct sgx_softc *sc, struct secs *secs,
    struct sgx_enclave **enclave0)
{
	struct sgx_enclave *enclave;

	enclave = malloc(sizeof(struct sgx_enclave),
	    M_SGX, M_WAITOK | M_ZERO);
	if (enclave == NULL) {
		dprintf("%s: Can't alloc memory for enclave.\n",
		    __func__);
		return (ENOMEM);
	}

	TAILQ_INIT(&enclave->pages);
	TAILQ_INIT(&enclave->va_pages);

	mtx_init(&enclave->mtx, "SGX enclave", NULL, MTX_DEF);

	enclave->base = secs->base;
	enclave->size = secs->size;

	*enclave0 = enclave;

	return (0);
}

static void
sgx_enclave_remove(struct sgx_softc *sc,
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

	KASSERT(TAILQ_EMPTY(&enclave->va_pages),
	    ("Enclave version-array pages tailq is not empty."));
	KASSERT(TAILQ_EMPTY(&enclave->pages),
	    ("Enclave pages is not empty."));

	mtx_destroy(&enclave->mtx);
	free(enclave, M_SGX);
}

static void
sgx_measure_page(struct sgx_softc *sc, struct epc_page *secs,
    struct epc_page *epc, uint16_t mrmask)
{
	int i, j;

	mtx_lock(&sc->mtx);

	for (i = 0, j = 1; i < PAGE_SIZE; i += 0x100, j <<= 1) {
		if (!(j & mrmask))
			continue;

		sgx_eextend((void *)secs->base,
		    (void *)((uint64_t)epc->base + i));
	}

	mtx_unlock(&sc->mtx);
}

static int
sgx_tcs_validate(struct tcs *tcs)
{
	int i;

	if ((tcs->flags) ||
	    (tcs->ossa & (PAGE_SIZE - 1)) ||
	    (tcs->ofsbasgx & (PAGE_SIZE - 1)) ||
	    (tcs->ogsbasgx & (PAGE_SIZE - 1)) ||
	    ((tcs->fslimit & 0xfff) != 0xfff) ||
	    ((tcs->gslimit & 0xfff) != 0xfff))
		return (EINVAL);

	for (i = 0; i < nitems(tcs->reserved3); i++)
		if (tcs->reserved3[i])
			return (EINVAL);

	return (0);
}

static void
sgx_tcs_dump(struct sgx_softc *sc, struct tcs *t)
{

	dprintf("t->flags %lx\n", t->flags);
	dprintf("t->ossa %lx\n", t->ossa);
	dprintf("t->cssa %x\n", t->cssa);
	dprintf("t->nssa %x\n", t->nssa);
	dprintf("t->oentry %lx\n", t->oentry);
	dprintf("t->ofsbasgx %lx\n", t->ofsbasgx);
	dprintf("t->ogsbasgx %lx\n", t->ogsbasgx);
	dprintf("t->fslimit %x\n", t->fslimit);
	dprintf("t->gslimit %x\n", t->gslimit);
}

static int
sgx_pg_ctor(void *handle, vm_ooffset_t size, vm_prot_t prot,
    vm_ooffset_t foff, struct ucred *cred, u_short *color)
{
	struct sgx_vm_handle *vmh;

	vmh = handle;
	if (vmh == NULL) {
		dprintf("%s: vmh not found.\n", __func__);
		return (0);
	}

	dprintf("%s: vmh->base %lx foff 0x%lx size 0x%lx\n",
	    __func__, vmh->base, foff, size);

	return (0);
}

static void
sgx_pg_dtor(void *handle)
{
	struct sgx_vm_handle *vmh;
	struct sgx_softc *sc;

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

	if (vmh->enclave == NULL) {
		dprintf("%s: Enclave not found.\n", __func__);
		return;
	}

	sgx_enclave_remove(sc, vmh->enclave);
	free(vmh, M_SGX);

	dprintf("%s: Free epc pages: %d\n",
	    __func__, sgx_count_epc_pages(sc));
}

static int
sgx_pg_fault(vm_object_t object, vm_ooffset_t offset,
    int prot, vm_page_t *mres)
{
	struct sgx_enclave *enclave;
	struct sgx_vm_handle *vmh;
	vm_page_t page;
	vm_memattr_t memattr;
	vm_pindex_t pidx;
	struct sgx_enclave_page *enclave_page_tmp;
	struct sgx_enclave_page *enclave_page;
	struct epc_page *epc;
	bool found;

	vmh = object->handle;
	if (vmh == NULL)
		return (VM_PAGER_FAIL);

	enclave = vmh->enclave;
	if (enclave == NULL)
		return (VM_PAGER_FAIL);

	dprintf("%s: offset 0x%lx\n", __func__, offset);

	memattr = object->memattr;
	pidx = OFF_TO_IDX(offset);

	found = false;
	mtx_lock(&enclave->mtx);
	TAILQ_FOREACH_SAFE(enclave_page, &enclave->pages, next,
	    enclave_page_tmp) {
		if ((vmh->base + offset) == enclave_page->addr) {
			found = true;
			break;
		}
	}
	mtx_unlock(&enclave->mtx);
	if (!found) {
		dprintf("%s: Page not found.\n", __func__);
		return (VM_PAGER_FAIL);
	}

	epc = enclave_page->epc_page;

	page = PHYS_TO_VM_PAGE(epc->phys);
	if (page == NULL)
		return (VM_PAGER_FAIL);

	KASSERT(page->flags & PG_FICTITIOUS,
	    ("Not fictitious page %p", page));
	KASSERT(page->wire_count == 1, ("wire_count is not 1 %p", page));
	KASSERT(vm_page_busied(page) == 0, ("page %p is busy", page));

	if (*mres != NULL) {
		vm_page_lock(*mres);
		vm_page_free(*mres);
		vm_page_unlock(*mres);
		*mres = NULL;
	}

	vm_page_insert(page, object, pidx);
	page->valid = VM_PAGE_BITS_ALL;
	vm_page_xbusy(page);

	*mres = page;  

	return (VM_PAGER_OK);
}

static struct cdev_pager_ops sgx_pg_ops = {
	.cdev_pg_ctor = sgx_pg_ctor,
	.cdev_pg_dtor = sgx_pg_dtor,
	.cdev_pg_fault = sgx_pg_fault,
};

static int
sgx_ioctl_create(struct sgx_softc *sc, struct sgx_enclave_create *param)
{
	struct sgx_vm_handle *vmh;
	vm_map_entry_t entry;
	vm_object_t mem;
	struct sgx_enclave_page *secs_page;
	struct page_info pginfo;
	struct secinfo secinfo;
	struct sgx_enclave *enclave;
	struct epc_page *epc;
	struct secs *secs;
	int ret;

	epc = NULL;
	secs = NULL;
	enclave = NULL;

	/* SGX Enclave Control Structure (SECS) */
	secs = (struct secs *)kmem_alloc_contig(kmem_arena, PAGE_SIZE,
	    M_WAITOK | M_ZERO, 0, BUS_SPACE_MAXADDR_32BIT,
	    PAGE_SIZE, 0, VM_MEMATTR_DEFAULT);
	if (secs == NULL) {
		dprintf("%s: Can't allocate memory.\n", __func__);
		ret = ENOMEM;
		goto error;
	}

	ret = copyin((void *)param->src, secs, sizeof(struct secs));
	if (ret) {
		dprintf("%s: Can't copy SECS.\n", __func__);
		goto error;
	}

	ret = sgx_mem_find(sc, secs->base, &entry, &mem);
	if (ret) {
		dprintf("%s: Can't find vm_map.\n", __func__);
		goto error;
	}

	vmh = mem->handle;
	if (!vmh) {
		dprintf("%s: Can't find vmh.\n", __func__);
		ret = ENXIO;
		goto error;
	}
	vmh->base = (entry->start - entry->offset);

	ret = sgx_enclave_alloc(sc, secs, &enclave);
	if (ret) {
		dprintf("%s: Can't alloc enclave.\n", __func__);
		goto error;
	}

	memset(&secinfo, 0, sizeof(struct secinfo));
	memset(&pginfo, 0, sizeof(struct page_info));
	pginfo.linaddr = 0;
	pginfo.srcpge = (uint64_t)secs;
	pginfo.secinfo = &secinfo;
	pginfo.secs = 0;

	ret = sgx_get_epc_page(sc, &epc);
	if (ret) {
		dprintf("%s: Failed to get free epc page.\n", __func__);
		goto error;
	}

	ret = sgx_enclave_page_construct(sc, enclave, &enclave->secs_page);
	if (ret) {
		dprintf("%s: Can't construct page.\n", __func__);
		goto error;
	}

	secs_page = &enclave->secs_page;
	secs_page->epc_page = epc;

	mtx_lock(&sc->mtx);
	sgx_ecreate(&pginfo, (void *)epc->base);
	TAILQ_INSERT_TAIL(&sc->enclaves, enclave, next);
	mtx_unlock(&sc->mtx);

	kmem_free(kmem_arena, (vm_offset_t)secs, PAGE_SIZE);

	enclave->vmh = vmh;
	vmh->enclave = enclave;

	return (0);

error:
	if (secs != NULL)
		kmem_free(kmem_arena, (vm_offset_t)secs, PAGE_SIZE);
	sgx_put_epc_page(sc, epc);
	free(enclave, M_SGX);

	return (ret);
}

static int
sgx_ioctl_add_page(struct sgx_softc *sc,
    struct sgx_enclave_add_page *addp)
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
	if (ret) {
		dprintf("%s: Failed to find enclave.\n", __func__);
		goto error;
	}

	ret = sgx_get_epc_page(sc, &epc);
	if (ret) {
		dprintf("%s: Failed to get free epc page.\n", __func__);
		goto error;
	}

	proc = curthread->td_proc;
	pmap = vm_map_pmap(&proc->p_vmspace->vm_map);

	memset(&secinfo, 0, sizeof(struct secinfo));
	ret = copyin((void *)addp->secinfo, &secinfo,
	    sizeof(struct secinfo));
	if (ret) {
		dprintf("%s: Failed to copy secinfo.\n", __func__);
		goto error;
	}

	tmp_vaddr = (void *)kmem_alloc_contig(kmem_arena, PAGE_SIZE,
	    M_WAITOK | M_ZERO, 0, BUS_SPACE_MAXADDR_32BIT,
	    PAGE_SIZE, 0, VM_MEMATTR_DEFAULT);
	if (tmp_vaddr == NULL) {
		dprintf("%s: Failed to alloc memory.\n", __func__);
		ret = ENOMEM;
		goto error;
	}

	ret = copyin((void *)addp->src, tmp_vaddr, PAGE_SIZE);
	if (ret) {
		dprintf("%s: Failed to copy page.\n", __func__);
		goto error;
	}

	page_type = (secinfo.flags & SECINFO_FLAGS_PT_M) >> \
	    SECINFO_FLAGS_PT_S;
	if (page_type == PT_TCS) {
		t = (struct tcs *)tmp_vaddr;
		ret = sgx_tcs_validate(t);
		if (ret) {
			dprintf("%s: TCS page validation failed.\n",
			    __func__);
			goto error;
		}
		sgx_tcs_dump(sc, t);
	}

	enclave_page = malloc(sizeof(struct sgx_enclave_page),
	    M_SGX, M_WAITOK | M_ZERO);
	if (enclave_page == NULL) {
		dprintf("%s: Can't allocate enclave page.\n", __func__);
		ret = ENOMEM;
		goto error;
	}

	ret = sgx_enclave_page_construct(sc, enclave, enclave_page);
	if (ret) {
		dprintf("%s: Can't construct page.\n", __func__);
		goto error;
	}

	enclave_page->epc_page = epc;
	enclave_page->addr = addp->addr;
	secs_epc_page = enclave->secs_page.epc_page;

	memset(&pginfo, 0, sizeof(struct page_info));
	pginfo.linaddr = (uint64_t)addp->addr;
	pginfo.srcpge = (uint64_t)tmp_vaddr;
	pginfo.secinfo = &secinfo;
	pginfo.secs = (uint64_t)secs_epc_page->base;

	mtx_lock(&sc->mtx);
	sgx_eadd(&pginfo, (void *)epc->base);
	mtx_unlock(&sc->mtx);

	kmem_free(kmem_arena, (vm_offset_t)tmp_vaddr, PAGE_SIZE);

	sgx_measure_page(sc, enclave->secs_page.epc_page, epc, addp->mrmask);

	mtx_lock(&enclave->mtx);
	TAILQ_INSERT_TAIL(&enclave->pages, enclave_page, next);
	mtx_unlock(&enclave->mtx);

	return (0);

error:
	if (tmp_vaddr != NULL)
		kmem_free(kmem_arena, (vm_offset_t)tmp_vaddr, PAGE_SIZE);

	sgx_put_epc_page(sc, epc);
	free(enclave_page, M_SGX);

	return (ret);
}

static int
sgx_ioctl_init(struct sgx_softc *sc, struct sgx_enclave_init *initp)
{
	struct epc_page *secs_epc_page;
	struct sgx_enclave *enclave;
	void *tmp_vaddr;
	void *einittoken;
	void *sigstruct;
	int retry;
	int ret;

	tmp_vaddr = NULL;

	dprintf("%s: addr %lx, sigstruct %lx, einittoken %lx\n",
	    __func__, initp->addr, initp->sigstruct, initp->einittoken);

	ret = sgx_enclave_find(sc, initp->addr, &enclave);
	if (ret) {
		dprintf("%s: Failed to get enclave.\n", __func__);
		goto error;
	}

	tmp_vaddr = (void *)kmem_alloc_contig(kmem_arena, PAGE_SIZE,
	    M_WAITOK | M_ZERO, 0, BUS_SPACE_MAXADDR_32BIT,
	    PAGE_SIZE, 0, VM_MEMATTR_DEFAULT);
	if (tmp_vaddr == NULL) {
		dprintf("%s: Failed to alloc memory.\n", __func__);
		ret = ENOMEM;
		goto error;
	}

	sigstruct = tmp_vaddr;
	einittoken = (void *)((uint64_t)sigstruct + PAGE_SIZE / 2);

	ret = copyin((void *)initp->sigstruct, sigstruct,
	    SIGSTRUCT_SIZE);
	if (ret) {
		dprintf("%s: Failed to copy SIGSTRUCT page.\n", __func__);
		goto error;
	}

	ret = copyin((void *)initp->einittoken, einittoken,
	    EINITTOKEN_SIZE);
	if (ret) {
		dprintf("%s: Failed to copy EINITTOKEN page.\n", __func__);
		goto error;
	}

	secs_epc_page = enclave->secs_page.epc_page;
	retry = 16;
	do {
		mtx_lock(&sc->mtx);
		ret = sgx_einit(sigstruct, (void *)secs_epc_page->base,
		    einittoken);
		mtx_unlock(&sc->mtx);
		dprintf("%s: sgx_einit returned %d\n", __func__, ret);
	} while (ret == SGX_UNMASKED_EVENT && retry--);

	if (ret) {
		dprintf("%s: Failed to init enclave: %d\n", __func__, ret);
		goto error;
	}

error:
	if (tmp_vaddr != NULL)
		kmem_free(kmem_arena, (vm_offset_t)tmp_vaddr, PAGE_SIZE);

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
	uint8_t data[IOCTL_MAX_DATA_LEN];
	int ret;
	int len;

	sc = dev->si_drv1;

	len = IOCPARM_LEN(cmd);

	dprintf("%s: cmd %lx, len %d\n", __func__, cmd, len);

	if (len > IOCTL_MAX_DATA_LEN)
		return (EINVAL);

	ret = copyin(addr, data, len);
	if (ret) {
		dprintf("%s: Can't copy data.\n", __func__);
		return (EINVAL);
	}

	switch (cmd) {
	case SGX_IOC_ENCLAVE_CREATE:
		param = (struct sgx_enclave_create *)data;
		ret = sgx_ioctl_create(sc, param);
		break;
	case SGX_IOC_ENCLAVE_ADD_PAGE:
		addp = (struct sgx_enclave_add_page *)data;
		ret = sgx_ioctl_add_page(sc, addp);
		break;
	case SGX_IOC_ENCLAVE_INIT:
		initp = (struct sgx_enclave_init *)data;
		ret = sgx_ioctl_init(sc, initp);
		break;
	default:
		return (EINVAL);
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

	dprintf("%s: mapsize 0x%lx, offset %lx\n",
	    __func__, mapsize, *offset);

	vmh = malloc(sizeof(struct sgx_vm_handle),
	    M_SGX, M_WAITOK | M_ZERO);
	if (vmh == NULL) {
		dprintf("%s: Can't alloc memory.\n", __func__);
		return (ENOMEM);
	}

	vmh->sc = sc;
	vmh->size = mapsize;
	vmh->mem = cdev_pager_allocate(vmh, OBJT_MGTDEVICE, &sgx_pg_ops,
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
	u_int cp[4];
	int error;
	int i;

	cpuid_count(SGX_CPUID, 0x2, cp);

	sc->epc_base = ((uint64_t)(cp[1] & 0xfffff) << 32) + \
	    (cp[0] & 0xfffff000);
	sc->epc_size = ((uint64_t)(cp[3] & 0xfffff) << 32) + \
	    (cp[2] & 0xfffff000);
	sc->npages = sc->epc_size / SGX_PAGE_SIZE;

	epc_base_vaddr = (vm_offset_t)pmap_mapdev_attr(sc->epc_base,
	    sc->epc_size, VM_MEMATTR_DEFAULT);

	sc->epc_pages = malloc(sizeof(struct epc_page) * sc->npages,
	    M_DEVBUF, M_WAITOK | M_ZERO);
	if (sc->epc_pages == NULL) {
		dprintf("%s: Can't alloc memory.\n", __func__);
		return (ENOMEM);
	}

	for (i = 0; i < sc->npages; i++) {
		sc->epc_pages[i].base = epc_base_vaddr + SGX_PAGE_SIZE * i;
		sc->epc_pages[i].phys = sc->epc_base + SGX_PAGE_SIZE * i;
		sc->epc_pages[i].used = 0;
	}

	error = vm_phys_fictitious_reg_range(sc->epc_base,
	    sc->epc_base + sc->epc_size, VM_MEMATTR_DEFAULT);
	if (error) { 
		printf("%s: Can't register fictitious space.\n", __func__);
		free(sc->epc_pages, M_SGX);
		return (EINVAL);
	}

	return (0);
}

static void
sgx_put_epc_area(struct sgx_softc *sc)
{

	vm_phys_fictitious_unreg_range(sc->epc_base,
	    sc->epc_base + sc->epc_size);

	free(sc->epc_pages, M_SGX);
}

static int
sgx_load(void)
{
	struct sgx_softc *sc;
	int error;

	sc = &sgx_sc;

	if ((cpu_stdext_feature & CPUID_STDEXT_SGX) == 0)
		return (ENXIO);

	mtx_init(&sc->mtx, "SGX", NULL, MTX_DEF);
	mtx_init(&sc->mtx_epc, "SGX EPC area", NULL, MTX_DEF);

	error = sgx_get_epc_area(sc);
	if (error) {
		printf("%s: Failed to get Processor Reserved Memory area.\n",
		    __func__);
		return (ENXIO);
	}

	TAILQ_INIT(&sc->enclaves);

	sc->sgx_cdev = make_dev(&sgx_cdevsw, 0, UID_ROOT, GID_WHEEL,
	    0600, "isgx");
	if (sc->sgx_cdev == NULL) {
		printf("%s: Failed to create character device.\n",
		    __func__);
		sgx_put_epc_area(sc);
		return (ENXIO);
	}
	sc->sgx_cdev->si_drv1 = sc;

	printf("SGX initialized: EPC base 0x%lx size %ld (%d pages)\n",
	    sc->epc_base, sc->epc_size, sc->npages);

	return (0);
}

static int
sgx_unload(void)
{
	struct sgx_softc *sc;

	sc = &sgx_sc;

	if (!TAILQ_EMPTY(&sc->enclaves))
		return (EBUSY);

	destroy_dev(sc->sgx_cdev);

	sgx_put_epc_area(sc);

	mtx_destroy(&sc->mtx);
	mtx_destroy(&sc->mtx_epc);

	return (0);
}

static int
sgx_handler(module_t mod, int what, void *arg)
{
	int error;

	switch (what) {
	case MOD_LOAD:
		error = sgx_load();
		break;
	case MOD_UNLOAD:
		error = sgx_unload();
		break;
	default:
		error = 0;
		break;
	}

	return (error);
}

static moduledata_t sgx_kmod = {
	"sgx",
	sgx_handler,
	NULL
};

DECLARE_MODULE(sgx, sgx_kmod, SI_SUB_LAST, SI_ORDER_ANY);
MODULE_VERSION(sgx, 1);
