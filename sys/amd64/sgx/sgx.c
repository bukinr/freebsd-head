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
#include <vm/vm_radix.h>
#include <vm/pmap.h>

#include <machine/md_var.h>
#include <machine/specialreg.h>
#include <machine/cpufunc.h>
#include <machine/sgx.h>
#include <machine/sgxreg.h>

#include <amd64/sgx/sgxvar.h>

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
sgx_va_slot_init(struct sgx_softc *sc,
    struct sgx_enclave *enclave,
    uint64_t addr)
{
	struct epc_page *epc;
	vm_pindex_t pidx;
	vm_page_t page;
	vm_page_t p;
	uint64_t va_page_idx;
	uint64_t idx;
	vm_object_t obj;
	int va_slot;
	int ret;

	obj = enclave->obj;

	VM_OBJECT_ASSERT_WLOCKED(obj);

	pidx = OFF_TO_IDX(addr);

	va_slot = pidx % SGX_VA_PAGE_SLOTS;
	va_page_idx = pidx / SGX_VA_PAGE_SLOTS;
	idx = - SGX_VA_PAGES_OFFS - va_page_idx;

	p = vm_page_lookup(obj, idx);
	if (p == NULL) {
		ret = sgx_get_epc_page(sc, &epc);
		if (ret) {
			dprintf("%s: No free EPC pages available.\n",
			    __func__);
			return (ret);
		}

		mtx_lock(&sc->mtx);
		sgx_epa((void *)epc->base);
		mtx_unlock(&sc->mtx);

		page = PHYS_TO_VM_PAGE(epc->phys);

		vm_page_insert(page, obj, idx);
		page->valid = VM_PAGE_BITS_ALL;
	}

	return (0);
}

static int
sgx_mem_find(struct sgx_softc *sc, uint64_t addr,
    vm_map_entry_t *entry0, vm_object_t *mem0)
{
	vm_map_t map;
	vm_map_entry_t entry;

	map = &curproc->p_vmspace->vm_map;

	vm_map_lock_read(map);
	if (!vm_map_lookup_entry(map, addr, &entry)) {
		vm_map_unlock_read(map);
		dprintf("%s: Can't find enclave.\n", __func__);
		return (EINVAL);
	}

	if (entry->object.vm_object == NULL) {
		vm_map_unlock_read(map);
		return (EINVAL);
	}

	vm_object_reference(entry->object.vm_object);

	*mem0 = entry->object.vm_object;
	*entry0 = entry;
	vm_map_unlock_read(map);

	return (0);
}

static int
sgx_enclave_find(struct sgx_softc *sc, uint64_t addr,
    struct sgx_enclave **encl)
{
	struct sgx_vm_handle *vmh;
	struct sgx_enclave *enclave;
	vm_map_entry_t entry;
	vm_object_t mem;
	int ret;

	ret = sgx_mem_find(sc, addr, &entry, &mem);
	if (ret)
		return (ret);

	KASSERT(mem != NULL, ("mem is NULL\n"));
	KASSERT(mem->handle != NULL, ("mem->handle is NULL\n"));

	vmh = mem->handle;

	enclave = vmh->enclave;
	enclave->obj = mem;

	*encl = enclave;

	return (0);
}

static int
sgx_enclave_alloc(struct sgx_softc *sc, struct secs *secs,
    struct sgx_enclave **enclave0)
{
	struct sgx_enclave *enclave;

	enclave = malloc(sizeof(struct sgx_enclave),
	    M_SGX, M_WAITOK | M_ZERO);

	enclave->base = secs->base;
	enclave->size = secs->size;

	*enclave0 = enclave;

	return (0);
}

static void
sgx_epc_page_remove(struct sgx_softc *sc,
    struct epc_page *epc)
{

	mtx_lock(&sc->mtx);
	sgx_eremove((void *)epc->base);
	mtx_unlock(&sc->mtx);
	sgx_put_epc_page(sc, epc);
}

static void
sgx_page_remove(struct sgx_softc *sc, vm_page_t p)
{
	struct epc_page *epc;
	vm_paddr_t pa;
	uint64_t offs;

	vm_page_lock(p);
	vm_page_remove(p);
	vm_page_unlock(p);

	pa = VM_PAGE_TO_PHYS(p);
	epc = &sc->epc_pages[0];
	offs = (pa - epc->phys) / PAGE_SIZE;
	epc = &sc->epc_pages[offs];

	sgx_epc_page_remove(sc, epc);
}

static void
sgx_enclave_remove(struct sgx_softc *sc,
    struct sgx_enclave *enclave)
{
	vm_object_t object;
	vm_page_t p, p0;

	mtx_lock(&sc->mtx);
	TAILQ_REMOVE(&sc->enclaves, enclave, next);
	mtx_unlock(&sc->mtx);

	object = enclave->obj;

	VM_OBJECT_WLOCK(enclave->obj);

	/*
	 * First remove all the pages except SECS,
	 * then remove SECS page.
	 */
	p0 = vm_page_lookup(enclave->obj, 0);
	p = TAILQ_NEXT(p0, listq);

	while (p) {
		sgx_page_remove(sc, p);
		p = TAILQ_NEXT(p, listq);
	}

	/* Now remove SECS page */
	sgx_page_remove(sc, p0);

	KASSERT(TAILQ_EMPTY(&object->memq) == 1, ("not empty"));
	KASSERT(object->resident_page_count == 0, ("count"));

	VM_OBJECT_WUNLOCK(enclave->obj);
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
		    (void *)(epc->base + i));
	}

	mtx_unlock(&sc->mtx);
}

static int
sgx_secs_validate(struct sgx_softc *sc, struct secs *secs)
{
	struct secs_attr *attr;
	int i;

	if (secs->size == 0)
		return (EINVAL);

	/* BASEADDR must be naturally aligned on an SECS.SIZE boundary. */
	if (secs->base & (secs->size - 1))
		return (EINVAL);

	/* SECS.SIZE must be at least 2 pages. */
	if (secs->size < 2 * PAGE_SIZE)
		return (EINVAL);

	if ((secs->size & (secs->size - 1)) != 0)
		return (EINVAL);

	attr = &secs->attributes;

	if (attr->reserved1 != 0 ||
	    attr->reserved2 != 0 ||
	    attr->reserved3 != 0)
		return (EINVAL);

	for (i = 0; i < SECS_ATTR_RSV4_SIZE; i++)
		if (attr->reserved4[i])
			return (EINVAL);

	/*
	 * Intel® Software Guard Extensions Programming Reference
	 * 6.7.2 Relevant Fields in Various Data Structures
	 * 6.7.2.1 SECS.ATTRIBUTES.XFRM
	 * XFRM[1:0] must be set to 0x3.
	 */
	if ((attr->xfrm & 0x3) != 0x3)
		return (EINVAL);

	if (!attr->mode64bit)
		return (EINVAL);

	if (secs->size > sc->enclave_size_max)
		return (EINVAL);

	for (i = 0; i < SECS_RSV1_SIZE; i++)
		if (secs->reserved1[i])
			return (EINVAL);

	for (i = 0; i < SECS_RSV2_SIZE; i++)
		if (secs->reserved2[i])
			return (EINVAL);

	for (i = 0; i < SECS_RSV3_SIZE; i++)
		if (secs->reserved3[i])
			return (EINVAL);

	for (i = 0; i < SECS_RSV4_SIZE; i++)
		if (secs->reserved4[i])
			return (EINVAL);

	return (0);
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

	free(vmh->enclave, M_SGX);
	free(vmh, M_SGX);

	dprintf("%s: Free epc pages: %d\n",
	    __func__, sgx_count_epc_pages(sc));
}

static int
sgx_pg_fault(vm_object_t object, vm_ooffset_t offset,
    int prot, vm_page_t *mres)
{

	printf("%s: offset 0x%lx\n", __func__, offset);

	return (VM_PAGER_FAIL);
}

static struct cdev_pager_ops sgx_pg_ops = {
	.cdev_pg_ctor = sgx_pg_ctor,
	.cdev_pg_dtor = sgx_pg_dtor,
	.cdev_pg_fault = sgx_pg_fault,
};

static void
sgx_insert_epc_page(struct sgx_enclave *enclave,
    struct epc_page *epc, uint64_t addr)
{
	vm_pindex_t pidx;
	vm_page_t page;

	VM_OBJECT_ASSERT_WLOCKED(enclave->obj);

	pidx = OFF_TO_IDX(addr);
	page = PHYS_TO_VM_PAGE(epc->phys);
	vm_page_insert(page, enclave->obj, pidx);
	page->valid = VM_PAGE_BITS_ALL;
}

static int
sgx_ioctl_create(struct sgx_softc *sc, struct sgx_enclave_create *param)
{
	struct sgx_vm_handle *vmh;
	vm_map_entry_t entry;
	vm_object_t mem;
	vm_page_t p;
	struct page_info pginfo;
	struct secinfo secinfo;
	struct sgx_enclave *enclave;
	struct epc_page *epc;
	struct secs *secs;
	vm_object_t obj;
	int ret;

	epc = NULL;
	secs = NULL;
	enclave = NULL;
	obj = NULL;

	/* SGX Enclave Control Structure (SECS) */
	secs = malloc(PAGE_SIZE, M_SGX, M_WAITOK | M_ZERO);
	ret = copyin((void *)param->src, secs, sizeof(struct secs));
	if (ret) {
		dprintf("%s: Can't copy SECS.\n", __func__);
		goto error;
	}

	ret = sgx_secs_validate(sc, secs);
	if (ret) {
		dprintf("%s: SECS validation failed.\n", __func__);
		goto error;
	}

	ret = sgx_mem_find(sc, secs->base, &entry, &mem);
	if (ret) {
		dprintf("%s: Can't find vm_map.\n", __func__);
		goto error;
	}
	obj = entry->object.vm_object;

	vmh = mem->handle;
	if (!vmh) {
		dprintf("%s: Can't find vmh.\n", __func__);
		ret = ENXIO;
		goto error;
	}

	dprintf("%s: entry start %lx offset %lx\n",
	    __func__, entry->start, entry->offset);
	vmh->base = (entry->start - entry->offset);

	ret = sgx_enclave_alloc(sc, secs, &enclave);
	if (ret) {
		dprintf("%s: Can't alloc enclave.\n", __func__);
		goto error;
	}
	enclave->obj = obj;
	enclave->vmh = vmh;

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
	enclave->secs_epc_page = epc;

	VM_OBJECT_WLOCK(obj);
	p = vm_page_lookup(obj, 0);
	if (p) {
		VM_OBJECT_WUNLOCK(obj);
		/* SECS page already added. */
		ret = ENXIO;
		goto error;
	}

	ret = sgx_va_slot_init(sc, enclave, 0);
	if (ret) {
		VM_OBJECT_WUNLOCK(obj);
		dprintf("%s: Can't init va slot.\n", __func__);
		goto error;
	}

	mtx_lock(&sc->mtx);
	if ((sc->state & SGX_STATE_RUNNING) == 0) {
		mtx_unlock(&sc->mtx);
		/* Remove VA page that was just created for SECS page. */
		p = vm_page_lookup(enclave->obj, -SGX_VA_PAGES_OFFS);
		sgx_page_remove(sc, p);
		VM_OBJECT_WUNLOCK(obj);
		goto error;
	}
	ret = sgx_ecreate(&pginfo, (void *)epc->base);
	if (ret == SGX_EFAULT) {
		debug_printf("%s: gp fault\n", __func__);
		mtx_unlock(&sc->mtx);
		/* Remove VA page that was just created for SECS page. */
		p = vm_page_lookup(enclave->obj, -SGX_VA_PAGES_OFFS);
		sgx_page_remove(sc, p);
		VM_OBJECT_WUNLOCK(obj);
		goto error;
	}

	TAILQ_INSERT_TAIL(&sc->enclaves, enclave, next);
	mtx_unlock(&sc->mtx);

	vmh->enclave = enclave;
	sgx_insert_epc_page(enclave, epc, 0);
	VM_OBJECT_WUNLOCK(obj);

	/* Release the reference. */
	vm_object_deallocate(obj);

	free(secs, M_SGX);

	return (0);

error:
	free(secs, M_SGX);
	sgx_put_epc_page(sc, epc);
	free(enclave, M_SGX);
	vm_object_deallocate(obj);

	return (ret);
}

static int
sgx_ioctl_add_page(struct sgx_softc *sc,
    struct sgx_enclave_add_page *addp)
{
	struct epc_page *secs_epc_page;
	struct sgx_enclave *enclave;
	struct sgx_vm_handle *vmh;
	struct epc_page *epc;
	struct page_info pginfo;
	struct secinfo secinfo;
	vm_object_t obj;
	void *tmp_vaddr;
	uint64_t page_type;
	struct tcs *t;
	uint64_t addr;
	uint64_t pidx;
	vm_page_t p;
	int ret;

	tmp_vaddr = NULL;
	epc = NULL;
	obj = NULL;

	/* Find and get reference to VM object. */
	ret = sgx_enclave_find(sc, addp->addr, &enclave);
	if (ret) {
		dprintf("%s: Failed to find enclave.\n", __func__);
		goto error;
	}

	obj = enclave->obj;
	KASSERT(obj != NULL, ("vm object is NULL\n"));
	vmh = obj->handle;

	ret = sgx_get_epc_page(sc, &epc);
	if (ret) {
		dprintf("%s: Failed to get free epc page.\n", __func__);
		goto error;
	}

	memset(&secinfo, 0, sizeof(struct secinfo));
	ret = copyin((void *)addp->secinfo, &secinfo,
	    sizeof(struct secinfo));
	if (ret) {
		dprintf("%s: Failed to copy secinfo.\n", __func__);
		goto error;
	}

	tmp_vaddr = malloc(PAGE_SIZE, M_SGX, M_WAITOK | M_ZERO);
	ret = copyin((void *)addp->src, tmp_vaddr, PAGE_SIZE);
	if (ret) {
		dprintf("%s: Failed to copy page.\n", __func__);
		goto error;
	}

	page_type = (secinfo.flags & SECINFO_FLAGS_PT_M) >>
	    SECINFO_FLAGS_PT_S;
	if (page_type == SGX_PT_TCS) {
		t = (struct tcs *)tmp_vaddr;
		ret = sgx_tcs_validate(t);
		if (ret) {
			dprintf("%s: TCS page validation failed.\n",
			    __func__);
			goto error;
		}
		sgx_tcs_dump(sc, t);
	}

	addr = (addp->addr - vmh->base);
	pidx = OFF_TO_IDX(addr);

	VM_OBJECT_WLOCK(obj);
	p = vm_page_lookup(obj, pidx);
	if (p) {
		VM_OBJECT_WUNLOCK(obj);
		/* Page already added. */
		ret = ENXIO;
		goto error;
	}

	ret = sgx_va_slot_init(sc, enclave, addr);
	if (ret) {
		VM_OBJECT_WUNLOCK(obj);
		dprintf("%s: Can't init va slot.\n", __func__);
		goto error;
	}

	secs_epc_page = enclave->secs_epc_page;
	memset(&pginfo, 0, sizeof(struct page_info));
	pginfo.linaddr = (uint64_t)addp->addr;
	pginfo.srcpge = (uint64_t)tmp_vaddr;
	pginfo.secinfo = &secinfo;
	pginfo.secs = (uint64_t)secs_epc_page->base;

	mtx_lock(&sc->mtx);
	ret = sgx_eadd(&pginfo, (void *)epc->base);
	if (ret == SGX_EFAULT) {
		debug_printf("%s: gp fault\n", __func__);
		mtx_unlock(&sc->mtx);
		VM_OBJECT_WUNLOCK(obj);
		goto error;
	}
	mtx_unlock(&sc->mtx);

	sgx_measure_page(sc, enclave->secs_epc_page, epc, addp->mrmask);

	sgx_insert_epc_page(enclave, epc, addr);

	VM_OBJECT_WUNLOCK(obj);

	/* Release the reference. */
	vm_object_deallocate(obj);

	free(tmp_vaddr, M_SGX);

	return (0);

error:
	free(tmp_vaddr, M_SGX);
	sgx_put_epc_page(sc, epc);
	vm_object_deallocate(obj);

	return (ret);
}

static int
sgx_ioctl_init(struct sgx_softc *sc, struct sgx_enclave_init *initp)
{
	struct epc_page *secs_epc_page;
	struct sgx_enclave *enclave;
	struct thread *td;
	void *tmp_vaddr;
	void *einittoken;
	void *sigstruct;
	vm_object_t obj;
	int retry;
	int ret;

	td = curthread;
	tmp_vaddr = NULL;
	obj = NULL;

	dprintf("%s: addr %lx, sigstruct %lx, einittoken %lx\n",
	    __func__, initp->addr, initp->sigstruct, initp->einittoken);

	/* Find and get reference to VM object. */
	ret = sgx_enclave_find(sc, initp->addr, &enclave);
	if (ret) {
		dprintf("%s: Failed to find enclave.\n", __func__);
		goto error;
	}

	obj = enclave->obj;

	tmp_vaddr = malloc(PAGE_SIZE, M_SGX, M_WAITOK | M_ZERO);
	sigstruct = tmp_vaddr;
	einittoken = (void *)((uint64_t)sigstruct + PAGE_SIZE / 2);

	ret = copyin((void *)initp->sigstruct, sigstruct,
	    SGX_SIGSTRUCT_SIZE);
	if (ret) {
		dprintf("%s: Failed to copy SIGSTRUCT page.\n", __func__);
		goto error;
	}

	ret = copyin((void *)initp->einittoken, einittoken,
	    SGX_EINITTOKEN_SIZE);
	if (ret) {
		dprintf("%s: Failed to copy EINITTOKEN page.\n", __func__);
		goto error;
	}

	secs_epc_page = enclave->secs_epc_page;
	retry = 16;
	do {
		mtx_lock(&sc->mtx);
		ret = sgx_einit(sigstruct, (void *)secs_epc_page->base,
		    einittoken);
		mtx_unlock(&sc->mtx);
		dprintf("%s: sgx_einit returned %d\n", __func__, ret);
	} while (ret == SGX_UNMASKED_EVENT && retry--);

	if (ret) {
		dprintf("%s: Failed init enclave: %d\n", __func__, ret);
		td->td_retval[0] = ret;
		ret = 0;
	}

error:
	free(tmp_vaddr, M_SGX);

	/* Release the reference. */
	vm_object_deallocate(obj);

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
	int len;

	sc = &sgx_sc;

	len = IOCPARM_LEN(cmd);

	dprintf("%s: cmd %lx, addr %lx, len %d\n",
	    __func__, cmd, (uint64_t)addr, len);

	if (len > SGX_IOCTL_MAX_DATA_LEN)
		return (EINVAL);

	switch (cmd) {
	case SGX_IOC_ENCLAVE_CREATE:
		param = (struct sgx_enclave_create *)addr;
		ret = sgx_ioctl_create(sc, param);
		break;
	case SGX_IOC_ENCLAVE_ADD_PAGE:
		addp = (struct sgx_enclave_add_page *)addr;
		ret = sgx_ioctl_add_page(sc, addp);
		break;
	case SGX_IOC_ENCLAVE_INIT:
		initp = (struct sgx_enclave_init *)addr;
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
	vm_object_t object;

	sc = &sgx_sc;

	dprintf("%s: mapsize 0x%lx, offset %lx\n",
	    __func__, mapsize, *offset);

	vmh = malloc(sizeof(struct sgx_vm_handle),
	    M_SGX, M_WAITOK | M_ZERO);
	vmh->sc = sc;
	vmh->size = mapsize;
	vmh->mem = cdev_pager_allocate(vmh, OBJT_MGTDEVICE, &sgx_pg_ops,
	    mapsize, nprot, *offset, NULL);
	if (vmh->mem == NULL) {
		free(vmh, M_SGX);
		return (ENOMEM);
	}

	object = vmh->mem;
	vm_object_set_flag(object, OBJ_PG_DTOR);
	*objp = object;

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

	sc->epc_base = ((uint64_t)(cp[1] & 0xfffff) << 32) +
	    (cp[0] & 0xfffff000);
	sc->epc_size = ((uint64_t)(cp[3] & 0xfffff) << 32) +
	    (cp[2] & 0xfffff000);
	sc->npages = sc->epc_size / SGX_PAGE_SIZE;

	if (cp[3] & 0xffff) {
		sc->enclave_size_max = (1 << ((cp[3] >> 8) & 0xff));
	} else {
		sc->enclave_size_max = SGX_ENCL_SIZE_MAX_DEF;
	}

	epc_base_vaddr = (vm_offset_t)pmap_mapdev_attr(sc->epc_base,
	    sc->epc_size, VM_MEMATTR_DEFAULT);

	sc->epc_pages = malloc(sizeof(struct epc_page) * sc->npages,
	    M_DEVBUF, M_WAITOK | M_ZERO);

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
	sc->state |= SGX_STATE_RUNNING;

	printf("SGX initialized: EPC base 0x%lx size %ld (%d pages)\n",
	    sc->epc_base, sc->epc_size, sc->npages);

	return (0);
}

static int
sgx_unload(void)
{
	struct sgx_softc *sc;

	sc = &sgx_sc;

	mtx_lock(&sc->mtx);
	if (!TAILQ_EMPTY(&sc->enclaves)) {
		mtx_unlock(&sc->mtx);
		return (EBUSY);
	}
	sc->state &= ~SGX_STATE_RUNNING;
	mtx_unlock(&sc->mtx);

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
