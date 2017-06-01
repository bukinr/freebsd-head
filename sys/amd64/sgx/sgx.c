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
#include <sys/capsicum.h>
#include <sys/uio.h>
#include <sys/bus.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/selinfo.h>
#include <sys/poll.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/ioccom.h>
#include <sys/rman.h>
#include <sys/tree.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/bitset.h>

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
#include "sgx_user.h"

#define	_SGX_IOC_ENCLAVE_CREATE		0xa400
#define	_SGX_IOC_ENCLAVE_ADD_PAGE	0xa401
#define	_SGX_IOC_ENCLAVE_INIT		0xa402

#ifdef __amd64__
#define	LOW_MEM_LIMIT	0x100000000ul
#else
#define	LOW_MEM_LIMIT	0
#endif

MALLOC_DEFINE(M_SGX, "sgx", "SGX driver");
MALLOC_DEFINE(M_PRIVCMD, "privcmd_dev", "SGX privcmd user-space device");

struct epc_page {
	uint64_t base;
	uint64_t phys;
	uint8_t used;
};

/* Version-Array slot */
struct va_page {
	struct epc_page *epc_page;
};

struct privcmd_map {
	struct sgx_softc *sc;
	vm_object_t mem;
	uint64_t base;
	vm_size_t size;
	struct resource *phys_res;
	int phys_res_id;
	vm_paddr_t phys_base_addr;
	boolean_t mapped;
	BITSET_DEFINE_VAR() *err;
	struct sgx_enclave *enclave;
};

struct sgx_enclave_page {
	struct epc_page *epc_page;
	struct va_page *va_page;
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
};

#define	SGX_CPUID		0x12
#define	SGX_PAGE_SIZE		4096

struct sgx_softc {
	struct cdev		*sgx_cdev;
	device_t		dev;

	struct epc_page		*epc_pages;
	uint32_t		npages;

	TAILQ_HEAD(, sgx_enclave)	enclaves;
};

static int
dump_pginfo(struct page_info *pginfo)
{

	printf("pginfo->linaddr = %lx\n", pginfo->linaddr);
	printf("pginfo->srcpge = %lx\n", pginfo->srcpge);
	printf("pginfo->secinfo = %lx\n", pginfo->secinfo);
	printf("pginfo->secs = %lx\n", pginfo->secs);

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
	struct epc_page *secs_epc_page;
	struct sgx_enclave *enclave;

	map = handle;
	enclave = map->enclave;

	secs_epc_page = enclave->secs_page.epc_page;
	printf("%s: enclave->secs_page.epc_page %lx\n", __func__, (uint64_t)secs_epc_page->base);
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

	map = object->handle;
	sc = map->sc;
	enclave = map->enclave;

	printf("%s: offset 0x%lx\n", __func__, offset);

	//printf("%lx %lx %lx\n", SGX_IOC_ENCLAVE_CREATE, SGX_IOC_ENCLAVE_ADD_PAGE, SGX_IOC_ENCLAVE_INIT);

	memattr = object->memattr;
	pidx = OFF_TO_IDX(offset);

	//paddr = map->phys_base_addr + offset;

	struct sgx_enclave_page *enclave_page_tmp;
	struct sgx_enclave_page *enclave_page;
	int found;

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
		return (-1);
	}
	struct epc_page *epc;
	epc = enclave_page->epc_page;
	paddr = epc->phys;

#if 0
	struct sgx_enclave *enclave_tmp;
	struct sgx_enclave *enclave;
	TAILQ_FOREACH_SAFE(enclave, &sc->enclaves, next, enclave_tmp) {
		TAILQ_FOREACH_SAFE(enclave_page, &enclave->pages, next, enclave_page_tmp) {
			//enclave_page->epc_page
#if 0
			if ((addr >= enclave->base) && \
			    (addr < (enclave->base + enclave->size))) {
				printf("enclave found\n");
				*encl = enclave;
				return (0);
			}
#endif
		}
	}
#endif

#if 0
	struct epc_page *epc;
	epc = get_epc_page(map->sc);
	if (epc == NULL) {
		printf("%s: failed to get epc page\n", __func__);
		return (-1);
	}
	paddr = epc->phys;
#endif

	if (((*mres)->flags & PG_FICTITIOUS) != 0) {
		printf("fake page\n");

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
sgx_open(struct cdev *dev, int flags __unused,
    int fmt __unused, struct thread *td __unused)
{
	struct sgx_softc *sc;

	sc = dev->si_drv1;

	//printf("%s\n", __func__);

	return (0);
}

static int
sgx_close(struct cdev *dev, int flags __unused,
    int fmt __unused, struct thread *td __unused)
{
	struct sgx_softc *sc;

	sc = dev->si_drv1;

	//printf("%s\n", __func__);

	return (0);
}

static int
sgx_read(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct sgx_softc *sc;

	sc = dev->si_drv1;

	//printf("%s\n", __func__);

	return (0);
}

static int
sgx_write(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct sgx_softc *sc;

	sc = dev->si_drv1;

	//printf("%s\n", __func__);

	return (0);
}

static int
sgx_construct_page(struct sgx_softc *sc,
    struct sgx_enclave_page *enclave_page)
{
	struct va_page *va_page;
	struct epc_page *epc;

	epc = get_epc_page(sc);
	if (epc == NULL) {
		printf("failed to get epc page\n");
		return (-1);
	}

	va_page = malloc(sizeof(struct va_page), M_SGX, M_WAITOK | M_ZERO);
	va_page->epc_page = epc;

	printf("EPA call\n");
	__epa((void *)epc->base);
	printf("EPA call done\n");

	enclave_page->va_page = va_page;

	return (0);
}

static int
sgx_create(struct sgx_softc *sc, struct secs *m_secs)
{
	struct sgx_enclave_page *secs_page;
	struct page_info pginfo;
	struct sgx_secinfo secinfo;
	struct sgx_enclave *enclave;
	struct epc_page *epc;

	enclave = malloc(sizeof(struct sgx_enclave), M_SGX, M_WAITOK | M_ZERO);
	TAILQ_INIT(&enclave->pages);
	enclave->base = m_secs->base;
	enclave->size = m_secs->size;

	memset(&secinfo, 0, sizeof(struct sgx_secinfo));

	//printf("enclave->base phys %lx\n", vtophys(enclave->base));

	struct proc *proc;
	pmap_t pmap;
	proc = curthread->td_proc;
	pmap = vm_map_pmap(&proc->p_vmspace->vm_map);
	printf("enclave->base phys %lx\n", pmap_extract(pmap, enclave->base));

	int error;
	vm_map_t map;
	vm_map_entry_t entry;
	vm_object_t mem;
	vm_pindex_t pindex;
	vm_prot_t prot;
	boolean_t wired;
	struct privcmd_map *priv_map;

	map = &proc->p_vmspace->vm_map;
	error = vm_map_lookup(&map, m_secs->base, VM_PROT_NONE, &entry,
	    &mem, &pindex, &prot, &wired);
	vm_map_lookup_done(map, entry);
	if (error != 0) {
		printf("Can't find vm_map\n");
		return (-1);
	}
	printf("%s: vm_map_lookup: entry->start 0x%lx, entry->end 0x%lx, entry->offset 0x%lx pindex 0x%lx\n",
	    __func__, entry->start, entry->end, entry->offset, (uint64_t)pindex);

	printf("vm_map->root->start %lx\n", map->root->start);
	priv_map = mem->handle;
	printf("vm_map found, size 0x%lx\n", priv_map->size);
	enclave->map = priv_map;
	priv_map->enclave = enclave;
	priv_map->base = (entry->start - entry->offset);

#if 0
	struct secinfo_flags *flags;

	flags = &secinfo.flags;
	flags->page_type = PT_SECS;
	flags->r = 1;
	flags->w = 1;
	flags->x = 0;
#endif

	memset(&pginfo, 0, sizeof(struct page_info));
	pginfo.linaddr = 0;
	pginfo.srcpge = (uint64_t)m_secs;
	pginfo.secinfo = (uint64_t)&secinfo;
	pginfo.secs = 0;

	dump_pginfo(&pginfo);

	printf("%s: secs->base 0x%lx, secs->size 0x%lx\n", __func__, m_secs->base, m_secs->size);

	epc = get_epc_page(sc);
	if (epc == NULL) {
		printf("failed to get epc page\n");
		return (-1);
	}

	sgx_construct_page(sc, &enclave->secs_page);

	secs_page = &enclave->secs_page;
	secs_page->epc_page = epc;

	__ecreate(&pginfo, (void *)epc->base);

	TAILQ_INSERT_TAIL(&sc->enclaves, enclave, next);

	return (0);
}

#define	GFP_NATIVE_MASK	(M_NOWAIT | M_WAITOK | M_USE_RESERVE | M_ZERO)

static int
enclave_get(struct sgx_softc *sc, uint64_t addr, struct sgx_enclave **encl)
{
	//struct sgx_enclave *enclave_tmp;
	//struct sgx_enclave *enclave;

	int error;
	vm_map_t map;
	vm_map_entry_t entry;
	vm_object_t mem;
	vm_pindex_t pindex;
	vm_prot_t prot;
	boolean_t wired;
	struct privcmd_map *priv_map;
	struct proc *proc;
	//pmap_t pmap;

	proc = curthread->td_proc;

	map = &proc->p_vmspace->vm_map;
	error = vm_map_lookup(&map, addr, VM_PROT_NONE, &entry,
	    &mem, &pindex, &prot, &wired);
	vm_map_lookup_done(map, entry);
	if (error != 0) {
		printf("Can't find enclave\n");
		return (-1);
	}
	priv_map = mem->handle;
	*encl = priv_map->enclave;
	return (0);

#if 0
	TAILQ_FOREACH_SAFE(enclave, &sc->enclaves, next, enclave_tmp) {
		if ((addr >= enclave->base) && \
		    (addr < (enclave->base + enclave->size))) {
			printf("enclave found\n");
			*encl = enclave;
			return (0);
		}
	}
#endif

	printf("enclave not found\n");

	return (-1);
}

static int
sgx_measure_page(struct epc_page *secs, struct epc_page *epc,
    uint16_t mrmask)
{
	int i, j;
	int ret;

	ret = 0;

	for (i = 0, j = 1; i < 0x1000 && !ret; i += 0x100, j <<= 1) {
		if (!(j & mrmask)) {
			continue;
		}

		__eextend((void *)secs->base, (void *)((uint64_t)epc->base + i));
	}

	return (0);
}

static int validate_tcs(struct tcs *tcs)
{
	int i;

	/* If FLAGS is not zero, ECALL will fail. */
	if ((tcs->flags != 0) ||
	    (tcs->ossa & (PAGE_SIZE - 1)) ||
	    (tcs->ofsbasgx & (PAGE_SIZE - 1)) ||
	    (tcs->ogsbasgx & (PAGE_SIZE - 1)) ||
	    ((tcs->fslimit & 0xFFF) != 0xFFF) ||
	    ((tcs->gslimit & 0xFFF) != 0xFFF))
		return -EINVAL;

	for (i = 0; i < sizeof(tcs->reserved)/sizeof(uint64_t); i++)
		if (tcs->reserved[i])
			return -EINVAL;

	return 0;
}

/*
 * struct sgx_enclave_add_page {
 *       uint64_t        addr;
 *       uint64_t        src;
 *       uint64_t        secinfo;
 *       uint16_t        mrmask;
 * } __attribute__((packed));
 */

static int
sgx_add_page(struct sgx_softc *sc, struct sgx_enclave_add_page *addp)
{
	struct sgx_enclave_page *enclave_page;
	struct epc_page *secs_epc_page;
	struct sgx_enclave *enclave;
	struct epc_page *epc;
	struct page_info pginfo;
	struct sgx_secinfo secinfo;
	uint32_t size;
	uint32_t flags;
	vm_offset_t tmp_vaddr;
	uint64_t page_type;

	int ret;

	ret = enclave_get(sc, addp->addr, &enclave);
	if (ret != 0) {
		printf("Failed to get enclave\n");
		return (-1);
	}

	struct proc *proc;
	pmap_t pmap;
	proc = curthread->td_proc;
	pmap = vm_map_pmap(&proc->p_vmspace->vm_map);
	printf("addp->addr phys %lx\n", pmap_extract(pmap, addp->addr));

	//printf("%s\n", __func__);
	printf("%s: add page addr %lx src %lx secinfo %lx mrmask %x\n", __func__,
	    addp->addr, addp->src, addp->secinfo, addp->mrmask);

	memset(&secinfo, 0, sizeof(struct sgx_secinfo));
	ret = copyin((void *)addp->secinfo, &secinfo, sizeof(struct sgx_secinfo));
	if (ret != 0) {
		printf("%s: failed to copy secinfo\n", __func__);
		return (-1);
	}

	size = PAGE_SIZE;
	flags = 0;

	tmp_vaddr = kmem_alloc_contig(kmem_arena, size,
	    flags & GFP_NATIVE_MASK, 0, BUS_SPACE_MAXADDR_32BIT,
	    PAGE_SIZE, 0, VM_MEMATTR_DEFAULT);

	ret = copyin((void *)addp->src, (void *)tmp_vaddr, PAGE_SIZE);
	if (ret != 0) {
		printf("%s: failed to copy page\n", __func__);
		return (-1);
	}

	page_type = (secinfo.flags >> 8) & 0xff;
	printf("page_type %ld\n", page_type);
	if (page_type == PT_TCS) {
		printf("TCS page\n");
		struct tcs *t;
		t = (struct tcs *)tmp_vaddr;
		if (validate_tcs(t) == 0) {
			printf("validated\n");
		} else {
			printf("TCS validation failed\n");
			return (-1);
		}
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
	}

	enclave_page = malloc(sizeof(struct sgx_enclave_page), M_SGX, M_WAITOK | M_ZERO);

	epc = get_epc_page(sc);
	if (epc == NULL) {
		printf("failed to get epc page\n");
		return (-1);
	}
	sgx_construct_page(sc, enclave_page);
	enclave_page->epc_page = epc;
	enclave_page->addr = addp->addr;

	secs_epc_page = enclave->secs_page.epc_page;

	memset(&pginfo, 0, sizeof(struct page_info));
	pginfo.linaddr = (uint64_t)addp->addr;
	pginfo.srcpge = (uint64_t)tmp_vaddr;
	pginfo.secinfo = (uint64_t)&secinfo;
	pginfo.secs = (uint64_t)secs_epc_page->base;

	dump_pginfo(&pginfo);
	printf("pginfo %lx epc %lx\n", (uint64_t)&pginfo, (uint64_t)epc->base);

	printf("%s: __eadd\n", __func__);
	__eadd(&pginfo, (void *)epc->base);

	printf("%s: sgx_measure_page\n", __func__);
	ret = sgx_measure_page(enclave->secs_page.epc_page, epc, addp->mrmask);
	if (ret != 0) {
		printf("sgx_measure_page returned %d\n", ret);
		return (-1);
	}

	kmem_free(kmem_arena, tmp_vaddr, size);

	TAILQ_INSERT_TAIL(&enclave->pages, enclave_page, next);

	return (0);
}

/*
 * struct sgx_enclave_init {
 *       uint64_t        addr;
 *       uint64_t        sigstruct;
 *       uint64_t        einittoken;
 * } __attribute__((packed));
 */

static int
sgx_init(struct sgx_softc *sc, struct sgx_enclave_init *initp)
{
	einittoken_t *einittoken;
	struct epc_page *secs_epc_page;
	struct sgx_enclave *enclave;
	vm_offset_t tmp_vaddr;
	void *sigstruct;
	int ret;

	printf("%s: addr %lx\n", __func__, initp->addr);
	printf("%s: sigstruct %lx\n", __func__, initp->sigstruct);
	printf("%s: einittoken %lx\n", __func__, initp->einittoken);

	ret = enclave_get(sc, initp->addr, &enclave);
	if (ret != 0) {
		printf("Failed to get enclave\n");
		return (-1);
	}

	printf("%s: enclave_id %lx\n", __func__, initp->addr);

	secs_epc_page = enclave->secs_page.epc_page;

	tmp_vaddr = kmem_alloc_contig(kmem_arena, PAGE_SIZE,
	    0/*flags*/, 0, BUS_SPACE_MAXADDR_32BIT,
	    PAGE_SIZE, 0, VM_MEMATTR_DEFAULT);

	sigstruct = (void *)tmp_vaddr;
	einittoken = (einittoken_t *)((uint64_t)sigstruct + PAGE_SIZE / 2);

	printf("%s: initp->sigstruct addr %lx\n", __func__, initp->sigstruct);
	printf("%s: initp->einittoken addr %lx\n", __func__, initp->einittoken);

	ret = copyin((void *)initp->sigstruct, sigstruct,
	    SIGSTRUCT_SIZE);
	if (ret != 0) {
		printf("%s: failed to copy SIGSTRUCT page\n", __func__);
		return (-1);
	}

	ret = copyin((void *)initp->einittoken, einittoken,
	    EINITTOKEN_SIZE);
	if (ret != 0) {
		printf("%s: failed to copy EINITTOKEN page\n", __func__);
		return (-1);
	}

#if 0
	uint32_t *eaddr;
	int i;

	eaddr = (void *)sigstruct;
	for (i = 0; i < SIGSTRUCT_SIZE / 4; i++) {
		printf("sigstruct[%d] == %x\n", i, eaddr[i]);
	}

	eaddr = (void *)einittoken;
	for (i = 0; i < sizeof(einittoken_t) / 4; i++) {
		printf("einittoken[%d] == %d\n", i, eaddr[i]);
	}
#endif

	uint16_t isgx_isvsvnle_min;
	isgx_isvsvnle_min = 0;
	if (einittoken->body.valid && einittoken->isv_svn_le < isgx_isvsvnle_min) {
		printf("ROLLBACK\n");
	}

	printf("%s: sigstruct addr %lx\n", __func__, (uint64_t)sigstruct);
	printf("%s: einittoken addr %lx\n", __func__, (uint64_t)einittoken);
	printf("%s: secs_epc_page addr %lx\n", __func__, (uint64_t)secs_epc_page->base);

#if 0
	//ATTRIBUTES  48  16
	uint32_t *addr;

	addr = (void *)secs_epc_page->base;
	addr = m_secs;
	for (i = 0; i < 32; i++) {
		printf("secs base[%d] %x\n", i, addr[i]);
	}
#endif

#if 0
	secs_t *secs;
	secs = m_secs;
	ret = memcmp(&new_secs->attributes, &einittoken->body.attributes, sizeof(sgx_attributes_t));
	printf("memcmp returned %d\n", ret);

	printf("&new_secs->attributes flags %lx\n", new_secs->attributes.flags);
	printf("&new_secs->attributes xfrm %lx\n", new_secs->attributes.xfrm);
	printf("&einittoken->body.attributes flags %lx\n", einittoken->body.attributes.flags);
	printf("&einittoken->body.attributes xfrm %lx\n", einittoken->body.attributes.xfrm);

	printf("secs->attributes flags %lx\n", secs->attributes.flags);
	printf("secs->attributes xfrm %lx\n", secs->attributes.xfrm);
#endif

	printf("%s: secs_epc_page->base %lx\n", __func__, secs_epc_page->base);
	do {
		ret = __einit(sigstruct, (void *)secs_epc_page->base, einittoken);
		printf("__einit returned %d\n", ret);
	} while (ret == SGX_UNMASKED_EVENT);

	if (ret != 0) {
		printf("Failed to init enclave\n");
	}

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

	printf("CR0: %lx\n", rcr0());
	printf("CR4: %lx\n", rcr4());

	return (ret);
}

static int
sgx_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{
	struct sgx_enclave_add_page *addp;
	struct sgx_enclave_create *param;
	struct sgx_enclave_init *initp;
	int ret;

	struct secs *m_secs;
	struct sgx_softc *sc;

	sc = dev->si_drv1;

	/* SGX Enclave Control Structure (SECS) */
	m_secs = (struct secs *)kmem_alloc_contig(kmem_arena, PAGE_SIZE,
	    0/*flags*/, 0, BUS_SPACE_MAXADDR_32BIT,
	    PAGE_SIZE, 0, VM_MEMATTR_DEFAULT);

	printf("%s: %ld, m_secs %lx\n", __func__, cmd, (uint64_t)m_secs);

	switch (cmd & 0xffff) {
	case _SGX_IOC_ENCLAVE_CREATE:
		printf("%s: enclave_create: addr %lx flags %d\n", __func__, (uint64_t)addr, flags);
		printf("%s: val %lx\n", __func__, *(uint64_t *)addr);
		//uint64_t uaddr;
		//uaddr = *(uint64_t *)addr;

		param = (struct sgx_enclave_create *)addr;
		ret = copyin((void *)param->src, m_secs, sizeof(struct secs));
		if (ret != 0) {
			printf("Can't copy SECS\n");
			return (-1);
		}
		printf("secs (%ld bytes) copied\n", sizeof(struct secs));

		sgx_create(sc, m_secs);

		//printf("m_secs.isv_svn %d\n", m_secs.isv_svn);
		break;
	case _SGX_IOC_ENCLAVE_ADD_PAGE:
		//printf("%s: enclave_add_page\n", __func__);

		addp = (struct sgx_enclave_add_page *)addr;
		sgx_add_page(sc, addp);

		break;
	case _SGX_IOC_ENCLAVE_INIT:

		printf("%s: enclave_init\n", __func__);
		initp = (struct sgx_enclave_init *)addr;
		return (sgx_init(sc, initp));

		break;
	default:
		return -EINVAL;
	}

	return (0);
}

static struct resource *
sgx_alloc(device_t dev, int *res_id, size_t size)
{
	struct resource *res;

	res = bus_alloc_resource(dev, SYS_RES_MEMORY, res_id, LOW_MEM_LIMIT,
		~0, size, RF_ACTIVE);
	if (res == NULL) {
		return (NULL);
	}

	return (res);
}

static int
sgx_mmap_single(struct cdev *cdev, vm_ooffset_t *offset, vm_size_t mapsize,
    struct vm_object **objp, int nprot)
{
	struct privcmd_map *map;
	struct sgx_softc *sc;

	map = malloc(sizeof(*map), M_PRIVCMD, M_WAITOK | M_ZERO);

	printf("%s: mapsize %ld\n", __func__, mapsize);
	//printf("%s: offset %ld\n", __func__, *offset);

	sc = cdev->si_drv1;

	map->sc = sc;
#if 0
	map->phys_res_id = 0;
	map->phys_res = sgx_alloc(sc->dev, &map->phys_res_id, mapsize);
	if (map->phys_res == NULL) {
		printf("Can't alloc phys mem\n");
		return (EINVAL);
	}

	map->phys_base_addr = rman_get_start(map->phys_res);
	printf("%s: phys addr 0x%lx\n", __func__, (uint64_t)map->phys_base_addr);
#endif

#if 0
	struct epc_page *epc;
	int i;

	for (i = 0; i < mapsize; i += PAGE_SIZE) {
		epc = get_epc_page(map->sc);
		if (epc == NULL) {
			printf("%s: failed to get epc page\n", __func__);
			return (-1);
		}

		enclave_page = malloc(sizeof(struct sgx_enclave_page), M_SGX, M_WAITOK | M_ZERO);
		enclave_page->epc_page = epc;
		TAILQ_INSERT_TAIL(&enclave->pages, enclave_page, next);
	}
#endif

	//map->mem = cdev_pager_allocate(map, OBJT_MGTDEVICE, &privcmd_pg_ops,
	map->size = mapsize;
	map->mem = cdev_pager_allocate(map, OBJT_DEVICE, &privcmd_pg_ops,
	    mapsize, nprot, *offset, NULL);
	if (map->mem == NULL) {
		//xenmem_free(privcmd_dev, map->phys_res_id,
		//    map->phys_res);
		free(map, M_PRIVCMD);
		return (ENOMEM);
	}

	*objp = map->mem;

	//int error;

	return (0);
}

static struct cdevsw sgx_cdevsw = {
	.d_version =		D_VERSION,
	.d_open =		sgx_open,
	.d_close =		sgx_close,
	.d_read =		sgx_read,
	.d_write =		sgx_write,
	.d_ioctl =		sgx_ioctl,
	.d_mmap_single =	sgx_mmap_single,
	.d_name =		"Intel SGX",
};

static void
sgx_identify(driver_t *driver, device_t parent)
{

	if ((cpu_stdext_feature & CPUID_STDEXT_SGX) == 0)
		return;

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
	uint64_t epc_base;
	uint64_t epc_size;

	sc = device_get_softc(dev);
	sc->dev = dev;

	sc->sgx_cdev = make_dev(&sgx_cdevsw, 0, UID_ROOT, GID_WHEEL,
	    0600, "isgx");

	if (sc->sgx_cdev == NULL) {
		device_printf(dev, "Failed to create character device.\n");
		return (ENXIO);
	}

	sc->sgx_cdev->si_drv1 = sc;

	u_int cp[4];
	cpuid_count(SGX_CPUID, 0x2, cp);

	__asm __volatile("cpuid" : : : "eax", "ebx", "ecx", "edx");

	printf("eax & 0xf == %x\n", cp[0] & 0xf);

	epc_base = ((uint64_t)(cp[1] & 0xfffff) << 32) + (cp[0] & 0xfffff000);
	epc_size = ((uint64_t)(cp[3] & 0xfffff) << 32) + (cp[2] & 0xfffff000);

	printf("%s: epc_base %lx size %lx\n", __func__, epc_base, epc_size);

	vm_offset_t epc_base_vaddr;
	int i;

	epc_base_vaddr = (vm_offset_t)pmap_mapdev(epc_base, epc_size);
	sc->npages = epc_size / SGX_PAGE_SIZE;
	sc->epc_pages = malloc(sizeof(struct epc_page) * sc->npages,
	    M_DEVBUF, M_WAITOK | M_ZERO);

	for (i = 0; i < sc->npages; i++) {
		sc->epc_pages[i].base = epc_base_vaddr + SGX_PAGE_SIZE * i;
		sc->epc_pages[i].phys = epc_base + SGX_PAGE_SIZE * i;
		sc->epc_pages[i].used = 0;
	}

	TAILQ_INIT(&sc->enclaves);

	unsigned regs[4];
	do_cpuid(1, regs);
	if (regs[2] & CPUID2_OSXSAVE) {
		printf("OSXSAVE found\n");
	} else {
		printf("OSXSAVE not found\n");
	}

	if (rcr4() & CR4_XSAVE) {
		printf("CR4_XSAVE found\n");
	} else {
		printf("CR4_XSAVE not found\n");
	}

	if (rcr4() & CR4_FXSR) {
		printf("CR4_FXSR found\n");
	} else {
		printf("CR4_FXSR not found\n");
	}

	printf("RXCR0: %lx\n", rxcr(0));

	printf("CR0: %lx\n", rcr0());
	printf("CR4: %lx\n", rcr4());

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
