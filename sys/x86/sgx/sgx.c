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

#ifdef __amd64__
#define	LOW_MEM_LIMIT	0x100000000ul
#else
#define	LOW_MEM_LIMIT	0
#endif

MALLOC_DEFINE(M_SGX, "sgx", "SGX driver");
MALLOC_DEFINE(M_PRIVCMD, "privcmd_dev", "SGX privcmd user-space device");

struct epc_page {
	uint64_t base;
	uint8_t used;
};

struct sgx_enclave_page {
	struct epc_page *epc_page;
};

struct sgx_enclave {
	uint64_t			base;
	uint64_t			size;
	struct sgx_enclave_page		secs_page;
	TAILQ_ENTRY(sgx_enclave)	next;
};

struct privcmd_map {
	vm_object_t mem;
	vm_size_t size;
	struct resource *phys_res;
	int phys_res_id;
	vm_paddr_t phys_base_addr;
	boolean_t mapped;
	BITSET_DEFINE_VAR() *err;
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

static int
privcmd_pg_ctor(void *handle, vm_ooffset_t size, vm_prot_t prot,
    vm_ooffset_t foff, struct ucred *cred, u_short *color)
{

	printf("%s\n", __func__);

	return (0);
}

static void
privcmd_pg_dtor(void *handle)
{

	printf("%s\n", __func__);
}

static int
privcmd_pg_fault(vm_object_t object, vm_ooffset_t offset,
    int prot, vm_page_t *mres)
{
	struct privcmd_map *map;
	vm_page_t page;
	vm_memattr_t memattr;
	vm_pindex_t pidx;
	vm_paddr_t paddr;

	map = object->handle;

	//printf("%lx %lx %lx\n", SGX_IOC_ENCLAVE_CREATE, SGX_IOC_ENCLAVE_ADD_PAGE, SGX_IOC_ENCLAVE_INIT);

	memattr = object->memattr;
	pidx = OFF_TO_IDX(offset);

	paddr = map->phys_base_addr + offset;

	//printf("%s: offset %lx, paddr %lx\n", __func__, offset, paddr);

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

	DELAY(5000);

	page->valid = VM_PAGE_BITS_ALL;
	return (VM_PAGER_OK);
}

static struct cdev_pager_ops privcmd_pg_ops = {
	.cdev_pg_fault = privcmd_pg_fault,
	.cdev_pg_ctor = privcmd_pg_ctor,
	.cdev_pg_dtor = privcmd_pg_dtor,
};

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

/* SGX Enclave Control Structure (SECS) */

struct secs g_secs __aligned(4096);
struct page_info pginfo __aligned(4096);
struct secinfo secinfo __aligned(4096);

static int
sgx_create(struct sgx_softc *sc, struct secs *m_secs)
{
	struct sgx_enclave *enclave;

	memset(&secinfo, 0, sizeof(struct secinfo));
	memset(&pginfo, 0, sizeof(struct page_info));

#if 1
	struct secinfo_flags *flags;

	flags = &secinfo.flags;
	flags->page_type = PT_SECS;
	flags->r = 1;
	flags->w = 1;
	flags->x = 0;
#endif

	pginfo.linaddr = 0;
	pginfo.srcpge = (uint64_t)&g_secs;
	pginfo.secinfo = (uint64_t)&secinfo;
	pginfo.secs = 0;

	dump_pginfo(&pginfo);

	printf("%s: secs->base 0x%lx, secs->size 0x%lx\n", __func__, g_secs.base, g_secs.size);

	struct epc_page *epc;
	epc = get_epc_page(sc);
	if (epc == NULL) {
		printf("failed to get epc page\n");
		return (-1);
	}

	uint64_t ret;
	ret = __ecreate(&pginfo, (void *)epc->base);
	printf("ecreate returned %lx\n", ret);

	enclave = malloc(sizeof(struct sgx_enclave), M_SGX, M_WAITOK | M_ZERO);
	enclave->base = g_secs.base;
	enclave->size = g_secs.size;
	enclave->secs_page.epc_page = epc;
	TAILQ_INSERT_TAIL(&sc->enclaves, enclave, next);

	return (0);
}

/*
 * struct sgx_enclave_add_page {
 *       uint64_t        addr;
 *       uint64_t        src;
 *       uint64_t        secinfo;
 *       uint16_t        mrmask;
 * } __attribute__((packed));
 */

#define	GFP_NATIVE_MASK	(M_NOWAIT | M_WAITOK | M_USE_RESERVE | M_ZERO)

static int
sgx_add_page(struct sgx_softc *sc, struct sgx_enclave_add_page *addp)
{
	struct sgx_enclave *enclave_tmp;
	struct sgx_enclave *enclave;
	//struct sgx_secinfo secinfo;
	int ret;

	TAILQ_FOREACH_SAFE(enclave, &sc->enclaves, next, enclave_tmp) {
		if ((addp->addr >= enclave->base) && \
		    (addp->addr < (enclave->base + enclave->size))) {
			printf("enclave found\n");
			break;
		}
	}
	if (enclave == NULL) {
		printf("enclave not found\n");
	}

	//printf("%s\n", __func__);
	printf("%s: add page addr %lx src %lx secinfo %lx mrmask %x\n", __func__,
	    addp->addr, addp->src, addp->secinfo, addp->mrmask);

	memset(&secinfo, 0, sizeof(struct secinfo));
	ret = copyin((void *)addp->secinfo, &secinfo, sizeof(struct sgx_secinfo));
	if (ret != 0) {
		printf("%s: failed to copy secinfo\n", __func__);
	}

	uint32_t size;
	uint32_t flags;
	vm_offset_t tmp_vaddr;

	size = PAGE_SIZE;
	flags = 0;

	tmp_vaddr = kmem_alloc_contig(kmem_arena, size,
	    flags & GFP_NATIVE_MASK, 0, BUS_SPACE_MAXADDR_32BIT,
	    PAGE_SIZE, 0, VM_MEMATTR_DEFAULT);

	ret = copyin((void *)addp->src, (void *)tmp_vaddr, PAGE_SIZE);
	if (ret != 0) {
		printf("%s: failed to copy page\n", __func__);
	}

	kmem_free(kmem_arena, tmp_vaddr, size);

	struct epc_page *epc;
	epc = get_epc_page(sc);
	if (epc == NULL) {
		printf("failed to get epc page\n");
		return (-1);
	}

	memset(&pginfo, 0, sizeof(struct page_info));

	pginfo.linaddr = (uint64_t)addp->addr;
	pginfo.srcpge = (uint64_t)addp->src;
	pginfo.secinfo = (uint64_t)&secinfo;

	struct epc_page *secs_epc_page;
	secs_epc_page = enclave->secs_page.epc_page;
	pginfo.secs = (uint64_t)secs_epc_page->base;

	dump_pginfo(&pginfo);
	printf("pginfo %lx epc %lx\n", (uint64_t)&pginfo, (uint64_t)epc->base);

	ret = __eadd(&pginfo, (void *)epc->base);
	printf("__eadd retured %d\n", ret);

	return (0);
}

#define	_SGX_IOC_ENCLAVE_CREATE		0xa400
#define	_SGX_IOC_ENCLAVE_ADD_PAGE	0xa401
#define	_SGX_IOC_ENCLAVE_INIT		0xa402

static int
sgx_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{
	struct sgx_enclave_create *param;
	struct sgx_enclave_add_page *addp;
	struct secs *m_secs;
	struct sgx_softc *sc;

	sc = dev->si_drv1;

	m_secs = &g_secs;

	//printf("%s: %ld\n", __func__, cmd);

	switch (cmd & 0xffff) {
	case _SGX_IOC_ENCLAVE_CREATE:
		printf("%s: enclave_create: addr %lx flags %d\n", __func__, (uint64_t)addr, flags);
		printf("%s: val %lx\n", __func__, *(uint64_t *)addr);
		//uint64_t uaddr;
		//uaddr = *(uint64_t *)addr;

		param = (struct sgx_enclave_create *)addr;
		copyin((void *)param->src, &g_secs, sizeof(struct secs));
		sgx_create(sc, m_secs);

		//printf("m_secs.isv_svn %d\n", m_secs.isv_svn);
		//handler = isgx_ioctl_enclave_create;
		break;
	case _SGX_IOC_ENCLAVE_ADD_PAGE:
		//printf("%s: enclave_add_page\n", __func__);

		addp = (struct sgx_enclave_add_page *)addr;
		sgx_add_page(sc, addp);

		//handler = isgx_ioctl_enclave_add_page;
		break;
	case _SGX_IOC_ENCLAVE_INIT:
		printf("%s: enclave_init\n", __func__);
		//handler = isgx_ioctl_enclave_init;
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

	sc = cdev->si_drv1;

	map->phys_res_id = 0;

	map->phys_res = sgx_alloc(sc->dev, &map->phys_res_id, mapsize);
	if (map->phys_res == NULL) {
		printf("Can't alloc phys mem\n");
		return (EINVAL);
	}

	map->phys_base_addr = rman_get_start(map->phys_res);
	printf("%s: phys addr 0x%lx\n", __func__, (uint64_t)map->phys_base_addr);

	//map->mem = cdev_pager_allocate(map, OBJT_MGTDEVICE, &privcmd_pg_ops,
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

	uint64_t epc_base;
	uint64_t epc_size;

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
		sc->epc_pages[i].used = 0;
	}

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
