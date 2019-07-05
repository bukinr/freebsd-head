/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Ruslan Bukin <br@bsdpad.com>
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

#include "opt_platform.h"
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>

#include <machine/cache.h>
#include <machine/bus.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_page.h>

#include <mips/beri/beri_iommu.h>

#ifdef FDT
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#endif

#include <dev/xdma/xdma.h>

void
iommu_kenter_attr(pmap_t p, vm_offset_t va,
    vm_paddr_t pa, vm_memattr_t ma)
{
	pt_entry_t *pte;
	vm_offset_t addr;
	pt_entry_t opte, npte;

	pte = pmap_pte(p, va);
	if (pte == NULL) {
		printf("%s: pte %p\n", __func__, pte);
		pmap_allocpte(p, va, 0);
		pte = pmap_pte(p, va);
		printf("%s: pte (again) %p\n", __func__, pte);
	}

	addr = (vm_offset_t)pte;
	addr &= ~((unsigned long long)MIPS_CCA_CACHED << 59);
	addr |= ((unsigned long long)MIPS_CCA_UNCACHED << 59);
	pte = (pt_entry_t *)addr;

	opte = *pte;
	npte = TLBLO_PA_TO_PFN(pa) | PTE_C(ma) | PTE_D | PTE_V | PTE_G;
	*pte = npte;
	//printf("pte %p opte %lx npte %lx\n", pte, opte, npte);
	if (pte_test(&opte, PTE_V) && opte != npte) {
		printf("reusing page %lx\n", va);
		//panic("page %lx update required\n", va);
		//pmap_update_page(p, va, npte);
	}
}

void
iommu_kenter_device(pmap_t p, vm_offset_t va, vm_size_t size, vm_paddr_t pa)
{

	KASSERT((size & PAGE_MASK) == 0,
	    ("%s: device mapping not page-sized", __func__));

	for (; size > 0; size -= PAGE_SIZE) {
		iommu_kenter_attr(p, va, pa, VM_MEMATTR_UNCACHEABLE);
		va += PAGE_SIZE;
		pa += PAGE_SIZE;
	}
}

void
xdma_iommu_remove_entry(xdma_channel_t *xchan, vm_offset_t va)
{
	struct xdma_iommu *xio;
	vm_offset_t va1;

	va1 = va & ~(PAGE_SIZE - 1);
	xio = xchan->xio;

	beri_iommu_invalidate(va);

	vmem_free(xio->vmem, va1, PAGE_SIZE);
}

void
xdma_iommu_add_entry(xdma_channel_t *xchan, vm_offset_t *va,
    vm_size_t size, vm_paddr_t pa)
{
	struct xdma_iommu *xio;
	vm_offset_t addr;

	size = roundup2(size, PAGE_SIZE);
	xio = xchan->xio;

	if (vmem_alloc(xio->vmem, size,
	    M_BESTFIT | M_NOWAIT, &addr)) {
		panic("cant allocate memory\n");
	}

	addr |= pa & (PAGE_SIZE - 1);

	*va = addr;

	printf("%s: va %lx size %lx pa %lx\n",
	    __func__, addr, size, pa);
	iommu_kenter_device(&xio->p, addr, size, pa);
}

int
xdma_iommu_init(struct xdma_iommu *xio)
{

	printf("%s\n", __func__);

	pmap_pinit(&xio->p);

	printf("%s: %lx\n", __func__, (uintptr_t)xio->p.pm_segtab);

	xio->vmem = vmem_create("xDMA vmem", 0, 0, PAGE_SIZE,
	    PAGE_SIZE, M_BESTFIT | M_WAITOK);
	if (xio->vmem == NULL)
		return (-1);

	vmem_add(xio->vmem, 0xC000000000000000, (1ULL << 39), 0);

	beri_iommu_set_base((uintptr_t)xio->p.pm_segtab);

	return (0);
}

int
xdma_iommu_release(struct xdma_iommu *xio)
{

	printf("%s\n", __func__);

	pmap_release(&xio->p);

	vmem_destroy(xio->vmem);

	beri_iommu_set_base(0);

	return (0);
}
