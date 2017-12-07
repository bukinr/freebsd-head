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
#include <sys/pmc.h>
#include <sys/pmckern.h>
#include <sys/systm.h>
#include <sys/ioccom.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/conf.h>
#include <sys/module.h>
#include <sys/mman.h>
#include <sys/proc.h>
#include <sys/vmem.h>
#include <sys/vmmeter.h>
#include <sys/bus.h>
#include <sys/kthread.h>
#include <sys/pmclog.h>

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
#include <machine/specialreg.h>

#include <dev/hwpmc/hwpmc_vm.h>

#include <x86/apicvar.h>
#include <x86/x86_var.h>

static MALLOC_DEFINE(M_PT, "pt", "PT driver");

extern struct cdev *pmc_cdev[MAXCPU];

/*
 * Intel PT support.
 */

#define	PT_CAPS	(PMC_CAP_READ | PMC_CAP_INTERRUPT | PMC_CAP_SYSTEM | PMC_CAP_USER)

#define	PMC_PT_DEBUG
#undef	PMC_PT_DEBUG

#ifdef	PMC_PT_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

struct pt_descr {
	struct pmc_descr pm_descr;  /* "base class" */
};

static struct pt_descr pt_pmcdesc[PT_NPMCS] =
{
    {
	.pm_descr =
	{
		.pd_name  = "PT",
		.pd_class = PMC_CLASS_PT,
		.pd_caps  = PT_CAPS,
		.pd_width = 64
	}
    }
};

/*
 * Per-CPU data structure for PTs.
 */

struct pt_cpu {
	struct pt_save_area		test_area;

	uint64_t			reserved[512];

	struct pmc_hw			tc_hw;
	uint32_t			l0_eax;
	uint32_t			l0_ebx;
	uint32_t			l0_ecx;
	uint32_t			l1_eax;
	uint32_t			l1_ebx;
	struct pmc			*pm_mmap;
	uint32_t			flags;
#define	FLAG_PT_ALLOCATED		(1 << 0)
} __aligned(PAGE_SIZE);

static struct pt_cpu **pt_pcpu;

static int
pt_save_restore(struct pt_cpu *pt_pc, int save)
{
	uint64_t xsave_mask;
	uint64_t val;
	u_int cp[4];
	uint64_t reg;

	cpuid_count(0xd, 0x1, cp);
	printf("enumerate 0xD, 1: %x\n", cp[0]);

	cpuid_count(0xd, 0x0, cp);
	xsave_mask = XFEATURE_ENABLED_X87 | XFEATURE_ENABLED_SSE;
	if ((cp[0] & xsave_mask) != xsave_mask)
		panic("PT: CPU0 does not support X87 or SSE: %x", cp[0]);

	load_cr4(rcr4() | CR4_XSAVE);
	wrmsr(MSR_IA32_XSS, 0x100);

	clts();

	val = rxcr(XCR0);
	load_xcr(XCR0, xsave_mask);
	if (save)
		pt_save(&pt_pc->test_area, 0x100);
	else {
		reg = rdmsr(MSR_IA32_RTIT_CTL);
		if (reg & RTIT_CTL_TRACEEN)
			panic("pt is enabled ?\n");
		pt_restore(&pt_pc->test_area, 0x100);
	}
	load_xcr(XCR0, val);
	load_cr0(rcr0() | CR0_TS);

	return (0);
}


static int
pt_buffer_allocate(uint32_t cpu, struct pt_buffer *pt_buf)
{
	struct pmc_vm_map *map;
	struct pt_cpu *pt_pc;
	uint64_t topa_size;
	uint64_t segsize;
	uint64_t offset;
	uint32_t size;
	uint32_t bufsize;
	struct cdev_cpu *cc;
	vm_object_t obj;
	vm_page_t m;
	int npages;
	int ntopa;
	int req;
	int i, j;

	pt_pc = pt_pcpu[cpu];

	bufsize = 128 * 1024 * 1024;

	if (pt_pc->l0_ecx & CPUPT_TOPA_MULTI)
		topa_size = TOPA_SIZE_4K;
	else
		topa_size = TOPA_SIZE_128M;

	segsize = PAGE_SIZE << (topa_size >> TOPA_SIZE_S);
	ntopa = bufsize / segsize;
	npages = segsize / PAGE_SIZE;

	pt_buf->obj = obj = vm_pager_allocate(OBJT_PHYS, 0, bufsize,
	    PROT_READ, 0, curthread->td_ucred);

	size = roundup2((ntopa + 1) * 8, PAGE_SIZE);
	pt_buf->topa_hw = malloc(size, M_PT, M_WAITOK | M_ZERO);
	pt_buf->topa_sw = malloc(ntopa * sizeof(struct topa_entry), M_PT,
	    M_WAITOK | M_ZERO);

	VM_OBJECT_WLOCK(obj);
	vm_object_reference_locked(obj);
	offset = 0;
	for (i = 0; i < ntopa; i++) {
		req = VM_ALLOC_NOBUSY | VM_ALLOC_ZERO;
		if (npages == 1)
			m = vm_page_alloc(obj, i, req);
		else
			m = vm_page_alloc_contig(obj, i, req, npages, 0, ~0,
			    bufsize, 0, VM_MEMATTR_DEFAULT);
		if (m == NULL) {
			VM_OBJECT_WUNLOCK(obj);
			printf("%s: Can't alloc page %d\n", __func__, i);
			goto error;
		}
		for (j = 0; j < npages; j++)
			m[j].valid = VM_PAGE_BITS_ALL;
		pt_buf->topa_sw[i].size = segsize;
		pt_buf->topa_sw[i].offset = offset;
		pt_buf->topa_hw[i] = VM_PAGE_TO_PHYS(m) | topa_size;
		if (i == (ntopa - 1))
			pt_buf->topa_hw[i] |= TOPA_INT;

		offset += segsize;
	}
	VM_OBJECT_WUNLOCK(obj);

	/* The last entry is a pointer to the base table. */
	pt_buf->topa_hw[ntopa] = vtophys(pt_buf->topa_hw) | TOPA_END;
	pt_buf->cycle = 0;

	map = malloc(sizeof(struct pmc_vm_map), M_PT, M_WAITOK | M_ZERO);
	map->t = curthread;
	map->obj = obj;
	map->pt_buf = pt_buf;

	cc = pmc_cdev[cpu]->si_drv1;

	mtx_lock(&cc->vm_mtx);
	TAILQ_INSERT_HEAD(&cc->pmc_maplist, map, map_next);
	mtx_unlock(&cc->vm_mtx);

	return (0);

error:
	free(pt_buf->topa_hw, M_PT);
	free(pt_buf->topa_sw, M_PT);
	vm_object_deallocate(obj);

	return (-1);
}

static int
pt_buffer_deallocate(uint32_t cpu, struct pt_buffer *pt_buf)
{
	struct pmc_vm_map *map, *map_tmp;
	struct cdev_cpu *cc;

	cc = pmc_cdev[cpu]->si_drv1;

	mtx_lock(&cc->vm_mtx);
	TAILQ_FOREACH_SAFE(map, &cc->pmc_maplist, map_next, map_tmp) {
		if (map->pt_buf == pt_buf) {
			TAILQ_REMOVE(&cc->pmc_maplist, map, map_next);
			free(map, M_PT);
			break;
		}
	}
	mtx_unlock(&cc->vm_mtx);

	free(pt_buf->topa_hw, M_PT);
	free(pt_buf->topa_sw, M_PT);
	vm_object_deallocate(pt_buf->obj);

	return (0);
}

static int
pt_buffer_prepare(uint32_t cpu, struct pmc *pm,
    const struct pmc_op_pmcallocate *a)
{
	struct pt_cpu *pt_pc;
	const struct pmc_md_pt_op_pmcallocate *pm_pta;
	struct pmc_md_pt_pmc *pm_pt;
	struct pt_buffer *pt_buf;
	int nranges;
	int error;
	int n;
	enum pmc_mode mode;
	struct xsave_header *hdr;
	struct pt_ext_area *pt_ext;
	struct pt_save_area *test_area;

	pt_pc = pt_pcpu[cpu];
	if ((pt_pc->l0_ecx & CPUPT_TOPA) == 0)
		return (ENXIO);	/* We rely on TOPA support */

	mode = PMC_TO_MODE(pm);

	pm_pta = (const struct pmc_md_pt_op_pmcallocate *)&a->pm_md.pm_pt;
	pm_pt = (struct pmc_md_pt_pmc *)&pm->pm_md;
	pt_buf = &pm_pt->pt_buffers[cpu];

	test_area = &pt_pc->test_area;
	bzero(test_area, sizeof(struct pt_save_area));

	hdr = &test_area->header;
	hdr->xsave_bv = 0x100;
	hdr->xcomp_bv = 0x100 | (1ULL << 63);

	pt_ext = &test_area->pt_ext_area;

	error = pt_buffer_allocate(cpu, pt_buf);
	if (error != 0) {
		dprintf("%s: can't allocate buffers\n", __func__);
		return (EINVAL);
	}

	pt_ext->rtit_ctl = RTIT_CTL_TOPA | RTIT_CTL_TRACEEN;
	pt_ext->rtit_output_base = (uint64_t)vtophys(pt_buf->topa_hw);
	pt_ext->rtit_output_mask_ptrs = 0x7f;

	if (pt_pc->l0_ebx & CPUPT_IPF) {
		/* How many ranges CPU does support ? */
		nranges = (pt_pc->l1_eax & CPUPT_NADDR_M) >> CPUPT_NADDR_S;

		/* xsave/xrstor supports two ranges only */
		if (nranges > 2)
			nranges = 2;

		n = pm_pta->addrn > nranges ? nranges : pm_pta->addrn;

		switch (n) {
		case 2:
			pt_ext->rtit_ctl |= (1UL << RTIT_CTL_ADDR_CFG_S(1));
			pt_ext->rtit_addr1_a = pm_pta->addra[1];
			pt_ext->rtit_addr1_b = pm_pta->addrb[1];
		case 1:
			pt_ext->rtit_ctl |= (1UL << RTIT_CTL_ADDR_CFG_S(0));
			pt_ext->rtit_addr0_a = pm_pta->addra[0];
			pt_ext->rtit_addr0_b = pm_pta->addrb[0];
		default:
			break;
		};
	}

	/*
	 * TODO
	 * if (sc->l0_ebx & CPUPT_PRW) {
	 *     reg |= RTIT_CTL_FUPONPTW;
	 *     reg |= RTIT_CTL_PTWEN;
	 * }
	 */

	if (mode == PMC_MODE_ST)
		pt_ext->rtit_ctl |= RTIT_CTL_OS;
	else if (mode == PMC_MODE_TT)
		pt_ext->rtit_ctl |= RTIT_CTL_USER;
	else {
		dprintf("%s: unsupported mode %d\n", __func__, mode);
		return (-1);
	}

	/* Enable FUP, TIP, TIP.PGE, TIP.PGD, TNT, MODE.Exec and MODE.TSX packets */
	if (pm_pta->flags & INTEL_PT_FLAG_BRANCHES)
		pt_ext->rtit_ctl |= RTIT_CTL_BRANCHEN;

	if (pm_pta->flags & INTEL_PT_FLAG_TSC)
		pt_ext->rtit_ctl |= RTIT_CTL_TSCEN;

	if ((pt_pc->l0_ebx & CPUPT_MTC) &&
	    (pm_pta->flags & INTEL_PT_FLAG_MTC))
		pt_ext->rtit_ctl |= RTIT_CTL_MTCEN;

	if (pm_pta->flags & INTEL_PT_FLAG_DISRETC)
		pt_ext->rtit_ctl |= RTIT_CTL_DISRETC;

	/*
	 * TODO: specify MTC frequency
	 * Note: Check Bitmap of supported MTC Period Encodings
	 * pt_ext->rtit_ctl |= RTIT_CTL_MTC_FREQ(6);
	 */

	return (0);
}

static int
pt_allocate_pmc(int cpu, int ri, struct pmc *pm,
    const struct pmc_op_pmcallocate *a)
{
	struct pt_cpu *pt_pc;
	int i;

	if ((cpu_stdext_feature & CPUID_STDEXT_PROCTRACE) == 0)
		return (ENXIO);

	pt_pc = pt_pcpu[cpu];

	dprintf("%s: curthread %lx, cpu %d (curcpu %d)\n", __func__,
	    (uint64_t)curthread, cpu, PCPU_GET(cpuid));
	dprintf("%s: cpu %d (curcpu %d)\n", __func__,
	    cpu, PCPU_GET(cpuid));

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[pt,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri >= 0 && ri < PT_NPMCS,
	    ("[pt,%d] illegal row index %d", __LINE__, ri));

	if (a->pm_class != PMC_CLASS_PT)
		return (EINVAL);

	if (a->pm_ev != PMC_EV_PT_PT)
		return (EINVAL);

	if ((pm->pm_caps & PT_CAPS) == 0)
		return (EINVAL);

	if ((pm->pm_caps & ~PT_CAPS) != 0)
		return (EPERM);

	if (a->pm_mode != PMC_MODE_ST &&
	    a->pm_mode != PMC_MODE_TT)
		return (EINVAL);

	/* Can't allocate multiple ST */
	if (a->pm_mode == PMC_MODE_ST &&
	    pt_pc->flags & FLAG_PT_ALLOCATED) {
		dprintf("error: pt is already allocated for CPU %d\n", cpu);
		return (EUSERS);
	}

	if (a->pm_mode == PMC_MODE_TT)
		for (i = 0; i < pmc_cpu_max(); i++) {
			if (pt_buffer_prepare(i, pm, a))
				return (EINVAL);
		}
	else
		if (pt_buffer_prepare(cpu, pm, a))
			return (EINVAL);

	if (a->pm_mode == PMC_MODE_ST)
		pt_pc->flags |= FLAG_PT_ALLOCATED;

	return (0);
}

int
pmc_pt_intr(int cpu, struct trapframe *tf)
{
	struct pmc_md_pt_pmc *pm_pt;
	struct pt_buffer *pt_buf;
	struct pt_cpu *pt_pc;
	struct pmc_hw *phw;
	struct pmc *pm;

	if (pt_pcpu == NULL)
		return (0);

	pt_pc = pt_pcpu[cpu];
	if (pt_pc == NULL)
		return (0);

	phw = &pt_pc->tc_hw;
	if (phw == NULL || phw->phw_pmc == NULL)
		return (0);

	pm = phw->phw_pmc;
	if (pm == NULL)
		return (0);

	KASSERT(pm != NULL, ("pm is NULL\n"));

	pm_pt = (struct pmc_md_pt_pmc *)&pm->pm_md;
	pt_buf = &pm_pt->pt_buffers[cpu];

	atomic_add_long(&pt_buf->cycle, 1);

	lapic_reenable_pmc();

	return (1);
}

static int
pt_config_pmc(int cpu, int ri, struct pmc *pm)
{
	struct pt_cpu *pt_pc;
	struct pmc_hw *phw;

	dprintf("%s: cpu %d (pm %lx)\n", __func__, cpu, (uint64_t)pm);

	PMCDBG3(MDP,CFG,1, "cpu=%d ri=%d pm=%p", cpu, ri, pm);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[pt,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[pt,%d] illegal row-index %d", __LINE__, ri));

	pt_pc = pt_pcpu[cpu];
	phw = &pt_pc->tc_hw;

	KASSERT(pm == NULL || phw->phw_pmc == NULL,
	    ("[pt,%d] pm=%p phw->pm=%p hwpmc not unconfigured", __LINE__,
	    pm, phw->phw_pmc));

	phw->phw_pmc = pm;

	return (0);
}

static int
pt_describe(int cpu, int ri, struct pmc_info *pi, struct pmc **ppmc)
{
	const struct pt_descr *pd;
	struct pmc_hw *phw;
	size_t copied;
	int error;

	dprintf("%s\n", __func__);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[pt,%d] illegal CPU %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[pt,%d] illegal row-index %d", __LINE__, ri));

	phw = &pt_pcpu[cpu]->tc_hw;
	pd  = &pt_pmcdesc[ri];

	if ((error = copystr(pd->pm_descr.pd_name, pi->pm_name,
	    PMC_NAME_MAX, &copied)) != 0)
		return (error);

	pi->pm_class = pd->pm_descr.pd_class;

	if (phw->phw_state & PMC_PHW_FLAG_IS_ENABLED) {
		pi->pm_enabled = TRUE;
		*ppmc          = phw->phw_pmc;
	} else {
		pi->pm_enabled = FALSE;
		*ppmc          = NULL;
	}

	return (0);
}

static int
pt_get_config(int cpu, int ri, struct pmc **ppm)
{
	struct pmc_hw *phw;
	struct pt_cpu *pt_pc;

	dprintf("%s\n", __func__);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[pt,%d] illegal CPU %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[pt,%d] illegal row-index %d", __LINE__, ri));

	pt_pc = pt_pcpu[cpu];
	phw = &pt_pc->tc_hw;

	*ppm = phw->phw_pmc;

	return (0);
}

static void
pt_enumerate(struct pt_cpu *pt_pc)
{
	u_int cp[4];
	u_int *eax;
	u_int *ebx;
	u_int *ecx;

	eax = &cp[0];
	ebx = &cp[1];
	ecx = &cp[2];

	dprintf("Enumerating part 1\n");

	cpuid_count(PT_CPUID, 0, cp);
	dprintf("%s: Maximum valid sub-leaf Index: %x\n", __func__, cp[0]);
	dprintf("%s: ebx %x\n", __func__, cp[1]);
	dprintf("%s: ecx %x\n", __func__, cp[2]);

	pt_pc->l0_eax = cp[0];
	pt_pc->l0_ebx = cp[1];
	pt_pc->l0_ecx = cp[2];

	dprintf("Enumerating part 2\n");

	cpuid_count(PT_CPUID, 1, cp);
	dprintf("%s: eax %x\n", __func__, cp[0]);
	dprintf("%s: ebx %x\n", __func__, cp[1]);

	pt_pc->l1_eax = cp[0];
	pt_pc->l1_ebx = cp[1];
}

static int
pt_pcpu_init(struct pmc_mdep *md, int cpu)
{
	struct pmc_cpu *pc;
	struct pt_cpu *pt_pc;
	int ri;

	dprintf("%s: cpu %d\n", __func__, cpu);

	KASSERT(cpu == PCPU_GET(cpuid), ("Init on wrong CPU\n"));

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[pt,%d] illegal cpu %d", __LINE__, cpu));
	KASSERT(pt_pcpu, ("[pt,%d] null pcpu", __LINE__));
	KASSERT(pt_pcpu[cpu] == NULL, ("[pt,%d] non-null per-cpu",
	    __LINE__));

	pt_pc = malloc(sizeof(struct pt_cpu), M_PT, M_WAITOK | M_ZERO);

	pt_pc->tc_hw.phw_state = PMC_PHW_FLAG_IS_ENABLED |
	    PMC_PHW_CPU_TO_STATE(cpu) | PMC_PHW_INDEX_TO_STATE(0) |
	    PMC_PHW_FLAG_IS_SHAREABLE;

	pt_pcpu[cpu] = pt_pc;

	ri = md->pmd_classdep[PMC_MDEP_CLASS_INDEX_PT].pcd_ri;

	KASSERT(pmc_pcpu, ("[pt,%d] null generic pcpu", __LINE__));

	pc = pmc_pcpu[cpu];

	KASSERT(pc, ("[pt,%d] null generic per-cpu", __LINE__));

	pc->pc_hwpmcs[ri] = &pt_pc->tc_hw;

	pt_enumerate(pt_pc);

	return (0);
}

static int
pt_pcpu_fini(struct pmc_mdep *md, int cpu)
{
	int ri;
	struct pmc_cpu *pc;
	struct pt_cpu *pt_pc;

	dprintf("%s: cpu %d\n", __func__, cpu);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[pt,%d] illegal cpu %d", __LINE__, cpu));
	KASSERT(pt_pcpu[cpu] != NULL, ("[pt,%d] null pcpu", __LINE__));

	pt_pc = pt_pcpu[cpu];

	free(pt_pcpu[cpu], M_PT);
	pt_pcpu[cpu] = NULL;

	ri = md->pmd_classdep[PMC_MDEP_CLASS_INDEX_PT].pcd_ri;

	pc = pmc_pcpu[cpu];
	pc->pc_hwpmcs[ri] = NULL;

	return (0);
}

static __inline void
xsave(char *addr, uint64_t mask)
{
	uint32_t low, hi;

	low = mask;
	hi = mask >> 32;
	__asm __volatile("xsave %0" : "=m" (*addr) : "a" (low), "d" (hi) :
	    "memory");
}

static int
pt_configure_ranges(struct pt_cpu *pt_pc,
    struct pmc_trace_filter_ip_range *ranges, uint32_t nranges)
{

	return (0);
}

static int
pt_trace_config(int cpu, int ri, struct pmc *pm,
    struct pmc_trace_filter_ip_range *ranges, uint32_t nranges)
{
	struct pt_buffer *pt_buf;
	struct pmc_md_pt_pmc *pm_pt;
	struct pt_cpu *pt_pc;
	uint64_t reg;

	struct pt_ext_area *pt_ext;
	struct pt_save_area *test_area;

	pt_pc = pt_pcpu[cpu];
	test_area = &pt_pc->test_area;
	pt_ext = &test_area->pt_ext_area;

	KASSERT(cpu == PCPU_GET(cpuid), ("Configuring wrong CPU\n"));

	dprintf("%s\n", __func__);
	
	pm_pt = (struct pmc_md_pt_pmc *)&pm->pm_md;
	pt_buf = &pm_pt->pt_buffers[cpu];

	/* Ensure tracing is turned off */
	reg = rdmsr(MSR_IA32_RTIT_CTL);
	if (reg & RTIT_CTL_TRACEEN)
		pt_save_restore(pt_pc, 1);

	pt_configure_ranges(pt_pc, ranges, nranges);

	int nranges_supp;
	int n;

	if (pt_pc->l0_ebx & CPUPT_IPF) {
		/* How many ranges CPU does support ? */
		nranges_supp = (pt_pc->l1_eax & CPUPT_NADDR_M) >> CPUPT_NADDR_S;

		/* xsave/xrstor supports two ranges only */
		if (nranges_supp > 2)
			nranges_supp = 2;

		n = nranges > nranges_supp ? nranges_supp : nranges;

		switch (n) {
		case 2:
			pt_ext->rtit_ctl |= (1UL << RTIT_CTL_ADDR_CFG_S(1));
			pt_ext->rtit_addr1_a = ranges[1].addra;
			pt_ext->rtit_addr1_b = ranges[1].addrb;
		case 1:
			pt_ext->rtit_ctl |= (1UL << RTIT_CTL_ADDR_CFG_S(0));
			pt_ext->rtit_addr0_a = ranges[0].addra;
			pt_ext->rtit_addr0_b = ranges[0].addrb;
		default:
			break;
		};
	}

	return (0);
}

static int
pt_read_trace(int cpu, int ri, struct pmc *pm,
    pmc_value_t *cycle, pmc_value_t *voffset)
{
	struct pt_ext_area *pt_ext;
	struct pt_save_area *test_area;
	struct pmc_md_pt_pmc *pm_pt;
	struct pt_buffer *pt_buf;
	struct pt_cpu *pt_pc;
	uint64_t offset;
	uint64_t reg;
	uint32_t idx;

	pt_pc = pt_pcpu[cpu];
	pt_pc->pm_mmap = pm;

	pm_pt = (struct pmc_md_pt_pmc *)&pm->pm_md;
	pt_buf = &pm_pt->pt_buffers[cpu];

	test_area = &pt_pc->test_area;
	pt_ext = &test_area->pt_ext_area;

	reg = rdmsr(MSR_IA32_RTIT_CTL);
	if (reg & RTIT_CTL_TRACEEN)
		reg = rdmsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS);
	else
		reg = pt_ext->rtit_output_mask_ptrs;

	idx = (reg & 0xffffffff) >> 7;
	*cycle = pt_buf->cycle;

	offset = reg >> 32;
	*voffset = pt_buf->topa_sw[idx].offset + offset;

	dprintf("%s: %lx\n", __func__, rdmsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS));
	dprintf("%s: cycle %ld offset %ld\n", __func__, pt_buf->cycle, offset);

	return (0);
}

static int
pt_read_pmc(int cpu, int ri, pmc_value_t *v)
{

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[pt,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[pt,%d] illegal ri %d", __LINE__, ri));

	*v = 0;

	return (0);
}

static int
pt_release_pmc(int cpu, int ri, struct pmc *pm)
{
	struct pmc_md_pt_pmc *pm_pt;
	struct pt_cpu *pt_pc;
	enum pmc_mode mode;
	struct pmc_hw *phw;
	int i;

	pm_pt = (struct pmc_md_pt_pmc *)&pm->pm_md;
	pt_pc = pt_pcpu[cpu];

	dprintf("%s: cpu %d (curcpu %d)\n", __func__, cpu, PCPU_GET(cpuid));

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[pt,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0,
	    ("[pt,%d] illegal row-index %d", __LINE__, ri));

	phw = &pt_pcpu[cpu]->tc_hw;
	phw->phw_pmc = NULL;

	KASSERT(phw->phw_pmc == NULL,
	    ("[pt,%d] PHW pmc %p non-NULL", __LINE__, phw->phw_pmc));

	dprintf("%s: cpu %d, output base %lx\n",
	    __func__, cpu, rdmsr(MSR_IA32_RTIT_OUTPUT_BASE));
	dprintf("%s: cpu %d, output base ptr %lx\n",
	    __func__, cpu, rdmsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS));

	mode = PMC_TO_MODE(pm);
	if (mode == PMC_MODE_TT)
		for (i = 0; i < pmc_cpu_max(); i++)
			pt_buffer_deallocate(i, &pm_pt->pt_buffers[i]);
	else
		pt_buffer_deallocate(cpu, &pm_pt->pt_buffers[cpu]);

	if (mode == PMC_MODE_ST)
		pt_pc->flags &= ~FLAG_PT_ALLOCATED;

	return (0);
}

static int
pt_start_pmc(int cpu, int ri)
{
	struct pmc_md_pt_pmc *pm_pt;
	struct pt_cpu *pt_pc;
	struct pt_buffer *pt_buf;
	struct pmc_hw *phw;
	struct pmc *pm;

	dprintf("%s: cpu %d (curcpu %d)\n", __func__, cpu, PCPU_GET(cpuid));

	pt_pc = pt_pcpu[cpu];
	phw = &pt_pc->tc_hw;
	if (phw == NULL || phw->phw_pmc == NULL)
		return (-1);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[pt,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[pt,%d] illegal row-index %d", __LINE__, ri));

	pm = phw->phw_pmc;
	pm_pt = (struct pmc_md_pt_pmc *)&pm->pm_md;
	pt_buf = &pm_pt->pt_buffers[cpu];

	pt_save_restore(pt_pc, 0);

	return (0);
}

static int
pt_stop_pmc(int cpu, int ri)
{
	struct pt_cpu *pt_pc;

	pt_pc = pt_pcpu[cpu];

	dprintf("%s: cpu %d, output base %lx, ptr %lx\n", __func__, cpu,
	    rdmsr(MSR_IA32_RTIT_OUTPUT_BASE),
	    rdmsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS));

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[pt,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[pt,%d] illegal row-index %d", __LINE__, ri));

	/*
	 * Save the PT state to memory.
	 * This operation will disable tracing.
	 */
	pt_save_restore(pt_pc, 1);

	return (0);
}

static int
pt_write_pmc(int cpu, int ri, pmc_value_t v)
{

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[pt,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[pt,%d] illegal row-index %d", __LINE__, ri));

	return (0);
}

int
pmc_pt_initialize(struct pmc_mdep *md, int maxcpu)
{
	struct pmc_classdep *pcd;

	dprintf("%s\n", __func__);

	KASSERT(md != NULL, ("[pt,%d] md is NULL", __LINE__));
	KASSERT(md->pmd_nclass >= 1, ("[pt,%d] dubious md->nclass %d",
	    __LINE__, md->pmd_nclass));

	pt_pcpu = malloc(sizeof(struct pt_cpu *) * maxcpu, M_PT,
	    M_WAITOK | M_ZERO);

	pcd = &md->pmd_classdep[PMC_MDEP_CLASS_INDEX_PT];

	pcd->pcd_caps	= PT_CAPS;
	pcd->pcd_class	= PMC_CLASS_PT;
	pcd->pcd_num	= PT_NPMCS;
	pcd->pcd_ri	= md->pmd_npmc;
	pcd->pcd_width	= 64;

	pcd->pcd_allocate_pmc = pt_allocate_pmc;
	pcd->pcd_config_pmc   = pt_config_pmc;
	pcd->pcd_describe     = pt_describe;
	pcd->pcd_get_config   = pt_get_config;
	pcd->pcd_pcpu_init    = pt_pcpu_init;
	pcd->pcd_pcpu_fini    = pt_pcpu_fini;
	pcd->pcd_read_pmc     = pt_read_pmc;
	pcd->pcd_read_trace   = pt_read_trace;
	pcd->pcd_trace_config = pt_trace_config;
	pcd->pcd_release_pmc  = pt_release_pmc;
	pcd->pcd_start_pmc    = pt_start_pmc;
	pcd->pcd_stop_pmc     = pt_stop_pmc;
	pcd->pcd_write_pmc    = pt_write_pmc;

	md->pmd_npmc += PT_NPMCS;

	return (0);
}

void
pmc_pt_finalize(struct pmc_mdep *md)
{

	dprintf("%s\n", __func__);

#ifdef	INVARIANTS
	int i, ncpus;

	ncpus = pmc_cpu_max();
	for (i = 0; i < ncpus; i++)
		KASSERT(pt_pcpu[i] == NULL, ("[pt,%d] non-null pcpu cpu %d",
		    __LINE__, i));

	KASSERT(md->pmd_classdep[PMC_MDEP_CLASS_INDEX_PT].pcd_class ==
	    PMC_CLASS_PT, ("[pt,%d] class mismatch", __LINE__));
#endif

	free(pt_pcpu, M_PT);
	pt_pcpu = NULL;
}
