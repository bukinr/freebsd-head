/*-
 * Copyright (c) 2018 Ruslan Bukin <br@bsdpad.com>
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

#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/bus.h>
#include <sys/rman.h>

#include <arm64/coresight/coresight.h>
#include <arm64/coresight/etm4x.h>

#include <dev/hwpmc/hwpmc_vm.h>

#include "tmc_if.h"
#include "etm_if.h"

static MALLOC_DEFINE(M_ETM, "etm", "ETM driver");

extern struct cdev *pmc_cdev[MAXCPU];

/*
 * ARM ETM support.
 */

#define	ETM_CAPS	(PMC_CAP_READ | PMC_CAP_INTERRUPT | PMC_CAP_SYSTEM | PMC_CAP_USER)

#define	PMC_ETM_DEBUG
#undef	PMC_ETM_DEBUG

#ifdef	PMC_ETM_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

struct etm_descr {
	struct pmc_descr pm_descr;  /* "base class" */
};

static struct etm_descr etm_pmcdesc[ETM_NPMCS] =
{
    {
	.pm_descr =
	{
		.pd_name  = "ETM",
		.pd_class = PMC_CLASS_ETM,
		.pd_caps  = ETM_CAPS,
		.pd_width = 64
	}
    }
};

/*
 * Per-CPU data structure for PTs.
 */

struct etm_cpu {
	struct pmc_hw			tc_hw;
	uint32_t			l0_eax;
	uint32_t			l0_ebx;
	uint32_t			l0_ecx;
	uint32_t			l1_eax;
	uint32_t			l1_ebx;
	struct pmc			*pm_mmap;
	uint32_t			flags;
#define	FLAG_ETM_ALLOCATED		(1 << 0)
	struct etm_save_area		save_area;
	device_t			dev_etr;
	device_t			dev_etf;
	device_t			dev_etm;
	struct coresight_event		event;
};

static struct etm_cpu **etm_pcpu;

#if 0
static __inline void
xrstors(char *addr, uint64_t mask)
{
	uint32_t low, hi;

	low = mask;
	hi = mask >> 32;
	__asm __volatile("xrstors %0" : : "m" (*addr), "a" (low), "d" (hi));
}

static __inline void
xsaves(char *addr, uint64_t mask)
{
	uint32_t low, hi;

	low = mask;
	hi = mask >> 32;
	__asm __volatile("xsaves %0" : "=m" (*addr) : "a" (low), "d" (hi) :
	    "memory");
}
#endif

static void
etm_save_restore(struct etm_cpu *etm_pc, bool save)
{
#if 0
	uint64_t val;

	clts();
	val = rxcr(XCR0);
	load_xcr(XCR0, etm_xsave_mask);
	wrmsr(MSR_IA32_XSS, XFEATURE_ENABLED_ETM);
	if (save) {
		KASSERT((rdmsr(MSR_IA32_RTIT_CTL) & RTIT_CTL_TRACEEN) != 0,
		    ("%s: PT is disabled", __func__));
		xsaves((char *)&etm_pc->save_area, XFEATURE_ENABLED_ETM);
	} else {
		KASSERT((rdmsr(MSR_IA32_RTIT_CTL) & RTIT_CTL_TRACEEN) == 0,
		    ("%s: PT is enabled", __func__));
		xrstors((char *)&etm_pc->save_area, XFEATURE_ENABLED_ETM);
	}
	load_xcr(XCR0, val);
	load_cr0(rcr0() | CR0_TS);
#endif
}

#if 0
static void
etm_configure_ranges(struct etm_cpu *etm_pc, const uint64_t *ranges,
    uint32_t nranges)
{
	struct etm_ext_area *etm_ext;
	struct etm_save_area *save_area;
	int nranges_supp;
	int n;

	save_area = &etm_pc->save_area;
	etm_ext = &save_area->etm_ext_area;

	if (etm_pc->l0_ebx & CPUETM_IPF) {
		/* How many ranges CPU does support ? */
		nranges_supp = (etm_pc->l1_eax & CPUETM_NADDR_M) >> CPUETM_NADDR_S;

		/* xsave/xrstor supports two ranges only */
		if (nranges_supp > 2)
			nranges_supp = 2;

		n = nranges > nranges_supp ? nranges_supp : nranges;

		switch (n) {
		case 2:
			etm_ext->rtit_ctl |= (1UL << RTIT_CTL_ADDR_CFG_S(1));
			etm_ext->rtit_addr1_a = ranges[2];
			etm_ext->rtit_addr1_b = ranges[3];
		case 1:
			etm_ext->rtit_ctl |= (1UL << RTIT_CTL_ADDR_CFG_S(0));
			etm_ext->rtit_addr0_a = ranges[0];
			etm_ext->rtit_addr0_b = ranges[1];
		default:
			break;
		};
	}
}
#endif

static int
etm_buffer_allocate(uint32_t cpu, struct etm_buffer *etm_buf,
    uint32_t bufsize)
{
	struct pmc_vm_map *map;
	struct etm_cpu *etm_pc;
	uint64_t phys_base;
	struct cdev_cpu *cc;
	vm_object_t obj;
	vm_page_t m;
	int npages;
	int i;

	printf("%s\n", __func__);

	etm_pc = etm_pcpu[cpu];

	etm_buf->obj = obj = vm_pager_allocate(OBJT_PHYS, 0, bufsize,
	    PROT_READ, 0, curthread->td_ucred);

	npages = bufsize / PAGE_SIZE;

	VM_OBJECT_WLOCK(obj);
	vm_object_reference_locked(obj);
	m = vm_page_alloc_contig(obj, 0, VM_ALLOC_NOBUSY | VM_ALLOC_ZERO,
	    npages, 0, ~0, PAGE_SIZE, 0, VM_MEMATTR_DEFAULT);
	if (m == NULL) {
		VM_OBJECT_WUNLOCK(obj);
		printf("%s: Can't allocate memory.\n", __func__);
		vm_object_deallocate(obj);
		return (-1);
	}
	for (i = 0; i < npages; i++)
		m[i].valid = VM_PAGE_BITS_ALL;
	phys_base = VM_PAGE_TO_PHYS(m);
	VM_OBJECT_WUNLOCK(obj);

	map = malloc(sizeof(struct pmc_vm_map), M_ETM, M_WAITOK | M_ZERO);
	map->t = curthread;
	map->obj = obj;
	map->buf = (void *)etm_buf;

	cc = pmc_cdev[cpu]->si_drv1;

	mtx_lock(&cc->vm_mtx);
	TAILQ_INSERT_HEAD(&cc->pmc_maplist, map, map_next);
	mtx_unlock(&cc->vm_mtx);

	etm_buf->phys_base = phys_base;
	etm_buf->cycle = 0;

	return (0);
}

static int
etm_buffer_deallocate(uint32_t cpu, struct etm_buffer *etm_buf)
{
	struct pmc_vm_map *map, *map_tmp;
	struct cdev_cpu *cc;

	cc = pmc_cdev[cpu]->si_drv1;

	printf("%s\n", __func__);

	mtx_lock(&cc->vm_mtx);
	TAILQ_FOREACH_SAFE(map, &cc->pmc_maplist, map_next, map_tmp) {
		if (map->buf == (void *)etm_buf) {
			TAILQ_REMOVE(&cc->pmc_maplist, map, map_next);
			free(map, M_ETM);
			break;
		}
	}
	mtx_unlock(&cc->vm_mtx);

	vm_object_deallocate(etm_buf->obj);

	return (0);
}

static int
etm_buffer_prepare(uint32_t cpu, struct pmc *pm,
    const struct pmc_op_pmcallocate *a)
{
	const struct pmc_md_etm_op_pmcallocate *pm_etma;
	struct etm_cpu *etm_pc;
	struct pmc_md_etm_pmc *pm_etm;
	struct etm_buffer *etm_buf;
	uint32_t bufsize;
	struct etm_config config;
	enum pmc_mode mode;
	uint32_t phys_lo;
	uint32_t phys_hi;
	int error;
	struct coresight_event *event;

	etm_pc = etm_pcpu[cpu];
	event = &etm_pc->event;

#if 0
	if ((etm_pc->l0_ecx & CPUETM_TOPA) == 0)
		return (ENXIO);	/* We rely on TOPA support */
#endif

	pm_etma = (const struct pmc_md_etm_op_pmcallocate *)&a->pm_md.pm_etm;
	pm_etm = (struct pmc_md_etm_pmc *)&pm->pm_md;
	etm_buf = &pm_etm->etm_buffers[cpu];

	bufsize = 16 * 1024 * 1024;
	error = etm_buffer_allocate(cpu, etm_buf, bufsize);
	if (error != 0) {
		dprintf("%s: can't allocate buffers\n", __func__);
		return (EINVAL);
	}

	phys_lo = etm_buf->phys_base & 0xffffffff;
	phys_hi = (etm_buf->phys_base >> 32) & 0xffffffff;
	config.naddr = 0;
	event->naddr = 0;

	event->low = phys_lo;
	event->high = phys_hi;
	event->rrp = phys_lo;
	event->rwp = phys_lo;

	//TMC_CONFIGURE_ETR(etm_pc->dev_etr, phys_lo, phys_hi, bufsize);

	mode = PMC_TO_MODE(pm);
	if (mode == PMC_MODE_ST) {
		event->excp_level = 1;
		config.excp_level = 1;
	} else if (mode == PMC_MODE_TT) {
		event->excp_level = 0;
		config.excp_level = 0;
	} else {
		dprintf("%s: unsupported mode %d\n", __func__, mode);
		return (-1);
	}

#if 0
	save_area = &etm_pc->save_area;
	bzero(save_area, sizeof(struct etm_save_area));

	hdr = &save_area->header;
	hdr->xsave_bv = XFEATURE_ENABLED_ETM;
	hdr->xcomp_bv = XFEATURE_ENABLED_ETM | (1ULL << 63) /* compaction */;

	etm_ext = &save_area->etm_ext_area;

	etm_ext->rtit_ctl = RTIT_CTL_TOPA | RTIT_CTL_TRACEEN;
	etm_ext->rtit_output_base = (uint64_t)vtophys(etm_buf->topa_hw);
	etm_ext->rtit_output_mask_etmrs = 0x7f;

	etm_configure_ranges(etm_pc, pm_etma->ranges, pm_etma->nranges);

	/* Enable FUP, TIP, TIP.PGE, TIP.PGD, TNT, MODE.Exec and MODE.TSX packets */
	if (pm_etma->flags & INTEL_ETM_FLAG_BRANCHES)
		etm_ext->rtit_ctl |= RTIT_CTL_BRANCHEN;

	if (pm_etma->flags & INTEL_ETM_FLAG_TSC)
		etm_ext->rtit_ctl |= RTIT_CTL_TSCEN;

	if ((etm_pc->l0_ebx & CPUETM_MTC) &&
	    (pm_etma->flags & INTEL_ETM_FLAG_MTC))
		etm_ext->rtit_ctl |= RTIT_CTL_MTCEN;

	if (pm_etma->flags & INTEL_ETM_FLAG_DISRETC)
		etm_ext->rtit_ctl |= RTIT_CTL_DISRETC;

	/*
	 * TODO: specify MTC frequency
	 * Note: Check Bitmap of supported MTC Period Encodings
	 * etm_ext->rtit_ctl |= RTIT_CTL_MTC_FREQ(6);
	 */
#endif

	event->src = CORESIGHT_ETMV4;
	event->sink = CORESIGHT_ETR;
	coresight_prepare(cpu, event);

	return (0);
}

static int
etm_allocate_pmc(int cpu, int ri, struct pmc *pm,
    const struct pmc_op_pmcallocate *a)
{
	struct etm_cpu *etm_pc;
	int i;

#if 0
	if ((cpu_stdext_feature & CPUID_STDEXT_PROCTRACE) == 0)
		return (ENXIO);
#endif

	etm_pc = etm_pcpu[cpu];

	dprintf("%s: curthread %lx, cpu %d (curcpu %d)\n", __func__,
	    (uint64_t)curthread, cpu, PCPU_GET(cpuid));
	dprintf("%s: cpu %d (curcpu %d)\n", __func__,
	    cpu, PCPU_GET(cpuid));

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[etm,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri >= 0 && ri < ETM_NPMCS,
	    ("[etm,%d] illegal row index %d", __LINE__, ri));

	if (a->pm_class != PMC_CLASS_ETM)
		return (EINVAL);

	if (a->pm_ev != PMC_EV_ETM_ETM)
		return (EINVAL);

	if ((pm->pm_caps & ETM_CAPS) == 0)
		return (EINVAL);

	if ((pm->pm_caps & ~ETM_CAPS) != 0)
		return (EPERM);

	if (a->pm_mode != PMC_MODE_ST &&
	    a->pm_mode != PMC_MODE_TT)
		return (EINVAL);

	/* Can't allocate multiple ST */
	if (a->pm_mode == PMC_MODE_ST &&
	    etm_pc->flags & FLAG_ETM_ALLOCATED) {
		dprintf("error: etm is already allocated for CPU %d\n", cpu);
		return (EUSERS);
	}

	if (a->pm_mode == PMC_MODE_TT)
		for (i = 0; i < pmc_cpu_max(); i++) {
			if (etm_buffer_prepare(i, pm, a))
				return (EINVAL);
		}
	else
		if (etm_buffer_prepare(cpu, pm, a))
			return (EINVAL);

	if (a->pm_mode == PMC_MODE_ST)
		etm_pc->flags |= FLAG_ETM_ALLOCATED;

	return (0);
}

#if 0
int
pmc_etm_intr(int cpu, struct trapframe *tf)
{
	struct pmc_md_etm_pmc *pm_etm;
	struct etm_buffer *etm_buf;
	struct etm_cpu *etm_pc;
	struct pmc_hw *phw;
	struct pmc *pm;

	if (etm_pcpu == NULL)
		return (0);

	etm_pc = etm_pcpu[cpu];
	if (etm_pc == NULL)
		return (0);

	phw = &etm_pc->tc_hw;
	if (phw == NULL || phw->phw_pmc == NULL)
		return (0);

	pm = phw->phw_pmc;
	if (pm == NULL)
		return (0);

	KASSERT(pm != NULL, ("pm is NULL\n"));

	pm_etm = (struct pmc_md_etm_pmc *)&pm->pm_md;
	etm_buf = &pm_etm->etm_buffers[cpu];

	atomic_add_long(&etm_buf->cycle, 1);

	lapic_reenable_pmc();

	return (1);
}
#endif

static int
etm_config_pmc(int cpu, int ri, struct pmc *pm)
{
	struct etm_cpu *etm_pc;
	struct pmc_hw *phw;

	dprintf("%s: cpu %d (pm %lx)\n", __func__, cpu, (uint64_t)pm);

	PMCDBG3(MDP,CFG,1, "cpu=%d ri=%d pm=%p", cpu, ri, pm);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[etm,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[etm,%d] illegal row-index %d", __LINE__, ri));

	etm_pc = etm_pcpu[cpu];
	phw = &etm_pc->tc_hw;

	KASSERT(pm == NULL || phw->phw_pmc == NULL,
	    ("[etm,%d] pm=%p phw->pm=%p hwpmc not unconfigured", __LINE__,
	    pm, phw->phw_pmc));

	phw->phw_pmc = pm;

	return (0);
}

static int
etm_describe(int cpu, int ri, struct pmc_info *pi, struct pmc **ppmc)
{
	const struct etm_descr *pd;
	struct pmc_hw *phw;
	size_t copied;
	int error;

	dprintf("%s\n", __func__);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[etm,%d] illegal CPU %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[etm,%d] illegal row-index %d", __LINE__, ri));

	phw = &etm_pcpu[cpu]->tc_hw;
	pd  = &etm_pmcdesc[ri];

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
etm_get_config(int cpu, int ri, struct pmc **ppm)
{
	struct pmc_hw *phw;
	struct etm_cpu *etm_pc;

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[etm,%d] illegal CPU %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[etm,%d] illegal row-index %d", __LINE__, ri));

	etm_pc = etm_pcpu[cpu];
	phw = &etm_pc->tc_hw;

	*ppm = phw->phw_pmc;

	return (0);
}

#if 0
static void
etm_enumerate(struct etm_cpu *etm_pc)
{
	u_int cp[4];
	u_int *eax;
	u_int *ebx;
	u_int *ecx;

	eax = &cp[0];
	ebx = &cp[1];
	ecx = &cp[2];

	dprintf("Enumerating part 1\n");

	cpuid_count(ETM_CPUID, 0, cp);
	dprintf("%s: Maximum valid sub-leaf Index: %x\n", __func__, cp[0]);
	dprintf("%s: ebx %x\n", __func__, cp[1]);
	dprintf("%s: ecx %x\n", __func__, cp[2]);

	etm_pc->l0_eax = cp[0];
	etm_pc->l0_ebx = cp[1];
	etm_pc->l0_ecx = cp[2];

	dprintf("Enumerating part 2\n");

	cpuid_count(ETM_CPUID, 1, cp);
	dprintf("%s: eax %x\n", __func__, cp[0]);
	dprintf("%s: ebx %x\n", __func__, cp[1]);

	etm_pc->l1_eax = cp[0];
	etm_pc->l1_ebx = cp[1];
}
#endif

static int
etm_pcpu_init(struct pmc_mdep *md, int cpu)
{
	struct pmc_cpu *pc;
	struct etm_cpu *etm_pc;
	int ri;

	dprintf("%s: cpu %d\n", __func__, cpu);

	devclass_t etm_devclass, tmc_devclass;
	device_t dev_etm, dev_etr, dev_etf;

	/* Find our ETM device */
	etm_devclass = devclass_find("etm");
	if (etm_devclass == NULL)
		return (ENXIO);
	dev_etm = devclass_get_device(etm_devclass, cpu);
	if (dev_etm == NULL)
		return (ENXIO);

	/* Find our TMC device */
	tmc_devclass = devclass_find("tmc");
	if (tmc_devclass == NULL)
		return (ENXIO);

	dev_etf = devclass_get_device(tmc_devclass, 0);
	if (dev_etf == NULL)
		return (ENXIO);
	dev_etr = devclass_get_device(tmc_devclass, 1);
	if (dev_etr == NULL)
		return (ENXIO);

#if 0
	u_int cp[4];
	/* We rely on XSAVE support */
	if ((cpu_feature2 & CPUID2_XSAVE) == 0) {
		printf("Intel PT: XSAVE is not supported\n");
		return (ENXIO);
	}

	cpuid_count(0xd, 0x0, cp);
	if ((cp[0] & etm_xsave_mask) != etm_xsave_mask) {
		printf("Intel PT: CPU0 does not support X87 or SSE: %x", cp[0]);
		return (ENXIO);
	}

	cpuid_count(0xd, 0x1, cp);
	if ((cp[0] & (1 << 0)) == 0) {
		printf("Intel PT: XSAVE compaction is not supported\n");
		return (ENXIO);
	}

	if ((cp[0] & (1 << 3)) == 0) {
		printf("Intel PT: XSAVES/XRSTORS are not supported\n");
		return (ENXIO);
	}

	/* Enable XSAVE */
	load_cr4(rcr4() | CR4_XSAVE);
#endif

	KASSERT(cpu == PCPU_GET(cpuid), ("Init on wrong CPU\n"));

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[etm,%d] illegal cpu %d", __LINE__, cpu));
	KASSERT(etm_pcpu, ("[etm,%d] null pcpu", __LINE__));
	KASSERT(etm_pcpu[cpu] == NULL, ("[etm,%d] non-null per-cpu",
	    __LINE__));

	etm_pc = malloc(sizeof(struct etm_cpu), M_ETM, M_WAITOK | M_ZERO);
	etm_pc->dev_etm = dev_etm;
	etm_pc->dev_etr = dev_etr;
	etm_pc->dev_etf = dev_etf;

	etm_pc->tc_hw.phw_state = PMC_PHW_FLAG_IS_ENABLED |
	    PMC_PHW_CPU_TO_STATE(cpu) | PMC_PHW_INDEX_TO_STATE(0) |
	    PMC_PHW_FLAG_IS_SHAREABLE;

	etm_pcpu[cpu] = etm_pc;

	ri = md->pmd_classdep[PMC_MDEP_CLASS_INDEX_ETM].pcd_ri;

	KASSERT(pmc_pcpu, ("[etm,%d] null generic pcpu", __LINE__));

	pc = pmc_pcpu[cpu];

	KASSERT(pc, ("[etm,%d] null generic per-cpu", __LINE__));

	pc->pc_hwpmcs[ri] = &etm_pc->tc_hw;

#if 0
	etm_enumerate(etm_pc);
#endif
	return (0);
}

static int
etm_pcpu_fini(struct pmc_mdep *md, int cpu)
{
	int ri;
	struct pmc_cpu *pc;
	struct etm_cpu *etm_pc;

	dprintf("%s: cpu %d\n", __func__, cpu);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[etm,%d] illegal cpu %d", __LINE__, cpu));
	KASSERT(etm_pcpu[cpu] != NULL, ("[etm,%d] null pcpu", __LINE__));

	etm_pc = etm_pcpu[cpu];

	free(etm_pcpu[cpu], M_ETM);
	etm_pcpu[cpu] = NULL;

	ri = md->pmd_classdep[PMC_MDEP_CLASS_INDEX_ETM].pcd_ri;

	pc = pmc_pcpu[cpu];
	pc->pc_hwpmcs[ri] = NULL;

	return (0);
}

static int
etm_trace_config(int cpu, int ri, struct pmc *pm,
    uint64_t *ranges, uint32_t nranges)
{
	struct etm_cpu *etm_pc;
	struct coresight_event *event;

	dprintf("%s\n", __func__);

	etm_pc = etm_pcpu[cpu];
	event = &etm_pc->event;

	KASSERT(cpu == PCPU_GET(cpuid), ("Configuring wrong CPU\n"));

#if 0
	uint64_t reg;
	/* Ensure tracing is turned off */
	reg = rdmsr(MSR_IA32_RTIT_CTL);
	if (reg & RTIT_CTL_TRACEEN)
		etm_save_restore(etm_pc, true);

	etm_configure_ranges(etm_pc, ranges, nranges);
#endif

	struct etm_config config;
	int i;

	for (i = 0; i < nranges * 2; i++) {
		event->addr[i] = ranges[i];
		config.addr[i] = ranges[i];
	}
	config.naddr = nranges;
	event->naddr = nranges;

	enum pmc_mode mode;
	mode = PMC_TO_MODE(pm);
	if (mode == PMC_MODE_ST) {
		event->excp_level = 1;
		config.excp_level = 1;
	} else {
		event->excp_level = 0;
		config.excp_level = 0;
	}

	event->src = CORESIGHT_ETMV4;
	event->sink = CORESIGHT_ETR;
	coresight_prepare(cpu, event);

	return (0);
}

static int
etm_read_trace(int cpu, int ri, struct pmc *pm,
    pmc_value_t *vcycle, pmc_value_t *voffset)
{
	//struct etm_ext_area *etm_ext;
	//struct etm_save_area *save_area;
	struct pmc_md_etm_pmc *pm_etm;
	struct etm_buffer *etm_buf;
	struct etm_cpu *etm_pc;
	uint64_t offset;
	uint64_t cycle;
	//uint64_t reg;
	//uint32_t idx;

	//dprintf("%s\n", __func__);

	etm_pc = etm_pcpu[cpu];
	etm_pc->pm_mmap = pm;

	struct coresight_event *event;
	event = &etm_pc->event;

	TMC_READ_TRACE(etm_pc->dev_etr, &cycle, &offset);
	//TMC_READ_TRACE(etm_pc->dev_etf, NULL, NULL);

	pm_etm = (struct pmc_md_etm_pmc *)&pm->pm_md;
	etm_buf = &pm_etm->etm_buffers[cpu];

#if 0
	save_area = &etm_pc->save_area;
	etm_ext = &save_area->etm_ext_area;

	reg = rdmsr(MSR_IA32_RTIT_CTL);
	if (reg & RTIT_CTL_TRACEEN)
		reg = rdmsr(MSR_IA32_RTIT_OUTPUT_MASK_ETMRS);
	else
		reg = etm_ext->rtit_output_mask_etmrs;

	idx = (reg & 0xffffffff) >> 7;
	*cycle = etm_buf->cycle;

	offset = reg >> 32;
	*voffset = etm_buf->topa_sw[idx].offset + offset;

	dprintf("%s: %lx\n", __func__, rdmsr(MSR_IA32_RTIT_OUTPUT_MASK_ETMRS));
	dprintf("%s: cycle %ld offset %ld\n", __func__, etm_buf->cycle, offset);
#endif

	*vcycle = cycle;
	*voffset = offset;

	return (0);
}

static int
etm_read_pmc(int cpu, int ri, pmc_value_t *v)
{

	dprintf("%s\n", __func__);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[etm,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[etm,%d] illegal ri %d", __LINE__, ri));

	*v = 0;

	return (0);
}

static int
etm_release_pmc(int cpu, int ri, struct pmc *pm)
{
	struct pmc_md_etm_pmc *pm_etm;
	struct etm_cpu *etm_pc;
	enum pmc_mode mode;
	struct pmc_hw *phw;
	int i;

	pm_etm = (struct pmc_md_etm_pmc *)&pm->pm_md;
	etm_pc = etm_pcpu[cpu];

	dprintf("%s: cpu %d (curcpu %d)\n", __func__, cpu, PCPU_GET(cpuid));

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[etm,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0,
	    ("[etm,%d] illegal row-index %d", __LINE__, ri));

	phw = &etm_pcpu[cpu]->tc_hw;
	phw->phw_pmc = NULL;

	KASSERT(phw->phw_pmc == NULL,
	    ("[etm,%d] PHW pmc %p non-NULL", __LINE__, phw->phw_pmc));

#if 0
	dprintf("%s: cpu %d, output base %lx\n",
	    __func__, cpu, rdmsr(MSR_IA32_RTIT_OUTPUT_BASE));
	dprintf("%s: cpu %d, output base etmr %lx\n",
	    __func__, cpu, rdmsr(MSR_IA32_RTIT_OUTPUT_MASK_ETMRS));
#endif

	struct coresight_event *event;
	event = &etm_pc->event;

	coresight_disable(cpu, event);
	//TMC_STOP(etm_pc->dev_etr);

	mode = PMC_TO_MODE(pm);
	if (mode == PMC_MODE_TT)
		for (i = 0; i < pmc_cpu_max(); i++)
			etm_buffer_deallocate(i, &pm_etm->etm_buffers[i]);
	else
		etm_buffer_deallocate(cpu, &pm_etm->etm_buffers[cpu]);

	if (mode == PMC_MODE_ST)
		etm_pc->flags &= ~FLAG_ETM_ALLOCATED;

	return (0);
}

//int flag = 0;

static int
etm_start_pmc(int cpu, int ri)
{
	struct etm_cpu *etm_pc;
	struct pmc_hw *phw;

	dprintf("%s: cpu %d (curcpu %d)\n", __func__, cpu, PCPU_GET(cpuid));

	etm_pc = etm_pcpu[cpu];
	phw = &etm_pc->tc_hw;
	if (phw == NULL || phw->phw_pmc == NULL)
		return (-1);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[etm,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[etm,%d] illegal row-index %d", __LINE__, ri));

	etm_save_restore(etm_pc, false);

	struct coresight_event *event;
	event = &etm_pc->event;
	coresight_enable_source(cpu, event);

	return (0);
}

static int
etm_stop_pmc(int cpu, int ri)
{
	struct etm_cpu *etm_pc;

	dprintf("%s\n", __func__);

	etm_pc = etm_pcpu[cpu];

#if 0
	dprintf("%s: cpu %d, output base %lx, etmr %lx\n", __func__, cpu,
	    rdmsr(MSR_IA32_RTIT_OUTPUT_BASE),
	    rdmsr(MSR_IA32_RTIT_OUTPUT_MASK_ETMRS));
#endif

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[etm,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[etm,%d] illegal row-index %d", __LINE__, ri));

	/*
	 * Save the PT state to memory.
	 * This operation will disable tracing.
	 */
	etm_save_restore(etm_pc, true);

	struct coresight_event *event;
	event = &etm_pc->event;
	coresight_disable_source(cpu, event);

	return (0);
}

static int
etm_write_pmc(int cpu, int ri, pmc_value_t v)
{

	dprintf("%s\n", __func__);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[etm,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[etm,%d] illegal row-index %d", __LINE__, ri));

	return (0);
}

int
pmc_etm_initialize(struct pmc_mdep *md, int maxcpu)
{
	struct pmc_classdep *pcd;

	dprintf("%s\n", __func__);

#if 0
	etm_xsave_mask = XFEATURE_ENABLED_X87 | XFEATURE_ENABLED_SSE;
#endif

	KASSERT(md != NULL, ("[etm,%d] md is NULL", __LINE__));
	KASSERT(md->pmd_nclass >= 1, ("[etm,%d] dubious md->nclass %d",
	    __LINE__, md->pmd_nclass));

	etm_pcpu = malloc(sizeof(struct etm_cpu *) * maxcpu, M_ETM,
	    M_WAITOK | M_ZERO);

	pcd = &md->pmd_classdep[PMC_MDEP_CLASS_INDEX_ETM];

	pcd->pcd_caps	= ETM_CAPS;
	pcd->pcd_class	= PMC_CLASS_ETM;
	pcd->pcd_num	= ETM_NPMCS;
	pcd->pcd_ri	= md->pmd_npmc;
	pcd->pcd_width	= 64;

	pcd->pcd_allocate_pmc = etm_allocate_pmc;
	pcd->pcd_config_pmc   = etm_config_pmc;
	pcd->pcd_describe     = etm_describe;
	pcd->pcd_get_config   = etm_get_config;
	pcd->pcd_pcpu_init    = etm_pcpu_init;
	pcd->pcd_pcpu_fini    = etm_pcpu_fini;
	pcd->pcd_read_pmc     = etm_read_pmc;
	pcd->pcd_read_trace   = etm_read_trace;
	pcd->pcd_trace_config = etm_trace_config;
	pcd->pcd_release_pmc  = etm_release_pmc;
	pcd->pcd_start_pmc    = etm_start_pmc;
	pcd->pcd_stop_pmc     = etm_stop_pmc;
	pcd->pcd_write_pmc    = etm_write_pmc;

	md->pmd_npmc += ETM_NPMCS;

	return (0);
}

void
pmc_etm_finalize(struct pmc_mdep *md)
{

	dprintf("%s\n", __func__);

#ifdef INVARIANTS
	int i, ncpus;

	ncpus = pmc_cpu_max();
	for (i = 0; i < ncpus; i++)
		KASSERT(etm_pcpu[i] == NULL, ("[etm,%d] non-null pcpu cpu %d",
		    __LINE__, i));

	KASSERT(md->pmd_classdep[PMC_MDEP_CLASS_INDEX_ETM].pcd_class ==
	    PMC_CLASS_ETM, ("[etm,%d] class mismatch", __LINE__));
#endif

	free(etm_pcpu, M_ETM);
	etm_pcpu = NULL;
}
