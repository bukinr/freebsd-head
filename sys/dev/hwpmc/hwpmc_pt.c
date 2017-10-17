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
#if (__FreeBSD_version >= 1100000)
#include <x86/apicvar.h>
#else
#include <machine/apicvar.h>
#endif

#include <machine/ptreg.h>
#include <machine/specialreg.h>

static MALLOC_DEFINE(M_PT, "pt", "PT driver");

/*
 * Intel PT support.
 */

#define	PT_CAPS	(PMC_CAP_READ | PMC_CAP_WRITE | PMC_CAP_INTERRUPT | PMC_CAP_SYSTEM | PMC_CAP_USER)

struct pt_descr {
	struct pmc_descr pm_descr;  /* "base class" */
};

static int pt_configure(int cpu, struct pmc *pm);
static int pt_buffer_allocate(struct pt_buffer *, uint64_t bufsize);
static int pt_buffer_deallocate(struct pt_buffer *);

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
	struct pmc_hw			tc_hw;
	uint32_t			s0_eax;
	uint32_t			s0_ebx;
	uint32_t			s0_ecx;
	uint32_t			s1_eax;
	uint32_t			s1_ebx;
	struct pmc			*pm_mmap;
};

static struct pt_cpu **pt_pcpu;

static int
pt_buf_allocate(uint32_t cpu, struct pmc *pm, const struct pmc_op_pmcallocate *a)
{
	const struct pmc_md_pt_op_pmcallocate *pm_pta;
	struct pmc_md_pt_pmc *pm_pt;
	struct pt_buffer *pt_buf;
	int error;
	int i;

	pm_pta = (const struct pmc_md_pt_op_pmcallocate *)&a->pm_md.pm_pt;
	pm_pt = (struct pmc_md_pt_pmc *)&pm->pm_md;
	pt_buf = &pm_pt->pt_buffers[cpu];

	error = pt_buffer_allocate(pt_buf, 256 * 1024 * 1024);
	if (error != 0) {
		printf("%s: can't allocate buffers\n", __func__);
		return (EINVAL);
	}

	pt_buf->pt_output_base = (uint64_t)vtophys(pt_buf->topa_hw);
	pt_buf->pt_output_mask_ptrs = 0x7f;
	pt_buf->flags = pm_pta->flags;
	pt_buf->addrn = pm_pta->addrn;

	for (i = 0; i < PT_NADDR; i++) {
		/* TODO: check caps: how many address ranges supported ? */

		pt_buf->addra[i] = pm_pta->addra[i];
		pt_buf->addrb[i] = pm_pta->addrb[i];
	}

	if (pm_pta->flags & INTEL_PT_FLAG_BRANCHES)
		pt_buf->flags |= INTEL_PT_FLAG_BRANCHES;

	return (0);
}

static int
pt_allocate_pmc(int cpu, int ri, struct pmc *pm,
    const struct pmc_op_pmcallocate *a)
{
	int i;

	//printf("%s: cpu %d (curcpu %d)\n", __func__, cpu, PCPU_GET(cpuid));
	//printf("pm_mode %d\n", a->pm_mode);

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

	if (a->pm_mode == PMC_MODE_TT)
		for (i = 0; i < pmc_cpu_max(); i++) {
			if (pt_buf_allocate(i, pm, a))
				return (EINVAL);
		}
	else
		if (pt_buf_allocate(cpu, pm, a))
			return (EINVAL);

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
pt_configure(int cpu, struct pmc *pm)
{
	struct pmc_md_pt_pmc *pm_pt;
	struct pt_cpu *pt_pc;
	enum pmc_mode mode;
	struct pt_buffer *pt_buf;
	uint64_t reg;
	int i;

	printf("%s\n", __func__);

	pm_pt = (struct pmc_md_pt_pmc *)&pm->pm_md;
	pt_buf = &pm_pt->pt_buffers[cpu];

	printf("%s: cpu %d (curcpu %d), pt_buf->pt_output_base %lx\n",
	    __func__, cpu, PCPU_GET(cpuid), pt_buf->pt_output_base);

	KASSERT(cpu == PCPU_GET(cpuid), ("Configuring wrong CPU\n"));

	mode = PMC_TO_MODE(pm);

	pt_pc = pt_pcpu[cpu];

	wrmsr(MSR_IA32_RTIT_CTL, 0);
	wrmsr(MSR_IA32_RTIT_STATUS, 0);

	wrmsr(MSR_IA32_RTIT_OUTPUT_BASE, pt_buf->pt_output_base);
	wrmsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, pt_buf->pt_output_mask_ptrs);

	/* Configure tracing */
	reg = RTIT_CTL_TOPA;

	//if (sc->s0_ebx & S0_EBX_PRW) {
	//	reg |= RTIT_CTL_FUPONPTW;
	//	reg |= RTIT_CTL_PTWEN;
	//}

	if (mode == PMC_MODE_ST)
		reg |= RTIT_CTL_OS;
	else if (mode == PMC_MODE_TT) {
		reg |= RTIT_CTL_USER;
		reg |= RTIT_CTL_CR3FILTER;
	} else {
		printf("%s: unknown mode %d\n", __func__, mode);
		return (-1);
	}

	/* Enable FUP, TIP, TIP.PGE, TIP.PGD, TNT, MODE.Exec and MODE.TSX packets */
	if (pt_buf->flags & INTEL_PT_FLAG_BRANCHES)
		reg |= RTIT_CTL_BRANCHEN;

	if (pt_buf->flags & INTEL_PT_FLAG_TSC)
		reg |= RTIT_CTL_TSCEN;

	if (pt_buf->flags & INTEL_PT_FLAG_MTC)
		reg |= RTIT_CTL_MTCEN;

	if (pt_buf->flags & INTEL_PT_FLAG_DISRETC)
		reg |= RTIT_CTL_DISRETC;

	//reg |= RTIT_CTL_MTC_FREQ(6);

	if (pt_buf->addrn == 0)
		printf("%s: no ranges\n", __func__);

	for (i = 0; i < pt_buf->addrn; i++) {
		printf("%s: range %lx -> %lx\n", __func__, pt_buf->addra[i], pt_buf->addrb[i]);
		reg |= (1UL << RTIT_CTL_ADDR_CFG_S(i));
		wrmsr(MSR_IA32_RTIT_ADDR_A(i), pt_buf->addra[i]);
		wrmsr(MSR_IA32_RTIT_ADDR_B(i), pt_buf->addrb[i]);
	}

	wrmsr(MSR_IA32_RTIT_CTL, reg);

	return (0);
}

static int
pt_attach_proc(int ri, struct pmc *pm, struct proc *p)
{
	struct pmc_md_pt_pmc *pm_pt;
	//struct pt_buffer *pt_buf;
	enum pmc_mode mode;
	pmap_t pmap;  
	uint64_t cr3;

	printf("%s\n", __func__);

	mode = PMC_TO_MODE(pm);
	if (mode != PMC_MODE_ST && mode != PMC_MODE_TT)
		return (0);

	//pmap = vmspace_pmap(td->td_proc->p_vmspace);
	pmap = vmspace_pmap(p->p_vmspace);
	cr3 = pmap->pm_cr3;

	pm_pt = (struct pmc_md_pt_pmc *)&pm->pm_md;
	pm_pt->cr3 = cr3;

	//pt_buf = &pm_pt->pt_buffers[cpu];
	//pt_buf->cr3 = cr3;

	return (0);
}

static int
pt_config_pmc(int cpu, int ri, struct pmc *pm)
{
	struct pmc_hw *phw;
	struct pt_cpu *pt_pc;
	int error;

	printf("%s: cpu %d (pm %lx)\n", __func__, cpu, (uint64_t)pm);

	PMCDBG3(MDP,CFG,1, "cpu=%d ri=%d pm=%p", cpu, ri, pm);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[pt,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[pt,%d] illegal row-index %d", __LINE__, ri));

	pt_pc = pt_pcpu[cpu];
	phw = &pt_pc->tc_hw;

#if 0
	KASSERT(pm == NULL || phw->phw_pmc == NULL,
	    ("[pt,%d] pm=%p phw->pm=%p hwpmc not unconfigured", __LINE__,
	    pm, phw->phw_pmc));
#endif

	phw->phw_pmc = pm;
	if (pm != NULL) {
		error = pt_configure(cpu, pm);
		if (error != 0) {
			printf("%s: can't enable PMC\n", __func__);
			return (error);
		}
	}

	return (0);
}

static int
pt_describe(int cpu, int ri, struct pmc_info *pi, struct pmc **ppmc)
{
	int error;
	size_t copied;
	const struct pt_descr *pd;
	struct pmc_hw *phw;

	printf("%s\n", __func__);

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

	//printf("%s\n", __func__);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[pt,%d] illegal CPU %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[pt,%d] illegal row-index %d", __LINE__, ri));

	pt_pc = pt_pcpu[cpu];
	phw = &pt_pc->tc_hw;

	*ppm = phw->phw_pmc;

	return (0);
}

static int
pt_get_msr(int ri, uint32_t *msr)
{

	printf("%s\n", __func__);

	KASSERT(ri >= 0 && ri < PT_NPMCS,
	    ("[pt,%d] ri %d out of range", __LINE__, ri));

	return (-1);

	//*msr = MSR_PT;

	return (0);
}

static int
pt_buffer_allocate(struct pt_buffer *pt_buf, uint64_t bufsize)
{
	struct topa_entry *entry;
	uint64_t offset;
	uint64_t segsize;
	uint64_t topa_size;
	void *buf;
	int i;
	int n;

	if (bufsize > (1 * 1024 * 1024 * 1024)) {
		topa_size = TOPA_SIZE_8M;
	} else if (bufsize > (128 * 1024 * 1024)) {
		topa_size = TOPA_SIZE_4M;
	} else {
		topa_size = TOPA_SIZE_1M;
	}

	segsize = 2 << (11 + (topa_size >> TOPA_SIZE_S));

	printf("%s: bufsize %lx, segsize %lx\n",
	    __func__, bufsize, segsize);

	if (bufsize % segsize)
		return (-1);

	n = bufsize / segsize;

	entry = malloc(n * sizeof(struct topa_entry), M_PT, M_ZERO);

	offset = 0;

	for (i = 0; i < n; i++) {
		buf = contigmalloc(segsize, M_PT, M_WAITOK | M_ZERO,
		    0,		/* low */
		    ~0,		/* high */
		    PAGE_SIZE,	/* alignment */
		    0);		/* boundary */
		if (buf == NULL) {
			printf("Can't allocate topa\n");
			/* TODO: deallocate */
			return (1);
		}

		entry[i].base = (uint64_t)buf;
		entry[i].size = segsize;
		entry[i].offset = offset;
		offset += segsize;
	}

	/* Now build hardware topa table. */

	pt_buf->topa_hw = malloc(PAGE_SIZE, M_PT, M_ZERO);
	for (i = 0; i < n; i++) {
		pt_buf->topa_hw[i] = (uint64_t)vtophys(entry[i].base) | topa_size;
		if (i == (n - 1))
			pt_buf->topa_hw[i] |= TOPA_INT;
	}

	/* The last entry is pointer to table. */
	pt_buf->topa_hw[n] = vtophys(pt_buf->topa_hw) | TOPA_END;
	pt_buf->topa_sw = entry;
	pt_buf->topa_n = n;
	pt_buf->cycle = 0;

	return (0);
}

static int
pt_buffer_deallocate(struct pt_buffer *pt_buf)
{
	int i;

	printf("%s\n", __func__);

	for (i = 0; i < pt_buf->topa_n; i++) {
		contigfree((void *)pt_buf->topa_sw[i].base, pt_buf->topa_sw[i].size, M_PT);
	}

	free(pt_buf->topa_sw, M_PT);
	free(pt_buf->topa_hw, M_PT);

	return (0);
}

int
pmc_pt_buffer_get_page(int cpu, vm_ooffset_t offset, vm_paddr_t *paddr)
{
	struct pmc_md_pt_pmc *pm_pt;
	struct pt_cpu *pt_pc;
	struct pmc *pm;
	struct pt_buffer *pt_buf;
	int i;

	pt_pc = pt_pcpu[cpu];
	pm = pt_pc->pm_mmap;
	if (pm == NULL) {
		printf("%s: FAIL: pm is null\n", __func__);
		return (-1);
	}

	pm_pt = (struct pmc_md_pt_pmc *)&pm->pm_md;
	pt_buf = &pm_pt->pt_buffers[cpu];

	for (i = 0; i < pt_buf->topa_n; i++) {
		if (offset < pt_buf->topa_sw[i].size) {
			*paddr = vtophys(pt_buf->topa_sw[i].base) + offset;
			break;
		}
		offset -= pt_buf->topa_sw[i].size;
	}

#if 0
	printf("%s: paddr %lx\n", __func__, *paddr);
#endif

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

	printf("Enumerating part 1\n");

	cpuid_count(PT_CPUID, 0, cp);
	printf("%s: Maximum valid sub-leaf Index: %x\n", __func__, cp[0]);
	printf("%s: ebx %x\n", __func__, cp[1]);
	printf("%s: ecx %x\n", __func__, cp[2]);

	pt_pc->s0_eax = cp[0];
	pt_pc->s0_ebx = cp[1];
	pt_pc->s0_ecx = cp[2];

	printf("Enumerating part 2\n");

	cpuid_count(PT_CPUID, 1, cp);
	printf("%s: eax %x\n", __func__, cp[0]);
	printf("%s: ebx %x\n", __func__, cp[1]);

	pt_pc->s1_eax = cp[0];
	pt_pc->s1_ebx = cp[1];
}

static int
pt_pcpu_init(struct pmc_mdep *md, int cpu)
{
	struct pmc_cpu *pc;
	struct pt_cpu *pt_pc;
	int ri;

	printf("%s: cpu %d\n", __func__, cpu);

	KASSERT(cpu == PCPU_GET(cpuid), ("Init on wrong CPU\n"));

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[pt,%d] illegal cpu %d", __LINE__, cpu));
	KASSERT(pt_pcpu, ("[pt,%d] null pcpu", __LINE__));
	KASSERT(pt_pcpu[cpu] == NULL, ("[pt,%d] non-null per-cpu",
	    __LINE__));

	pt_pc = malloc(sizeof(struct pt_cpu), M_PMC, M_WAITOK | M_ZERO);

	pt_pc->tc_hw.phw_state = PMC_PHW_FLAG_IS_ENABLED |
	    PMC_PHW_CPU_TO_STATE(cpu) | PMC_PHW_INDEX_TO_STATE(0) |
	    PMC_PHW_FLAG_IS_SHAREABLE;

	pt_pcpu[cpu] = pt_pc;

#if 0
	int error;
	error = pt_buffer_allocate(pt_pc, 256 * 1024 * 1024);
	if (error != 0) {
		printf("%s: can't allocate buffers\n", __func__);
		return (-1);
	}
#endif

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

	printf("%s: cpu %d\n", __func__, cpu);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[pt,%d] illegal cpu %d", __LINE__, cpu));
	KASSERT(pt_pcpu[cpu] != NULL, ("[pt,%d] null pcpu", __LINE__));

	pt_pc = pt_pcpu[cpu];

#if 0
	pt_buffer_deallocate(pt_pc);
#endif

	free(pt_pcpu[cpu], M_PMC);
	pt_pcpu[cpu] = NULL;

	ri = md->pmd_classdep[PMC_MDEP_CLASS_INDEX_PT].pcd_ri;

	pc = pmc_pcpu[cpu];
	pc->pc_hwpmcs[ri] = NULL;

	return (0);
}

static int
pt_trace_config(int cpu, int ri, struct pmc *pm,
    struct pmc_trace_filter_ip_range *ranges, uint32_t nranges)
{
	struct pt_buffer *pt_buf;
	struct pmc_md_pt_pmc *pm_pt;
	uint64_t reg;
	int i;

	KASSERT(cpu == PCPU_GET(cpuid), ("Configuring wrong CPU\n"));

	printf("%s\n", __func__);
	
	pm_pt = (struct pmc_md_pt_pmc *)&pm->pm_md;
	pt_buf = &pm_pt->pt_buffers[cpu];

	/* Turn off tracing */
	reg = rdmsr(MSR_IA32_RTIT_CTL);
	if (reg & RTIT_CTL_TRACEEN)
		wrmsr(MSR_IA32_RTIT_CTL, reg & ~RTIT_CTL_TRACEEN);

	pt_buf->addrn = nranges;

	for (i = 0; i < nranges; i++) {
		printf("%s: range %lx -> %lx\n", __func__, ranges[0].addra, ranges[0].addrb);
 
		pt_buf->addra[i] = ranges[i].addra;
		pt_buf->addrb[i] = ranges[i].addrb;

		reg |= (1UL << RTIT_CTL_ADDR_CFG_S(i));
		wrmsr(MSR_IA32_RTIT_ADDR_A(i), ranges[i].addra);
		wrmsr(MSR_IA32_RTIT_ADDR_B(i), ranges[i].addrb);
	}

	//if (reg & RTIT_CTL_TRACEEN)

	wrmsr(MSR_IA32_RTIT_CTL, reg);

	printf("%s: range CTL %lx\n", __func__, reg);

	return (0);
}

static int
pt_read_trace(int cpu, int ri, struct pmc *pm,
    pmc_value_t *cycle, pmc_value_t *voffset)
{
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

	reg = rdmsr(MSR_IA32_RTIT_CTL);
	if (reg & RTIT_CTL_TRACEEN) {
		reg = rdmsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS);
	} else {
		reg = pt_buf->pt_output_mask_ptrs;
	}

	idx = (reg & 0xffffffff) >> 7;
	*cycle = pt_buf->cycle;

	offset = reg >> 32;
	*voffset = pt_buf->topa_sw[idx].offset + offset;

	printf("%s: %lx\n", __func__, rdmsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS));

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
	enum pmc_mode mode;
	struct pmc_hw *phw;
	int i;

	pm_pt = (struct pmc_md_pt_pmc *)&pm->pm_md;

	printf("%s: cpu %d (curcpu %d)\n", __func__, cpu, PCPU_GET(cpuid));

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[pt,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0,
	    ("[pt,%d] illegal row-index %d", __LINE__, ri));

	phw = &pt_pcpu[cpu]->tc_hw;
	phw->phw_pmc = NULL;

	KASSERT(phw->phw_pmc == NULL,
	    ("[pt,%d] PHW pmc %p non-NULL", __LINE__, phw->phw_pmc));

	printf("%s: cpu %d, output base %lx\n",
	    __func__, cpu, rdmsr(MSR_IA32_RTIT_OUTPUT_BASE));
	printf("%s: cpu %d, output base ptr %lx\n",
	    __func__, cpu, rdmsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS));

	mode = PMC_TO_MODE(pm);
	if (mode == PMC_MODE_TT) {
		for (i = 0; i < pmc_cpu_max(); i++)
			pt_buffer_deallocate(&pm_pt->pt_buffers[i]);
	} else {
		pt_buffer_deallocate(&pm_pt->pt_buffers[cpu]);
	}

	/*
	 * Nothing to do.
	 */
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
	uint64_t reg;

	printf("%s: cpu %d (curcpu %d)\n", __func__, cpu, PCPU_GET(cpuid));

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

	wrmsr(MSR_IA32_RTIT_CR3_MATCH, pm_pt->cr3);

	/* Enable tracing */
	reg = rdmsr(MSR_IA32_RTIT_CTL);
	reg |= RTIT_CTL_TRACEEN;
	wrmsr(MSR_IA32_RTIT_CTL, reg);

	printf("%s: ctl %lx\n", __func__, reg);

	return (0);	/* PTs are always running. */
}

static int
pt_stop_pmc(int cpu, int ri)
{
	struct pmc_md_pt_pmc *pm_pt;
	struct pt_cpu *pt_pc;
	struct pmc_hw *phw;
	struct pt_buffer *pt_buf;
	struct pmc *pm;
	uint64_t reg;

	pt_pc = pt_pcpu[cpu];
	phw = &pt_pc->tc_hw;
	if (phw == NULL || phw->phw_pmc == NULL)
		return (-1);

	pm = phw->phw_pmc;
	pm_pt = (struct pmc_md_pt_pmc *)&pm->pm_md;
	pt_buf = &pm_pt->pt_buffers[cpu];
	pt_buf->pt_output_base = rdmsr(MSR_IA32_RTIT_OUTPUT_BASE);
	pt_buf->pt_output_mask_ptrs = rdmsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS);

	printf("%s: cpu %d (curcpu %d)\n", __func__, cpu, PCPU_GET(cpuid));
	printf("%s: cpu %d, output base %lx\n",
	    __func__, cpu, rdmsr(MSR_IA32_RTIT_OUTPUT_BASE));
	printf("%s: cpu %d, output base ptr %lx\n",
	    __func__, cpu, rdmsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS));

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[pt,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[pt,%d] illegal row-index %d", __LINE__, ri));

	/* Disable tracing */
	reg = rdmsr(MSR_IA32_RTIT_CTL);
	reg &= ~RTIT_CTL_TRACEEN;
	wrmsr(MSR_IA32_RTIT_CTL, reg);

	pt_buf->pt_output_mask_ptrs = rdmsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS);

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

	printf("%s\n", __func__);

	KASSERT(md != NULL, ("[pt,%d] md is NULL", __LINE__));
	KASSERT(md->pmd_nclass >= 1, ("[pt,%d] dubious md->nclass %d",
	    __LINE__, md->pmd_nclass));

	pt_pcpu = malloc(sizeof(struct pt_cpu *) * maxcpu, M_PMC,
	    M_ZERO | M_WAITOK);

	pcd = &md->pmd_classdep[PMC_MDEP_CLASS_INDEX_PT];

	pcd->pcd_caps	= PT_CAPS;
	pcd->pcd_class	= PMC_CLASS_PT;
	pcd->pcd_num	= PT_NPMCS;
	pcd->pcd_ri	= md->pmd_npmc;
	pcd->pcd_width	= 64;

	printf("PT ri %d\n", pcd->pcd_ri);

	pcd->pcd_allocate_pmc = pt_allocate_pmc;
	pcd->pcd_config_pmc   = pt_config_pmc;
	pcd->pcd_describe     = pt_describe;
	pcd->pcd_get_config   = pt_get_config;
	pcd->pcd_get_msr      = pt_get_msr;
	pcd->pcd_pcpu_init    = pt_pcpu_init;
	pcd->pcd_pcpu_fini    = pt_pcpu_fini;
	pcd->pcd_read_pmc     = pt_read_pmc;
	pcd->pcd_read_trace   = pt_read_trace;
	pcd->pcd_trace_config = pt_trace_config;
	pcd->pcd_attach_proc  = pt_attach_proc;
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

	printf("%s\n", __func__);

#ifdef	INVARIANTS
	int i, ncpus;

	ncpus = pmc_cpu_max();
	for (i = 0; i < ncpus; i++)
		KASSERT(pt_pcpu[i] == NULL, ("[pt,%d] non-null pcpu cpu %d",
		    __LINE__, i));

	KASSERT(md->pmd_classdep[PMC_MDEP_CLASS_INDEX_PT].pcd_class ==
	    PMC_CLASS_PT, ("[pt,%d] class mismatch", __LINE__));
#endif

	free(pt_pcpu, M_PMC);
	pt_pcpu = NULL;
}
