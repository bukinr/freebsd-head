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

#include <arm64/coresight/coresight.h>

#include <dev/hwpmc/hwpmc_vm.h>

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
	struct coresight_event		event;
};

static struct etm_cpu **etm_pcpu;

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

	dprintf("%s\n", __func__);

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

	dprintf("%s\n", __func__);

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
	enum pmc_mode mode;
	uint32_t phys_lo;
	uint32_t phys_hi;
	int error;
	struct coresight_event *event;

	etm_pc = etm_pcpu[cpu];
	event = &etm_pc->event;

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
	event->naddr = 0;

	event->started = 0;
	event->low = phys_lo;
	event->high = phys_hi;

	mode = PMC_TO_MODE(pm);
	if (mode == PMC_MODE_ST)
		event->excp_level = 1;
	else if (mode == PMC_MODE_TT)
		event->excp_level = 0;
	else {
		dprintf("%s: unsupported mode %d\n", __func__, mode);
		return (-1);
	}

	event->src = CORESIGHT_ETMV4;
	event->sink = CORESIGHT_ETR;

	coresight_init_event(cpu, event);

	return (0);
}

static int
etm_allocate_pmc(int cpu, int ri, struct pmc *pm,
    const struct pmc_op_pmcallocate *a)
{
	struct etm_cpu *etm_pc;
	int i;

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
	pd = &etm_pmcdesc[ri];

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
	struct etm_cpu *etm_pc;
	struct pmc_hw *phw;

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[etm,%d] illegal CPU %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[etm,%d] illegal row-index %d", __LINE__, ri));

	etm_pc = etm_pcpu[cpu];
	phw = &etm_pc->tc_hw;

	*ppm = phw->phw_pmc;

	return (0);
}

static int
etm_pcpu_init(struct pmc_mdep *md, int cpu)
{
	struct pmc_cpu *pc;
	struct etm_cpu *etm_pc;
	int ri;

	dprintf("%s: cpu %d\n", __func__, cpu);

	KASSERT(cpu == PCPU_GET(cpuid), ("Init on wrong CPU\n"));

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[etm,%d] illegal cpu %d", __LINE__, cpu));
	KASSERT(etm_pcpu, ("[etm,%d] null pcpu", __LINE__));
	KASSERT(etm_pcpu[cpu] == NULL, ("[etm,%d] non-null per-cpu",
	    __LINE__));

	etm_pc = malloc(sizeof(struct etm_cpu), M_ETM, M_WAITOK | M_ZERO);
	etm_pc->tc_hw.phw_state = PMC_PHW_FLAG_IS_ENABLED |
	    PMC_PHW_CPU_TO_STATE(cpu) | PMC_PHW_INDEX_TO_STATE(0) |
	    PMC_PHW_FLAG_IS_SHAREABLE;

	etm_pcpu[cpu] = etm_pc;

	ri = md->pmd_classdep[PMC_MDEP_CLASS_INDEX_ETM].pcd_ri;

	KASSERT(pmc_pcpu, ("[etm,%d] null generic pcpu", __LINE__));

	pc = pmc_pcpu[cpu];

	KASSERT(pc, ("[etm,%d] null generic per-cpu", __LINE__));

	pc->pc_hwpmcs[ri] = &etm_pc->tc_hw;

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
	struct coresight_event *event;
	struct etm_cpu *etm_pc;
	int i;

	dprintf("%s\n", __func__);

	etm_pc = etm_pcpu[cpu];
	event = &etm_pc->event;

	KASSERT(cpu == PCPU_GET(cpuid), ("Configuring wrong CPU\n"));

	for (i = 0; i < nranges * 2; i++)
		event->addr[i] = ranges[i];

	event->naddr = nranges;

	enum pmc_mode mode;
	mode = PMC_TO_MODE(pm);
	if (mode == PMC_MODE_ST)
		event->excp_level = 1;
	else
		event->excp_level = 0;

	event->src = CORESIGHT_ETMV4;
	event->sink = CORESIGHT_ETR;

	return (0);
}

static int
etm_read_trace(int cpu, int ri, struct pmc *pm,
    pmc_value_t *vcycle, pmc_value_t *voffset)
{
	struct pmc_md_etm_pmc *pm_etm;
	struct coresight_event *event;
	struct etm_buffer *etm_buf;
	struct etm_cpu *etm_pc;
	uint64_t offset;
	uint64_t cycle;

	dprintf("%s\n", __func__);

	etm_pc = etm_pcpu[cpu];
	etm_pc->pm_mmap = pm;
	event = &etm_pc->event;

	coresight_read(cpu, event);

	cycle = event->cycle;
	offset = event->offset;

	pm_etm = (struct pmc_md_etm_pmc *)&pm->pm_md;
	etm_buf = &pm_etm->etm_buffers[cpu];

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
	struct coresight_event *event;
	struct etm_cpu *etm_pc;
	enum pmc_mode mode;
	struct pmc_hw *phw;
	int i;

	pm_etm = (struct pmc_md_etm_pmc *)&pm->pm_md;
	etm_pc = etm_pcpu[cpu];
	event = &etm_pc->event;

	dprintf("%s: cpu %d (curcpu %d)\n", __func__, cpu, PCPU_GET(cpuid));

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[etm,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0,
	    ("[etm,%d] illegal row-index %d", __LINE__, ri));

	phw = &etm_pcpu[cpu]->tc_hw;
	phw->phw_pmc = NULL;

	KASSERT(phw->phw_pmc == NULL,
	    ("[etm,%d] PHW pmc %p non-NULL", __LINE__, phw->phw_pmc));

	coresight_disable(cpu, event);

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

static int
etm_start_pmc(int cpu, int ri)
{
	struct coresight_event *event;
	struct etm_cpu *etm_pc;
	struct pmc_hw *phw;

	dprintf("%s: cpu %d (curcpu %d)\n", __func__, cpu, PCPU_GET(cpuid));

	etm_pc = etm_pcpu[cpu];
	event = &etm_pc->event;
	phw = &etm_pc->tc_hw;
	if (phw == NULL || phw->phw_pmc == NULL)
		return (-1);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[etm,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[etm,%d] illegal row-index %d", __LINE__, ri));

	coresight_enable(cpu, event);

	return (0);
}

static int
etm_stop_pmc(int cpu, int ri)
{
	struct coresight_event *event;
	struct etm_cpu *etm_pc;

	dprintf("%s\n", __func__);

	etm_pc = etm_pcpu[cpu];
	event = &etm_pc->event;

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[etm,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[etm,%d] illegal row-index %d", __LINE__, ri));

	coresight_disable(cpu, event);

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
