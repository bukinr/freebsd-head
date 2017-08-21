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
#include <sys/vmem.h>
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
#include <machine/pt.h>
#include <machine/ptreg.h>

#include <amd64/pt/ptvar.h>

#define	PT_DEBUG
#undef	PT_DEBUG

#ifdef	PT_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

static struct cdev_pager_ops pt_pg_ops;
struct pt_softc pt_sc;

static int
pt_pg_ctor(void *handle, vm_ooffset_t size, vm_prot_t prot,
    vm_ooffset_t foff, struct ucred *cred, u_short *color)
{

	return (0);
}

static void
pt_pg_dtor(void *handle)
{

}

static int
pt_pg_fault(vm_object_t object, vm_ooffset_t offset,
    int prot, vm_page_t *mres)
{

	dprintf("%s: offset 0x%lx\n", __func__, offset);

	return (VM_PAGER_FAIL);
}

static struct cdev_pager_ops pt_pg_ops __unused = {
	.cdev_pg_ctor = pt_pg_ctor,
	.cdev_pg_dtor = pt_pg_dtor,
	.cdev_pg_fault = pt_pg_fault,
};


static int
pt_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{

	return (0);
}

static int
pt_mmap_single(struct cdev *cdev, vm_ooffset_t *offset,
    vm_size_t mapsize, struct vm_object **objp, int nprot)
{

	return (0);
}

static struct cdevsw pt_cdevsw = {
	.d_version =		D_VERSION,
	.d_ioctl =		pt_ioctl,
	.d_mmap_single =	pt_mmap_single,
	.d_name =		"Intel PT",
};

static int
pt_get_epc_area(struct pt_softc *sc)
{
	u_int cp[4];
	u_int *eax;
	u_int *ebx;
	u_int *ecx;

	printf("Enumerating part 1\n");
	cpuid_count(PT_CPUID, 0, cp);

	eax = &cp[0];
	ebx = &cp[1];
	ecx = &cp[2];

	printf("Maximum valid sub-leaf Index: %x\n", cp[0]);
	printf("b %x\n", cp[1]);
	printf("c %x\n", cp[2]);

	printf("Enumerating part 2\n");
	cpuid_count(PT_CPUID, 1, cp);
	printf("a %x\n", cp[0]);
	printf("b %x\n", cp[1]);

	return (0);
}

static int
pt_load(void)
{
	struct pt_softc *sc;
	int error;

	sc = &pt_sc;

	printf("%s, cpu_stdext_feature %x\n", __func__, cpu_stdext_feature);
	if ((cpu_stdext_feature & CPUID_STDEXT_PROCTRACE) == 0)
		return (ENXIO);

	printf("%s\n", __func__);
	mtx_init(&sc->mtx, "PT driver", NULL, MTX_DEF);

	error = pt_get_epc_area(sc);
	if (error) {
		printf("%s: Failed to get Processor Reserved Memory area.\n",
		    __func__);
		return (ENXIO);
	}

	printf("%s\n", __func__);
	sc->pt_cdev = make_dev(&pt_cdevsw, 0, UID_ROOT, GID_WHEEL,
	    0600, "ipt");

	sc->state |= PT_STATE_RUNNING;

	printf("%s\n", __func__);
	printf("PT initialized\n");

	return (0);
}

static int
pt_unload(void)
{
	struct pt_softc *sc;

	sc = &pt_sc;

	printf("%s\n", __func__);

	if ((sc->state & PT_STATE_RUNNING) == 0)
		return (0);

	printf("%s\n", __func__);

	mtx_lock(&sc->mtx);
	sc->state &= ~PT_STATE_RUNNING;
	mtx_unlock(&sc->mtx);

	printf("%s\n", __func__);

	destroy_dev(sc->pt_cdev);
	mtx_destroy(&sc->mtx);

	printf("%s\n", __func__);

	return (0);
}

static int
pt_handler(module_t mod, int what, void *arg)
{
	int error;

	switch (what) {
	case MOD_LOAD:
		error = pt_load();
		break;
	case MOD_UNLOAD:
		error = pt_unload();
		break;
	default:
		error = 0;
		break;
	}

	return (error);
}

static moduledata_t pt_kmod = {
	"pt",
	pt_handler,
	NULL
};

DECLARE_MODULE(pt, pt_kmod, SI_SUB_LAST, SI_ORDER_ANY);
MODULE_VERSION(pt, 1);
