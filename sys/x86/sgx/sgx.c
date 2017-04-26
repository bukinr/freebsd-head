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
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/rman.h>
#include <sys/timeet.h>
#include <sys/timetc.h>
#include <sys/conf.h>
#include <sys/uio.h>

#include <machine/md_var.h>
#include <machine/specialreg.h>

#include "sgx.h"
#include "sgx_user.h"

struct sgx_softc {
	struct cdev		*sgx_cdev;
	device_t		dev;
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
sgx_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{

	//printf("%s: %ld\n", __func__, cmd);

	switch (cmd) {
	case SGX_IOC_ENCLAVE_CREATE:
		printf("%s: enclave_create\n", __func__);
		//handler = isgx_ioctl_enclave_create;
		break;
	case SGX_IOC_ENCLAVE_ADD_PAGE:
		printf("%s: enclave_add_page\n", __func__);
		//handler = isgx_ioctl_enclave_add_page;
		break;
	case SGX_IOC_ENCLAVE_INIT:
		printf("%s: enclave_init\n", __func__);
		//handler = isgx_ioctl_enclave_init;
		break;
	default:
		return -EINVAL;
	}

	return (0);
}

static int
sgx_mmap(struct cdev *dev, vm_ooffset_t offset, vm_paddr_t *paddr, int nprot,
    vm_memattr_t *memattr)
{
	struct sgx_softc *sc;

	sc = dev->si_drv1;

#if 0
	if (offset < sc->mem_size) {
		*paddr = sc->mem_start + offset;
		return (0);
        }
#endif

	return (EINVAL);
}

static struct cdevsw sgx_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	sgx_open,
	.d_close =	sgx_close,
	.d_read =	sgx_read,
	.d_write =	sgx_write,
	.d_ioctl =	sgx_ioctl,
	.d_mmap =	sgx_mmap,
	.d_name =	"Intel SGX",
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

DRIVER_MODULE(sgx, cpu, sgx_driver, sgx_devclass, 0, 0);
