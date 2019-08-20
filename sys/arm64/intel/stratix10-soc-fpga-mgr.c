/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Ruslan Bukin <br@bsdpad.com>
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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

/*
 * Intel Stratix 10 FPGA Manager.
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

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <arm64/intel/stratix10-svc.h>

#include <machine/bus.h>
#include <machine/cpu.h>
#include <machine/intr.h>

#define	SVC_BUF_SIZE	(2 * 1024 * 1024)

struct fpgamgr_s10_softc {
	struct cdev		*mgr_cdev;
	device_t		dev;
	struct s10_svc_mem	mem;
	struct mtx		mtx;
	int			busy;
};

static int
fpga_open(struct cdev *dev, int flags __unused,
    int fmt __unused, struct thread *td __unused)
{
	struct fpgamgr_s10_softc *sc;
	struct s10_svc_msg msg;
	int ret;
	int err;

	sc = dev->si_drv1;

	mtx_lock(&sc->mtx);

	if (sc->busy) {
		mtx_unlock(&sc->mtx);
		return (EBUSY);
	}

	sc->mem.size = SVC_BUF_SIZE;
	sc->mem.fill = 0;
	err = s10_svc_allocate_memory(&sc->mem);
	if (err != 0) {
		mtx_unlock(&sc->mtx);
		return (ENXIO);
	}

	msg.command = COMMAND_RECONFIG;
	ret = s10_svc_send(&msg);

	if (ret != 0) {
		mtx_unlock(&sc->mtx);
		return (ENXIO);
	}

	sc->busy = 1;

	mtx_unlock(&sc->mtx);

	return (0);
}

static int
fpga_write(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct fpgamgr_s10_softc *sc;
	vm_offset_t addr;
	int amnt;

	sc = dev->si_drv1;

	while (uio->uio_resid > 0) {
		addr = sc->mem.vaddr + sc->mem.fill;
		if (sc->mem.fill >= SVC_BUF_SIZE)
			return (ENOMEM);
		amnt = MIN(uio->uio_resid, (SVC_BUF_SIZE - sc->mem.fill));
		uiomove((void *)addr, amnt, uio);
		sc->mem.fill += amnt;
	}

	return (0);
}

static int
fpga_close(struct cdev *dev, int flags __unused,
    int fmt __unused, struct thread *td __unused)
{
	struct fpgamgr_s10_softc *sc;
	struct s10_svc_msg msg;
	int ret;

	sc = dev->si_drv1;

	msg.command = COMMAND_RECONFIG_DATA_SUBMIT;
	msg.payload = (void *)sc->mem.paddr;
	msg.payload_length = sc->mem.fill;

	ret = s10_svc_send(&msg);
	if (ret != 0)
		device_printf(sc->dev, "Failed to submit data\n");

	msg.command = COMMAND_RECONFIG_DATA_CLAIM;
	ret = s10_svc_send(&msg);
	printf("%s: COMMAND_RECONFIG_DATA_CLAIM returned %d\n",
	    __func__, ret);

	s10_svc_free_memory(&sc->mem);

	sc->busy = 0;

	return (0);
}

static int
fpga_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{

	return (0);
}

static struct cdevsw fpga_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	fpga_open,
	.d_close =	fpga_close,
	.d_write =	fpga_write,
	.d_ioctl =	fpga_ioctl,
	.d_name =	"FPGA Manager",
};

static int
fpgamgr_s10_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (!ofw_bus_is_compatible(dev, "intel,stratix10-soc-fpga-mgr"))
		return (ENXIO);

	device_set_desc(dev, "Stratix 10 SOC FPGA Manager");

	return (BUS_PROBE_DEFAULT);
}

static int
fpgamgr_s10_attach(device_t dev)
{
	struct fpgamgr_s10_softc *sc;

	sc = device_get_softc(dev);
	sc->dev = dev;

	mtx_init(&sc->mtx, "s10 fpga", NULL, MTX_DEF);

	sc->mgr_cdev = make_dev(&fpga_cdevsw, 0, UID_ROOT, GID_WHEEL,
	    0600, "fpga%d", device_get_unit(sc->dev));

	if (sc->mgr_cdev == NULL) {
		device_printf(dev, "Failed to create character device.\n");
		return (ENXIO);
	}

	sc->mgr_cdev->si_drv1 = sc;

	return (0);
}

static device_method_t fpgamgr_s10_methods[] = {
	DEVMETHOD(device_probe,		fpgamgr_s10_probe),
	DEVMETHOD(device_attach,	fpgamgr_s10_attach),
	{ 0, 0 }
};

static driver_t fpgamgr_s10_driver = {
	"fpgamgr_s10",
	fpgamgr_s10_methods,
	sizeof(struct fpgamgr_s10_softc),
};

static devclass_t fpgamgr_s10_devclass;

DRIVER_MODULE(fpgamgr_s10, simplebus, fpgamgr_s10_driver,
    fpgamgr_s10_devclass, 0, 0);
