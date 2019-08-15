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

struct fpgamgr_s10_softc {
	struct cdev		*mgr_cdev;
	device_t		dev;
	void			*mem;
};

#define	SVC_BUF_SIZE	(512 * 1024)

static int
fpga_open(struct cdev *dev, int flags __unused,
    int fmt __unused, struct thread *td __unused)
{
	struct fpgamgr_s10_softc *sc;
	struct s10_svc_msg msg;
	int ret;

	sc = dev->si_drv1;

	printf("%s\n", __func__);

	sc->mem = s10_svc_allocate_memory(SVC_BUF_SIZE);
	printf("%s: mem %p\n", __func__, sc->mem);

	msg.command = COMMAND_RECONFIG;

	ret = s10_svc_send(&msg);

	printf("%s done, ret %d\n", __func__, ret);

	return (0);
}

static int
fpga_close(struct cdev *dev, int flags __unused,
    int fmt __unused, struct thread *td __unused)
{
	struct fpgamgr_s10_softc *sc;

	sc = dev->si_drv1;

	printf("%s\n", __func__);

	return (0);
}

static int
fpga_write(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct fpgamgr_s10_softc *sc;
	struct s10_svc_msg msg;
	uint32_t buffer;
	uint64_t addr;
	int ret;
	int count;
	int i;

	sc = dev->si_drv1;

	printf("%s: uio->uio_resid %ld\n", __func__, uio->uio_resid);

	i = 0;
	count = 0;

	while (uio->uio_resid > 0 && count < SVC_BUF_SIZE) {
		addr = (uint64_t)sc->mem + count;
		uiomove((void *)addr, 4, uio);
		count += 4;

		if (count == SVC_BUF_SIZE || uio->uio_resid == 0) {
			printf("%s: writing %d chunk\n", __func__, i++);
			msg.command = COMMAND_RECONFIG_DATA_SUBMIT;
			msg.payload = sc->mem;
			msg.payload_length = count;
			ret = s10_svc_send(&msg);
			printf("%s: ret %d\n", __func__, ret);
			count = 0;
		}
	}

	while (uio->uio_resid >= SVC_BUF_SIZE) {
		uiomove(sc->mem, SVC_BUF_SIZE, uio);

#if 0
		bus_space_write_4(sc->bst_data, sc->bsh_data,
		    0x0, buffer);
#endif
	}

	switch (uio->uio_resid) {
	case 3:
		uiomove(&buffer, 3, uio);
		buffer &= 0xffffff;
#if 0
		bus_space_write_4(sc->bst_data, sc->bsh_data,
		    0x0, buffer);
#endif
		break;
	case 2:
		uiomove(&buffer, 2, uio);
		buffer &= 0xffff;
#if 0
		bus_space_write_4(sc->bst_data, sc->bsh_data,
		    0x0, buffer);
#endif
		break;
	case 1:
		uiomove(&buffer, 1, uio);
		buffer &= 0xff;
#if 0
		bus_space_write_4(sc->bst_data, sc->bsh_data,
		    0x0, buffer);
#endif
		break;
	default:
		break;
	};

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
