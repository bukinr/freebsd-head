/*-
 * Copyright (c) 2018 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <machine/bus.h>
#include <machine/cpu.h>
#include <machine/intr.h>

struct berimgr_softc {
	struct resource		*res[3];
	struct cdev		*mgr_cdev;
	device_t		dev;
	bus_space_tag_t		bst_data;
	bus_space_handle_t	bsh_data;
};

static struct resource_spec berimgr_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ -1, 0 }
};


static int
beri_open(struct cdev *dev, int flags __unused,
    int fmt __unused, struct thread *td __unused)
{
	struct berimgr_softc *sc;

	sc = dev->si_drv1;

	printf("%s\n", __func__);

	return (0);
}

static int
beri_close(struct cdev *dev, int flags __unused,
    int fmt __unused, struct thread *td __unused)
{
	struct berimgr_softc *sc;

	sc = dev->si_drv1;

	printf("%s\n", __func__);

	return (0);
}

static int
beri_write(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct berimgr_softc *sc;
	uint32_t offs;
	int buffer;

	sc = dev->si_drv1;

	printf("%s\n", __func__);

	offs = 0;

	while (uio->uio_resid > 0) {
		uiomove(&buffer, 4, uio);
		bus_space_write_4(sc->bst_data, sc->bsh_data,
		    offs, buffer);
		offs += 4;
	}

	if (offs > 0)
		printf("%s: written %d bytes\n", __func__, offs);

	return (0);
}

static int
beri_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{

	return (0);
}

static struct cdevsw beri_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	beri_open,
	.d_close =	beri_close,
	.d_write =	beri_write,
	.d_ioctl =	beri_ioctl,
	.d_name =	"BERI Manager",
};

static int
berimgr_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (!ofw_bus_is_compatible(dev, "beri,mgr"))
		return (ENXIO);

	device_set_desc(dev, "BERI Manager");

	return (BUS_PROBE_DEFAULT);
}

static int
berimgr_attach(device_t dev)
{
	struct berimgr_softc *sc;

	sc = device_get_softc(dev);
	sc->dev = dev;

	if (bus_alloc_resources(dev, berimgr_spec, sc->res)) {
		device_printf(dev, "could not allocate resources\n");
		return (ENXIO);
	}

	/* Memory interface */
	sc->bst_data = rman_get_bustag(sc->res[0]);
	sc->bsh_data = rman_get_bushandle(sc->res[0]);

	sc->mgr_cdev = make_dev(&beri_cdevsw, 0, UID_ROOT, GID_WHEEL,
	    0600, "beri%d", device_get_unit(sc->dev));
	if (sc->mgr_cdev == NULL) {
		device_printf(dev, "Failed to create character device.\n");
		return (ENXIO);
	}

	sc->mgr_cdev->si_drv1 = sc;

	return (0);
}

static device_method_t berimgr_methods[] = {
	DEVMETHOD(device_probe,		berimgr_probe),
	DEVMETHOD(device_attach,	berimgr_attach),
	{ 0, 0 }
};

static driver_t berimgr_driver = {
	"berimgr",
	berimgr_methods,
	sizeof(struct berimgr_softc),
};

static devclass_t berimgr_devclass;

DRIVER_MODULE(berimgr, simplebus, berimgr_driver, berimgr_devclass, 0, 0);
