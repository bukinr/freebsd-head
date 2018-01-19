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
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/rman.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <machine/bus.h>

#include <arm64/coresight/tmc.h>

#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include "tmc_if.h"

#define CORESIGHT_ITCTRL        0xf00
#define CORESIGHT_CLAIMSET      0xfa0
#define CORESIGHT_CLAIMCLR      0xfa4
#define CORESIGHT_LAR           0xfb0
#define CORESIGHT_LSR           0xfb4
#define CORESIGHT_AUTHSTATUS    0xfb8
#define CORESIGHT_DEVID         0xfc8
#define CORESIGHT_DEVTYPE       0xfcc

#define CORESIGHT_UNLOCK        0xc5acce55

static struct ofw_compat_data compat_data[] = {
	{ "arm,coresight-tmc",			1 },
	{ NULL,					0 }
};

struct tmc_softc {
	struct resource		*res;
};

#if 0
struct tmc_softc *tmc_sc;
#endif

static struct resource_spec tmc_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ -1, 0 }
};

static int
tmc_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "Coresight Trace Memory Controller (TMC)");

	return (BUS_PROBE_DEFAULT);
}

static int
tmc_attach(device_t dev)
{
	struct tmc_softc *sc;

	sc = device_get_softc(dev);

	if (bus_alloc_resources(dev, tmc_spec, &sc->res) != 0) {
		device_printf(dev, "cannot allocate resources for device\n");
		return (ENXIO);
	}

#if 0
	if (device_get_unit(dev) != 1)
		return (0);

	tmc_sc = sc;

#endif

	//printf("%s: DEVID %x\n", __func__, bus_read_4(sc->res, TMC_DEVID));

	uint32_t reg;
	reg = bus_read_4(sc->res, TMC_DEVID);
	reg &= DEVID_CONFIGTYPE_M;
	if (reg == DEVID_CONFIGTYPE_ETR) {
		printf("ETR configuration found\n");
	}

	return (0);
}

static int
tmc_configure(device_t dev, uint32_t low, uint32_t high)
{
	struct tmc_softc *sc;
	uint32_t reg;
 
	sc = device_get_softc(dev);

	printf("%s unit %d\n", __func__, device_get_unit(dev));

	/* Unlock Coresight */
	bus_write_4(sc->res, CORESIGHT_LAR, CORESIGHT_UNLOCK);
	wmb();

	/* Unlock TMC */
	bus_write_4(sc->res, TMC_LAR, 0);
	wmb();

	/* Configure TMC */
	bus_write_4(sc->res, TMC_MODE, MODE_CIRCULAR_BUFFER);
	bus_write_4(sc->res, TMC_AXICTL, AXICTL_SG_MODE);
	bus_write_4(sc->res, TMC_DBALO, low);
	bus_write_4(sc->res, TMC_DBAHI, high);

	/* Enable TMC */
	bus_write_4(sc->res, TMC_CTL, CTL_TRACECAPTEN);

	do {
		reg = bus_read_4(sc->res, TMC_STS);
	} while ((reg & STS_TMCREADY) == 0);

	return (0);
}

static int
tmc_set_base(device_t dev, uint32_t low, uint32_t high)
{
	struct tmc_softc *sc;
 
	sc = device_get_softc(dev);

	bus_write_4(sc->res, TMC_DBALO, low);
	bus_write_4(sc->res, TMC_DBAHI, high);

	return (0);
}

static int
tmc_read_trace(device_t dev)
{
	struct tmc_softc *sc;
 
	sc = device_get_softc(dev);

	printf("%s: status 0x%x\n", __func__, bus_read_4(sc->res, TMC_STS));

	return (0);
}

static device_method_t tmc_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,			tmc_probe),
	DEVMETHOD(device_attach,		tmc_attach),

	/* TMC interface */
	DEVMETHOD(tmc_configure,	tmc_configure),
	DEVMETHOD(tmc_set_base,		tmc_set_base),
	DEVMETHOD(tmc_read_trace,	tmc_read_trace),
	DEVMETHOD_END
};

static driver_t tmc_driver = {
	"tmc",
	tmc_methods,
	sizeof(struct tmc_softc),
};

static devclass_t tmc_devclass;

DRIVER_MODULE(tmc, simplebus, tmc_driver, tmc_devclass, 0, 0);
MODULE_VERSION(tmc, 1);
