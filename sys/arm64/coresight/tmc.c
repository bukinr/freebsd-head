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
	device_t		dev;
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
tmc_unlock(struct tmc_softc *sc)
{

	/* Unlock Coresight */
	bus_write_4(sc->res, CORESIGHT_LAR, CORESIGHT_UNLOCK);
	wmb();

	/* Unlock TMC */
	bus_write_4(sc->res, TMC_LAR, 0);
	wmb();

	return (0);
}

static int
tmc_enable(struct tmc_softc *sc)
{
	uint32_t reg;

	/* Enable TMC */
	bus_write_4(sc->res, TMC_CTL, CTL_TRACECAPTEN);

	do {
		reg = bus_read_4(sc->res, TMC_STS);
	} while ((reg & STS_TMCREADY) == 0);

	return (0);
}

static void
tmc_configure_etf(struct tmc_softc *sc)
{

	printf("%s\n", __func__);

	tmc_unlock(sc);

	bus_write_4(sc->res, TMC_MODE, MODE_HW_FIFO);
	bus_write_4(sc->res, TMC_FFCR, FFCR_EN_FMT | FFCR_EN_TI);
	bus_write_4(sc->res, TMC_BUFWM, 0);

	tmc_enable(sc);
}

static int
tmc_attach(device_t dev)
{
	struct tmc_softc *sc;

	sc = device_get_softc(dev);

	sc->dev = dev;

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
	switch (reg) {
	case DEVID_CONFIGTYPE_ETR:
		printf("ETR configuration found, unit %d\n", device_get_unit(dev));
		//tmc_configure_etr(sc);
		break;
	case DEVID_CONFIGTYPE_ETF:
		printf("ETF configuration found, unit %d\n", device_get_unit(dev));
		tmc_configure_etf(sc);
		break;
	default:
		break;
	}

	return (0);
}

static int
tmc_configure_etr(device_t dev, uint32_t low, uint32_t high)
{
	struct tmc_softc *sc;
	uint32_t reg;
 
	sc = device_get_softc(dev);

	printf("%s unit %d\n", __func__, device_get_unit(dev));

	tmc_unlock(sc);

	/* Configure TMC */
	bus_write_4(sc->res, TMC_MODE, MODE_CIRCULAR_BUFFER);

	reg = AXICTL_PROT_CTRL_BIT1 | AXICTL_WRBURSTLEN_16;
	reg |= AXICTL_SG_MODE;
	reg |= AXICTL_AXCACHE_OS;
	bus_write_4(sc->res, TMC_AXICTL, reg);

	reg = FFCR_EN_FMT | FFCR_EN_TI | FFCR_FON_FLIN |
	    FFCR_FON_TRIG_EVT | FFCR_TRIGON_TRIGIN;
	bus_write_4(sc->res, TMC_FFCR, reg);

	bus_write_4(sc->res, TMC_TRG, 16);

	bus_write_4(sc->res, TMC_DBALO, low);
	bus_write_4(sc->res, TMC_DBAHI, high);

	tmc_enable(sc);

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

	printf("%s: STS 0x%x, RRP 0x%x, RWP 0x%x, LBUFLEVEL %x\n", __func__,
	    bus_read_4(sc->res, TMC_STS),
	    bus_read_4(sc->res, TMC_RRP),
	    bus_read_4(sc->res, TMC_RWP),
	    bus_read_4(sc->res, TMC_LBUFLEVEL));

	return (0);
}

static device_method_t tmc_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,			tmc_probe),
	DEVMETHOD(device_attach,		tmc_attach),

	/* TMC interface */
	DEVMETHOD(tmc_configure,	tmc_configure_etr),
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
