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

#include <arm64/coresight/coresight.h>
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
	struct resource			*res;
	device_t			dev;
	uint64_t			cycle;
	struct coresight_platform_data	*pdata;
};

static struct resource_spec tmc_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ -1, 0 }
};

#define	ACCESS_W	0xC5ACCE55

static int
tmc_unlock(struct tmc_softc *sc)
{

	/* Unlock Coresight */
	bus_write_4(sc->res, CORESIGHT_LAR, CORESIGHT_UNLOCK);
	wmb();

	/* Unlock TMC */
	bus_write_4(sc->res, TMC_LAR, ACCESS_W);
	wmb();

	return (0);
}

static int
tmc_enable0(struct tmc_softc *sc)
{
	uint32_t reg;

	if (bus_read_4(sc->res, TMC_CTL) & CTL_TRACECAPTEN)
		return (-1);
		
	/* Enable TMC */
	bus_write_4(sc->res, TMC_CTL, CTL_TRACECAPTEN);
	if ((bus_read_4(sc->res, TMC_CTL) & CTL_TRACECAPTEN) == 0)
		panic("not enabled0\n");

	do {
		reg = bus_read_4(sc->res, TMC_STS);
	} while ((reg & STS_TMCREADY) == 1);

	if ((bus_read_4(sc->res, TMC_CTL) & CTL_TRACECAPTEN) == 0)
		panic("not enabled1\n");

	printf("%s: enabled. RRP %x, RWP %x\n", __func__,
	    bus_read_4(sc->res, TMC_RRP), bus_read_4(sc->res, TMC_RWP));

	return (0);
}

static int
tmc_start(device_t dev)
{
	struct tmc_softc *sc;
 
	printf("%s\n", __func__);

	sc = device_get_softc(dev);

	tmc_enable0(sc);

	return (0);
}

static int
tmc_stop(device_t dev)
{
	struct tmc_softc *sc;
	uint32_t reg;
 
	printf("%s\n", __func__);

	sc = device_get_softc(dev);

	reg = bus_read_4(sc->res, TMC_CTL);
	reg &= ~CTL_TRACECAPTEN;
	bus_write_4(sc->res, TMC_CTL, reg);

	return (0);
}

static int
tmc_configure_etf(device_t dev)
{
	struct tmc_softc *sc;
	uint32_t reg;
 
	sc = device_get_softc(dev);

	printf("%s\n", __func__);

	tmc_unlock(sc);

	do {
		reg = bus_read_4(sc->res, TMC_STS);
	} while ((reg & STS_TMCREADY) == 0);

	bus_write_4(sc->res, TMC_MODE, MODE_HW_FIFO);
	bus_write_4(sc->res, TMC_FFCR, FFCR_EN_FMT | FFCR_EN_TI);
	bus_write_4(sc->res, TMC_BUFWM, 0x800-1);

	tmc_enable0(sc);

	printf("%s: STS %x, CTL %x, RSZ %x, RRP %x, RWP %x, LBUFLEVEL %x, CBUFLEVEL %x, \n", __func__,
	    bus_read_4(sc->res, TMC_STS),
	    bus_read_4(sc->res, TMC_CTL),
	    bus_read_4(sc->res, TMC_RSZ),
	    bus_read_4(sc->res, TMC_RRP),
	    bus_read_4(sc->res, TMC_RWP),
	    bus_read_4(sc->res, TMC_CBUFLEVEL),
	    bus_read_4(sc->res, TMC_LBUFLEVEL));

	return (0);
}

static int
tmc_configure_etr(device_t dev, uint32_t low, uint32_t high,
    uint32_t bufsize)
{
	struct tmc_softc *sc;
	uint32_t reg;
 
	sc = device_get_softc(dev);

	printf("%s unit %d\n", __func__, device_get_unit(dev));

	tmc_unlock(sc);

	do {
		reg = bus_read_4(sc->res, TMC_STS);
	} while ((reg & STS_TMCREADY) == 0);

	/* Configure TMC */
	bus_write_4(sc->res, TMC_MODE, MODE_CIRCULAR_BUFFER);

	reg = AXICTL_PROT_CTRL_BIT1;
	reg |= AXICTL_WRBURSTLEN_16;

	/*
	 * SG operation is broken on DragonBoard 410c
	 * reg |= AXICTL_SG_MODE;
	 */

	reg |= AXICTL_AXCACHE_OS;
	bus_write_4(sc->res, TMC_AXICTL, reg);

	reg = FFCR_EN_FMT | FFCR_EN_TI | FFCR_FON_FLIN |
	    FFCR_FON_TRIG_EVT | FFCR_TRIGON_TRIGIN;
	bus_write_4(sc->res, TMC_FFCR, reg);

	bus_write_4(sc->res, TMC_TRG, 8);

	bus_write_4(sc->res, TMC_DBALO, low);
	bus_write_4(sc->res, TMC_DBAHI, high);

	//?
	bus_write_4(sc->res, TMC_RSZ, bufsize / 4); // size in 32bit words
	//bus_write_4(sc->res, TMC_RRP, low);
	//bus_write_4(sc->res, TMC_RWP, low);

	reg = bus_read_4(sc->res, TMC_STS);
	reg &= ~STS_FULL;
	bus_write_4(sc->res, TMC_STS, reg);

	sc->cycle = 0;

	return (0);
}

static int
tmc_enable(struct coresight_device *out, struct endpoint *endp)
{

	printf("%s\n", __func__);

	return (0);
}

static void
tmc_disable(void)
{

	printf("%s\n", __func__);
}

static struct coresight_ops_sink ops = {
	.enable = &tmc_enable,
	.disable = &tmc_disable,
};

static struct coresight_ops tmc_cs_ops = {
	.sink_ops = &ops,
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

	sc->dev = dev;

	if (bus_alloc_resources(dev, tmc_spec, &sc->res) != 0) {
		device_printf(dev, "cannot allocate resources for device\n");
		return (ENXIO);
	}

	sc->pdata = coresight_get_platform_data(dev);

	printf("%s: DEVID %x\n", __func__, bus_read_4(sc->res, TMC_DEVID));

	struct coresight_desc desc;
	desc.pdata = sc->pdata;
	desc.dev = dev;
	desc.ops = &tmc_cs_ops;

	uint32_t reg;
	reg = bus_read_4(sc->res, TMC_DEVID);
	reg &= DEVID_CONFIGTYPE_M;
	switch (reg) {
	case DEVID_CONFIGTYPE_ETR:
		desc.dev_type = CORESIGHT_ETR;
		coresight_register(&desc);
		printf("ETR configuration found, unit %d\n", device_get_unit(dev));
		break;
	case DEVID_CONFIGTYPE_ETF:
		desc.dev_type = CORESIGHT_ETF;
		coresight_register(&desc);
		tmc_configure_etf(dev);
		printf("ETF configuration found, unit %d\n", device_get_unit(dev));
		break;
	default:
		break;
	}

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
tmc_read_trace(device_t dev, uint64_t *cycle, uint64_t *offset)
{
	struct tmc_softc *sc;
 
	sc = device_get_softc(dev);

#if 0
	printf("%s: STS %x, CTL %x, RSZ %x, RRP %x, RWP %x, LBUFLEVEL %x, CBUFLEVEL %x, RRD %x\n", __func__,
	    bus_read_4(sc->res, TMC_STS),
	    bus_read_4(sc->res, TMC_CTL),
	    bus_read_4(sc->res, TMC_RSZ),
	    bus_read_4(sc->res, TMC_RRP),
	    bus_read_4(sc->res, TMC_RWP),
	    bus_read_4(sc->res, TMC_CBUFLEVEL),
	    bus_read_4(sc->res, TMC_LBUFLEVEL),
	    bus_read_4(sc->res, TMC_RRD));
#endif
	printf("%s%d: STS %x, CTL %x, RSZ %x, RRP %x, RWP %x, LBUFLEVEL %x, CBUFLEVEL %x, \n", __func__,
	    device_get_unit(dev),
	    bus_read_4(sc->res, TMC_STS),
	    bus_read_4(sc->res, TMC_CTL),
	    bus_read_4(sc->res, TMC_RSZ),
	    bus_read_4(sc->res, TMC_RRP),
	    bus_read_4(sc->res, TMC_RWP),
	    bus_read_4(sc->res, TMC_CBUFLEVEL),
	    bus_read_4(sc->res, TMC_LBUFLEVEL));

	uint32_t base_ptr;
	uint32_t cur_ptr;
	base_ptr = bus_read_4(sc->res, TMC_RRP);
	cur_ptr = bus_read_4(sc->res, TMC_RWP);

	if (bus_read_4(sc->res, TMC_STS) & STS_FULL) {
		sc->cycle++;
		if (offset != NULL)
			*offset = 0;
		tmc_stop(dev);
		tmc_start(dev);
		printf("%s1: STS %x, CTL %x, RSZ %x, RRP %x, RWP %x, LBUFLEVEL %x, CBUFLEVEL %x, \n", __func__,
		    bus_read_4(sc->res, TMC_STS),
		    bus_read_4(sc->res, TMC_CTL),
		    bus_read_4(sc->res, TMC_RSZ),
		    bus_read_4(sc->res, TMC_RRP),
		    bus_read_4(sc->res, TMC_RWP),
		    bus_read_4(sc->res, TMC_CBUFLEVEL),
		    bus_read_4(sc->res, TMC_LBUFLEVEL));
	} else {
		if (offset != NULL)
			*offset = (cur_ptr - base_ptr);
	}

	if (cycle != NULL)
		*cycle = sc->cycle;

	//if (device_get_unit(dev) == 0)
	//	printf("RRD: %x\n", bus_read_4(sc->res, TMC_RRD));

	return (0);
}

static device_method_t tmc_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,			tmc_probe),
	DEVMETHOD(device_attach,		tmc_attach),

	/* TMC interface */
	DEVMETHOD(tmc_configure_etr,	tmc_configure_etr),
	DEVMETHOD(tmc_configure_etf,	tmc_configure_etf),
	DEVMETHOD(tmc_start,		tmc_start),
	DEVMETHOD(tmc_stop,		tmc_stop),
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
