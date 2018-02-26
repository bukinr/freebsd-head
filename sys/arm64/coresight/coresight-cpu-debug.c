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

#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#define EDPCSR                          0x0A0
#define EDCIDSR                         0x0A4
#define EDVIDSR                         0x0A8
#define EDPCSR_HI                       0x0AC
#define EDOSLAR                         0x300
#define EDPRCR                          0x310
/* bits definition for EDPRCR */
#define EDPRCR_COREPURQ                 (1 << 3)
#define EDPRCR_CORENPDRQ                (1 << 0)

#define EDPRSR                          0x314
#define EDDEVID1                        0xFC4
#define EDDEVID                         0xFC8

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
	{ "arm,coresight-cpu-debug",		1 },
	{ NULL,					0 }
};

struct debug_softc {
	struct resource		*res;
};

struct debug_softc *debug_sc;

static struct resource_spec debug_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ -1, 0 }
};

static int
debug_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "Coresight CPU Debug");

	return (BUS_PROBE_DEFAULT);
}

static int
debug_attach(device_t dev)
{
	struct debug_softc *sc;
	uint32_t reg;

	sc = device_get_softc(dev);

	if (bus_alloc_resources(dev, debug_spec, &sc->res) != 0) {
		device_printf(dev, "cannot allocate resources for device\n");
		return (ENXIO);
	}

	if (debug_sc != NULL)
		return (0);

	debug_sc = sc;

	/* Unlock Coresight */
	bus_write_4(sc->res, CORESIGHT_LAR, CORESIGHT_UNLOCK);

	wmb();

	/* Unlock Debug */
	bus_write_4(sc->res, EDOSLAR, 0);

	wmb();

	/* Enable power */
	reg = bus_read_4(sc->res, EDPRCR);
	reg |= EDPRCR_COREPURQ;
	bus_write_4(sc->res, EDPRCR, reg);

	do {
		reg = bus_read_4(sc->res, EDPRSR);
	} while ((reg & EDPRCR_CORENPDRQ) == 0);

	return (0);
}

static device_method_t debug_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		debug_probe),
	DEVMETHOD(device_attach,	debug_attach),
	DEVMETHOD_END
};

static driver_t debug_driver = {
	"debug",
	debug_methods,
	sizeof(struct debug_softc),
};

static devclass_t debug_devclass;

EARLY_DRIVER_MODULE(debug, simplebus, debug_driver, debug_devclass,
    0, 0, BUS_PASS_BUS + BUS_PASS_ORDER_LATE);
MODULE_VERSION(debug, 1);
