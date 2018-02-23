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

#include <arm64/coresight/coresight.h>
#include <arm64/coresight/etm4x.h>

#define CORESIGHT_LAR           0xfb0
#define CORESIGHT_LSR           0xfb4
#define CORESIGHT_AUTHSTATUS    0xfb8
#define CORESIGHT_DEVID         0xfc8
#define CORESIGHT_DEVTYPE       0xfcc
   
#define CORESIGHT_UNLOCK        0xc5acce55

/*
 * Typical trace flow:
 *
 * CPU0 -> ETM0 -> funnel1 -> funnel0 -> TMC(ETF) -> replicator -> TMC(ETR) -> DRAM
 * CPU1 -> ETM1 -> funnel1 -^
 * CPU2 -> ETM2 -> funnel1 -^
 * CPU3 -> ETM3 -> funnel1 -^
 */

static struct ofw_compat_data compat_data[] = {
	{ "arm,coresight-etm4x",		1 },
	{ NULL,					0 }
};

struct etm_softc {
	struct resource			*res;
	struct coresight_platform_data	*pdata;
};

static struct resource_spec etm_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ -1, 0 }
};

static void
etm_print_version(struct etm_softc *sc)
{
	uint32_t reg;

	/* Unlocking Coresight */
	bus_write_4(sc->res, CORESIGHT_LAR, CORESIGHT_UNLOCK);

	isb();

	/* Unlocking ETM */
	bus_write_4(sc->res, TRCOSLAR, 0);

	isb();

	return;

	reg = bus_read_4(sc->res, TRCIDR(1));
	printf("ETM Version: %d.%d\n",
	    (reg & TRCIDR1_TRCARCHMAJ_M) >> TRCIDR1_TRCARCHMAJ_S,
	    (reg & TRCIDR1_TRCARCHMIN_M) >> TRCIDR1_TRCARCHMIN_S);
}

static int
etm_start(device_t dev)
{
	struct etm_softc *sc;
	uint32_t reg;

	sc = device_get_softc(dev);

	printf("%s\n", __func__);

	/* Enable the trace unit */
	bus_write_4(sc->res, TRCPRGCTLR, 1);

	/* Wait for an IDLE bit to be LOW */
	do {
		reg = bus_read_4(sc->res, TRCSTATR);
		//printf(".");
	} while ((reg & TRCSTATR_IDLE) == 1);

	if ((bus_read_4(sc->res, TRCPRGCTLR) & 1) == 0)
		panic("etm is not enabled\n");

	return (0);
}

static int
etm_stop(device_t dev)
{
	struct etm_softc *sc;
	uint32_t reg;

	sc = device_get_softc(dev);

	printf("%s\n", __func__);

	/* Disable the trace unit */
	bus_write_4(sc->res, TRCPRGCTLR, 0);

	/* Wait for an IDLE bit */
	do {
		reg = bus_read_4(sc->res, TRCSTATR);
	} while ((reg & TRCSTATR_IDLE) == 0);

	return (0);
}

static int
etm_prepare(struct coresight_device *out, struct coresight_event *config)
{
	struct etm_softc *sc;
	uint32_t reg;

	printf("%s\n", __func__);

	sc = device_get_softc(out->dev);

	//device_t out_dev;
	//out_dev = coresight_get_output_device(sc->pdata);
	//printf("out_dev %lx\n", (uint64_t)out_dev);

	etm_print_version(sc);

	//etm_stop(out->dev);

	/* Configure ETM */

	/* Enable the return stack, global timestamping, Context ID, and Virtual context identifier tracing. */
	//reg = TRCCONFIGR_RS | TRCCONFIGR_TS | TRCCONFIGR_CID | TRCCONFIGR_VMID;
	//reg = 0x18C1;
	//reg = 0x00031FC7; /* Enable all the options except cycle counting and branch broadcast. */

	reg = TRCCONFIGR_RS | TRCCONFIGR_CID | TRCCONFIGR_VMID;
	reg |= TRCCONFIGR_COND_ALL;
	reg |= TRCCONFIGR_INSTP0_LDRSTR;
	reg = 0x00031FC7; /* Enable all the options except cycle counting and branch broadcast. */
	bus_write_4(sc->res, TRCCONFIGR, reg);

	/* Disable all event tracing. */
	bus_write_4(sc->res, TRCEVENTCTL0R, 0);
	bus_write_4(sc->res, TRCEVENTCTL1R, 0);

	/* Disable stalling, if implemented. */
	bus_write_4(sc->res, TRCSTALLCTLR, 0);

	/* Enable trace synchronization every 4096 bytes of trace. */
	bus_write_4(sc->res, TRCSYNCPR, 0xC);

	/* Set a value for the trace ID, with bit[0]=0. */
	bus_write_4(sc->res, TRCTRACEIDR, 0x10);

	/*
	 * Disable the timestamp event. The trace unit still generates
	 * timestamps due to other reasons such as trace synchronization.
	 */
	bus_write_4(sc->res, TRCTSCTLR, 0);

	/* Enable ViewInst to trace everything, with the start/stop logic started. */
	reg = 0x201;
	//reg = TRCVICTLR_SSSTATUS;
	//reg |= 1;

	if (config->excp_level > 2)
		return (-1);

	//printf("%s: Configure exception level %d\n", __func__, config->excp_level);

	reg |= TRCVICTLR_EXLEVEL_NS_M;
	reg &= ~TRCVICTLR_EXLEVEL_NS(config->excp_level);
	reg |= TRCVICTLR_EXLEVEL_S_M;
	reg &= ~TRCVICTLR_EXLEVEL_S(config->excp_level);
	bus_write_4(sc->res, TRCVICTLR, reg);

	bus_write_4(sc->res, TRCRSCTLR(0), (5 << 16) | (1 << 0));

	int i;
	for (i = 0; i < config->naddr * 2; i++) {
		printf("configure range %d, address %lx\n", i, config->addr[i]);
		bus_write_8(sc->res, TRCACVR(i), config->addr[i]);

		reg = 0;
		/* Secure state */
		reg |= TRCACATR_EXLEVEL_S_M;
		reg &= ~TRCACATR_EXLEVEL_S(config->excp_level);
		/* Non-secure state */
		reg |= TRCACATR_EXLEVEL_NS_M;
		reg &= ~TRCACATR_EXLEVEL_NS(config->excp_level);
		bus_write_4(sc->res, TRCACATR(i), reg);
	}

	/* No address filtering for ViewData. */
	bus_write_4(sc->res, TRCVDARCCTLR, 0);

	/* Clear the STATUS bit to zero */
	bus_write_4(sc->res, TRCSSCSR(0), 0);

	/* No address range filtering for ViewInst. */
	if (config->naddr == 0)
		bus_write_4(sc->res, TRCVIIECTLR, 0);
	else
		bus_write_4(sc->res, TRCVIIECTLR, (1 << 0));

	/* No start or stop points for ViewInst. */
	bus_write_4(sc->res, TRCVISSCTLR, 0);

	/* Disable ViewData */
	bus_write_4(sc->res, TRCVDCTLR, 0);

	/* No address filtering for ViewData. */
	bus_write_4(sc->res, TRCVDSACCTLR, 0);

	return (0);
}

static int
etm_enable(struct coresight_device *out, struct coresight_event *config)
{

	printf("%s\n", __func__);

	etm_start(out->dev);

	return (0);
}

static int
etm_disable(struct coresight_device *out)
{

	printf("%s\n", __func__);

	etm_stop(out->dev);

	return (0);
}

static struct coresight_ops_source ops = {
	.prepare = &etm_prepare,
	.enable = &etm_enable,
	.disable = &etm_disable,
};

static struct coresight_ops etmv4_cs_ops = {
	.source_ops = &ops,
};

static int
etm_probe(device_t dev)
{
	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "AArch64 Embedded Trace Macrocell");

	return (BUS_PROBE_DEFAULT);
}

static int
etm_attach(device_t dev)
{
	struct etm_softc *sc;

	sc = device_get_softc(dev);

	if (bus_alloc_resources(dev, etm_spec, &sc->res) != 0) {
		device_printf(dev, "cannot allocate resources for device\n");
		return (ENXIO);
	}

	if (device_get_unit(dev) == 0) {
		int i;
		for (i = 0; i < 14; i++)
			printf("TRCIDR%d: %x\n", i, bus_read_4(sc->res, TRCIDR(i)));
	}

	sc->pdata = coresight_get_platform_data(dev);

	struct coresight_desc desc;
	desc.pdata = sc->pdata;
	desc.dev = dev;
	desc.dev_type = CORESIGHT_ETMV4;
	desc.ops = &etmv4_cs_ops;
	coresight_register(&desc);

	return (0);
}

static device_method_t etm_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		etm_probe),
	DEVMETHOD(device_attach,	etm_attach),
	DEVMETHOD_END
};

static driver_t etm_driver = {
	"etm",
	etm_methods,
	sizeof(struct etm_softc),
};

static devclass_t etm_devclass;

DRIVER_MODULE(etm, simplebus, etm_driver, etm_devclass, 0, 0);
MODULE_VERSION(etm, 1);
