/*-
 * Copyright (c) 2014-2017 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
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

/*
 * SOCFPGA Reset Manager.
 * Chapter 3, Cyclone V Device Handbook (CV-5V2 2014.07.22)
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
#include <sys/sysctl.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <machine/bus.h>
#include <machine/fdt.h>
#include <machine/cpu.h>
#include <machine/intr.h>

#include <arm/altera/socfpga/socfpga_common.h>
#include <arm/altera/socfpga/socfpga_rstmgr.h>
#include <arm/altera/socfpga/socfpga_l3regs.h>
#include <arm/altera/socfpga/socfpga_sysmgr.h>

struct sysmgr_softc {
	struct resource		*res[1];
	bus_space_tag_t		bst;
	bus_space_handle_t	bsh;
	device_t		dev;
};

struct sysmgr_softc *sysmgr_sc;

static struct resource_spec sysmgr_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ -1, 0 }
};

#if 0
enum {
	RSTMGR_SYSCTL_FPGA2HPS,
	RSTMGR_SYSCTL_LWHPS2FPGA,
	RSTMGR_SYSCTL_HPS2FPGA
};

static int
l3remap(struct sysmgr_softc *sc, int remap, int enable)
{
	uint32_t paddr;
	bus_addr_t vaddr;
	phandle_t node;
	int reg;

	return (0);

	/*
	 * Control whether bridge is visible to L3 masters or not.
	 * Register is write-only.
	 */

	reg = REMAP_MPUZERO;
	if (enable)
		reg |= (remap);
	else
		reg &= ~(remap);

	node = OF_finddevice("l3regs");
	if (node == -1) {
		device_printf(sc->dev, "Can't find l3regs node\n");
		return (1);
	}

	if ((OF_getencprop(node, "reg", &paddr, sizeof(paddr))) > 0) {
		if (bus_space_map(fdtbus_bs_tag, paddr, 0x4, 0, &vaddr) == 0) {
			bus_space_write_4(fdtbus_bs_tag, vaddr,
			    L3REGS_REMAP, reg);
			return (0);
		}
	}

	return (1);
}

static int
sysmgr_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct sysmgr_softc *sc;
	int enable;
	int remap;
	int err;
	int reg;
	int bit;

	sc = arg1;

	switch (arg2) {
	case RSTMGR_SYSCTL_FPGA2HPS:
		bit = BRGMODRST_FPGA2HPS;
		remap = 0;
		break;
	case RSTMGR_SYSCTL_LWHPS2FPGA:
		bit = BRGMODRST_LWHPS2FPGA;
		remap = REMAP_LWHPS2FPGA;
		break;
	case RSTMGR_SYSCTL_HPS2FPGA:
		bit = BRGMODRST_HPS2FPGA;
		remap = REMAP_HPS2FPGA;
		break;
	default:
		return (1);
	}

	reg = READ4(sc, RSTMGR_BRGMODRST);
	enable = reg & bit ? 0 : 1;

	err = sysctl_handle_int(oidp, &enable, 0, req);
	if (err || !req->newptr)
		return (err);

	if (enable == 1)
		reg &= ~(bit);
	else if (enable == 0)
		reg |= (bit);
	else
		return (EINVAL);

	WRITE4(sc, RSTMGR_BRGMODRST, reg);
	l3remap(sc, remap, enable);

	return (0);
}

int
sysmgr_warmreset(uint32_t reg)
{
	struct sysmgr_softc *sc;

	sc = sysmgr_sc;
	if (sc == NULL)
		return (1);

	/* Request warm reset */
	WRITE4(sc, reg, CTRL_SWWARMRSTREQ);

	return (0);
}

static int
sysmgr_add_sysctl(struct sysmgr_softc *sc)
{
	struct sysctl_oid_list *children;
	struct sysctl_ctx_list *ctx;

	ctx = device_get_sysctl_ctx(sc->dev);
	children = SYSCTL_CHILDREN(device_get_sysctl_tree(sc->dev));

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "fpga2hps",
	    CTLTYPE_UINT | CTLFLAG_RW, sc, RSTMGR_SYSCTL_FPGA2HPS,
	    sysmgr_sysctl, "I", "Enable fpga2hps bridge");
	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "lwhps2fpga",
	    CTLTYPE_UINT | CTLFLAG_RW, sc, RSTMGR_SYSCTL_LWHPS2FPGA,
	    sysmgr_sysctl, "I", "Enable lwhps2fpga bridge");
	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "hps2fpga",
	    CTLTYPE_UINT | CTLFLAG_RW, sc, RSTMGR_SYSCTL_HPS2FPGA,
	    sysmgr_sysctl, "I", "Enable hps2fpga bridge");

	return (0);
}
#endif

static int
sysmgr_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (!ofw_bus_is_compatible(dev, "altr,sys-mgr"))
		return (ENXIO);

	device_set_desc(dev, "System Manager");

	return (BUS_PROBE_DEFAULT);
}

static int
sysmgr_attach(device_t dev)
{
	struct sysmgr_softc *sc;
	uint32_t reg;

	sc = device_get_softc(dev);
	sc->dev = dev;

	if (bus_alloc_resources(dev, sysmgr_spec, sc->res)) {
		device_printf(dev, "could not allocate resources\n");
		return (ENXIO);
	}

	/* Memory interface */
	sc->bst = rman_get_bustag(sc->res[0]);
	sc->bsh = rman_get_bushandle(sc->res[0]);

	sysmgr_sc = sc;

	//sysmgr_add_sysctl(sc);
	//return (0);

#if 1
	printf("Disabling bridges\n");
	WRITE4(sc, FPGAINTF_EN_GLOBAL, 0);

	reg = (FPGA2SDRAM2 | FPGA2SDRAM1 | FPGA2SDRAM0);
	reg |= (FPGA2SOC | LWSOC2FPGA | SOC2FPGA);
	WRITE4(sc, NOC_IDLEREQ_SET, reg);

	WRITE4(sc, NOC_TIMEOUT, NOC_TIMEOUT_EN);

	while (READ4(sc, NOC_IDLEACK) ^ reg)
		;
	while (READ4(sc, NOC_IDLESTATUS) ^ reg)
		;

#endif

	rstmgr_a10_reset();

#if 1
	WRITE4(sc, NOC_TIMEOUT, 0);
#endif

	return (0);
}

static device_method_t sysmgr_methods[] = {
	DEVMETHOD(device_probe,		sysmgr_probe),
	DEVMETHOD(device_attach,	sysmgr_attach),
	{ 0, 0 }
};

static driver_t sysmgr_driver = {
	"sysmgr",
	sysmgr_methods,
	sizeof(struct sysmgr_softc),
};

static devclass_t sysmgr_devclass;

DRIVER_MODULE(sysmgr, simplebus, sysmgr_driver, sysmgr_devclass, 0, 0);
