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
#include <sys/kthread.h>
#include <sys/rman.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <machine/bus.h>

#include <dev/fdt/simplebus.h>
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

MALLOC_DEFINE(M_SMD, "SMD", "SMD");

//#include <arm/qualcomm/qcom_smd.h>
extern struct bus_space memmap_bus;

static struct ofw_compat_data compat_data[] = {
	{ "qcom,smd",		1 },
	{ NULL,			0 }
};

struct qcom_smd_softc {
	struct simplebus_softc	sc;
	device_t dev;
	phandle_t node;
	struct resource		*res;
};

struct qcom_smd_softc *qcom_smd_sc;

struct qcom_smd_devinfo {
        struct ofw_bus_devinfo  di_dinfo;
        struct resource_list    di_rl;
};

static const struct ofw_bus_devinfo *
qcom_smd_get_devinfo(device_t bus __unused, device_t child)
{
        struct qcom_smd_devinfo *di;

        di = device_get_ivars(child);
        return (&di->di_dinfo);
}

static int
qcom_smd_probe(device_t dev)
{
	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "Qualcomm Shared Memory Device");

	return (BUS_PROBE_DEFAULT);
}


static int
qcom_smd_attach(device_t dev)
{
	struct qcom_smd_softc *sc;
	device_t gcdev;

	sc = device_get_softc(dev);

	qcom_smd_sc = sc;

	phandle_t node, child, grandchild;
	struct qcom_smd_devinfo *di;
	pcell_t addr_cells, size_cells;

	node = ofw_bus_get_node(dev);
	simplebus_init(dev, node);

	OF_getencprop(node, "#address-cells", &addr_cells,
	    sizeof(addr_cells));
	size_cells = 2;
	OF_getencprop(node, "#size-cells", &size_cells,   
	    sizeof(size_cells));

	for (child = OF_child(node); child != 0;
	    child = OF_peer(child)) {

		for (grandchild = OF_child(child); grandchild != 0;
		    grandchild = OF_peer(grandchild)) {

			/* Allocate and populate devinfo. */
			di = malloc(sizeof(*di), M_SMD, M_WAITOK | M_ZERO);
 
			if (ofw_bus_gen_setup_devinfo(&di->di_dinfo, grandchild)) {
				panic("a");
			}

			/* Initialize and populate resource list. */
			resource_list_init(&di->di_rl);
			ofw_bus_reg_to_rl(dev, grandchild, addr_cells, size_cells,
			    &di->di_rl);

			/* Add newbus device for this FDT node */
			gcdev = device_add_child(dev, NULL, -1);
			if (gcdev == NULL)
				panic("here");

			device_set_ivars(gcdev, di);
		}
	}

	return (bus_generic_attach(dev));
}

static device_method_t qcom_smd_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		qcom_smd_probe),
	DEVMETHOD(device_attach,	qcom_smd_attach),

	DEVMETHOD(ofw_bus_get_devinfo,	qcom_smd_get_devinfo),
	DEVMETHOD(ofw_bus_get_compat,   ofw_bus_gen_get_compat),
	DEVMETHOD(ofw_bus_get_model,	ofw_bus_gen_get_model),
	DEVMETHOD(ofw_bus_get_name,	ofw_bus_gen_get_name),
	DEVMETHOD(ofw_bus_get_node,	ofw_bus_gen_get_node),
	DEVMETHOD(ofw_bus_get_type,	ofw_bus_gen_get_type),

	DEVMETHOD_END
};

static driver_t qcom_smd_driver = {
	"qcom_smd",
	qcom_smd_methods,
	sizeof(struct qcom_smd_softc),
};

devclass_t qcom_smd_devclass;

EARLY_DRIVER_MODULE(qcom_smd, simplebus, qcom_smd_driver, qcom_smd_devclass,
    0, 0, BUS_PASS_BUS + BUS_PASS_ORDER_MIDDLE);
MODULE_VERSION(qcom_smd, 1);
