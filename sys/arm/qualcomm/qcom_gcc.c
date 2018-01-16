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

#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

//#include <arm/qualcomm/qcom_gcc.h>

static struct ofw_compat_data compat_data[] = {
	{ "qcom,gcc-msm8916",			1 },
	{ NULL,					0 }
};

struct qcom_gcc_softc {
	struct resource		*res;
};
struct qcom_gcc_softc *qcom_gcc_sc;

static struct resource_spec qcom_gcc_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ -1, 0 }
};

static int
qcom_gcc_probe(device_t dev)
{
	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "Qualcomm Global Clock Controller");

	return (BUS_PROBE_DEFAULT);
}

static int
qcom_gcc_attach(device_t dev)
{
	struct qcom_gcc_softc *sc;

	sc = device_get_softc(dev);

	if (bus_alloc_resources(dev, qcom_gcc_spec, &sc->res) != 0) {
		device_printf(dev, "cannot allocate resources for device\n");
		return (ENXIO);
	}

	qcom_gcc_sc = sc;

#define	GCC_PCNOC_RPM_AHB_CBCR	0x027024

#define	GCC_QDSS_BCR		0x29000
#define	GCC_QDSS_CFG_AHB_CBCR	0x29008
#define	GCC_QDSS_DAP_CBCR	0x29084
#define	GCC_QDSS_ETR_USB_CBCR	0x29028

	bus_write_4(sc->res, GCC_QDSS_BCR, 1);
	DELAY(100000);
	bus_write_4(sc->res, GCC_QDSS_CFG_AHB_CBCR, 1);
	DELAY(100000);
	bus_write_4(sc->res, GCC_QDSS_DAP_CBCR, 1);
	DELAY(100000);
	bus_write_4(sc->res, GCC_QDSS_ETR_USB_CBCR, 1);
	DELAY(100000);
	bus_write_4(sc->res, GCC_QDSS_BCR, 0);

	printf("GCC_PCNOC_RPM_AHB_CBCR %x\n", bus_read_4(sc->res, GCC_PCNOC_RPM_AHB_CBCR));
	return (0);

	int reg;

#define	GCC_GPLL0_MODE	0x21000
#define	GCC_GPLL0_L_VAL	0x21004
#define	GCC_GPLL0_M_VAL	0x21008
#define	GCC_GPLL0_N_VAL	0x2100C

	//bus_write_4(sc->res, GCC_GPLL0_L_VAL, 29);

	reg = bus_read_4(sc->res, GCC_GPLL0_L_VAL);
	printf("GCC_GPLL0_L_VAL: %x\n", reg);
	reg = bus_read_4(sc->res, GCC_GPLL0_M_VAL);
	printf("GCC_GPLL0_M_VAL: %x\n", reg);
	reg = bus_read_4(sc->res, GCC_GPLL0_N_VAL);
	printf("GCC_GPLL0_N_VAL: %x\n", reg);

	reg = bus_read_4(sc->res, GCC_GPLL0_MODE);
	printf("GCC_GPLL0_MODE: %x\n", reg);
	bus_write_4(sc->res, GCC_GPLL0_MODE, reg);

#define	GCC_GPLL1_MODE	0x20000
#define	 PLL_OUTCTRL	(1 << 0)	/* Activate PLL output */
#define	 PLL_BYPASSNL	(1 << 1)	/* Use PLL */
#define	 PLL_RESET_N	(1 << 2)	/* Reset PLL */

	reg = ~(PLL_OUTCTRL | PLL_BYPASSNL | PLL_RESET_N);
	reg = 0;
	bus_write_4(sc->res, GCC_GPLL1_MODE, reg);

#define	GCC_GPLL2_MODE	0x4A000
	bus_write_4(sc->res, GCC_GPLL2_MODE, reg);

	return (0);
}

static device_method_t qcom_gcc_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		qcom_gcc_probe),
	DEVMETHOD(device_attach,	qcom_gcc_attach),

	DEVMETHOD_END
};

static driver_t qcom_gcc_driver = {
	"qcom_gcc",
	qcom_gcc_methods,
	sizeof(struct qcom_gcc_softc),
};

static devclass_t qcom_gcc_devclass;

EARLY_DRIVER_MODULE(qcom_gcc, simplebus, qcom_gcc_driver, qcom_gcc_devclass,
    0, 0, BUS_PASS_BUS + BUS_PASS_ORDER_MIDDLE);
MODULE_VERSION(qcom_gcc, 1);
