/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
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
#include <sys/endian.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <machine/bus.h>
#include <machine/cpu.h>
#include <machine/intr.h>

#include <mips/beri/beri_iommu.h>

struct beri_iommu_softc {
	struct resource		*res[3];
	device_t		dev;
	bus_space_tag_t		bst_data;
	bus_space_handle_t	bsh_data;
	uint32_t		offs;
};

struct beri_iommu_softc *beri_iommu_sc;

static struct resource_spec beri_iommu_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ -1, 0 }
};

void
beri_iommu_invalidate(vm_offset_t addr)
{
	struct beri_iommu_softc *sc;

	sc = beri_iommu_sc;
	if (sc == NULL)
		return;

	bus_write_8(sc->res[0], 0x0, htole64(addr));
}

static int
beri_iommu_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (!ofw_bus_is_compatible(dev, "beri,iommu"))
		return (ENXIO);

	device_set_desc(dev, "BERI IOMMU");

	return (BUS_PROBE_DEFAULT);
}

static int
beri_iommu_attach(device_t dev)
{
	struct beri_iommu_softc *sc;

	sc = device_get_softc(dev);
	sc->dev = dev;

	printf("%s: nameunit %s\n", __func__, device_get_nameunit(sc->dev));

	if (bus_alloc_resources(dev, beri_iommu_spec, sc->res)) {
		device_printf(dev, "could not allocate resources\n");
		return (ENXIO);
	}

	/* Memory interface */
	sc->bst_data = rman_get_bustag(sc->res[0]);
	sc->bsh_data = rman_get_bushandle(sc->res[0]);

	beri_iommu_sc = sc;

	return (0);
}

static int
beri_iommu_detach(device_t dev)
{
	struct beri_iommu_softc *sc;

	sc = device_get_softc(dev);

	bus_release_resources(dev, beri_iommu_spec, sc->res);

	return (0);
}

static device_method_t beri_iommu_methods[] = {
	DEVMETHOD(device_probe,		beri_iommu_probe),
	DEVMETHOD(device_attach,	beri_iommu_attach),
	DEVMETHOD(device_detach,	beri_iommu_detach),
	{ 0, 0 }
};

static driver_t beri_iommu_driver = {
	"beri_iommu",
	beri_iommu_methods,
	sizeof(struct beri_iommu_softc),
};

static devclass_t beri_iommu_devclass;

DRIVER_MODULE(beri_iommu, simplebus, beri_iommu_driver,
    beri_iommu_devclass, 0, 0);
