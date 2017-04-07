/*-
 * Copyright (c) 2013 SRI International
 * Copyright (c) 2017 Ruslan Bukin <br@bsdpad.com>
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
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "opt_platform.h"

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/systm.h>
#include <sys/bus.h>

#include <sys/proc.h>

#include <machine/bus.h>
#include <machine/intr.h>

#include <dev/fdt/fdt_common.h>
#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include "pic_if.h"

struct beripic_softc;

#if 0
static uint64_t	bp_read_cfg(struct beripic_softc *, int);
static void	bp_write_cfg(struct beripic_softc *, int, uint64_t);
#endif

struct beri_pic_isrc {
	struct intr_irqsrc isrc;
	u_int irq;
};

#define	BP_MAX_HARD_IRQS	6
#define	BP_FIRST_SOFT		64

struct hirq {
	uint32_t		irq;
	struct beripic_softc	*sc;
};

struct beripic_softc {
	device_t		dev;

#if 0
	device_t		bp_dev;
	struct resource		*bp_cfg_res;
	struct resource		*bp_read_res;
	struct resource		*bp_set_res;
	struct resource		*bp_clear_res;
	int			bp_cfg_rid;
	int			bp_read_rid;
	int			bp_set_rid;
	int			bp_clear_rid;
	bus_space_tag_t		bp_cfg_bst;
	bus_space_tag_t		bp_read_bst;
	bus_space_tag_t		bp_set_bst;
	bus_space_tag_t		bp_clear_bst;
	bus_space_handle_t	bp_cfg_bsh;
	bus_space_handle_t	bp_read_bsh;
	bus_space_handle_t	bp_set_bsh;
	bus_space_handle_t	bp_clear_bsh;

	struct resource		*bp_irqs[BP_MAX_HARD_IRQS];
	int			bp_irq_rids[BP_MAX_HARD_IRQS];
	int			bp_nirqs;
	int			bp_next_irq;
	int			bp_next_tid;

	int			bp_nthreads;

	int			bp_nhard;
	int			bp_nsoft;
	int			bp_nsrcs;
	struct rman		bp_src_rman;

#ifdef __mips__
	//mips_intrcnt_t		*bp_counters;
#endif
#endif

	struct mtx		bp_cfgmtx;

	uint32_t		nirqs;
	struct beri_pic_isrc	irqs[64];
	struct resource		*res[9];
	void			*ih[5];
	struct hirq		hirq[5];
};

struct beripic_intr_arg {
	driver_filter_t		*filter;
	driver_intr_t		*intr;
	void			*arg;
	struct resource		*irq;
#ifdef __mips__
	////mips_intrcnt_t		counter;
#endif
};

struct beripic_cookie {
	struct beripic_intr_arg	*bpia;
	struct resource		*hirq;
	void			*cookie;
};

#define	BP_CFG_MASK_E		0x80000000ull
#define	BP_CFG_SHIFT_E		31
#define	BP_CFG_MASK_TID		0x7FFFFF00ull	/* Depends on CPU */
#define	BP_CFG_SHIFT_TID	8
#define	BP_CFG_MASK_IRQ		0x0000000Full
#define BP_CFG_SHIFT_IRQ	0
#define	BP_CFG_VALID		(BP_CFG_MASK_E|BP_CFG_MASK_TID|BP_CFG_MASK_IRQ)
#define	BP_CFG_RESERVED		~BP_CFG_VALID

#define	BP_CFG_ENABLED(cfg)	(((cfg) & BP_CFG_MASK_E) >> BP_CFG_SHIFT_E)
#define	BP_CFG_TID(cfg)		(((cfg) & BP_CFG_MASK_TID) >> BP_CFG_SHIFT_TID)
#define	BP_CFG_IRQ(cfg)		(((cfg) & BP_CFG_MASK_IRQ) >> BP_CFG_SHIFT_IRQ)

MALLOC_DEFINE(M_BERIPIC, "beripic", "beripic memory");

static struct resource_spec beri_pic_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ SYS_RES_MEMORY,	1,	RF_ACTIVE },
	{ SYS_RES_MEMORY,	2,	RF_ACTIVE },
	{ SYS_RES_MEMORY,	3,	RF_ACTIVE },
	{ SYS_RES_IRQ,		0,	RF_ACTIVE },
	{ SYS_RES_IRQ,		1,	RF_ACTIVE },
	{ SYS_RES_IRQ,		2,	RF_ACTIVE },
	{ SYS_RES_IRQ,		3,	RF_ACTIVE },
	{ SYS_RES_IRQ,		4,	RF_ACTIVE },
	{ -1, 0 }
};

#if 0
static uint64_t
bp_read_cfg(struct beripic_softc *sc, int irq)
{
	
	KASSERT((irq >= 0 && irq < sc->bp_nsrcs),
	    ("IRQ of of range %d (0-%d)", irq, sc->bp_nsrcs - 1));
	return (bus_space_read_8(sc->bp_cfg_bst, sc->bp_cfg_bsh, irq * 8));
}

static void
bp_write_cfg(struct beripic_softc *sc, int irq, uint64_t config)
{
	
	KASSERT((irq >= 0 && irq < sc->bp_nsrcs),
	    ("IRQ of of range %d (0-%d)", irq, sc->bp_nsrcs - 1));
	bus_space_write_8(sc->bp_cfg_bst, sc->bp_cfg_bsh, irq * 8, config);
}

static void
bp_config_source(device_t ic, int src, int enable, u_long tid, u_long irq)
{
	struct beripic_softc *sc;
	uint64_t config;

	sc = device_get_softc(ic);

	config = 0;
	config |= enable << BP_CFG_SHIFT_E;
	config |= tid << BP_CFG_SHIFT_TID;
	config |= irq << BP_CFG_SHIFT_IRQ;

	bp_write_cfg(sc, src, config);
}
#endif

static int
beri_pic_intr(void *arg)
{
	struct hirq *h;
	struct beripic_softc *sc;
	struct intr_irqsrc *isrc;
	//uint64_t reg;
	struct thread *td;

	td = curthread;
	td->td_intr_nesting_level--;

	h = arg;
	sc = h->sc;

#if 0
	reg = bus_read_8(sc->res[0], 0);
	printf("%s: %x\n", __func__, reg);
	reg = bus_read_8(sc->res[0], 8);
	printf("%s: %x\n", __func__, reg);
#endif

	int i;

#if 0
	printf("%s(%d):", __func__, h->irq);
	for (i = 0; i < 16; i++) {
		printf(" %lx", bus_read_8(sc->res[0], 0x8 * i));
	}
	printf("\n");
#endif

	uint64_t intr;

	intr = bus_read_8(sc->res[1], 0);
	while ((i = fls(intr)) != 0) {
		i--;
		intr &= ~(1u << i);

		isrc = &sc->irqs[i].isrc;
		//printf("intr %d, pending %lx\n", i, reg);

		if (intr_isrc_dispatch(isrc, curthread->td_intr_frame) != 0) {
			device_printf(sc->dev, "Stray interrupt %u detected\n", i);
		}

		bus_write_8(sc->res[3], 0, (1 << i));
	}

	return (0);
}

static int
beripic_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (!ofw_bus_is_compatible(dev, "sri-cambridge,beri-pic"))
		return (ENXIO);
		
	device_set_desc(dev, "BERI Programmable Interrupt Controller (INTRNG)");

	return (BUS_PROBE_DEFAULT);
}

static int
beripic_attach(device_t dev)
{
	struct beripic_softc *sc;
	intptr_t xref;
	int i;

	sc = device_get_softc(dev);
	sc->dev = dev;

	if (bus_alloc_resources(dev, beri_pic_spec, sc->res)) {
		device_printf(dev, "could not allocate resources\n");
		return (ENXIO);
	}

	xref = OF_xref_from_node(ofw_bus_get_node(dev));

	const char *name;
	struct intr_irqsrc *isrc;
	int err;

	name = device_get_nameunit(dev);
	sc->nirqs = 16; //nitems(sc->pic_irqs);
	printf("nirqs %d\n", sc->nirqs);

	for (i = 0; i < sc->nirqs; i++) {
		sc->irqs[i].irq = i;
		isrc = &sc->irqs[i].isrc;
		err = intr_isrc_register(isrc, sc->dev,
		    0, "%s,i%u", name, i);
		bus_write_8(sc->res[0], i * 8, 0);
	}

	/*
	 * Now, when everything is initialized, it's right time to
	 * register interrupt controller to interrupt framefork.
	 */
	if (intr_pic_register(dev, xref) == NULL) {
		device_printf(dev, "could not register PIC\n");
		//goto cleanup;
	}

	for (i = 3; i < 4; i++) {
		sc->hirq[i].sc = sc;
		sc->hirq[i].irq = i;
		if (bus_setup_intr(dev, sc->res[4+i], INTR_TYPE_CLK,
		    beri_pic_intr, NULL, &sc->hirq[i], sc->ih[i])) {
			device_printf(dev, "could not setup irq handler\n");
			intr_pic_deregister(dev, xref);
			//goto cleanup;
			return (ENXIO);
		}
	}

	mtx_init(&sc->bp_cfgmtx, "beripic config lock", NULL, MTX_DEF);

	return (0);
}

static void
beri_pic_enable_intr(device_t dev, struct intr_irqsrc *isrc)
{
	struct beri_pic_isrc *pic_isrc;
	struct beripic_softc *sc;
	uint64_t reg;

	sc = device_get_softc(dev);
	pic_isrc = (struct beri_pic_isrc *)isrc;

	//printf("%s: %d\n", __func__, pic_isrc->irq);

	reg = (1 << BP_CFG_SHIFT_E);
	reg |= (1 << BP_CFG_SHIFT_IRQ);

	if (pic_isrc->irq == 0) {
		//return;
	}

	bus_write_8(sc->res[0], pic_isrc->irq * 8, reg);
}

static void
beri_pic_disable_intr(device_t dev, struct intr_irqsrc *isrc)
{
	struct beri_pic_isrc *pic_isrc;
	struct beripic_softc *sc;
	uint64_t reg;

	sc = device_get_softc(dev);
	pic_isrc = (struct beri_pic_isrc *)isrc;

	//printf("%s: %d\n", __func__, pic_isrc->irq);

	if (pic_isrc->irq == 0) {
		//return;
	}

	reg = bus_read_8(sc->res[0], pic_isrc->irq * 8);
	reg &= ~(1 << BP_CFG_SHIFT_E);
	bus_write_8(sc->res[0], pic_isrc->irq * 8, reg);

	bus_write_8(sc->res[3], pic_isrc->irq * 8, 1);
}

static int
beri_pic_map_intr(device_t dev, struct intr_map_data *data,
        struct intr_irqsrc **isrcp)
{
	struct beripic_softc *sc;
	struct intr_map_data_fdt *daf;

	printf("%s\n", __func__);

	sc = device_get_softc(dev);
	daf = (struct intr_map_data_fdt *)data;

	if (data == NULL || data->type != INTR_MAP_DATA_FDT ||
	    daf->ncells != 1 || daf->cells[0] >= sc->nirqs)
		return (EINVAL);

	uint32_t irq;
	irq = daf->cells[0];
	printf("%s: irq %d\n", __func__, irq);

	*isrcp = &sc->irqs[irq].isrc;

	return (0);
}

static void
beri_pic_post_ithread(device_t dev, struct intr_irqsrc *isrc)
{

	//printf("%s\n", __func__);
	beri_pic_enable_intr(dev, isrc);
}

static void
beri_pic_pre_ithread(device_t dev, struct intr_irqsrc *isrc)
{

	//printf("%s\n", __func__);
	beri_pic_disable_intr(dev, isrc);
}

static device_method_t beripic_fdt_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		beripic_probe),
	DEVMETHOD(device_attach,	beripic_attach),

	/* Interrupt controller interface */
	DEVMETHOD(pic_enable_intr,	beri_pic_enable_intr),
	DEVMETHOD(pic_disable_intr,	beri_pic_disable_intr),
	DEVMETHOD(pic_map_intr,		beri_pic_map_intr),
	DEVMETHOD(pic_post_ithread,	beri_pic_post_ithread),
	DEVMETHOD(pic_pre_ithread,	beri_pic_pre_ithread),

	DEVMETHOD_END
};

devclass_t beripic_devclass;

static driver_t beripic_driver = {
	"beripic",
	beripic_fdt_methods,
	sizeof(struct beripic_softc)
};

EARLY_DRIVER_MODULE(beripic, ofwbus, beripic_driver, beripic_devclass, 0, 0,
    BUS_PASS_INTERRUPT + BUS_PASS_ORDER_MIDDLE);
