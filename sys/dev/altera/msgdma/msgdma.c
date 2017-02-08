/*-
 * Copyright (c) 2016 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
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

/* Altera mSGDMA driver. */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_platform.h"
#include <sys/param.h>
#include <sys/endian.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/sglist.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/resource.h>
#include <sys/rman.h>

#include <machine/bus.h>
#include <machine/fdt.h>
#include <machine/cache.h>

#ifdef FDT
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#endif

#include <dev/xdma/xdma.h>
#include "xdma_if.h"

#include <dev/altera/msgdma/msgdma.h>

#define	MSGDMA_NCHANNELS	1

struct msgdma_channel {
	struct msgdma_softc	*sc;
	struct mtx		mtx;
	xdma_channel_t		*xchan;
	struct proc		*p;
	int			used;
	int			index;
	int			run;
	int			idx_head;
	int			idx_tail;
};

struct msgdma_softc {
	device_t		dev;
	struct resource		*res[3];
	bus_space_tag_t		bst;
	bus_space_handle_t	bsh;
	bus_space_tag_t		bst_d;
	bus_space_handle_t	bsh_d;
	void			*ih;
	struct msgdma_desc	desc;
	struct msgdma_channel	channels[MSGDMA_NCHANNELS];
};

static inline uint32_t
next_idx(xdma_channel_t *xchan, uint32_t curidx)
{
	xdma_config_t *conf;

	conf = &xchan->conf;

	return ((curidx + 1) % conf->block_num);
}

static struct resource_spec msgdma_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ SYS_RES_MEMORY,	1,	RF_ACTIVE },
	{ SYS_RES_IRQ,		0,	RF_ACTIVE },
	{ -1, 0 }
};

#define	HWTYPE_NONE	0
#define	HWTYPE_STD	1

static struct ofw_compat_data compat_data[] = {
	{ "altr,msgdma-16.0",	HWTYPE_STD },
	{ "altr,msgdma-1.0",	HWTYPE_STD },
	{ NULL,			HWTYPE_NONE },
};

static int msgdma_probe(device_t dev);
static int msgdma_attach(device_t dev);
static int msgdma_detach(device_t dev);

static void
msgdma_intr(void *arg)
{
	xdma_transfer_status_t status;
	struct xdma_desc_status st;
	struct msgdma_desc *desc;
	struct msgdma_channel *chan;
	struct xdma_channel *xchan;
	struct msgdma_softc *sc;
	xdma_config_t *conf;
	uint32_t tot_copied;
	uint32_t cnt_done;

	sc = arg;
	chan = &sc->channels[0];
	xchan = chan->xchan;
	conf = &xchan->conf;

	//TAILQ_INIT(&sg_queue);
	//printf("%s(%d): status 0x%08x next_descr 0x%08x, control 0x%08x\n", __func__,
	//    device_get_unit(sc->dev),
	//	READ4_DESC(sc, PF_STATUS),
	//	READ4_DESC(sc, PF_NEXT_LO),
	//	READ4_DESC(sc, PF_CONTROL));
	//len = le32toh(desc->transferred);
	//if (desc->read_lo == 0) {
	//	printf("%s: rx 0x%08x, transferred %d\n", __func__, READ4_DESC(sc, PF_STATUS), len);
	//} else {
	//	printf("%s: tx 0x%08x, transferred %d\n", __func__, READ4_DESC(sc, PF_STATUS), len);
	//}

	cnt_done = 0;
	tot_copied = 0;

	while (chan->idx_tail != chan->idx_head) {
		xdma_enqueue_sync_post(xchan, chan->idx_tail);
		desc = xchan->descs[chan->idx_tail].desc;
		if ((le32toh(desc->control) & CONTROL_OWN) != 0) {
			break;
		}

		//printf("%s(%d) p %d\n", __func__, device_get_unit(sc->dev), chan->idx_tail);

		tot_copied += le32toh(desc->transferred);
		cnt_done++;
		st.error = 0;
		st.transferred = le32toh(desc->transferred);
		xdma_desc_done(xchan, chan->idx_tail, &st);
		chan->idx_tail = next_idx(xchan, chan->idx_tail);
	}

	WRITE4_DESC(sc, PF_STATUS, PF_STATUS_IRQ);

	/* Finish operation */
	//chan->run = 0;
	status.error = 0;
	status.total_copied = tot_copied;
	status.cnt_done = cnt_done;
	xdma_callback(chan->xchan, &status);
}

static int
msgdma_probe(device_t dev)
{
	int hwtype;

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	hwtype = ofw_bus_search_compatible(dev, compat_data)->ocd_data;
	if (hwtype == HWTYPE_NONE)
		return (ENXIO);

	device_set_desc(dev, "Altera mSGDMA");

	return (BUS_PROBE_DEFAULT);
}

static int
msgdma_attach(device_t dev)
{
	struct msgdma_softc *sc;
	phandle_t xref, node;
	int err;

	sc = device_get_softc(dev);
	sc->dev = dev;

	if (bus_alloc_resources(dev, msgdma_spec, sc->res)) {
		device_printf(dev, "could not allocate resources for device\n");
		return (ENXIO);
	}

	/* CSR memory interface */
	sc->bst = rman_get_bustag(sc->res[0]);
	sc->bsh = rman_get_bushandle(sc->res[0]);

	/* Descriptor memory interface */
	sc->bst_d = rman_get_bustag(sc->res[1]);
	sc->bsh_d = rman_get_bushandle(sc->res[1]);

	/* Setup interrupt handler */
	err = bus_setup_intr(dev, sc->res[2], INTR_TYPE_MISC | INTR_MPSAFE,
	    NULL, msgdma_intr, sc, &sc->ih);
	if (err) {
		device_printf(dev, "Unable to alloc interrupt resource.\n");
		return (ENXIO);
	}

	node = ofw_bus_get_node(dev);
	xref = OF_xref_from_node(node);
	OF_device_register_xref(xref, dev);

	printf("%s: read status: %x\n", __func__, READ4(sc, 0x00));
	printf("%s: read control: %x\n", __func__, READ4(sc, 0x04));
	printf("%s: read 1: %x\n", __func__, READ4(sc, 0x08));
	printf("%s: read 2: %x\n", __func__, READ4(sc, 0x0C));

	int timeout;

	WRITE4(sc, DMA_STATUS, 0x3ff);
	WRITE4(sc, DMA_CONTROL, CONTROL_RESET);

	timeout = 100;
	do {
		if ((READ4(sc, DMA_STATUS) & STATUS_RESETTING) == 0)
			break;
	} while (timeout--);

	printf("timeout %d\n", timeout);

	WRITE4(sc, DMA_CONTROL, CONTROL_GIEM);

	printf("%s: read control after reset: %x\n", __func__, READ4(sc, DMA_CONTROL));

#if 0
	int i;
	for (i = 0; i < 10000; i++) {
		printf("%s: read control after reset: %x\n", __func__, READ4(sc, DMA_CONTROL));
		DELAY(1);
	}

	for (i = 0; i < 20; i++) {
		printf("%s: read status after reset: %x\n", __func__, READ4(sc, DMA_STATUS));
	}
#endif

	return (0);
}

static int
msgdma_detach(device_t dev)
{
	struct msgdma_softc *sc;

	sc = device_get_softc(dev);

	return (0);
}

static int
msgdma_channel_alloc(device_t dev, struct xdma_channel *xchan)
{
	struct msgdma_channel *chan;
	struct msgdma_softc *sc;
	int i;

	sc = device_get_softc(dev);

	xdma_assert_locked();

	for (i = 0; i < MSGDMA_NCHANNELS; i++) {
		chan = &sc->channels[i];
		if (chan->used == 0) {
			chan->xchan = xchan;
			xchan->chan = (void *)chan;
			chan->index = i;
			chan->sc = sc;
			chan->used = 1;
			chan->idx_head = 0;
			chan->idx_tail = 0;

			return (0);
		}
	}

	return (-1);
}

static int
msgdma_channel_free(device_t dev, struct xdma_channel *xchan)
{
	struct msgdma_channel *chan;
	struct msgdma_softc *sc;

	sc = device_get_softc(dev);

	xdma_assert_locked();

	chan = (struct msgdma_channel *)xchan->chan;
	//mtx_destroy(&chan->mtx);
	chan->used = 0;

	return (0);
}

static int
msgdma_channel_submit_sg(device_t dev, struct xdma_channel *xchan, struct xdma_sg_queue *sg_queue)
{
	struct msgdma_channel *chan;
	//struct msgdma_desc *descs;
	struct msgdma_desc *desc;
	struct msgdma_softc *sc;
	//struct sglist_seg *seg;
	xdma_config_t *conf;
	uint32_t addr;
	uint32_t len;
	//uint32_t reg;
	//int i;
	struct xdma_sg *sg;
	struct xdma_sg *sg_tmp;

	sc = device_get_softc(dev);

	conf = &xchan->conf;
	chan = (struct msgdma_channel *)xchan->chan;

	//printf("%s(%d)\n", __func__, device_get_unit(dev));
	//printf("%s(%d): nseg %d\n", __func__, device_get_unit(dev), (uint32_t)sg->sg_nseg);
	//mips_dcache_wbinv_all();
	//descs = (struct msgdma_desc *)xchan->descs;
	//WRITE4_DESC(sc, PF_CONTROL, 0);
	//WRITE4_DESC(sc, PF_NEXT_LO, (uint32_t)vtophys(&descs[chan->idx_head]));
	//WRITE4_DESC(sc, PF_NEXT_LO, xchan->descs_phys[chan->idx_head].ds_addr);

	uint32_t tmp;
	TAILQ_FOREACH_SAFE(sg, sg_queue, sg_next, sg_tmp) {
		addr = (uint32_t)sg->paddr;
		len = (uint32_t)sg->len;

		//printf("%s(%d): descr %d segment 0x%x (%d bytes)\n", __func__,
		//    device_get_unit(dev), chan->idx_head, addr, len);

		//desc = &descs[chan->idx_head];
		desc = xchan->descs[chan->idx_head].desc;
		if (conf->direction == XDMA_MEM_TO_DEV) {
			desc->read_lo = htole32(addr);
			desc->write_lo = 0;
		} else {
			desc->read_lo = 0;
			desc->write_lo = htole32(addr);
		}
		desc->length = htole32(len);
		desc->transferred = 0;
		desc->status = 0;
		desc->reserved = 0;

		if (conf->direction == XDMA_MEM_TO_DEV) {
			desc->control = htole32(CONTROL_GEN_SOP | CONTROL_GEN_EOP);
		} else {
			desc->control = htole32(CONTROL_END_ON_EOP | (1 << 13));
		}
		desc->control |= htole32(CONTROL_TC_IRQ_EN | CONTROL_ET_IRQ_EN | CONTROL_ERR_M);
		tmp = chan->idx_head;
		chan->idx_head = next_idx(xchan, chan->idx_head);
		desc->control |= htole32(CONTROL_OWN | CONTROL_GO);
		xdma_enqueue_sync_pre(xchan, tmp);
	}

	//mips_dcache_wbinv_all();
	//uint32_t reg0;
	//reg0 = READ4_DESC(sc, PF_CONTROL);
	//reg = (PF_CONTROL_GIEM | PF_CONTROL_DESC_POLL_EN);
	//reg |= PF_CONTROL_RUN;
	//WRITE4_DESC(sc, PF_CONTROL, reg);
	//printf("Reg0 %x reg %x, next_descr %x\n", reg0, reg, READ4_DESC(sc, PF_NEXT_LO));
	//printf("%s: next_descr %x\n", __func__, READ4_DESC(sc, PF_NEXT_LO));

	return (0);
}

static int
msgdma_channel_prep_sg(device_t dev, struct xdma_channel *xchan)
{
	//struct msgdma_channel *chan;
	//struct msgdma_desc *descs;
	struct msgdma_desc *desc;
	struct msgdma_softc *sc;
	xdma_config_t *conf;
	uint32_t addr;
	uint32_t reg;
	int ret;
	int i;

	sc = device_get_softc(dev);

	conf = &xchan->conf;

	printf("%s(%d)\n", __func__, device_get_unit(dev));

#if 1
	ret = xdma_desc_alloc(xchan, sizeof(struct msgdma_desc), 16);
	if (ret != 0) {
		device_printf(sc->dev,
		    "%s: Can't allocate descriptors.\n", __func__);
		return (-1);
	}
#endif

	//xchan->descs = contigmalloc(sizeof(struct msgdma_desc)*32, M_DEVBUF, M_ZERO, 0, ~0, PAGE_SIZE, 0);
	//xchan->descs = (void *)kmem_alloc_contig(kernel_arena,
	//    sizeof(struct msgdma_desc)*32, M_ZERO, 0, ~0, PAGE_SIZE, 0,
	//    VM_MEMATTR_UNCACHEABLE);

	//descs = (struct msgdma_desc *)xchan->descs;
	for (i = 0; i < conf->block_num; i++) {
		//desc = &descs[i];
		desc = xchan->descs[i].desc;

		//desc->read_lo = htole32(conf->src_addr);
		//desc->write_lo = htole32(conf->dst_addr);
		//desc->length = htole32(conf->block_len);

		if (i == (conf->block_num - 1)) {
			//desc->next = htole32(vtophys(&descs[0]));
			desc->next = htole32(xchan->descs[0].ds_addr);
		} else {
			//desc->next = htole32(vtophys(&descs[i+1]));
			desc->next = htole32(xchan->descs[i+1].ds_addr);
		}
		printf("%s(%d): desc %d vaddr %lx next paddr %x\n", __func__,
		    device_get_unit(dev), i, (uint64_t)desc, le32toh(desc->next));
	}

	//addr = (uint32_t)vtophys(descs);
	addr = xchan->descs[0].ds_addr;
	WRITE4_DESC(sc, PF_NEXT_LO, addr);
	WRITE4_DESC(sc, PF_NEXT_HI, 0);
	WRITE4_DESC(sc, PF_POLL_FREQ, 1000);

	reg = (PF_CONTROL_GIEM | PF_CONTROL_DESC_POLL_EN);
	reg |= PF_CONTROL_RUN;
	WRITE4_DESC(sc, PF_CONTROL, reg);

	return (0);
}

static int
msgdma_channel_control(device_t dev, xdma_channel_t *xchan, int cmd)
{
	struct msgdma_channel *chan;
	struct msgdma_softc *sc;

	sc = device_get_softc(dev);

	chan = (struct msgdma_channel *)xchan->chan;

	switch (cmd) {
	case XDMA_CMD_BEGIN:
	case XDMA_CMD_TERMINATE:
	case XDMA_CMD_PAUSE:
		/* TODO: implement me */
		return (-1);
	}

	return (0);
}

#ifdef FDT
static int
msgdma_ofw_md_data(device_t dev, pcell_t *cells, int ncells, void **ptr)
{

	return (0);
}
#endif

static device_method_t msgdma_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,			msgdma_probe),
	DEVMETHOD(device_attach,		msgdma_attach),
	DEVMETHOD(device_detach,		msgdma_detach),

	/* xDMA Interface */
	DEVMETHOD(xdma_channel_alloc,		msgdma_channel_alloc),
	DEVMETHOD(xdma_channel_free,		msgdma_channel_free),
	DEVMETHOD(xdma_channel_control,		msgdma_channel_control),

	DEVMETHOD(xdma_channel_prep_sg,		msgdma_channel_prep_sg),
	DEVMETHOD(xdma_channel_submit_sg,	msgdma_channel_submit_sg),

#ifdef FDT
	DEVMETHOD(xdma_ofw_md_data,		msgdma_ofw_md_data),
#endif

	DEVMETHOD_END
};

static driver_t msgdma_driver = {
	"msgdma",
	msgdma_methods,
	sizeof(struct msgdma_softc),
};

static devclass_t msgdma_devclass;

EARLY_DRIVER_MODULE(msgdma, simplebus, msgdma_driver, msgdma_devclass, 0, 0,
    BUS_PASS_INTERRUPT + BUS_PASS_ORDER_LATE);
