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
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/resource.h>
#include <sys/rman.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>

#include <machine/bus.h>
#include <machine/fdt.h>
#include <machine/cache.h>

#ifdef FDT
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#endif

#include <dev/altera/atse/a_api.h>

#define	AVALON_FIFO_TX_BASIC_OPTS_DEPTH		16

#define	DMA_STATUS		0x00
#define	 STATUS_RESETTING	(1 << 6)
#define	DMA_CONTROL		0x04
#define	 CONTROL_GIEM		(1 << 4) /* Global Interrupt Enable Mask */
#define	 CONTROL_RESET		(1 << 1) /* Reset Dispatcher */

#define	READ4(_sc, _reg)	\
	le32toh(bus_space_read_4(_sc->bst, _sc->bsh, _reg))
#define	WRITE4(_sc, _reg, _val)	\
	bus_space_write_4(_sc->bst, _sc->bsh, _reg, htole32(_val))

#define	READ4_DESC(_sc, _reg)	\
	le32toh(bus_space_read_4(_sc->bst_d, _sc->bsh_d, _reg))
#define	WRITE4_DESC(_sc, _reg, _val)	\
	bus_space_write_4(_sc->bst_d, _sc->bsh_d, _reg, htole32(_val))

#define	CONTROL_GO		(1 << 31)	/* Commit all the descriptor info */
#define	CONTROL_OWN		(1 << 30)	/* Owned by hardware (prefetcher-enabled only) */
#define	CONTROL_EDE		(1 << 24)	/* Early done enable */
#define	CONTROL_ERR_S		16		/* Transmit Error, Error IRQ Enable */
#define	CONTROL_ERR_M		(0xff << CONTROL_ERR_S)
#define	CONTROL_ET_IRQ_EN	(1 << 15)	/* Early Termination IRQ Enable */
#define	CONTROL_TC_IRQ_EN	(1 << 14)	/* Transfer Complete IRQ Enable */
#define	CONTROL_END_ON_EOP	(1 << 12)	/* End on EOP */
#define	CONTROL_PARK_WR		(1 << 11)	/* Park Writes */
#define	CONTROL_PARK_RD		(1 << 10)	/* Park Reads */
#define	CONTROL_GEN_EOP		(1 << 9)	/* Generate EOP */
#define	CONTROL_GEN_SOP		(1 << 8)	/* Generate SOP */
#define	CONTROL_TX_CHANNEL_S	0		/* Transmit Channel */
#define	CONTROL_TX_CHANNEL_M	(0xff << CONTROL_TRANSMIT_CH_S)

#include <dev/xdma/xdma.h>
#include "xdma_if.h"

struct msgdma_channel {
	struct msgdma_softc	*sc;
	struct mtx		mtx;
	xdma_channel_t		*xchan;
	struct proc		*p;
	int			used;
	int			index;
	int			run;
};


#define	PF_CONTROL			0x00
#define	 PF_CONTROL_GIEM		(1 << 3)
#define	 PF_CONTROL_RESET		(1 << 2)
#define	 PF_CONTROL_DESC_POLL_EN	(1 << 1)
#define	 PF_CONTROL_RUN			(1 << 0)
#define	PF_NEXT_LO			0x04
#define	PF_NEXT_HI			0x08
#define	PF_POLL_FREQ			0x0C
#define	PF_STATUS			0x10
#define	 PF_STATUS_IRQ			(1 << 0)

//#define	PREFETCHER_DISABLED	1

#ifdef PREFETCHER_DISABLED
struct msgdma_desc1 {
	uint32_t src_addr;
	uint32_t dst_addr;
	uint32_t length;
	uint32_t control;
};

#else

struct msgdma_desc1 {
	uint32_t read_lo;
	uint32_t write_lo;
	uint32_t length;
	uint32_t next;
	uint32_t transfered;
	uint32_t status;
	uint32_t reserved;
	uint32_t control;
};
#endif

struct msgdma_desc {
	uint32_t		src_addr;
	uint32_t		dst_addr;
	uint32_t		access_width;
	uint32_t		len;
	uint32_t		count;
	uint16_t		src_incr;
	uint16_t		dst_incr;
	struct msgdma_desc	*next;
	uint32_t		direction;
};

struct msgdma_softc {
	device_t		dev;
	struct resource		*res[3];
	bus_space_tag_t		bst;
	bus_space_handle_t	bsh;
	bus_space_tag_t		bst_d;
	bus_space_handle_t	bsh_d;
	void			*ih;
	struct msgdma_desc1	desc;
	struct msgdma_desc1	*curdesc;
	struct msgdma_channel	*curchan;

#define	SOFTDMA_NCHANNELS	32
	struct msgdma_channel msgdma_channels[SOFTDMA_NCHANNELS];
};

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
	struct msgdma_desc1 *desc;
	struct msgdma_channel *chan;
	struct msgdma_softc *sc;
	uint32_t len;

	sc = arg;
	chan = sc->curchan;
	desc = sc->curdesc;

	mips_dcache_wbinv_all();

	len = le32toh(desc->transfered);
	if (desc->read_lo == 0) {
		printf("%s: rx 0x%08x, transfered %d\n", __func__, READ4_DESC(sc, PF_STATUS), len);
	} else {
		printf("%s: tx 0x%08x, transfered %d\n", __func__, READ4_DESC(sc, PF_STATUS), len);
	}

	WRITE4_DESC(sc, PF_STATUS, PF_STATUS_IRQ);


	/* Finish operation */
	chan->run = 0;
	status.error = 0;
	status.total_copied = len;
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
msgdma_process_tx(struct msgdma_channel *chan, struct msgdma_desc *desc)
{
	struct msgdma_softc *sc;
	uint32_t reg;
	size_t len;

	sc = chan->sc;

	len = (desc->count * desc->access_width);

	mips_dcache_wbinv_all();

	printf("%s\n", __func__);

	//printf("%s: read status before GO: %x\n", __func__, READ4(sc, DMA_STATUS));

	struct msgdma_desc1 *desc1;

#ifdef PREFETCHER_DISABLED
	desc1 = &sc->desc;
	desc1->src_addr = desc->src_addr;
	desc1->dst_addr = 0;
	desc1->length = desc->len;
	desc1->control = (CONTROL_GO | CONTROL_GEN_SOP | CONTROL_GEN_EOP);
	desc1->control |= (CONTROL_TC_IRQ_EN | CONTROL_ET_IRQ_EN);
	//desc1->control |= CONTROL_ERR_M;
	//desc1->control |= CONTROL_END_ON_EOP;
	//desc1->control |= (1 << 13);

	uint32_t *tmp;
	tmp = (uint32_t *)desc1;
	for (i = 0; i<4; i++) {
		printf("write 0x%08x to 0x%08x\n", tmp[i], (uint32_t)(rman_get_start(sc->res[1]) + 4*i));
		WRITE4_DESC(sc, 4*i, tmp[i]);
	}
#else
	//desc1 = &sc->desc;
	desc1 = contigmalloc(sizeof(struct msgdma_desc1), M_DEVBUF, M_ZERO, 0, ~0, PAGE_SIZE, 0);
	sc->curdesc = desc1;
	desc1->read_lo = htole32(desc->src_addr);
	desc1->write_lo = 0;
	desc1->length = htole32(desc->len);
	desc1->next = 0;
	desc1->transfered = 0;
	desc1->status = 0;
	desc1->reserved = 0;
	desc1->control = htole32(CONTROL_GO | CONTROL_GEN_SOP | CONTROL_GEN_EOP | CONTROL_TC_IRQ_EN | CONTROL_ET_IRQ_EN | CONTROL_ERR_M | CONTROL_OWN);
	//desc1->control |= CONTROL_END_ON_EOP;
	//desc1->control |= (1 << 13);

	uint32_t addr;

	//uint32_t *tmp;
	//tmp = (uint32_t *)desc1;
	//for (i = 0; i < 8; i++) {
	//	printf("desc1[%d] == %08x\n", i, tmp[i]);
	//}

	addr = (uint32_t)vtophys(desc1);
	printf("writing desc1 addr 0x%08x\n", addr);

	sc->curchan = chan;

	WRITE4_DESC(sc, PF_NEXT_LO, addr);
	WRITE4_DESC(sc, PF_NEXT_HI, 0);
	WRITE4_DESC(sc, PF_POLL_FREQ, 10000);
	reg = (PF_CONTROL_GIEM | PF_CONTROL_RUN);
	//reg |= PF_CONTROL_DESC_POLL_EN);

	mips_dcache_wbinv_all();
	WRITE4_DESC(sc, PF_CONTROL, reg);
#endif

	//printf("%s: read status after GO: %x\n", __func__, READ4(sc, DMA_STATUS));

	return (desc->len);
}

static int
msgdma_process_rx(struct msgdma_channel *chan, struct msgdma_desc *desc)
{
	uint32_t src_offs, dst_offs;
	struct msgdma_softc *sc;
	uint32_t empty;
	uint32_t reg;
	int error;

	sc = chan->sc;
	empty = 0;
	src_offs = dst_offs = 0;
	error = 0;

	printf("%s\n", __func__);

	struct msgdma_desc1 *desc1;

#ifdef PREFETCHER_DISABLED
	desc1 = &sc->desc;
	desc1->src_addr = 0;
	desc1->dst_addr = desc->dst_addr;
	desc1->length = desc->len;
	desc1->control = (CONTROL_GO);
	desc1->control |= (CONTROL_TC_IRQ_EN | CONTROL_ET_IRQ_EN);
	desc1->control |= CONTROL_ERR_M;
	desc1->control |= CONTROL_END_ON_EOP;
	desc1->control |= (1 << 13);

	uint32_t *tmp;
	tmp = (uint32_t *)desc1;
	for (i = 0; i<4; i++) {
		printf("rx: write 0x%08x to 0x%08x\n", tmp[i], (uint32_t)(rman_get_start(sc->res[1]) + 4*i));
		WRITE4_DESC(sc, 4*i, tmp[i]);
	}
#else
	//desc1 = &sc->desc;
	desc1 = contigmalloc(sizeof(struct msgdma_desc1), M_DEVBUF, M_ZERO, 0, ~0, PAGE_SIZE, 0);
	sc->curdesc = desc1;
	desc1->read_lo = 0;
	desc1->write_lo = htole32(desc->dst_addr);
	desc1->length = htole32(desc->len);
	desc1->next = 0;
	desc1->transfered = 0;
	desc1->status = 0;
	desc1->reserved = 0;
	desc1->control = htole32(CONTROL_GO | CONTROL_TC_IRQ_EN | CONTROL_ET_IRQ_EN | CONTROL_ERR_M | CONTROL_OWN | CONTROL_END_ON_EOP | (0 << 13));
	//desc1->control |= (1 << 13);

	uint32_t addr;

	//uint32_t *tmp;
	//tmp = (uint32_t *)desc1;
	//for (i = 0; i < 8; i++) {
	//	printf("rx desc1[%d] == %08x\n", i, tmp[i]);
	//}

	addr = (uint32_t)vtophys(desc1);
	printf("rx: writing desc1 addr 0x%08x\n", addr);

	sc->curchan = chan;

	WRITE4_DESC(sc, PF_NEXT_LO, addr);
	WRITE4_DESC(sc, PF_NEXT_HI, 0);
	WRITE4_DESC(sc, PF_POLL_FREQ, 10000);
	reg = (PF_CONTROL_GIEM | PF_CONTROL_RUN);
	//reg |= PF_CONTROL_DESC_POLL_EN);

	mips_dcache_wbinv_all();
	WRITE4_DESC(sc, PF_CONTROL, reg);
#endif

	return (0);
}

static uint32_t
msgdma_process_descriptors(struct msgdma_channel *chan, xdma_transfer_status_t *status)
{
	struct xdma_channel *xchan;
	struct msgdma_desc *desc;
	struct msgdma_softc *sc;
	int ret;

	sc = chan->sc;

	xchan = chan->xchan;
	//conf = &xchan->conf;

	desc = (struct msgdma_desc *)xchan->descs;

	while (desc != NULL) {
		if (desc->direction == XDMA_MEM_TO_DEV) {
			ret = msgdma_process_tx(chan, desc);
		} else {
			ret = msgdma_process_rx(chan, desc);
		}

		if (ret >= 0) {
			status->total_copied += ret;
		} else {
			status->error = 1;
			break;
		}

		/* Process next descriptor, if any. */
		desc = desc->next;
	}

	return (0);
}

static void
msgdma_worker(void *arg)
{
	xdma_transfer_status_t status;
	struct msgdma_channel *chan;
	struct msgdma_softc *sc;

	chan = arg;

	sc = chan->sc;

	while (1) {
		mtx_lock(&chan->mtx);

		//do {
		//	mtx_sleep(chan, &chan->mtx, 0, "msgdma_wait", hz / 2);
		//} while (chan->run == 0);
		mtx_sleep(chan, &chan->mtx, 0, "msgdma_wait", 0);

		status.error = 0;
		status.total_copied = 0;

		msgdma_process_descriptors(chan, &status);

		mtx_unlock(&chan->mtx);
	}

}

static int
msgdma_proc_create(struct msgdma_channel *chan)
{
	struct msgdma_softc *sc;

	sc = chan->sc;

	if (chan->p != NULL) {
		/* Already created */
		return (0);
	}

	mtx_init(&chan->mtx, "SoftDMA", NULL, MTX_DEF);

	if (kproc_create(msgdma_worker, (void *)chan, &chan->p, 0, 0,
	    "msgdma_worker") != 0) {
		device_printf(sc->dev,
		    "%s: Failed to create worker thread.\n", __func__);
		return (-1);
	}

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

	for (i = 0; i < SOFTDMA_NCHANNELS; i++) {
		chan = &sc->msgdma_channels[i];
		if (chan->used == 0) {
			chan->xchan = xchan;
			xchan->chan = (void *)chan;
			chan->index = i;
			chan->sc = sc;

			if (msgdma_proc_create(chan) != 0) {
				return (-1);
			}

			chan->used = 1;

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
msgdma_channel_prep_cyclic(device_t dev, struct xdma_channel *xchan)
{

	return (0);
}

static int
msgdma_channel_prep_memcpy(device_t dev, struct xdma_channel *xchan)
{
	struct msgdma_channel *chan;
	struct msgdma_desc *desc;
	struct msgdma_softc *sc;
	xdma_config_t *conf;
	int ret;

	sc = device_get_softc(dev);

	chan = (struct msgdma_channel *)xchan->chan;

	/* Ensure we are not in operation */
	//chan_stop(sc, chan);

	ret = xdma_desc_alloc(xchan, sizeof(struct msgdma_desc), 8);
	if (ret != 0) {
		device_printf(sc->dev,
		    "%s: Can't allocate descriptors.\n", __func__);
		return (-1);
	}

	conf = &xchan->conf;
	desc = (struct msgdma_desc *)xchan->descs;

	desc[0].src_addr = conf->src_addr;
	desc[0].dst_addr = conf->dst_addr;
	desc[0].access_width = 4;
	desc[0].count = (conf->block_len / 4);
	desc[0].src_incr = 1;
	desc[0].dst_incr = 1;
	desc[0].next = NULL;

	return (0);
}

static int
msgdma_channel_prep_fifo(device_t dev, struct xdma_channel *xchan)
{
	struct msgdma_channel *chan;
	struct msgdma_desc *desc;
	struct msgdma_softc *sc;
	xdma_config_t *conf;
	int ret;

	conf = &xchan->conf;
	if (conf->direction == XDMA_MEM_TO_DEV) {
		//printf("%s: TX\n", __func__);
	} else {
		//printf("%s: RX\n", __func__);
	}

	sc = device_get_softc(dev);

	chan = (struct msgdma_channel *)xchan->chan;

	ret = xdma_desc_alloc(xchan, sizeof(struct msgdma_desc), 8);
	if (ret != 0) {
		device_printf(sc->dev,
		    "%s: Can't allocate descriptors.\n", __func__);
		return (-1);
	}

	desc = (struct msgdma_desc *)xchan->descs;
	desc[0].src_addr = conf->src_addr;
	desc[0].dst_addr = conf->dst_addr;
	desc[0].access_width = 4;
	desc[0].len = conf->block_len;
	desc[0].count = (conf->block_len / 4);
	if (conf->direction == XDMA_MEM_TO_DEV) {
		desc[0].src_incr = 1;
		desc[0].dst_incr = 0;
	} else {
		desc[0].src_incr = 0;
		desc[0].dst_incr = 1;
	}
	desc[0].direction = conf->direction;
	desc[0].next = NULL;

	return (0);
}

static int
chan_start(struct msgdma_channel *chan)
{
	//struct msgdma_softc *sc;

	//sc = chan->sc;

	chan->run = 1;
	wakeup(chan);

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
		chan_start(chan);
		break;
	case XDMA_CMD_TERMINATE:
		//chan_stop(sc, chan);
		break;
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
	DEVMETHOD(xdma_channel_prep_cyclic,	msgdma_channel_prep_cyclic),
	DEVMETHOD(xdma_channel_prep_memcpy,	msgdma_channel_prep_memcpy),
	DEVMETHOD(xdma_channel_prep_fifo,	msgdma_channel_prep_fifo),
	DEVMETHOD(xdma_channel_control,		msgdma_channel_control),
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
