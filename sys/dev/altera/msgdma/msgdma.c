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

#define	TX_DESC_COUNT	32

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
struct msgdma_desc {
	uint32_t src_addr;
	uint32_t dst_addr;
	uint32_t length;
	uint32_t control;
};
#else
struct msgdma_desc {
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

struct msgdma_softc {
	device_t		dev;
	struct resource		*res[3];
	bus_space_tag_t		bst;
	bus_space_handle_t	bsh;
	bus_space_tag_t		bst_d;
	bus_space_handle_t	bsh_d;
	void			*ih;
	struct msgdma_desc	desc;
	struct msgdma_desc	*curdesc;
	struct msgdma_channel	*curchan;
#define	SOFTDMA_NCHANNELS	32
	struct msgdma_channel msgdma_channels[SOFTDMA_NCHANNELS];
};

static inline uint32_t
next_idx(struct msgdma_softc *sc, uint32_t curidx)
{

	return ((curidx + 1) % TX_DESC_COUNT);
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
	struct msgdma_desc *descs;
	struct msgdma_desc *desc;
	struct msgdma_channel *chan;
	struct xdma_channel *xchan;
	struct msgdma_softc *sc;
	//uint32_t len;

	sc = arg;
	chan = sc->curchan;
	//desc = sc->curdesc;

	printf("%s(%d): status 0x%08x next_descr 0x%08x, control 0x%08x\n", __func__,
	    device_get_unit(sc->dev),
		READ4_DESC(sc, PF_STATUS),
		READ4_DESC(sc, PF_NEXT_LO),
		READ4_DESC(sc, PF_CONTROL));

	//mips_dcache_wbinv_all();
	//len = le32toh(desc->transfered);
	//if (desc->read_lo == 0) {
	//	printf("%s: rx 0x%08x, transfered %d\n", __func__, READ4_DESC(sc, PF_STATUS), len);
	//} else {
	//	printf("%s: tx 0x%08x, transfered %d\n", __func__, READ4_DESC(sc, PF_STATUS), len);
	//}

	xchan = chan->xchan;

	descs = (struct msgdma_desc *)xchan->descs;

	uint32_t cnt_done;
	uint32_t tot_copied;

	cnt_done = 0;
	tot_copied = 0;
	do {
		desc = &descs[chan->idx_tail];
		if ((le32toh(desc->control) & CONTROL_OWN) != 0) {
			break;
		}
		printf("%s(%d): marking desc %d done\n", __func__, device_get_unit(sc->dev), chan->idx_tail);
		chan->idx_tail = next_idx(sc, chan->idx_tail);
		tot_copied += le32toh(desc->transfered);
		cnt_done++;
	} while (chan->idx_tail != chan->idx_head);

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
msgdma_process_desc(struct msgdma_channel *chan, struct msgdma_desc *desc)
{
	struct msgdma_softc *sc;
	uint32_t reg;

	sc = chan->sc;

	//mips_dcache_wbinv_all();

	printf("%s\n", __func__);

	//printf("%s: read status before GO: %x\n", __func__, READ4(sc, DMA_STATUS));

#ifdef PREFETCHER_DISABLED
	desc->src_addr = desc->src_addr;
	desc->dst_addr = 0;
	desc->length = desc->len;
	desc->control = (CONTROL_GO | CONTROL_GEN_SOP | CONTROL_GEN_EOP);
	desc->control |= (CONTROL_TC_IRQ_EN | CONTROL_ET_IRQ_EN);
	//desc->control |= CONTROL_ERR_M;
	//desc->control |= CONTROL_END_ON_EOP;
	//desc->control |= (1 << 13);

	uint32_t *tmp;
	tmp = (uint32_t *)desc;
	for (i = 0; i<4; i++) {
		printf("write 0x%08x to 0x%08x\n", tmp[i], (uint32_t)(rman_get_start(sc->res[1]) + 4*i));
		WRITE4_DESC(sc, 4*i, tmp[i]);
	}
#else
	//desc = &sc->desc;
	sc->curdesc = desc;


	uint32_t addr;

	//uint32_t *tmp;
	//tmp = (uint32_t *)desc;
	//for (i = 0; i < 8; i++) {
	//	printf("desc[%d] == %08x\n", i, tmp[i]);
	//}

	addr = (uint32_t)vtophys(desc);
	printf("writing desc addr 0x%08x\n", addr);

	sc->curchan = chan;

	WRITE4_DESC(sc, PF_NEXT_LO, addr);
	WRITE4_DESC(sc, PF_NEXT_HI, 0);
	WRITE4_DESC(sc, PF_POLL_FREQ, 10000);
	reg = (PF_CONTROL_GIEM | PF_CONTROL_RUN);
	//reg |= PF_CONTROL_DESC_POLL_EN);

	//mips_dcache_wbinv_all();
	WRITE4_DESC(sc, PF_CONTROL, reg);
#endif

	//printf("%s: read status after GO: %x\n", __func__, READ4(sc, DMA_STATUS));

	return (0); //desc->len);
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
		//if (desc->direction == XDMA_MEM_TO_DEV) {
		//	ret = msgdma_process_tx(chan, desc);
		//} else {
		//	ret = msgdma_process_rx(chan, desc);
		//}
		//}

		ret = msgdma_process_desc(chan, desc);

		if (ret >= 0) {
			status->total_copied += ret;
		} else {
			status->error = 1;
			break;
		}

		/* Process next descriptor, if any. */
		//desc = desc->next;
		break;
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

#if 0
	desc[0].src_addr = conf->src_addr;
	desc[0].dst_addr = conf->dst_addr;
	desc[0].access_width = 4;
	desc[0].count = (conf->block_len / 4);
	desc[0].src_incr = 1;
	desc[0].dst_incr = 1;
	desc[0].next = NULL;
#endif

	return (0);
}

static int
msgdma_channel_submit_sg(device_t dev, struct xdma_channel *xchan, struct xdma_sglist_list *sg_queue)
{
	struct msgdma_channel *chan;
	struct msgdma_desc *descs;
	struct msgdma_desc *desc;
	struct msgdma_softc *sc;
	//struct sglist_seg *seg;
	xdma_config_t *conf;
	uint32_t addr;
	uint32_t len;
	//uint32_t reg;
	//int i;
	struct xdma_sglist *sg;
	struct xdma_sglist *sg_tmp;

	sc = device_get_softc(dev);

	conf = &xchan->conf;
	chan = (struct msgdma_channel *)xchan->chan;
	sc->curchan = chan;

	printf("%s(%d)\n", __func__, device_get_unit(dev));

	//printf("%s(%d): nseg %d\n", __func__, device_get_unit(dev), (uint32_t)sg->sg_nseg);

	//mips_dcache_wbinv_all();

	descs = (struct msgdma_desc *)xchan->descs;

	//WRITE4_DESC(sc, PF_CONTROL, 0);
	//WRITE4_DESC(sc, PF_NEXT_LO, (uint32_t)vtophys(&descs[chan->idx_head]));
	//WRITE4_DESC(sc, PF_NEXT_LO, xchan->descs_phys[chan->idx_head].ds_addr);

	TAILQ_FOREACH_SAFE(sg, sg_queue, sg_next, sg_tmp) {
	//for (i = 0; i < sg->sg_nseg; i++) {
	//	seg = &sg->sg_segs[i];

	//	addr = (uint32_t)seg->ss_paddr;
	//	len = (uint32_t)seg->ss_len;
		addr = (uint32_t)sg->paddr;
		len = (uint32_t)sg->len;

	//	if (seg->ss_paddr & 0x3) {
	//		//addr -= 2;
	//		//len += 2;
	//	}

		printf("%s(%d): descr %d segment 0x%x (%d bytes)\n", __func__,
		    device_get_unit(dev), chan->idx_head, addr, len);

		desc = &descs[chan->idx_head];
		if (conf->direction == XDMA_MEM_TO_DEV) {
			desc->read_lo = htole32(addr);
			desc->write_lo = 0;
		} else {
			desc->read_lo = 0;
			desc->write_lo = htole32(addr);
		}
		desc->length = htole32(len);
		desc->transfered = 0;
		desc->status = 0;
		desc->reserved = 0;

		chan->idx_head = next_idx(sc, chan->idx_head);

		if (conf->direction == XDMA_MEM_TO_DEV) {
			desc->control = htole32(CONTROL_GEN_SOP | CONTROL_GEN_EOP);
		} else {
			desc->control = htole32(CONTROL_END_ON_EOP | (1 << 13));
		}
		//if (i == (sg->sg_nseg - 1)) {
		desc->control |= htole32(CONTROL_TC_IRQ_EN | CONTROL_ET_IRQ_EN | CONTROL_ERR_M);
		//}

		wmb();
		desc->control |= htole32(CONTROL_OWN | CONTROL_GO);
		wmb();
	}

	//mips_dcache_wbinv_all();

	//xdma_enqueue_sync(xchan);

	//uint32_t reg0;
	//reg0 = READ4_DESC(sc, PF_CONTROL);
	//reg = (PF_CONTROL_GIEM | PF_CONTROL_DESC_POLL_EN);
	//reg |= PF_CONTROL_RUN;
	//WRITE4_DESC(sc, PF_CONTROL, reg);
	//printf("Reg0 %x reg %x, next_descr %x\n", reg0, reg, READ4_DESC(sc, PF_NEXT_LO));

	printf("%s: next_descr %x\n", __func__, READ4_DESC(sc, PF_NEXT_LO));

	return (0);
}

static int
msgdma_channel_prep_sg(device_t dev, struct xdma_channel *xchan)
{
	//struct msgdma_channel *chan;
	struct msgdma_desc *descs;
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
	xchan->descs = (void *)kmem_alloc_contig(kernel_arena,
	    sizeof(struct msgdma_desc)*32, M_ZERO, 0, ~0, PAGE_SIZE, 0,
	    VM_MEMATTR_UNCACHEABLE);

	descs = (struct msgdma_desc *)xchan->descs;
	for (i = 0; i < 32; i++) {
		desc = &descs[i];

		//desc->read_lo = htole32(conf->src_addr);
		//desc->write_lo = htole32(conf->dst_addr);
		//desc->length = htole32(conf->block_len);

		if (i == (32 - 1)) {
			desc->next = htole32(vtophys(&descs[0]));
			//desc->next = htole32(xchan->descs_phys[0].ds_addr);
		} else {
			desc->next = htole32(vtophys(&descs[i+1]));
			//desc->next = htole32(xchan->descs_phys[i+1].ds_addr);
		}
		printf("%s(%d): desc %d next addr %x\n", __func__, device_get_unit(dev), i, le32toh(desc->next));
	}

	addr = (uint32_t)vtophys(descs);
	//addr = xchan->descs_phys[0].ds_addr;
	WRITE4_DESC(sc, PF_NEXT_LO, addr);
	WRITE4_DESC(sc, PF_NEXT_HI, 0);
	WRITE4_DESC(sc, PF_POLL_FREQ, 1000);

	reg = (PF_CONTROL_GIEM | PF_CONTROL_DESC_POLL_EN);
	reg |= PF_CONTROL_RUN;
	WRITE4_DESC(sc, PF_CONTROL, reg);

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

	desc->read_lo = htole32(conf->src_addr);
	desc->write_lo = htole32(conf->dst_addr);
	desc->length = htole32(conf->block_len);
	desc->next = 0;
	desc->transfered = 0;
	desc->status = 0;
	desc->reserved = 0;
	desc->control = htole32(CONTROL_GO | CONTROL_OWN);
	desc->control |= htole32(CONTROL_TC_IRQ_EN | CONTROL_ET_IRQ_EN | CONTROL_ERR_M);
	if (conf->direction == XDMA_MEM_TO_DEV) {
		desc->control |= htole32(CONTROL_GEN_SOP | CONTROL_GEN_EOP);
	} else {
		desc->control |= htole32(CONTROL_END_ON_EOP | (0 << 13));
	}

#ifdef PREFETCHER_DISABLED
	desc->control = (CONTROL_GO);
	desc->control |= (CONTROL_TC_IRQ_EN | CONTROL_ET_IRQ_EN);
	desc->control |= CONTROL_ERR_M;
	desc->control |= CONTROL_END_ON_EOP;
	desc->control |= (1 << 13);
#endif

#if 0
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
#endif

	return (0);
}

static int
chan_start(struct msgdma_channel *chan)
{
	xdma_transfer_status_t status;
	//struct msgdma_softc *sc;

	//sc = chan->sc;

	chan->run = 1;

	status.error = 0;
	status.total_copied = 0;
	msgdma_process_descriptors(chan, &status);

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
