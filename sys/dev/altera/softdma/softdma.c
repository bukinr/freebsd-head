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

/* The software implementation of Altera mSGDMA */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_platform.h"
#include <sys/param.h>
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

#include <dev/xdma/xdma.h>
#include "xdma_if.h"

struct softdma_channel {
	struct softdma_softc	*sc;
	struct mtx		mtx;
	xdma_channel_t		*xchan;
	struct proc		*p;
	int			used;
	int			index;
	int			run;

	uint32_t		idx_tail;
	uint32_t		idx_head;
};

extern uint32_t total_copied;
#define	SOFTDMA_NCHANNELS	32
struct softdma_channel softdma_channels[SOFTDMA_NCHANNELS];

struct softdma_desc {
	uint32_t		src_addr;
	uint32_t		dst_addr;
	uint32_t		access_width;
	uint32_t		len;
	uint32_t		count;
	uint16_t		src_incr;
	uint16_t		dst_incr;
	uint32_t		direction;

	uint32_t read_lo;
	uint32_t write_lo;
	uint32_t length;
	//uint32_t next;
	struct softdma_desc	*next;
	uint32_t transfered;
	uint32_t status;
	uint32_t reserved;
	uint32_t control;
};

struct softdma_softc {
	device_t		dev;
	struct resource		*res[3];
	bus_space_tag_t		bst;
	bus_space_handle_t	bsh;
	bus_space_tag_t		bst_c;
	bus_space_handle_t	bsh_c;
	void			*ih;
};

static struct resource_spec softdma_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ SYS_RES_MEMORY,	1,	RF_ACTIVE },
	{ SYS_RES_IRQ,		0,	RF_ACTIVE },
	{ -1, 0 }
};

static int softdma_probe(device_t dev);
static int softdma_attach(device_t dev);
static int softdma_detach(device_t dev);

static void
softdma_intr(void *arg)
{
	struct softdma_softc *sc;

	sc = arg;

	printf("%s(%d)\n", __func__, device_get_unit(sc->dev));
}

static int
softdma_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (!ofw_bus_is_compatible(dev, "freebsd,softdma"))
		return (ENXIO);

	device_set_desc(dev, "SoftDMA");

	return (BUS_PROBE_DEFAULT);
}

static int
softdma_attach(device_t dev)
{
	struct softdma_softc *sc;
	phandle_t xref, node;
	int err;

	sc = device_get_softc(dev);
	sc->dev = dev;

	if (bus_alloc_resources(dev, softdma_spec, sc->res)) {
		device_printf(dev, "could not allocate resources for device\n");
		return (ENXIO);
	}

	/* FIFO memory interface */
	sc->bst = rman_get_bustag(sc->res[0]);
	sc->bsh = rman_get_bushandle(sc->res[0]);

	/* FIFO control memory interface */
	sc->bst_c = rman_get_bustag(sc->res[1]);
	sc->bsh_c = rman_get_bushandle(sc->res[1]);

	/* Setup interrupt handler */
	err = bus_setup_intr(dev, sc->res[2], INTR_TYPE_MISC | INTR_MPSAFE,
	    NULL, softdma_intr, sc, &sc->ih);
	if (err) {
		device_printf(dev, "Unable to alloc interrupt resource.\n");
		return (ENXIO);
	}

	node = ofw_bus_get_node(dev);
	xref = OF_xref_from_node(node);
	OF_device_register_xref(xref, dev);

	return (0);
}

static int
softdma_detach(device_t dev)
{
	struct softdma_softc *sc;

	sc = device_get_softc(dev);

	return (0);
}

static int
softdma_process_tx(struct softdma_channel *chan, struct softdma_desc *desc)
{
	uint32_t src_offs, dst_offs;
	bus_space_handle_t bsh_src;
	bus_space_handle_t bsh_dst;
	struct softdma_softc *sc;
	bus_space_tag_t bst;
	uint32_t reg;
	uint32_t val; /* TODO */
	uint32_t fill_level;
	uint32_t leftm;
	uint32_t c;
	size_t len;

	sc = chan->sc;

	bst = fdtbus_bs_tag;
	len = (desc->count * desc->access_width);

	bus_space_map(bst, desc->src_addr, len, 0, &bsh_src);
	bus_space_map(bst, desc->dst_addr, 4, 0, &bsh_dst);
	mips_dcache_wbinv_all();

	fill_level = atse_tx_read_fill_level();
	//if (fill_level == 0) {
	//}
	//printf("TX fill_level is %d\n", fill_level);

	/* Set start of packet. */
	reg = A_ONCHIP_FIFO_MEM_CORE_SOP;
	reg &= ~A_ONCHIP_FIFO_MEM_CORE_EOP;
	atse_tx_mem_write(A_ONCHIP_FIFO_MEM_CORE_METADATA, reg);

	//printf("copy %x -> %x (%d bytes, %d times)\n",
	//    (uint32_t)bsh_src, (uint32_t)bsh_dst, desc->len, desc->count);

	src_offs = dst_offs = 0;
	c = 0;
	while ((desc->len - c) > 4) {
		val = bus_space_read_4(bst, bsh_src, src_offs);
		bus_space_write_4(bst, bsh_dst, dst_offs, val);
		if (desc->src_incr)
			src_offs += 4;
		if (desc->dst_incr)
			dst_offs += 4;
		fill_level += 1;

		while (fill_level == AVALON_FIFO_TX_BASIC_OPTS_DEPTH) {
			//printf("FILL LEVEL %d, hz %d\n", fill_level, hz);
			fill_level = atse_tx_read_fill_level();
			if (fill_level == AVALON_FIFO_TX_BASIC_OPTS_DEPTH) {
				//mtx_sleep(sc, &chan->mtx, 0, "softdma_delay", hz);
			}
		}
		c += 4;
	}

	leftm = (desc->len - c);
	switch (leftm) {
	case 1:
		val = bus_space_read_1(bst, bsh_src, src_offs);
		val <<= 24;
		src_offs += 1;
		break;
	case 2:
		val = bus_space_read_2(bst, bsh_src, src_offs);
		val <<= 16;
		src_offs += 2;
		break;
	case 4:
		val = bus_space_read_4(bst, bsh_src, src_offs);
		src_offs += 4;
		break;
	default:
		break;
	}

	/* Set end of packet. */
	reg = A_ONCHIP_FIFO_MEM_CORE_EOP;
	reg |= ((4 - leftm) << A_ONCHIP_FIFO_MEM_CORE_EMPTY_SHIFT);
	atse_tx_mem_write(A_ONCHIP_FIFO_MEM_CORE_METADATA, reg);

	/* Ensure there is a FIFO entry available. */
	while (fill_level == AVALON_FIFO_TX_BASIC_OPTS_DEPTH) {
		fill_level = atse_tx_read_fill_level();
	};

	bus_space_write_4(bst, bsh_dst, dst_offs, val);
	bus_space_unmap(bst, bsh_src, len);
	bus_space_unmap(bst, bsh_dst, 4);

	return (dst_offs);
}

static int
softdma_process_rx(struct softdma_channel *chan, struct softdma_desc *desc)
{
	uint32_t src_offs, dst_offs;
	bus_space_handle_t bsh_src;
	bus_space_handle_t bsh_dst;
	struct softdma_softc *sc;
	bus_space_tag_t bst;
	uint32_t fill_level;
	uint32_t empty;
	uint32_t meta;
	uint32_t data;
	int sop_rcvd;
	int timeout;
	size_t len;
	int error;

	sc = chan->sc;
	empty = 0;
	src_offs = dst_offs = 0;
	error = 0;

	bst = fdtbus_bs_tag;

	//printf("%s\n", __func__);

	fill_level = atse_rx_read_fill_level();
	if (fill_level == 0) {
		return (0);
	}

	//printf("RX fill_level is %d, desc->len %d\n", fill_level, desc->len);

	//len = (desc->count * desc->access_width);
	len = desc->len;
	bus_space_map(bst, desc->src_addr, 4, 0, &bsh_src);
	bus_space_map(bst, desc->dst_addr, len, 0, &bsh_dst);
	mips_dcache_wbinv_all();

	sop_rcvd = 0;
	while (fill_level) {
		empty = 0;
		//data = atse_rx_mem_read(A_ONCHIP_FIFO_MEM_CORE_DATA);
		data = bus_space_read_4(bst, bsh_src, src_offs);
		meta = atse_rx_mem_read(A_ONCHIP_FIFO_MEM_CORE_METADATA);

		if (meta & A_ONCHIP_FIFO_MEM_CORE_ERROR_MASK) {
			//printf("RX ERROR\n");
			error = 1;
			break;
		}

		if ((meta & A_ONCHIP_FIFO_MEM_CORE_CHANNEL_MASK) != 0) {
			//printf("RX ERR: channel mask != 0\n");
			error = 1;
			break;
		}

		if (meta & A_ONCHIP_FIFO_MEM_CORE_SOP) {
			//printf("RX: SOP received\n");
			sop_rcvd = 1;
		}

		if (meta & A_ONCHIP_FIFO_MEM_CORE_EOP) {
			empty = (meta & A_ONCHIP_FIFO_MEM_CORE_EMPTY_MASK) >>
			    A_ONCHIP_FIFO_MEM_CORE_EMPTY_SHIFT;
			//printf("RX: EOP received, empty %d\n", empty);
		}

		if (sop_rcvd == 0) {
			error = 1;
			break;
		}

		bus_space_write_2(bst, bsh_dst, dst_offs, ((data >> 16) & 0xffff));
		dst_offs += 2;

		if (empty == 0) {
			bus_space_write_2(bst, bsh_dst, dst_offs, ((data >> 0) & 0xffff));
			dst_offs += 2;
		} else if (empty == 1) {
			bus_space_write_1(bst, bsh_dst, dst_offs, ((data >> 8) & 0xff));
			dst_offs += 1;
		}

		if (meta & A_ONCHIP_FIFO_MEM_CORE_EOP) {
			break;
		}

		fill_level = atse_rx_read_fill_level();
		timeout = 100;
		while (fill_level == 0 && timeout--) {
			//mtx_sleep(sc, &chan->mtx, 0, "softdma_delay", hz);
			fill_level = atse_rx_read_fill_level();
			printf(".");
		}
		if (timeout == 0) {
			/* No EOP received. Broken packet. */
			error = 1;
			break;
		}
	}

	//printf("%s finished: tot_rcvd %d\n", __func__, dst_offs);

	bus_space_unmap(bst, bsh_src, 4);
	bus_space_unmap(bst, bsh_dst, len);

	if (error) {
		return (-1);
	}

	return (dst_offs);
}

static uint32_t
softdma_process_descriptors(struct softdma_channel *chan, xdma_transfer_status_t *status)
{
	struct xdma_channel *xchan;
	struct softdma_desc *desc;
	struct softdma_softc *sc;
	int ret;

	sc = chan->sc;

	xchan = chan->xchan;
	//conf = &xchan->conf;

	desc = (struct softdma_desc *)xchan->descs;

	while (desc != NULL) {
		if (desc->direction == XDMA_MEM_TO_DEV) {
			ret = softdma_process_tx(chan, desc);
		} else {
			ret = softdma_process_rx(chan, desc);
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
softdma_worker(void *arg)
{
	xdma_transfer_status_t status;
	struct softdma_channel *chan;
	struct softdma_softc *sc;

	chan = arg;

	sc = chan->sc;

	while (1) {
		mtx_lock(&chan->mtx);

		do {
			mtx_sleep(chan, &chan->mtx, 0, "softdma_wait", hz / 2);
		} while (chan->run == 0);

		status.error = 0;
		status.total_copied = 0;

		softdma_process_descriptors(chan, &status);

		/* Finish operation */
		chan->run = 0;
		xdma_callback(chan->xchan, &status);

		mtx_unlock(&chan->mtx);
	}

}

static int
softdma_proc_create(struct softdma_channel *chan)
{
	struct softdma_softc *sc;

	sc = chan->sc;

	if (chan->p != NULL) {
		/* Already created */
		return (0);
	}

	mtx_init(&chan->mtx, "SoftDMA", NULL, MTX_DEF);

	if (kproc_create(softdma_worker, (void *)chan, &chan->p, 0, 0,
	    "softdma_worker") != 0) {
		device_printf(sc->dev,
		    "%s: Failed to create worker thread.\n", __func__);
		return (-1);
	}

	return (0);
}

static int
softdma_channel_alloc(device_t dev, struct xdma_channel *xchan)
{
	struct softdma_channel *chan;
	struct softdma_softc *sc;
	int i;

	sc = device_get_softc(dev);

	xdma_assert_locked();

	for (i = 0; i < SOFTDMA_NCHANNELS; i++) {
		chan = &softdma_channels[i];
		if (chan->used == 0) {
			chan->xchan = xchan;
			xchan->chan = (void *)chan;
			chan->index = i;
			chan->sc = sc;

			if (softdma_proc_create(chan) != 0) {
				return (-1);
			}

			chan->used = 1;

			return (0);
		}
	}

	return (-1);
}

static int
softdma_channel_free(device_t dev, struct xdma_channel *xchan)
{
	struct softdma_channel *chan;
	struct softdma_softc *sc;

	sc = device_get_softc(dev);

	xdma_assert_locked();

	chan = (struct softdma_channel *)xchan->chan;
	//mtx_destroy(&chan->mtx);
	chan->used = 0;

	return (0);
}

static int
softdma_channel_prep_sg(device_t dev, struct xdma_channel *xchan)
{
	//struct softdma_channel *chan;
	//struct softdma_desc *descs;
	//uint32_t addr;
	//uint32_t reg;

	struct softdma_desc *desc;
	struct softdma_softc *sc;
	xdma_config_t *conf;
	int ret;
	int i;

	sc = device_get_softc(dev);

	conf = &xchan->conf;

	printf("%s\n", __func__);

	ret = xdma_desc_alloc(xchan, sizeof(struct softdma_desc), 4);
	if (ret != 0) {
		device_printf(sc->dev,
		    "%s: Can't allocate descriptors.\n", __func__);
		return (-1);
	}

	for (i = 0; i < conf->block_num; i++) {
		desc = xchan->descs[i].desc;

		if (i == (conf->block_num - 1)) {
			desc->next = xchan->descs[0].desc;
		} else {
			desc->next = xchan->descs[i+1].desc;
		}

		printf("%s(%d): desc %d vaddr %lx next vaddr %lx\n", __func__,
		    device_get_unit(dev), i, (uint64_t)desc, (uint64_t)desc->next);
	}


	return (0);
}

static int
softdma_channel_submit_sg(device_t dev, struct xdma_channel *xchan,
    struct xdma_sglist_list *sg_queue)
{
	struct softdma_channel *chan;
	//struct softdma_desc *descs;
	struct softdma_desc *desc;
	struct softdma_softc *sc;
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

	chan = (struct softdma_channel *)xchan->chan;

	//sc->curchan = chan;

	printf("%s(%d)\n", __func__, device_get_unit(dev));

	//printf("%s(%d): nseg %d\n", __func__, device_get_unit(dev), (uint32_t)sg->sg_nseg);
	//mips_dcache_wbinv_all();
	//descs = (struct softdma_desc *)xchan->descs;
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
			desc->read_lo = addr;
			desc->write_lo = 0;
		} else {
			desc->read_lo = 0;
			desc->write_lo = addr;
		}
		desc->length = len;
		desc->transfered = 0;
		desc->status = 0;
		desc->reserved = 0;

		//if (conf->direction == XDMA_MEM_TO_DEV) {
		//	desc->control = htole32(CONTROL_GEN_SOP | CONTROL_GEN_EOP);
		//} else {
		//	desc->control = htole32(CONTROL_END_ON_EOP | (1 << 13));
		//}
		//desc->control |= htole32(CONTROL_TC_IRQ_EN | CONTROL_ET_IRQ_EN | CONTROL_ERR_M);

		tmp = chan->idx_head;
		chan->idx_head = xchan_next_idx(xchan, chan->idx_head);
		//desc->control |= htole32(CONTROL_OWN | CONTROL_GO);
		xdma_enqueue_sync_pre(xchan, tmp);
	}

	return (0);
}

static int
softdma_channel_prep_cyclic(device_t dev, struct xdma_channel *xchan)
{

	return (0);
}

static int
softdma_channel_prep_memcpy(device_t dev, struct xdma_channel *xchan)
{
	struct softdma_channel *chan;
	struct softdma_desc *desc;
	struct softdma_softc *sc;
	xdma_config_t *conf;
	int ret;

	sc = device_get_softc(dev);

	chan = (struct softdma_channel *)xchan->chan;

	/* Ensure we are not in operation */
	//chan_stop(sc, chan);

	ret = xdma_desc_alloc(xchan, sizeof(struct softdma_desc), 8);
	if (ret != 0) {
		device_printf(sc->dev,
		    "%s: Can't allocate descriptors.\n", __func__);
		return (-1);
	}

	conf = &xchan->conf;
	desc = (struct softdma_desc *)xchan->descs;

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
softdma_channel_prep_fifo(device_t dev, struct xdma_channel *xchan)
{
	struct softdma_channel *chan;
	struct softdma_desc *desc;
	struct softdma_softc *sc;
	xdma_config_t *conf;
	int ret;

	conf = &xchan->conf;
	if (conf->direction == XDMA_MEM_TO_DEV) {
		//printf("%s: TX\n", __func__);
	} else {
		//printf("%s: RX\n", __func__);
	}

	sc = device_get_softc(dev);

	chan = (struct softdma_channel *)xchan->chan;

	ret = xdma_desc_alloc(xchan, sizeof(struct softdma_desc), 8);
	if (ret != 0) {
		device_printf(sc->dev,
		    "%s: Can't allocate descriptors.\n", __func__);
		return (-1);
	}

	desc = (struct softdma_desc *)xchan->descs;
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
chan_start(struct softdma_channel *chan)
{
	//struct softdma_softc *sc;

	//sc = chan->sc;

	chan->run = 1;
	wakeup(chan);

	return (0);
}

static int
softdma_channel_control(device_t dev, xdma_channel_t *xchan, int cmd)
{
	struct softdma_channel *chan;
	struct softdma_softc *sc;

	sc = device_get_softc(dev);

	chan = (struct softdma_channel *)xchan->chan;

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
softdma_ofw_md_data(device_t dev, pcell_t *cells, int ncells, void **ptr)
{

	return (0);
}
#endif

static device_method_t softdma_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,			softdma_probe),
	DEVMETHOD(device_attach,		softdma_attach),
	DEVMETHOD(device_detach,		softdma_detach),

	/* xDMA Interface */
	DEVMETHOD(xdma_channel_alloc,		softdma_channel_alloc),
	DEVMETHOD(xdma_channel_free,		softdma_channel_free),
	DEVMETHOD(xdma_channel_prep_cyclic,	softdma_channel_prep_cyclic),
	DEVMETHOD(xdma_channel_prep_memcpy,	softdma_channel_prep_memcpy),
	DEVMETHOD(xdma_channel_prep_fifo,	softdma_channel_prep_fifo),
	DEVMETHOD(xdma_channel_control,		softdma_channel_control),

	DEVMETHOD(xdma_channel_prep_sg,		softdma_channel_prep_sg),
	DEVMETHOD(xdma_channel_submit_sg,	softdma_channel_submit_sg),
#ifdef FDT
	DEVMETHOD(xdma_ofw_md_data,		softdma_ofw_md_data),
#endif

	DEVMETHOD_END
};

static driver_t softdma_driver = {
	"softdma",
	softdma_methods,
	sizeof(struct softdma_softc),
};

static devclass_t softdma_devclass;

EARLY_DRIVER_MODULE(softdma, simplebus, softdma_driver, softdma_devclass, 0, 0,
    BUS_PASS_INTERRUPT + BUS_PASS_ORDER_LATE);
