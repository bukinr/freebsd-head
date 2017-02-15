/*-
 * Copyright (c) 2017 Ruslan Bukin <br@bsdpad.com>
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

/* Altera FIFO driver with xDMA(4) interface. */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_platform.h"
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/bus.h>
#include <sys/endian.h>
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

#include <dev/altera/softdma/a_api.h>

#include <dev/xdma/xdma.h>
#include "xdma_if.h"

#define	AVALON_FIFO_TX_BASIC_OPTS_DEPTH		16
#define	SOFTDMA_NCHANNELS			1
#define	CONTROL_GEN_SOP				(1 << 0)
#define	CONTROL_GEN_EOP				(1 << 1)
#define	CONTROL_OWN				(1 << 31)

#define	ATSE_RX_EVENTS	(A_ONCHIP_FIFO_MEM_CORE_INTR_FULL	|\
			 A_ONCHIP_FIFO_MEM_CORE_INTR_OVERFLOW	|\
			 A_ONCHIP_FIFO_MEM_CORE_INTR_UNDERFLOW)
#define	ATSE_TX_EVENTS	(A_ONCHIP_FIFO_MEM_CORE_INTR_EMPTY	|\
			 A_ONCHIP_FIFO_MEM_CORE_INTR_OVERFLOW	|\
			 A_ONCHIP_FIFO_MEM_CORE_INTR_UNDERFLOW)

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

struct softdma_desc {
	uint32_t		src_addr;
	uint32_t		dst_addr;
	uint32_t		len;
	uint32_t		access_width;
	uint32_t		count;
	uint16_t		src_incr;
	uint16_t		dst_incr;
	uint32_t		direction;
	struct softdma_desc	*next;
	uint32_t		transfered;
	uint32_t		status;
	uint32_t		reserved;
	uint32_t		control;
};

struct softdma_softc {
	device_t		dev;
	struct resource		*res[3];
	bus_space_tag_t		bst;
	bus_space_handle_t	bsh;
	bus_space_tag_t		bst_c;
	bus_space_handle_t	bsh_c;
	void			*ih;
	struct softdma_channel	channels[SOFTDMA_NCHANNELS];
};

static struct resource_spec softdma_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },	/* fifo */
	{ SYS_RES_MEMORY,	1,	RF_ACTIVE },	/* core */
	{ SYS_RES_IRQ,		0,	RF_ACTIVE },
	{ -1, 0 }
};

static int softdma_probe(device_t dev);
static int softdma_attach(device_t dev);
static int softdma_detach(device_t dev);

static void
softdma_mem_write(struct softdma_softc *sc, uint32_t reg, uint32_t val)
{

	bus_write_4(sc->res[0], reg, htole32(val));
}

static uint32_t
softdma_mem_read(struct softdma_softc *sc, uint32_t reg)
{
	uint32_t val;

	val = bus_read_4(sc->res[0], reg);

	return (le32toh(val));
}

static void
softdma_memc_write(struct softdma_softc *sc, uint32_t reg, uint32_t val)
{

	bus_write_4(sc->res[1], reg, htole32(val));
}

static uint32_t
softdma_memc_read(struct softdma_softc *sc, uint32_t reg)
{
	uint32_t val;

	val = bus_read_4(sc->res[1], reg);

	return (le32toh(val));
}

static uint32_t
softdma_fill_level(struct softdma_softc *sc)
{
	uint32_t val;

	val = softdma_memc_read(sc,
	    A_ONCHIP_FIFO_MEM_CORE_STATUS_REG_FILL_LEVEL);

	return (val);
}

static void
softdma_intr(void *arg)
{
	struct softdma_channel *chan;
	struct softdma_softc *sc;
	int reg;
	int err;

	sc = arg;

	chan = &sc->channels[0];

	reg = softdma_memc_read(sc, A_ONCHIP_FIFO_MEM_CORE_STATUS_REG_EVENT);

	if (reg & (A_ONCHIP_FIFO_MEM_CORE_EVENT_OVERFLOW | 
	    A_ONCHIP_FIFO_MEM_CORE_EVENT_UNDERFLOW)) {
		/* Errors */
		err = (((reg & A_ONCHIP_FIFO_MEM_CORE_ERROR_MASK) >> \
		    A_ONCHIP_FIFO_MEM_CORE_ERROR_SHIFT) & 0xff);
	}

	if (reg != 0) {
		softdma_memc_write(sc, A_ONCHIP_FIFO_MEM_CORE_STATUS_REG_EVENT, reg);
		chan->run = 1;
		wakeup(chan);
	}
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
	struct softdma_softc *sc;
	bus_space_tag_t bst;
	uint32_t reg;
	uint32_t fill_level;
	uint32_t leftm;
	uint32_t tmp;
	uint32_t val;
	uint32_t c;

	sc = chan->sc;

	bst = fdtbus_bs_tag;
	bus_space_map(bst, desc->src_addr, desc->len, 0, &bsh_src);

	fill_level = softdma_fill_level(sc);
	while (fill_level == AVALON_FIFO_TX_BASIC_OPTS_DEPTH) {
		fill_level = softdma_fill_level(sc);
	}

	/* Set start of packet. */
	if (desc->control & CONTROL_GEN_SOP) {
		reg = 0;
		reg |= A_ONCHIP_FIFO_MEM_CORE_SOP;
		softdma_mem_write(sc, A_ONCHIP_FIFO_MEM_CORE_METADATA, reg);
	}

	src_offs = dst_offs = 0;
	c = 0;
	while ((desc->len - c) >= 4) {
		val = bus_space_read_4(bst, bsh_src, src_offs);
		bus_write_4(sc->res[0], A_ONCHIP_FIFO_MEM_CORE_DATA, val);
		if (desc->src_incr)
			src_offs += 4;
		if (desc->dst_incr)
			dst_offs += 4;
		fill_level += 1;

		while (fill_level == AVALON_FIFO_TX_BASIC_OPTS_DEPTH) {
			fill_level = softdma_fill_level(sc);
		}
		c += 4;
	}

	val = 0;
	leftm = (desc->len - c);
	switch (leftm) {
	case 1:
		val = bus_space_read_1(bst, bsh_src, src_offs);
		val <<= 24;
		src_offs += 1;
		break;
	case 2:
	case 3:
		val = bus_space_read_2(bst, bsh_src, src_offs);
		val <<= 16;
		src_offs += 2;

		if (leftm == 3) {
			tmp = bus_space_read_1(bst, bsh_src, src_offs);
			val |= (tmp << 8);
			src_offs += 1;
		}
		break;
	case 0:
	default:
		break;
	}

	/* Set end of packet. */
	reg = 0;
	if (desc->control & CONTROL_GEN_EOP) {
		reg |= A_ONCHIP_FIFO_MEM_CORE_EOP;
	}
	reg |= ((4 - leftm) << A_ONCHIP_FIFO_MEM_CORE_EMPTY_SHIFT);
	softdma_mem_write(sc, A_ONCHIP_FIFO_MEM_CORE_METADATA, reg);

	/* Ensure there is a FIFO entry available. */
	fill_level = softdma_fill_level(sc);
	while (fill_level == AVALON_FIFO_TX_BASIC_OPTS_DEPTH) {
		fill_level = softdma_fill_level(sc);
	};

	/* Final write */
	bus_write_4(sc->res[0], A_ONCHIP_FIFO_MEM_CORE_DATA, val);
	bus_space_unmap(bst, bsh_src, desc->len);

	return (dst_offs);
}

static int
softdma_process_rx(struct softdma_channel *chan, struct softdma_desc *desc)
{
	uint32_t src_offs, dst_offs;
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

	fill_level = softdma_fill_level(sc);
	if (fill_level == 0) {
		/* Nothing to receive. */
		return (0);
	}

	len = desc->len;
	bus_space_map(bst, desc->dst_addr, len, 0, &bsh_dst);

	sop_rcvd = 0;
	while (fill_level) {
		empty = 0;
		data = bus_read_4(sc->res[0], A_ONCHIP_FIFO_MEM_CORE_DATA);
		meta = softdma_mem_read(sc, A_ONCHIP_FIFO_MEM_CORE_METADATA);

		if (meta & A_ONCHIP_FIFO_MEM_CORE_ERROR_MASK) {
			error = 1;
			break;
		}

		if ((meta & A_ONCHIP_FIFO_MEM_CORE_CHANNEL_MASK) != 0) {
			error = 1;
			break;
		}

		if (meta & A_ONCHIP_FIFO_MEM_CORE_SOP) {
			sop_rcvd = 1;
		}

		if (meta & A_ONCHIP_FIFO_MEM_CORE_EOP) {
			empty = (meta & A_ONCHIP_FIFO_MEM_CORE_EMPTY_MASK) >>
			    A_ONCHIP_FIFO_MEM_CORE_EMPTY_SHIFT;
		}

		if (sop_rcvd == 0) {
			error = 1;
			break;
		}

		bus_space_write_2(bst, bsh_dst, dst_offs, ((data >> 16) & 0xffff));
		dst_offs += 2;

		if (empty == 0) {
			bus_space_write_2(bst, bsh_dst, dst_offs,
			    ((data >> 0) & 0xffff));
			dst_offs += 2;
		} else if (empty == 1) {
			bus_space_write_1(bst, bsh_dst, dst_offs,
			    ((data >> 8) & 0xff));
			dst_offs += 1;
		} else {
			panic("empty %d\n", empty);
		}

		if (meta & A_ONCHIP_FIFO_MEM_CORE_EOP) {
			break;
		}

		fill_level = softdma_fill_level(sc);
		timeout = 100;
		while (fill_level == 0 && timeout--) {
			fill_level = softdma_fill_level(sc);
		}
		if (timeout == 0) {
			/* No EOP received. Broken packet. */
			error = 1;
			break;
		}
	}

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
	xdma_descriptor_t *descs;
	xdma_transfer_status_t st;
	int ret;

	sc = chan->sc;

	xchan = chan->xchan;

	descs = xchan->descs;
	desc = (struct softdma_desc *)descs[chan->idx_tail].desc;

	while (desc != NULL) {

		if ((desc->control & CONTROL_OWN) == 0) {
			break;
		}

		if (desc->direction == XDMA_MEM_TO_DEV) {
			ret = softdma_process_tx(chan, desc);
		} else {
			ret = softdma_process_rx(chan, desc);
			if (ret == 0) {
				/* No new data available. */
				break;
			}
			xchan_desc_sync_post(xchan, chan->idx_tail);
		}

		/* Descriptor processed. */
		desc->control = 0;

		if (ret >= 0) {
			st.error = 0;
			st.transferred = ret;
		} else {
			st.error = ret;
			st.transferred = 0;
		}

		xchan_desc_done(xchan, chan->idx_tail, &st);

		if (ret >= 0) {
			status->transferred += ret;
		} else {
			status->error = 1;
			break;
		}

		chan->idx_tail = xchan_next_idx(xchan, chan->idx_tail);

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
		status.transferred = 0;

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
		chan = &sc->channels[i];
		if (chan->used == 0) {
			chan->xchan = xchan;
			xchan->chan = (void *)chan;
			chan->index = i;
			chan->idx_head = 0;
			chan->idx_tail = 0;
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
	chan->used = 0;

	return (0);
}

static int
softdma_channel_prep_sg(device_t dev, struct xdma_channel *xchan)
{
	struct softdma_desc *desc;
	struct softdma_softc *sc;
	xdma_config_t *conf;
	int ret;
	int i;

	sc = device_get_softc(dev);

	conf = &xchan->conf;

	ret = xchan_desc_alloc(xchan, sizeof(struct softdma_desc), 4);
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
	}


	return (0);
}

static int
softdma_channel_submit_sg(device_t dev, struct xdma_channel *xchan,
    struct xdma_sglist *sg, uint32_t sg_n)
{
	struct softdma_channel *chan;
	struct softdma_desc *desc;
	struct softdma_softc *sc;
	xdma_config_t *conf;
	uint32_t enqueued;
	uint32_t saved_dir;
	uint32_t tmp;
	uint32_t addr;
	uint32_t len;
	int i;

	sc = device_get_softc(dev);

	conf = &xchan->conf;
	chan = (struct softdma_channel *)xchan->chan;

	enqueued = 0;

	for (i = 0; i < sg_n; i++) {
		addr = (uint32_t)sg[i].paddr;
		len = (uint32_t)sg[i].len;

		desc = xchan->descs[chan->idx_head].desc;
		if (sg[i].direction == XDMA_MEM_TO_DEV) {
			desc->src_addr = addr;
			desc->src_incr = 1;

			desc->dst_addr = 0;
			desc->dst_incr = 0;
		} else {
			desc->src_addr = 0;
			desc->src_incr = 0;

			desc->dst_addr = addr;
			desc->dst_incr = 1;
		}
		desc->direction = sg[i].direction;
		saved_dir = sg[i].direction;
		desc->len = len;
		desc->transfered = 0;
		desc->status = 0;
		desc->reserved = 0;
		desc->control = 0;

		if (sg[i].first == 1) {
			desc->control |= CONTROL_GEN_SOP;
		}

		if (sg[i].last == 1) {
			desc->control |= CONTROL_GEN_EOP;
		}

		tmp = chan->idx_head;
		chan->idx_head = xchan_next_idx(xchan, chan->idx_head);
		desc->control |= CONTROL_OWN;
		xchan_desc_sync_pre(xchan, tmp);

		enqueued += 1;
	}

	if (enqueued == 0) {
		return (0);
	}

	if (saved_dir == XDMA_MEM_TO_DEV) {
		chan->run = 1;
		wakeup(chan);
	} else {
		softdma_memc_write(sc, A_ONCHIP_FIFO_MEM_CORE_STATUS_REG_INT_ENABLE, ATSE_RX_EVENTS);
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

	ret = xchan_desc_alloc(xchan, sizeof(struct softdma_desc), 8);
	if (ret != 0) {
		device_printf(sc->dev,
		    "%s: Can't allocate descriptors.\n", __func__);
		return (-1);
	}

	conf = &xchan->conf;
	desc = (struct softdma_desc *)xchan->descs;

	desc[0].src_addr = conf->src_addr;
	desc[0].dst_addr = conf->dst_addr;
	desc[0].len = conf->block_len;
	desc[0].src_incr = 1;
	desc[0].dst_incr = 1;
	desc[0].next = NULL;

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
	case XDMA_CMD_TERMINATE:
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
