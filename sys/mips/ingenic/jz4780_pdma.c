/*-
 * Copyright (c) 2016-2017 Ruslan Bukin <br@bsdpad.com>
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

/* Ingenic JZ4780 PDMA Controller. */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_platform.h"
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/resource.h>
#include <sys/rman.h>

#include <machine/bus.h>
#include <machine/cache.h>

#ifdef FDT
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#endif

#include <dev/xdma/xdma.h>

#include <mips/ingenic/jz4780_common.h>
#include <mips/ingenic/jz4780_pdma.h>

#include "xdma_if.h"

struct pdma_softc {
	device_t		dev;
	struct resource		*res[2];
	bus_space_tag_t		bst;
	bus_space_handle_t	bsh;
	void			*ih;
};

struct pdma_fdt_data {
	int tx;
	int rx;
	int chan;
};

struct pdma_channel {
	xdma_channel_t		*xchan;
	struct pdma_fdt_data	data;
	int			cur_desc;
	int			used;
	int			index;
	int			flags;
	uint32_t		idx_head;
	uint32_t		idx_tail;
	uint32_t		enq;
#define	CHAN_DESCR_RELINK	(1 << 0)
};

#define	PDMA_NCHANNELS	32
struct pdma_channel pdma_channels[PDMA_NCHANNELS];

static struct resource_spec pdma_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ SYS_RES_IRQ,		0,	RF_ACTIVE },
	{ -1, 0 }
};

static int pdma_probe(device_t dev);
static int pdma_attach(device_t dev);
static int pdma_detach(device_t dev);
static int chan_start(struct pdma_softc *sc, struct pdma_channel *chan);

static void
pdma_intr(void *arg)
{
	xdma_transfer_status_t status;
	xdma_transfer_status_t st;
	struct pdma_hwdesc *desc;
	struct pdma_channel *chan;
	struct pdma_softc *sc;
	xdma_channel_t *xchan;
	xdma_config_t *conf;
	int pending;
	int i;

	sc = arg;

	pending = READ4(sc, PDMA_DIRQP);

	/* Ack all the channels. */
	WRITE4(sc, PDMA_DIRQP, 0);

	for (i = 0; i < PDMA_NCHANNELS; i++) {
		if (pending & (1 << i)) {
			printf("pdma_intr %d\n", i);
			chan = &pdma_channels[i];
			xchan = chan->xchan;
			conf = &xchan->conf;

			/* TODO: check for AR, HLT error bits here. */
			printf("DCS %x\n", READ4(sc, PDMA_DCS(chan->index)));

			/* Disable channel */
			WRITE4(sc, PDMA_DCS(chan->index), 0);

			if (chan->flags & CHAN_DESCR_RELINK) {
				/* Enable again */
				chan->cur_desc = (chan->cur_desc + 1) % \
				    conf->block_num;
				chan_start(sc, chan);
			} else {
				//for
				for (i = 0; i < chan->enq; i++) {
					xchan_desc_sync_post(xchan, chan->idx_tail);
					st.error = 0;
					st.transferred = 0;

					desc = xchan->descs[chan->idx_tail].desc;
					printf("%s: desc src_addr %x\n", __func__, desc->dsa);

					xchan_desc_done(xchan, chan->idx_tail, &st);
					chan->idx_tail = xchan_next_desc(xchan, chan->idx_tail);
				}
			}

			status.error = 0;
			xdma_callback(chan->xchan, &status);
		}
	}
}

static int
pdma_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (!ofw_bus_is_compatible(dev, "ingenic,jz4780-dma"))
		return (ENXIO);

	device_set_desc(dev, "Ingenic JZ4780 PDMA Controller");

	return (BUS_PROBE_DEFAULT);
}

static int
pdma_attach(device_t dev)
{
	struct pdma_softc *sc;
	phandle_t xref, node;
	int err;
	int reg;

	sc = device_get_softc(dev);
	sc->dev = dev;

	if (bus_alloc_resources(dev, pdma_spec, sc->res)) {
		device_printf(dev, "could not allocate resources for device\n");
		return (ENXIO);
	}

	/* Memory interface */
	sc->bst = rman_get_bustag(sc->res[0]);
	sc->bsh = rman_get_bushandle(sc->res[0]);

	/* Setup interrupt handler */
	err = bus_setup_intr(dev, sc->res[1], INTR_TYPE_MISC | INTR_MPSAFE,
	    NULL, pdma_intr, sc, &sc->ih);
	if (err) {
		device_printf(dev, "Unable to alloc interrupt resource.\n");
		return (ENXIO);
	}

	node = ofw_bus_get_node(dev);
	xref = OF_xref_from_node(node);
	OF_device_register_xref(xref, dev);

	reg = READ4(sc, PDMA_DMAC);
	reg &= ~(DMAC_HLT | DMAC_AR);
	reg |= (DMAC_DMAE);
	//reg |= (1 << 1); //CH01
	WRITE4(sc, PDMA_DMAC, reg);

	WRITE4(sc, PDMA_DMACP, 0);

	return (0);
}

static int
pdma_detach(device_t dev)
{
	struct pdma_softc *sc;

	sc = device_get_softc(dev);

	bus_release_resources(dev, pdma_spec, sc->res);

	return (0);
}

static int
chan_start(struct pdma_softc *sc, struct pdma_channel *chan)
{
	struct xdma_channel *xchan;

	xchan = chan->xchan;

	/* 8 byte descriptor. */
	WRITE4(sc, PDMA_DCS(chan->index), DCS_DES8);
	WRITE4(sc, PDMA_DDA(chan->index),
	    xchan->descs[chan->cur_desc].ds_addr);
	WRITE4(sc, PDMA_DDS, (1 << chan->index));

	/* Channel transfer enable. */
	WRITE4(sc, PDMA_DCS(chan->index), (DCS_DES8 | DCS_CTE));

	return (0);
}

static int
chan_stop(struct pdma_softc *sc, struct pdma_channel *chan)
{
	int timeout;

	WRITE4(sc, PDMA_DCS(chan->index), 0);

	timeout = 100;

	do {
		if ((READ4(sc, PDMA_DCS(chan->index)) & DCS_CTE) == 0) {
			break;
		}
	} while (timeout--);

	if (timeout == 0) {
		device_printf(sc->dev, "%s: Can't stop channel %d\n",
		    __func__, chan->index);
	}

	return (0);
}

static int
pdma_channel_alloc(device_t dev, struct xdma_channel *xchan)
{
	struct pdma_channel *chan;
	struct pdma_softc *sc;
	int i;

	sc = device_get_softc(dev);

	xdma_assert_locked();

	for (i = 0; i < PDMA_NCHANNELS; i++) {
		chan = &pdma_channels[i];
		if (chan->used == 0) {
			chan->xchan = xchan;
			xchan->chan = (void *)chan;
			chan->used = 1;
			chan->index = i;
			chan->idx_tail = 0;
			chan->idx_head = 0;

			printf("channel %d allocated\n", i);

			return (0);
		}
	}

	return (-1);
}

static int
pdma_channel_free(device_t dev, struct xdma_channel *xchan)
{
	struct pdma_channel *chan;
	struct pdma_softc *sc;

	sc = device_get_softc(dev);

	xdma_assert_locked();

	chan = (struct pdma_channel *)xchan->chan;
	chan->used = 0;

	return (0);
}

static int
pdma_channel_prep_memcpy(device_t dev, struct xdma_channel *xchan)
{
	struct pdma_channel *chan;
	xdma_descriptor_t *descs;
	struct pdma_hwdesc *desc;
	struct pdma_softc *sc;
	xdma_config_t *conf;
	int ret;

	sc = device_get_softc(dev);

	chan = (struct pdma_channel *)xchan->chan;
	/* Ensure we are not in operation */
	chan_stop(sc, chan);

	ret = xchan_desc_alloc(xchan, sizeof(struct pdma_hwdesc), 16);
	if (ret != 0) {
		device_printf(sc->dev,
		    "%s: Can't allocate descriptors.\n", __func__);
		return (-1);
	}

	conf = &xchan->conf;
	descs = xchan->descs;

	desc = descs[0].desc;
	desc->dsa = conf->src_addr;
	desc->dta = conf->dst_addr;
	desc->drt = DRT_AUTO;
	desc->dcm = DCM_SAI | DCM_DAI;

	/* 4 byte copy for now. */
	desc->dtc = (conf->block_len / 4);
	desc->dcm |= DCM_SP_4 | DCM_DP_4 | DCM_TSZ_4;
	desc->dcm |= DCM_TIE;

	return (0);
}

static int
access_width(xdma_config_t *conf, uint32_t *dcm, uint32_t *max_width)
{

	*dcm = 0;
	*max_width = max(conf->src_width, conf->dst_width);

	switch (conf->src_width) {
	case 1:
		*dcm |= DCM_SP_1;
		break;
	case 2:
		*dcm |= DCM_SP_2;
		break;
	case 4:
		*dcm |= DCM_SP_4;
		break;
	default:
		return (-1);
	}

	switch (conf->dst_width) {
	case 1:
		*dcm |= DCM_DP_1;
		break;
	case 2:
		*dcm |= DCM_DP_2;
		break;
	case 4:
		*dcm |= DCM_DP_4;
		break;
	default:
		return (-1);
	}

	switch (*max_width) {
	case 1:
		*dcm |= DCM_TSZ_1;
		break;
	case 2:
		*dcm |= DCM_TSZ_2;
		break;
	case 4:
		*dcm |= DCM_TSZ_4;
		break;
	default:
		return (-1);
	};

	return (0);
}

static int
pdma_channel_prep_cyclic(device_t dev, struct xdma_channel *xchan)
{
	struct pdma_fdt_data *data;
	struct pdma_channel *chan;
	xdma_descriptor_t *descs;
	struct pdma_hwdesc *desc;
	xdma_controller_t *xdma;
	struct pdma_softc *sc;
	xdma_config_t *conf;
	int max_width;
	uint32_t reg;
	uint32_t dcm;
	int ret;
	int i;

	sc = device_get_softc(dev);

	conf = &xchan->conf;
	xdma = xchan->xdma;
	data = (struct pdma_fdt_data *)xdma->data;

	ret = xchan_desc_alloc(xchan, sizeof(struct pdma_hwdesc), 16);
	if (ret != 0) {
		device_printf(sc->dev,
		    "%s: Can't allocate descriptors.\n", __func__);
		return (-1);
	}

	chan = (struct pdma_channel *)xchan->chan;
	/* Ensure we are not in operation */
	chan_stop(sc, chan);
	chan->flags = CHAN_DESCR_RELINK;
	chan->cur_desc = 0;

	descs = xchan->descs;

	for (i = 0; i < conf->block_num; i++) {
		desc = (struct pdma_hwdesc *)descs[i].desc;

		if (conf->direction == XDMA_MEM_TO_DEV) {
			desc->dsa = conf->src_addr + (i * conf->block_len);
			desc->dta = conf->dst_addr;
			desc->drt = data->tx;
			desc->dcm = DCM_SAI;
		} else if (conf->direction == XDMA_DEV_TO_MEM) {
			desc->dsa = conf->src_addr;
			desc->dta = conf->dst_addr + (i * conf->block_len);
			desc->drt = data->rx;
			desc->dcm = DCM_DAI;
		} else if (conf->direction == XDMA_MEM_TO_MEM) {
			desc->dsa = conf->src_addr + (i * conf->block_len);
			desc->dta = conf->dst_addr + (i * conf->block_len);
			desc->drt = DRT_AUTO;
			desc->dcm = DCM_SAI | DCM_DAI;
		}

		if (access_width(conf, &dcm, &max_width) != 0) {
			device_printf(dev,
			    "%s: can't configure access width\n", __func__);
			return (-1);
		}

		desc->dcm |= (dcm | DCM_TIE);
		desc->dtc = (conf->block_len / max_width);

		xchan_desc_sync_pre(xchan, i);

		/*
		 * PDMA does not provide interrupt after processing each descriptor,
		 * but after processing all the chain only.
		 * As a workaround we do unlink descriptors here, so our chain will
		 * consists of single descriptor only. And then we reconfigure channel
		 * on each interrupt again.
		 */
		if ((chan->flags & CHAN_DESCR_RELINK) == 0) {
			if (i != (conf->block_num - 1)) {
				desc->dcm |= DCM_LINK;
				reg = ((i + 1) * sizeof(struct pdma_hwdesc));
				desc->dtc |= (reg >> 4) << 24;
			}
		}
	}

	return (0);
}

static int
pdma_channel_prep_sg(device_t dev, struct xdma_channel *xchan)
{
	xdma_descriptor_t *descs;
	struct pdma_hwdesc *desc;
	struct pdma_softc *sc;
	uint32_t reg;
	int ret;
	int i;

	printf("%s\n", __func__);

	ret = xchan_desc_alloc(xchan, sizeof(struct pdma_hwdesc), 16);
	if (ret != 0) {
		device_printf(sc->dev,
		    "%s: Can't allocate descriptors.\n", __func__);
		return (-1);
	}

	descs = xchan->descs;

	for (i = 0; i < xchan->descs_num; i++) {
		desc = (struct pdma_hwdesc *)descs[i].desc;

		if (i != (xchan->descs_num - 1)) {
			desc->dcm = DCM_LINK;
			reg = ((i + 1) * sizeof(struct pdma_hwdesc));
			desc->dtc = (reg >> 4) << 24;
		}

		desc->dsa = 0;
		desc->dta = 0;
		desc->drt = 0;
		desc->dcm = 0;
		desc->dtc = 0;
	}

	sc = device_get_softc(dev);

	return (0);
}

#if 0
static int
pdma_channel_submit_sg(device_t dev, struct xdma_channel *xchan,
    struct xdma_sglist *sg, uint32_t sg_n)
{
	struct pdma_channel *chan;
	struct pdma_softc *sc;
	uint32_t src_addr;
	uint32_t dst_addr;
	uint32_t len;
	uint32_t enq;
	uint32_t reg;
	int i;

	printf("%s: sg_n %d\n", __func__, sg_n);

	sc = device_get_softc(dev);

	chan = (struct pdma_channel *)xchan->chan;

	enq = 0;

	//uint32_t ds_addr;
	//ds_addr = xchan->descs[chan->idx_head].ds_addr;
	//void *a = malloc(2048, M_DEVBUF);

	for (i = 0; i < sg_n; i++) {
		src_addr = (uint32_t)sg[i].src_paddr;
		dst_addr = (uint32_t)sg[i].dst_paddr;
		len = (uint32_t)sg[i].len;

		WRITE4(sc, PDMA_DSA(chan->index), src_addr);
		WRITE4(sc, PDMA_DTA(chan->index), 0x13422000); //dst_addr);
		WRITE4(sc, PDMA_DTC(chan->index), len / 4);
		WRITE4(sc, PDMA_DRT(chan->index), DRT_AUTO);

		reg = DCM_SP_4 | DCM_DP_4 | DCM_TSZ_A | DCM_TIE;
		if (sg->direction == XDMA_MEM_TO_DEV) {
			reg |= DCM_SAI;
			//desc->dcm |= (1 << 24); // destination is NEMC
			//desc->dcm |= (2 << 26); // source is DDR
		} else if (sg->direction == XDMA_DEV_TO_MEM) {
			reg |= DCM_DAI;
			//desc->dcm |= (1 << 26); // source is NEMC
		} else {
			panic("here\n");
		}
		WRITE4(sc, PDMA_DCM(chan->index), reg);
	}

	chan->enq = 1;

	/* No descriptor mode. */
	WRITE4(sc, PDMA_DCS(chan->index), DCS_NDES);
	WRITE4(sc, PDMA_DDS, (1 << chan->index));
	/* Channel transfer enable. */
	WRITE4(sc, PDMA_DCS(chan->index), (DCS_NDES | DCS_CTE));

	return (0);
}
#endif

#if 1
static int
pdma_channel_submit_sg(device_t dev, struct xdma_channel *xchan,
    struct xdma_sglist *sg, uint32_t sg_n)
{
	struct pdma_channel *chan;
	struct pdma_hwdesc *desc;
	struct pdma_softc *sc;
	uint32_t src_addr;
	uint32_t dst_addr;
	uint32_t len;
	uint32_t tmp;
	uint32_t enq;
	uint32_t reg;
	int i;

	printf("%s: sg_n %d\n", __func__, sg_n);

	sc = device_get_softc(dev);

	chan = (struct pdma_channel *)xchan->chan;

	enq = 0;

	uint32_t ds_addr;
	ds_addr = xchan->descs[chan->idx_head].ds_addr;

	//void *a = malloc(2048, M_DEVBUF);

	for (i = 0; i < sg_n; i++) {
		src_addr = (uint32_t)sg[i].src_addr;
		dst_addr = (uint32_t)sg[i].dst_addr;
		len = (uint32_t)sg[i].len;

		printf("src addr %x dst addr %x len %d, desc idx_head %d\n",
		    src_addr, dst_addr, len, chan->idx_head);

		desc = xchan->descs[chan->idx_head].desc;

		desc->dsa = 0;
		desc->dta = 0;
		desc->drt = 0;
		desc->dcm = 0;
		desc->dtc = 0;

		//desc->dsa = 0x13422000; //TCSM
		//desc->dta = 0x13422000; //TCSM

		desc->dsa = src_addr;
		desc->dta = dst_addr;
		desc->drt = DRT_AUTO;
		desc->dcm = DCM_SP_1 | DCM_DP_1 | DCM_TSZ_A | DCM_TIE;
		//desc->dtc &= ~(0xffffff);
		desc->dtc = len;

		if (sg->direction == XDMA_MEM_TO_DEV) {
			desc->dcm |= DCM_SAI;
			//desc->dcm |= (1 << 24); // destination is NEMC
			//desc->dcm |= (2 << 26); // source is DDR
		} else if (sg->direction == XDMA_DEV_TO_MEM) {
			desc->dcm |= DCM_DAI;
			desc->dcm |= (1 << 26); // source is NEMC
		} else {
			panic("here\n");
		}

		//desc->dcm |= (1 << 16); //RDIL Recommended data unit size (unit: byte) for triggering device`s DMA request when TSZ is autonomy.

		if (i != (sg_n - 1)) {
			//desc->dcm |= DCM_LINK;

			reg = ((i + 1) * sizeof(struct pdma_hwdesc));
			//desc->dtc |= (reg >> 4) << 24;
		}

		tmp = chan->idx_head;
		chan->idx_head = xchan_next_desc(xchan, chan->idx_head);
		//desc->control |= htole32(CONTROL_OWN | CONTROL_GO);
		xchan_desc_sync_pre(xchan, tmp);

		enq++;
	}

	if (enq != 0) {
		chan->enq = enq;
		printf("ds addr %x\n", ds_addr);

		/* 8 byte descriptor. */
		WRITE4(sc, PDMA_DCS(chan->index), DCS_DES8);
		//WRITE4(sc, PDMA_DDA(chan->index),
		//    xchan->descs[chan->idx_tail].ds_addr);
		WRITE4(sc, PDMA_DDA(chan->index), ds_addr);
		WRITE4(sc, PDMA_DDS, (1 << chan->index));

		/* Channel transfer enable. */
		WRITE4(sc, PDMA_DCS(chan->index), (DCS_DES8 | DCS_CTE));
	}

	return (0);
}
#endif

static int
pdma_channel_control(device_t dev, xdma_channel_t *xchan, int cmd)
{
	struct pdma_channel *chan;
	struct pdma_softc *sc;

	sc = device_get_softc(dev);

	chan = (struct pdma_channel *)xchan->chan;

	switch (cmd) {
	case XDMA_CMD_BEGIN:
		chan_start(sc, chan);
		break;
	case XDMA_CMD_TERMINATE:
		chan_stop(sc, chan);
		break;
	case XDMA_CMD_PAUSE:
		/* TODO: implement me */
		return (-1);
	}

	return (0);
}

#ifdef FDT
static int
pdma_ofw_md_data(device_t dev, pcell_t *cells, int ncells, void **ptr)
{
	struct pdma_fdt_data *data;

	if (ncells != 3) {
		return (-1);
	}

	data = malloc(sizeof(struct pdma_fdt_data), M_DEVBUF, (M_WAITOK | M_ZERO));
	if (data == NULL) {
		device_printf(dev, "%s: Cant allocate memory\n", __func__);
		return (-1);
	}

	data->tx = cells[0];
	data->rx = cells[1];
	data->chan = cells[2];

	*ptr = data;

	return (0);
}
#endif

static device_method_t pdma_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,			pdma_probe),
	DEVMETHOD(device_attach,		pdma_attach),
	DEVMETHOD(device_detach,		pdma_detach),

	/* xDMA Interface */
	DEVMETHOD(xdma_channel_alloc,		pdma_channel_alloc),
	DEVMETHOD(xdma_channel_free,		pdma_channel_free),
	DEVMETHOD(xdma_channel_prep_cyclic,	pdma_channel_prep_cyclic),
	DEVMETHOD(xdma_channel_prep_memcpy,	pdma_channel_prep_memcpy),
	DEVMETHOD(xdma_channel_control,		pdma_channel_control),

	/* xDMA SG Interface */
	DEVMETHOD(xdma_channel_prep_sg,		pdma_channel_prep_sg),
	DEVMETHOD(xdma_channel_submit_sg,	pdma_channel_submit_sg),

#ifdef FDT
	DEVMETHOD(xdma_ofw_md_data,		pdma_ofw_md_data),
#endif

	DEVMETHOD_END
};

static driver_t pdma_driver = {
	"pdma",
	pdma_methods,
	sizeof(struct pdma_softc),
};

static devclass_t pdma_devclass;

EARLY_DRIVER_MODULE(pdma, simplebus, pdma_driver, pdma_devclass, 0, 0,
    BUS_PASS_INTERRUPT + BUS_PASS_ORDER_LATE);
