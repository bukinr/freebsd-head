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

#ifdef FDT
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#endif

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
};

#define	SOFTDMA_NCHANNELS	32
struct softdma_channel softdma_channels[SOFTDMA_NCHANNELS];

struct softdma_desc {
	uint32_t		src_addr;
	uint32_t		dst_addr;
	uint32_t		access_width;
	uint32_t		count;
	uint16_t		src_incr;
	uint16_t		dst_incr;
	struct softdma_desc	*next;
	uint32_t		__reserved[2];
};

struct softdma_softc {
	device_t		dev;
};

static int softdma_probe(device_t dev);
static int softdma_attach(device_t dev);
static int softdma_detach(device_t dev);

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

	sc = device_get_softc(dev);
	sc->dev = dev;

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

static void
softdma_process_descriptors(struct softdma_channel *chan)
{
	bus_space_handle_t bsh_src;
	bus_space_handle_t bsh_dst;
	struct xdma_channel *xchan;
	struct softdma_desc *desc;
	struct softdma_softc *sc;
	bus_space_tag_t bst;
	uint32_t src_offs, dst_offs;
	uint32_t val; /* TODO */
	size_t len;
	int i;

	sc = chan->sc;

	xchan = chan->xchan;
	//conf = &xchan->conf;

	desc = (struct softdma_desc *)xchan->descs;

	bst = fdtbus_bs_tag;

	while (desc != NULL) {
		len = (desc->count * desc->access_width);

		bus_space_map(bst, desc->src_addr, len, 0, &bsh_src);
		bus_space_map(bst, desc->dst_addr, len, 0, &bsh_dst);

		//printf("copy %x -> %x (%d times)\n", bsh_src, bsh_dst, desc->count);

		if (desc->src_incr && desc->dst_incr) {
			bus_space_copy_region_4(bst, bsh_src, 0, bsh_dst, 0, desc->count);
		} else {
			src_offs = dst_offs = 0;
			for (i = 0; i < desc->count; i++) {
				val = bus_space_read_4(bst, bsh_src, src_offs);
				bus_space_write_4(bst, bsh_dst, dst_offs, val);
				if (desc->src_incr)
					src_offs += 4;
				if (desc->dst_incr)
					dst_offs += 4;
			}
		}

		bus_space_unmap(bst, bsh_src, len);
		bus_space_unmap(bst, bsh_dst, len);

		/* Process next descriptor, if any. */
		desc = desc->next;
	}
}

static void
softdma_worker(void *arg)
{
	struct softdma_channel *chan;
	struct softdma_softc *sc;

	chan = arg;

	sc = chan->sc;

	while (1) {
		mtx_lock(&chan->mtx);

		do {
			mtx_sleep(chan, &chan->mtx, 0, "softdma_wait", hz / 2);
		} while (chan->run == 0);

		softdma_process_descriptors(chan);

		/* Finish operation */
		chan->run = 0;
		xdma_callback(chan->xchan);

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
	DEVMETHOD(xdma_channel_control,		softdma_channel_control),
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
