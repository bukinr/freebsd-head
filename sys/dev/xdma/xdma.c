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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_platform.h"
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/queue.h>
#include <sys/kobj.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/mbuf.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/sx.h>
#include <sys/bus_dma.h>

#include <machine/bus.h>

#ifdef FDT
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#endif

#include <dev/xdma/xdma.h>

#include <xdma_if.h>

MALLOC_DEFINE(M_XDMA, "xdma", "xDMA framework");

/*
 * Multiple xDMA controllers may work with single DMA device,
 * so we have global lock for physical channel management.
 */
static struct mtx xdma_mtx;

#define	XDMA_LOCK()		mtx_lock(&xdma_mtx)
#define	XDMA_UNLOCK()		mtx_unlock(&xdma_mtx)
#define	XDMA_ASSERT_LOCKED()	mtx_assert(&xdma_mtx, MA_OWNED)

/*
 * Per channel locks.
 */
#define	XCHAN_LOCK(xchan)		mtx_lock(&(xchan)->mtx_lock)
#define	XCHAN_UNLOCK(xchan)		mtx_unlock(&(xchan)->mtx_lock)
#define	XCHAN_ASSERT_LOCKED(xchan)	mtx_assert(&(xchan)->mtx_lock, MA_OWNED)

/*
 * Channel queues locks.
 */
#define	QUEUE_IN_LOCK(xchan)		mtx_lock(&(xchan)->mtx_qin_lock)
#define	QUEUE_IN_UNLOCK(xchan)		mtx_unlock(&(xchan)->mtx_qin_lock)
#define	QUEUE_IN_ASSERT_LOCKED(xchan)	mtx_assert(&(xchan)->mtx_qin_lock, MA_OWNED)

#define	QUEUE_OUT_LOCK(xchan)		mtx_lock(&(xchan)->mtx_qout_lock)
#define	QUEUE_OUT_UNLOCK(xchan)		mtx_unlock(&(xchan)->mtx_qout_lock)
#define	QUEUE_OUT_ASSERT_LOCKED(xchan)	mtx_assert(&(xchan)->mtx_qout_lock, MA_OWNED)

/*
 * Allocate virtual xDMA channel.
 */
xdma_channel_t *
xdma_channel_alloc(xdma_controller_t *xdma)
{
	xdma_channel_t *xchan;
	int ret;

	xchan = malloc(sizeof(xdma_channel_t), M_XDMA, M_WAITOK | M_ZERO);
	if (xchan == NULL) {
		device_printf(xdma->dev,
		    "%s: Can't allocate memory for channel.\n", __func__);
		return (NULL);
	}
	xchan->xdma = xdma;

	XDMA_LOCK();

	/* Request a real channel from hardware driver. */
	ret = XDMA_CHANNEL_ALLOC(xdma->dma_dev, xchan);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't request hardware channel.\n", __func__);
		XDMA_UNLOCK();
		free(xchan, M_XDMA);

		return (NULL);
	}

	TAILQ_INIT(&xchan->ie_handlers);
	mtx_init(&xchan->mtx_lock, "xDMA", NULL, MTX_DEF);
	mtx_init(&xchan->mtx_qin_lock, "xDMA queue in", NULL, MTX_DEF);
	mtx_init(&xchan->mtx_qout_lock, "xDMA queue out", NULL, MTX_DEF);

	TAILQ_INSERT_TAIL(&xdma->channels, xchan, xchan_next);

	XDMA_UNLOCK();

	return (xchan);
}

int
xdma_channel_free(xdma_channel_t *xchan)
{
	xdma_controller_t *xdma;
	int err;

	xdma = xchan->xdma;

	XDMA_LOCK();

	/* Free the real DMA channel. */
	err = XDMA_CHANNEL_FREE(xdma->dma_dev, xchan);
	if (err != 0) {
		device_printf(xdma->dev,
		    "%s: Can't free real hw channel.\n", __func__);
		XDMA_UNLOCK();
		return (-1);
	}

	xdma_teardown_all_intr(xchan);

	/* Deallocate descriptors, if any. */
	xdma_desc_free(xchan);
	xdma_bufs_free(xchan);

	mtx_destroy(&xchan->mtx_lock);

	TAILQ_REMOVE(&xdma->channels, xchan, xchan_next);

	free(xchan, M_XDMA);

	XDMA_UNLOCK();

	return (0);
}

int
xdma_setup_intr(xdma_channel_t *xchan,
    int (*cb)(void *, xdma_transfer_status_t *),
    void *arg, void **ihandler)
{
	struct xdma_intr_handler *ih;
	xdma_controller_t *xdma;

	xdma = xchan->xdma;
	KASSERT(xdma != NULL, ("xdma is NULL"));

	/* Sanity check. */
	if (cb == NULL) {
		device_printf(xdma->dev,
		    "%s: Can't setup interrupt handler.\n",
		    __func__);

		return (-1);
	}

	ih = malloc(sizeof(struct xdma_intr_handler),
	    M_XDMA, M_WAITOK | M_ZERO);
	if (ih == NULL) {
		device_printf(xdma->dev,
		    "%s: Can't allocate memory for interrupt handler.\n",
		    __func__);

		return (-1);
	}

	ih->cb = cb;
	ih->cb_user = arg;

	TAILQ_INSERT_TAIL(&xchan->ie_handlers, ih, ih_next);

	if (ihandler != NULL) {
		*ihandler = ih;
	}

	return (0);
}

int
xdma_teardown_intr(xdma_channel_t *xchan, struct xdma_intr_handler *ih)
{
	xdma_controller_t *xdma;

	xdma = xchan->xdma;
	KASSERT(xdma != NULL, ("xdma is NULL"));

	/* Sanity check. */
	if (ih == NULL) {
		device_printf(xdma->dev,
		    "%s: Can't teardown interrupt.\n", __func__);
		return (-1);
	}

	TAILQ_REMOVE(&xchan->ie_handlers, ih, ih_next);
	free(ih, M_XDMA);

	return (0);
}

int
xdma_teardown_all_intr(xdma_channel_t *xchan)
{
	struct xdma_intr_handler *ih_tmp;
	struct xdma_intr_handler *ih;
	xdma_controller_t *xdma;

	xdma = xchan->xdma;
	KASSERT(xdma != NULL, ("xdma is NULL"));

	TAILQ_FOREACH_SAFE(ih, &xchan->ie_handlers, ih_next, ih_tmp) {
		TAILQ_REMOVE(&xchan->ie_handlers, ih, ih_next);
		free(ih, M_XDMA);
	}

	return (0);
}

static void
xdma_dmamap_cb(void *arg, bus_dma_segment_t *segs, int nseg, int err)
{
	xdma_controller_t *xdma;
	xdma_channel_t *xchan;

	xchan = (xdma_channel_t *)arg;
	KASSERT(xchan != NULL, ("xchan is NULL"));

	xdma = xchan->xdma;
	KASSERT(xdma != NULL, ("xdma is NULL"));

	if (err) {
		device_printf(xdma->dma_dev, "%s failed\n", __func__);
		xchan->map_err = 1;
		return;
	}

	xchan->descs[xchan->map_descr].ds_addr = segs[0].ds_addr;
	xchan->descs[xchan->map_descr].ds_len = segs[0].ds_len;
}

static int
xdma_desc_alloc_bus_dma(xdma_channel_t *xchan, uint32_t desc_size,
    uint32_t align)
{
	xdma_descriptor_t *desc;
	xdma_controller_t *xdma;
	xdma_config_t *conf;
	int nsegments;
	int err;
	int i;

	xdma = xchan->xdma;
	conf = &xchan->conf;

	nsegments = conf->block_num;

	err = bus_dma_tag_create(
	    bus_get_dma_tag(xdma->dev),
	    align, 0,			/* alignment, boundary */
	    BUS_SPACE_MAXADDR_32BIT,	/* lowaddr */
	    BUS_SPACE_MAXADDR,		/* highaddr */
	    NULL, NULL,			/* filter, filterarg */
	    desc_size, 1,		/* maxsize, nsegments*/
	    desc_size, 0,		/* maxsegsize, flags */
	    NULL, NULL,			/* lockfunc, lockarg */
	    &xchan->dma_tag);
	if (err) {
		device_printf(xdma->dev,
		    "%s: Can't create bus_dma tag.\n", __func__);
		return (-1);
	}

	/* Descriptors. */
	xchan->descs = malloc(nsegments * sizeof(xdma_descriptor_t),
	    M_XDMA, (M_WAITOK | M_ZERO));
	if (xchan->descs == NULL) {
		device_printf(xdma->dev,
		    "%s: Can't allocate memory.\n", __func__);
		return (-1);
	}

	/* Allocate bus_dma memory for each descriptor. */
	for (i = 0; i < nsegments; i++) {
		desc = &xchan->descs[i];
		err = bus_dmamem_alloc(xchan->dma_tag, (void **)&desc->desc,
		    BUS_DMA_WAITOK | BUS_DMA_ZERO, &desc->dma_map);
		if (err) {
			device_printf(xdma->dev,
			    "%s: Can't allocate memory for descriptors.\n", __func__);
			return (-1);
		}

		xchan->map_err = 0;
		xchan->map_descr = i;
		err = bus_dmamap_load(xchan->dma_tag, desc->dma_map, desc->desc,
		    desc_size, xdma_dmamap_cb, xchan, BUS_DMA_WAITOK);
		if (err) {
			device_printf(xdma->dev,
			    "%s: Can't load DMA map.\n", __func__);
			return (-1);
		}

		if (xchan->map_err != 0) {
			device_printf(xdma->dev,
			    "%s: Can't load DMA map.\n", __func__);
			return (-1);
		}
	}

	return (0);
}

static int
xdma_bufs_alloc_bus_dma(xdma_channel_t *xchan, uint32_t align)
{
	xdma_controller_t *xdma;
	xdma_config_t *conf;
	int nsegments;
	int err;
	int i;

	xdma = xchan->xdma;
	conf = &xchan->conf;

	nsegments = conf->block_num;

	xchan->bufs = malloc(nsegments * sizeof(struct xchan_buf),
	    M_XDMA, (M_WAITOK | M_ZERO));
	if (xchan->bufs == NULL) {
		device_printf(xdma->dev,
		    "%s: Can't allocate memory.\n", __func__);
		return (-1);
	}

	/* Allocate bus_dma memory for mbufs. */
	err = bus_dma_tag_create(
	    bus_get_dma_tag(xdma->dev),	/* Parent tag. */
	    align, 0,			/* alignment, boundary */
	    BUS_SPACE_MAXADDR_32BIT,	/* lowaddr */
	    BUS_SPACE_MAXADDR,		/* highaddr */
	    NULL, NULL,			/* filter, filterarg */
	    MCLBYTES, 1, 		/* maxsize, nsegments */
	    MCLBYTES,			/* maxsegsize */
	    0,				/* flags */
	    NULL, NULL,			/* lockfunc, lockarg */
	    &xchan->dma_tag_bufs);
	if (err != 0) {
		device_printf(xdma->dev,
		    "%s: Can't create bus_dma tag.\n", __func__);
		return (-1);
	}

	for (i = 0; i < nsegments; i++) {
		err = bus_dmamap_create(xchan->dma_tag_bufs, BUS_DMA_COHERENT,
		    &xchan->bufs[i].map);
		if (err != 0) {
			device_printf(xdma->dev,
			    "%s: Can't create buf DMA map.\n", __func__);
			return (-1);
		}
	}

	return (0);
}

/*
 * This function called by DMA controller driver.
 */
int
xdma_desc_alloc(xdma_channel_t *xchan, uint32_t desc_size, uint32_t align)
{
	xdma_controller_t *xdma;
	xdma_config_t *conf;
	int ret;

	XCHAN_ASSERT_LOCKED(xchan);

	xdma = xchan->xdma;
	if (xdma == NULL) {
		device_printf(xdma->dev,
		    "%s: Channel was not allocated properly.\n", __func__);
		return (-1);
	}

	if (xchan->flags & XCHAN_DESC_ALLOCATED) {
		device_printf(xdma->dev,
		    "%s: Descriptors already allocated.\n", __func__);
		return (-1);
	}

	if ((xchan->flags & XCHAN_CONFIGURED) == 0) {
		device_printf(xdma->dev,
		    "%s: Channel has no configuration.\n", __func__);
		return (-1);
	}

	conf = &xchan->conf;

	ret = xdma_desc_alloc_bus_dma(xchan, desc_size, align);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't allocate memory for descriptors.\n",
		    __func__);
		return (-1);
	}

	xchan->flags |= XCHAN_DESC_ALLOCATED;

	ret = xdma_bufs_alloc_bus_dma(xchan, align);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't allocate memory for mbufs.\n",
		    __func__);
		return (-1);
	}

	xchan->flags |= XCHAN_BUFS_ALLOCATED;

	return (0);
}

int
xdma_desc_free(xdma_channel_t *xchan)
{
	xdma_descriptor_t *desc;
	xdma_config_t *conf;
	int i;

	conf = &xchan->conf;

	if ((xchan->flags & XCHAN_DESC_ALLOCATED) == 0) {
		/* No descriptors allocated. */
		return (-1);
	}

	for (i = 0; i < conf->block_num; i++) {
		desc = &xchan->descs[i];
		bus_dmamap_unload(xchan->dma_tag, desc->dma_map);
		bus_dmamem_free(xchan->dma_tag, desc->desc, desc->dma_map);
	}

	bus_dma_tag_destroy(xchan->dma_tag);
	free(xchan->descs, M_XDMA);

	xchan->flags &= ~(XCHAN_DESC_ALLOCATED);

	return (0);
}

int
xdma_bufs_free(xdma_channel_t *xchan)
{
	xdma_config_t *conf;
	xdma_buf_t *b;
	int i;

	conf = &xchan->conf;

	if ((xchan->flags & XCHAN_BUFS_ALLOCATED) == 0) {
		/* No bufs allocated. */
		return (-1);
	}

	for (i = 0; i < conf->block_num; i++) {
		b = &xchan->bufs[i];
		bus_dmamap_destroy(xchan->dma_tag_bufs, b->map);
	}

	bus_dma_tag_destroy(xchan->dma_tag_bufs);
	free(xchan->bufs, M_XDMA);

	xchan->flags &= ~(XCHAN_BUFS_ALLOCATED);

	return (0);
}

int
xdma_prep_memcpy(xdma_channel_t *xchan, uintptr_t src_addr,
    uintptr_t dst_addr, size_t len)
{
	xdma_controller_t *xdma;
	xdma_config_t *conf;
	int ret;

	xdma = xchan->xdma;
	KASSERT(xdma != NULL, ("xdma is NULL"));

	conf = &xchan->conf;
	conf->direction = XDMA_MEM_TO_MEM;
	conf->src_addr = src_addr;
	conf->dst_addr = dst_addr;
	conf->block_len = len;
	conf->block_num = 1;

	xchan->flags |= (XCHAN_CONFIGURED | XCHAN_TYPE_MEMCPY);

	XCHAN_LOCK(xchan);

	/* Deallocate old descriptors, if any. */
	xdma_desc_free(xchan);

	ret = XDMA_CHANNEL_PREP_MEMCPY(xdma->dma_dev, xchan);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't prepare memcpy transfer.\n", __func__);
		XCHAN_UNLOCK(xchan);

		return (-1);
	}

	XCHAN_UNLOCK(xchan);

	return (0);
}

int
xdma_prep_sg(xdma_channel_t *xchan, uint32_t ndesc)
{
	xdma_controller_t *xdma;
	xdma_config_t *conf;
	int ret;

	xdma = xchan->xdma;

	KASSERT(xdma != NULL, ("xdma is NULL"));

	if (xchan->flags & XCHAN_CONFIGURED) {
		device_printf(xdma->dev,
		    "%s: Channel is already configured.\n", __func__);
		return (-1);
	}

	conf = &xchan->conf;
	conf->block_num = ndesc;

	TAILQ_INIT(&xchan->queue_out);
	TAILQ_INIT(&xchan->queue_in);

	xchan->flags |= (XCHAN_CONFIGURED | XCHAN_TYPE_SG);

	XCHAN_LOCK(xchan);

	/* Deallocate old descriptors, if any. */
	xdma_desc_free(xchan);
	xdma_bufs_free(xchan);

	ret = XDMA_CHANNEL_PREP_SG(xdma->dma_dev, xchan);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't prepare SG transfer.\n", __func__);
		XCHAN_UNLOCK(xchan);

		return (-1);
	}

	XCHAN_UNLOCK(xchan);

	return (0);
}

inline uint32_t
xchan_next_idx(xdma_channel_t *xchan, uint32_t curidx)
{
	xdma_config_t *conf;

	conf = &xchan->conf;

	return ((curidx + 1) % conf->block_num);
}

int
xdma_dequeue_mbuf(xdma_channel_t *xchan, struct mbuf **mp)
{
	struct xdma_mbuf_entry *xm_tmp;
	struct xdma_mbuf_entry *xm;
	xdma_config_t *conf;

	conf = &xchan->conf;

	QUEUE_OUT_LOCK(xchan);

	TAILQ_FOREACH_SAFE(xm, &xchan->queue_out, xm_next, xm_tmp) {
		*mp = xm->m;
		TAILQ_REMOVE(&xchan->queue_out, xm, xm_next);
		QUEUE_OUT_UNLOCK(xchan);

		free(xm, M_XDMA);

		return (0);
	}

	QUEUE_OUT_UNLOCK(xchan);

	return (-1);
}

int
xdma_enqueue_mbuf(xdma_channel_t *xchan, struct mbuf **mp,
    uintptr_t addr, enum xdma_direction dir)
{
	struct xdma_mbuf_entry *xm;
	xdma_controller_t *xdma;
	xdma_config_t *conf;
	struct mbuf *m;

	xdma = xchan->xdma;
	conf = &xchan->conf;

	if ((m = m_defrag(*mp, M_NOWAIT)) == NULL) {
		device_printf(xdma->dma_dev,
		    "%s: Can't defrag mbuf\n", __func__);
		return (ENOMEM);
	}

	xm = malloc(sizeof(struct xdma_mbuf_entry), M_XDMA, M_WAITOK | M_ZERO);
	xm->direction = dir;
	xm->m = m;
	if (dir == XDMA_MEM_TO_DEV) {
		xm->dst_addr = addr;
	} else {
		xm->src_addr = addr;
	}

	QUEUE_IN_LOCK(xchan);
	TAILQ_INSERT_TAIL(&xchan->queue_in, xm, xm_next);
	QUEUE_IN_UNLOCK(xchan);

	return (0);
}

int
xdma_enqueue_sync_post(xdma_channel_t *xchan, uint32_t i)
{
	xdma_config_t *conf;

	conf = &xchan->conf;

	if (xchan->flags & XCHAN_DESC_ALLOCATED) {
		bus_dmamap_sync(xchan->dma_tag, xchan->descs[i].dma_map,
		    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
	}

	return (0);
}

int
xdma_enqueue_sync_pre(xdma_channel_t *xchan, uint32_t i)
{
	xdma_config_t *conf;

	conf = &xchan->conf;

	if (xchan->flags & XCHAN_DESC_ALLOCATED) {
		bus_dmamap_sync(xchan->dma_tag, xchan->descs[i].dma_map,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
	}

	return (0);
}

static int
xdma_sg_queue_init(struct xdma_sg_queue *sg_queue)
{

	TAILQ_INIT(sg_queue);

	return (0);
}

static int
xdma_sg_queue_destroy(struct xdma_sg_queue *sg_queue)
{
	struct xdma_sg *sg;
	struct xdma_sg *sg_tmp;

	TAILQ_FOREACH_SAFE(sg, sg_queue, sg_next, sg_tmp) {
		TAILQ_REMOVE(sg_queue, sg, sg_next);
		free(sg, M_XDMA);
	}

	return (0);
}

static int
xdma_sg_queue_add(struct xdma_sg_queue *sg_queue,
    struct bus_dma_segment *seg, enum xdma_direction dir)
{
	struct xdma_sg *sg;

	sg = malloc(sizeof(struct xdma_sg), M_XDMA, M_WAITOK | M_ZERO);
	sg->paddr = seg->ds_addr;
	sg->len = seg->ds_len;
	sg->direction = dir;
	TAILQ_INSERT_TAIL(sg_queue, sg, sg_next);

	return (0);
}

int
xdma_enqueue_submit(xdma_channel_t *xchan)
{
	struct xdma_sg_queue sg_queue;
	struct xdma_mbuf_entry *xm_tmp;
	struct xdma_mbuf_entry *xm;
	struct mbuf *m;
	xdma_controller_t *xdma;
	xdma_config_t *conf;
	int ret;
	int i;
	struct bus_dma_segment seg;
	int error, nsegs;

	conf = &xchan->conf;
	xdma = xchan->xdma;
	KASSERT(xdma != NULL, ("xdma is NULL"));

	QUEUE_IN_LOCK(xchan);

	if (TAILQ_EMPTY(&xchan->queue_in)) {

		QUEUE_IN_UNLOCK(xchan);
		return (0);
	}

	xdma_sg_queue_init(&sg_queue);

	TAILQ_FOREACH_SAFE(xm, &xchan->queue_in, xm_next, xm_tmp) {
		m = xm->m;

		if (xchan->idx_count == (conf->block_num - 1)) {
			break;
		}

		i = xchan->idx_head;

		error = bus_dmamap_load_mbuf_sg(xchan->dma_tag_bufs,
		    xchan->bufs[i].map, m, &seg, &nsegs, 0);
		if (error != 0) {
			printf("ERROR: nomem\n");
			break;
		}

		KASSERT(nsegs == 1, ("%s: %d segments returned!", __func__, nsegs));

		if (xm->direction == XDMA_MEM_TO_DEV) {
			bus_dmamap_sync(xchan->dma_tag_bufs, xchan->bufs[i].map,
			    BUS_DMASYNC_PREWRITE);
		} else {
			bus_dmamap_sync(xchan->dma_tag_bufs, xchan->bufs[i].map,
			    BUS_DMASYNC_PREREAD);
		}

		xchan->bufs[i].xm = xm;
		xdma_sg_queue_add(&sg_queue, &seg, xm->direction);

		xchan->idx_head = xchan_next_idx(xchan, xchan->idx_head);
		atomic_add_int(&xchan->idx_count, 1);

		TAILQ_REMOVE(&xchan->queue_in, xm, xm_next);
	}

	QUEUE_IN_UNLOCK(xchan);

	XCHAN_LOCK(xchan);

	ret = XDMA_CHANNEL_SUBMIT_SG(xdma->dma_dev, xchan, &sg_queue);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't submit SG transfer.\n", __func__);

		XCHAN_UNLOCK(xchan);

		return (-1);
	}

	XCHAN_UNLOCK(xchan);

	xdma_sg_queue_destroy(&sg_queue);

	return (0);
}

int
xdma_prep_cyclic(xdma_channel_t *xchan, enum xdma_direction dir,
    uintptr_t src_addr, uintptr_t dst_addr, int block_len,
    int block_num, int src_width, int dst_width)
{
	xdma_controller_t *xdma;
	xdma_config_t *conf;
	int ret;

	xdma = xchan->xdma;
	KASSERT(xdma != NULL, ("xdma is NULL"));

	conf = &xchan->conf;
	conf->direction = dir;
	conf->src_addr = src_addr;
	conf->dst_addr = dst_addr;
	conf->block_len = block_len;
	conf->block_num = block_num;
	conf->src_width = src_width;
	conf->dst_width = dst_width;

	xchan->flags |= (XCHAN_CONFIGURED | XCHAN_TYPE_CYCLIC);

	XCHAN_LOCK(xchan);

	/* Deallocate old descriptors, if any. */
	xdma_desc_free(xchan);
	xdma_bufs_free(xchan);

	ret = XDMA_CHANNEL_PREP_CYCLIC(xdma->dma_dev, xchan);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't prepare cyclic transfer.\n", __func__);
		XCHAN_UNLOCK(xchan);

		return (-1);
	}

	XCHAN_UNLOCK(xchan);

	return (0);
}

int
xdma_begin(xdma_channel_t *xchan)
{
	xdma_controller_t *xdma;
	int ret;

	xdma = xchan->xdma;

	if (xchan->flags & XCHAN_TYPE_SG) {
		/* Not valid. */
		return (0);
	};

	ret = XDMA_CHANNEL_CONTROL(xdma->dma_dev, xchan, XDMA_CMD_BEGIN);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't begin the channel operation.\n", __func__);
		return (-1);
	}

	return (0);
}

int
xdma_terminate(xdma_channel_t *xchan)
{
	xdma_controller_t *xdma;
	int ret;

	xdma = xchan->xdma;

	ret = XDMA_CHANNEL_CONTROL(xdma->dma_dev, xchan, XDMA_CMD_TERMINATE);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't terminate the channel operation.\n", __func__);
		return (-1);
	}

	return (0);
}

int
xdma_pause(xdma_channel_t *xchan)
{
	xdma_controller_t *xdma;
	int ret;

	xdma = xchan->xdma;

	ret = XDMA_CHANNEL_CONTROL(xdma->dma_dev, xchan, XDMA_CMD_PAUSE);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't pause the channel operation.\n", __func__);
		return (-1);
	}

	return (ret);
}

int
xdma_desc_done(xdma_channel_t *xchan, uint32_t idx,
    struct xdma_desc_status *status)
{
	struct xdma_mbuf_entry *xm;
	struct xchan_buf *b;
	xdma_controller_t *xdma;
	xdma_config_t *conf;
	struct mbuf *m;

	if (mtx_owned(&xchan->mtx_lock) != 0) {
		printf("o\n");
	}

	QUEUE_OUT_LOCK(xchan);

	if (mtx_recursed(&xchan->mtx_lock) != 0) {
		printf("r\n");
	}

	conf = &xchan->conf;
	xdma = xchan->xdma;

	b = &xchan->bufs[xchan->idx_tail];
	xm = b->xm;

	if (xm->direction == XDMA_MEM_TO_DEV) {
		bus_dmamap_sync(xchan->dma_tag_bufs, b->map, 
		    BUS_DMASYNC_POSTWRITE);
	} else {
		bus_dmamap_sync(xchan->dma_tag_bufs, b->map, 
		    BUS_DMASYNC_POSTREAD);
	}
	bus_dmamap_unload(xchan->dma_tag_bufs, b->map);

	m = xm->m;
	m->m_pkthdr.len = m->m_len = status->transferred;

	TAILQ_INSERT_TAIL(&xchan->queue_out, xm, xm_next);

	xchan->idx_tail = xchan_next_idx(xchan, xchan->idx_tail);
	atomic_subtract_int(&xchan->idx_count, 1);

	QUEUE_OUT_UNLOCK(xchan);

	return (0);
}

int
xdma_callback(xdma_channel_t *xchan, xdma_transfer_status_t *status)
{
	struct xdma_intr_handler *ih_tmp;
	struct xdma_intr_handler *ih;

	TAILQ_FOREACH_SAFE(ih, &xchan->ie_handlers, ih_next, ih_tmp) {
		if (ih->cb != NULL) {
			ih->cb(ih->cb_user, status);
		}
	}

	if (xchan->flags & XCHAN_TYPE_SG) {
		/* Check if more entries available in queue. */
		xdma_enqueue_submit(xchan);
		return (0);
	};

	return (0);
}

void
xdma_assert_locked(void)
{

	XDMA_ASSERT_LOCKED();
}

#ifdef FDT
/*
 * Notify the DMA driver we have machine-dependent data in FDT.
 */
static int
xdma_ofw_md_data(xdma_controller_t *xdma, pcell_t *cells, int ncells)
{
	uint32_t ret;

	ret = XDMA_OFW_MD_DATA(xdma->dma_dev, cells, ncells, (void **)&xdma->data);

	return (ret);
}

/*
 * Allocate xdma controller.
 */
xdma_controller_t *
xdma_ofw_get(device_t dev, const char *prop)
{
	phandle_t node, parent;
	xdma_controller_t *xdma;
	device_t dma_dev;
	pcell_t *cells;
	int ncells;
	int error;
	int ndmas;
	int idx;

	node = ofw_bus_get_node(dev);
	if (node <= 0) {
		device_printf(dev,
		    "%s called on not ofw based device.\n", __func__);
	}

	error = ofw_bus_parse_xref_list_get_length(node,
	    "dmas", "#dma-cells", &ndmas);
	if (error) {
		device_printf(dev,
		    "%s can't get dmas list.\n", __func__);
		return (NULL);
	}

	if (ndmas == 0) {
		device_printf(dev,
		    "%s dmas list is empty.\n", __func__);
		return (NULL);
	}

	error = ofw_bus_find_string_index(node, "dma-names", prop, &idx);
	if (error != 0) {
		device_printf(dev,
		    "%s can't find string index.\n", __func__);
		return (NULL);
	}

	error = ofw_bus_parse_xref_list_alloc(node, "dmas", "#dma-cells",
	    idx, &parent, &ncells, &cells);
	if (error != 0) {
		device_printf(dev,
		    "%s can't get dma device xref.\n", __func__);
		return (NULL);
	}

	dma_dev = OF_device_from_xref(parent);
	if (dma_dev == NULL) {
		device_printf(dev,
		    "%s can't get dma device.\n", __func__);
		return (NULL);
	}

	xdma = malloc(sizeof(struct xdma_controller), M_XDMA, M_WAITOK | M_ZERO);
	if (xdma == NULL) {
		device_printf(dev,
		    "%s can't allocate memory for xdma.\n", __func__);
		return (NULL);
	}
	xdma->dev = dev;
	xdma->dma_dev = dma_dev;

	TAILQ_INIT(&xdma->channels);

	xdma_ofw_md_data(xdma, cells, ncells);
	free(cells, M_OFWPROP);

	return (xdma);
}
#endif

/*
 * Free xDMA controller object.
 */
int
xdma_put(xdma_controller_t *xdma)
{

	XDMA_LOCK();

	/* Ensure no channels allocated. */
	if (!TAILQ_EMPTY(&xdma->channels)) {
		device_printf(xdma->dev, "%s: Can't free xDMA\n", __func__);
		return (-1);
	}

	free(xdma->data, M_DEVBUF);
	free(xdma, M_XDMA);

	XDMA_UNLOCK();

	return (0);
}

static void
xdma_init(void)
{

	mtx_init(&xdma_mtx, "xDMA", NULL, MTX_DEF);
}

SYSINIT(xdma, SI_SUB_DRIVERS, SI_ORDER_FIRST, xdma_init, NULL);
