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
#include <sys/kthread.h>
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

static int xchan_bufs_alloc(xdma_channel_t *xchan);
static int xchan_bufs_free(xdma_channel_t *xchan);

static void
xdma_task(void *arg)
{
	xdma_controller_t *xdma;
	xdma_channel_t *xchan_tmp;
	xdma_channel_t *xchan;

	xdma = arg;

	for (;;) {
		mtx_lock(&xdma->proc_mtx);
		msleep(xdma, &xdma->proc_mtx, PRIBIO, "jobqueue", hz);
		mtx_unlock(&xdma->proc_mtx);

		if (TAILQ_EMPTY(&xdma->channels)) {
			continue;
		}

		TAILQ_FOREACH_SAFE(xchan, &xdma->channels, xchan_next, xchan_tmp) {
			if (xchan->flags & XCHAN_TYPE_SG) {
				xdma_queue_submit(xchan);
			}
		}
	}
}

/*
 * Allocate virtual xDMA channel.
 */
xdma_channel_t *
xdma_channel_alloc(xdma_controller_t *xdma, uint32_t caps)
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
	xchan->caps = caps;

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

	/* Deallocate bufs, if any. */
	xchan_bufs_free(xchan);
	xchan_sglist_free(xchan);

	if (xchan->flags & XCHAN_TYPE_SG) {
		free(xchan->xr, M_XDMA);
	}

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

static int
xdma_bufs_alloc_no_busdma(xdma_channel_t *xchan)
{
	xdma_controller_t *xdma;
	int nsegments;
	int i;

	xdma = xchan->xdma;

	nsegments = xchan->bufs_num;

	xchan->bufs = malloc(nsegments * sizeof(struct xchan_buf),
	    M_XDMA, (M_WAITOK | M_ZERO));
	if (xchan->bufs == NULL) {
		device_printf(xdma->dev,
		    "%s: Can't allocate memory.\n", __func__);
		return (-1);
	}

	for (i = 0; i < nsegments; i++) {
		xchan->bufs[i].cbuf = contigmalloc(xchan->maxsegsize,
		    M_XDMA, 0, 0, ~0, PAGE_SIZE, 0);
	}

	return (0);
}

static int
xdma_bufs_alloc_busdma(xdma_channel_t *xchan)
{
	xdma_controller_t *xdma;
	int nsegments;
	int err;
	int i;

	xdma = xchan->xdma;

	nsegments = xchan->bufs_num;

#if 0
	printf("%s: nseg %d\n", __func__, nsegments);
#endif

	xchan->bufs = malloc(nsegments * sizeof(struct xchan_buf),
	    M_XDMA, (M_WAITOK | M_ZERO));
	if (xchan->bufs == NULL) {
		device_printf(xdma->dev,
		    "%s: Can't allocate memory.\n", __func__);
		return (-1);
	}

	err = bus_dma_tag_create(
	    bus_get_dma_tag(xdma->dev),	/* Parent tag. */
	    xchan->alignment, 0,	/* alignment, boundary */
	    BUS_SPACE_MAXADDR_32BIT,	/* lowaddr */
	    BUS_SPACE_MAXADDR,		/* highaddr */
	    NULL, NULL,			/* filter, filterarg */
	    xchan->maxsegsize * xchan->maxnsegs,		/* maxsize */
	    xchan->maxnsegs,		/* nsegments */
	    xchan->maxsegsize,		/* maxsegsize */
	    0,				/* flags */
	    NULL, NULL,			/* lockfunc, lockarg */
	    &xchan->dma_tag_bufs);
	if (err != 0) {
		device_printf(xdma->dev,
		    "%s: Can't create bus_dma tag.\n", __func__);
		return (-1);
	}

	for (i = 0; i < nsegments; i++) {
		err = bus_dmamap_create(xchan->dma_tag_bufs, 0,
		    &xchan->bufs[i].map);
		if (err != 0) {
			device_printf(xdma->dev,
			    "%s: Can't create buf DMA map.\n", __func__);
			return (-1);
		}
	}

	return (0);
}

static int
xchan_bufs_alloc(xdma_channel_t *xchan)
{
	xdma_controller_t *xdma;
	int ret;

	xdma = xchan->xdma;
	if (xdma == NULL) {
		device_printf(xdma->dev,
		    "%s: Channel was not allocated properly.\n", __func__);
		return (-1);
	}

	if (xchan->caps & XCHAN_CAP_BUSDMA) {
		ret = xdma_bufs_alloc_busdma(xchan);
	} else {
		ret = xdma_bufs_alloc_no_busdma(xchan);
	}
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't setup busdma.\n",
		    __func__);
		return (-1);
	}

	xchan->flags |= XCHAN_BUFS_ALLOCATED;

	return (0);
}

static int
xchan_bufs_free(xdma_channel_t *xchan)
{
	xchan_buf_t *b;
	int i;

	if ((xchan->flags & XCHAN_BUFS_ALLOCATED) == 0) {
		/* No bufs allocated. */
		return (-1);
	}

	for (i = 0; i < xchan->bufs_num; i++) {
		b = &xchan->bufs[i];
		bus_dmamap_destroy(xchan->dma_tag_bufs, b->map);
	}

	bus_dma_tag_destroy(xchan->dma_tag_bufs);
	free(xchan->bufs, M_XDMA);

	xchan->flags &= ~XCHAN_BUFS_ALLOCATED;

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

/*
 * xr_num - xdma requests queue size,
 * maxsegsize - maximum allowed scatter-gather list element size in bytes
 */
int
xdma_prep_sg(xdma_channel_t *xchan, uint32_t xr_num,
    uint32_t maxsegsize, uint32_t alignment)
{
	xdma_controller_t *xdma;
	int ret;

	xdma = xchan->xdma;

	KASSERT(xdma != NULL, ("xdma is NULL"));

	if (xchan->flags & XCHAN_CONFIGURED) {
		device_printf(xdma->dev,
		    "%s: Channel is already configured.\n", __func__);
		return (-1);
	}

	xchan->maxsegsize = maxsegsize;
	xchan->alignment = alignment;
	xchan->maxnsegs = 8;
	xchan->bufs_num = xr_num;
	xchan->xr_num = xr_num;

	/* Allocate sglist. */
	ret = xchan_sglist_init(xchan);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't allocate sglist.\n", __func__);
		return (-1);
	}

	/* Allocate request queue. */
	xchan->xr = malloc(sizeof(struct xdma_request) * xr_num,
	    M_XDMA, M_WAITOK | M_ZERO);
	if (xchan->xr == NULL) {
		device_printf(xdma->dev,
		    "%s: Can't allocate request queue.\n", __func__);
		return (-1);
	}

	xchan->flags |= (XCHAN_CONFIGURED | XCHAN_TYPE_SG);

	XCHAN_LOCK(xchan);

	/* Deallocate bufs, if any. */
	xchan_bufs_free(xchan);

	ret = XDMA_CHANNEL_PREP_SG(xdma->dma_dev, xchan);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't prepare SG transfer.\n", __func__);
		XCHAN_UNLOCK(xchan);

		return (-1);
	}

	/* Allocate bufs */
	ret = xchan_bufs_alloc(xchan);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't allocate bufs.\n", __func__);
		return (-1);
	}

	XCHAN_UNLOCK(xchan);

	return (0);
}

int
xdma_dequeue(xdma_channel_t *xchan, void **user,
    xdma_transfer_status_t *status)
{
	struct xdma_request *xr;

	if (xchan->xr_tail == xchan->xr_processed) {
		return (-1);
	}

	xr = &xchan->xr[xchan->xr_tail];
	if (xr->done == 0) {
		return (-1);
	}

	*user = xr->user;
	status->error = xr->status.error;
	status->transferred = xr->status.transferred;
	xchan->xr_tail = xchan_next_req(xchan, xchan->xr_tail);
	atomic_subtract_int(&xchan->xr_count, 1);

	return (0);
}

int
xdma_enqueue(xdma_channel_t *xchan, uintptr_t src, uintptr_t dst,
    bus_size_t len, enum xdma_direction dir, void *user)
{
	struct xdma_request *xr;
	xdma_controller_t *xdma;

	xdma = xchan->xdma;

	if (xchan->xr_count >= (xchan->xr_num - 1)) {
		/* No space is available yet. */
		return (-1);
	}

	xr = &xchan->xr[xchan->xr_head];
	xr->user = user;
	xr->direction = dir;
	xr->m = NULL;
	xr->len = len;
	xr->type = 0;
	xr->src_addr = src;
	xr->dst_addr = dst;
#if 0
	if (dir == XDMA_MEM_TO_DEV) {
		xr->dst_addr = addr;
		xr->src_addr = 0;
	} else {
		xr->src_addr = addr;
		xr->dst_addr = 0;
	}
#endif
	xr->done = 0;
	xchan->xr_head = xchan_next_req(xchan, xchan->xr_head);
	atomic_add_int(&xchan->xr_count, 1);

	return (0);
}

struct seg_load_request {
	struct bus_dma_segment *seg;
	uint32_t nsegs;
	uint32_t error;
};

static void
xdma_get1paddr(void *arg, bus_dma_segment_t *segs, int nsegs, int error)
{
	struct seg_load_request *slr;
	struct bus_dma_segment *seg;
	int i;

	slr = arg;
	seg = slr->seg;

	if (error != 0) {
		slr->error = error;
		return;
	}

	slr->nsegs = nsegs;

	for (i = 0; i < nsegs; i++) {
		seg[i].ds_addr = segs[i].ds_addr;
		seg[i].ds_len = segs[i].ds_len;
	}
}

static int
xdma_load_busdma(xdma_channel_t *xchan, struct xdma_request *xr,
    struct bus_dma_segment *seg, uint32_t i)
{
	xdma_controller_t *xdma;
	struct seg_load_request slr;
	uint32_t nsegs;
	void *addr;
	int error;

	xdma = xchan->xdma;

	error = 0;
	nsegs = 0;

	switch (xr->type) {
	case XR_TYPE_MBUF:
		error = bus_dmamap_load_mbuf_sg(xchan->dma_tag_bufs,
		    xchan->bufs[i].map, xr->m, seg, &nsegs, BUS_DMA_NOWAIT);
		break;
	case XR_TYPE_BIO:
		slr.nsegs = 0;
		slr.error = 0;
		slr.seg = seg;
		error = bus_dmamap_load_bio(xchan->dma_tag_bufs,
		    xchan->bufs[i].map, xr->bp, xdma_get1paddr, &slr, BUS_DMA_NOWAIT);
		if (slr.error != 0) {
			device_printf(xdma->dma_dev,
			    "%s: bus_dmamap_load failed, err %d\n",
			    __func__, slr.error);
			return (0);
		}
		nsegs = slr.nsegs;
		break;
	case XR_TYPE_ADDR:
		switch (xr->direction) {
		case XDMA_MEM_TO_DEV:
			addr = (void *)xr->src_addr;
			break;
		case XDMA_DEV_TO_MEM:
			addr = (void *)xr->dst_addr;
			break;
		default:
			device_printf(xdma->dma_dev,
			    "%s: Direction is not supported\n", __func__);
			return (0);
		}
		slr.nsegs = 0;
		slr.error = 0;
		slr.seg = seg;
		error = bus_dmamap_load(xchan->dma_tag_bufs, xchan->bufs[i].map,
		    addr, xr->len, xdma_get1paddr, &slr, BUS_DMA_NOWAIT);
		if (slr.error != 0) {
			device_printf(xdma->dma_dev,
			    "%s: bus_dmamap_load failed, err %d\n",
			    __func__, slr.error);
			return (0);
		}
		nsegs = slr.nsegs;
		break;
	default:
		break;
	}

	if (error != 0) {
		if (error == ENOMEM) {
			/*
			 * Out of memory. Try again later.
			 * TODO: count errors.
			 */
		} else {
			device_printf(xdma->dma_dev,
			    "%s: bus_dmamap_load failed with err %d\n",
			    __func__, error);
		}
		return (0);
	}

	if (xr->direction == XDMA_MEM_TO_DEV) {
		bus_dmamap_sync(xchan->dma_tag_bufs, xchan->bufs[i].map,
		    BUS_DMASYNC_PREWRITE);
	} else {
		bus_dmamap_sync(xchan->dma_tag_bufs, xchan->bufs[i].map,
		    BUS_DMASYNC_PREREAD);
	}

	return (nsegs);
}

static int
xdma_load_no_busdma(xdma_channel_t *xchan, struct xdma_request *xr,
    struct bus_dma_segment *seg, uint32_t i)
{
	xdma_controller_t *xdma;
	struct mbuf *m;
	uint32_t nsegs;

	xdma = xchan->xdma;

	m = xr->m;

	nsegs = 1;

	switch (xr->type) {
	case XR_TYPE_MBUF:
		if (xr->direction == XDMA_MEM_TO_DEV) {
			m_copydata(m, 0, m->m_pkthdr.len, xchan->bufs[i].cbuf);
			seg[0].ds_addr = (bus_addr_t)xchan->bufs[i].cbuf;
			seg[0].ds_len = m->m_pkthdr.len;
		} else {
			seg[0].ds_addr = mtod(m, bus_addr_t);
			seg[0].ds_len = m->m_pkthdr.len;
		}
		break;
	case XR_TYPE_BIO:
	case XR_TYPE_ADDR:
	default:
		panic("implement me\n");
	}

	return (nsegs);
}

static int
xdma_sglist_prepare_one(xdma_channel_t *xchan,
    struct xdma_request *xr, struct bus_dma_segment *seg)
{
	xdma_controller_t *xdma;
	int error;
	int nsegs;
	int i;

	xdma = xchan->xdma;

	error = 0;
	nsegs = 0;

	i = xchan->buf_head;

	if (xchan->caps & XCHAN_CAP_BUSDMA) {
		nsegs = xdma_load_busdma(xchan, xr, seg, i);
	} else {
		nsegs = xdma_load_no_busdma(xchan, xr, seg, i);
	}
	if (nsegs == 0) {
		printf(".");
		return (0);
	}

	xchan->bufs[i].xr = xr;
	xchan->bufs[i].nsegs = nsegs;
	xchan->bufs[i].nsegs_left = nsegs;

	xchan->buf_head = xchan_next_buf(xchan, xchan->buf_head);

	return (nsegs);
}

static int
xdma_sglist_prepare(xdma_channel_t *xchan,
    struct xdma_sglist *sg)
{
	struct bus_dma_segment seg[128];
	struct xdma_request *xr;
	xdma_controller_t *xdma;
	uint32_t capacity;
	uint32_t n;
	uint32_t c;
	int nsegs;
	int ret;

	xdma = xchan->xdma;

	n = 0;

	ret = XDMA_CHANNEL_CAPACITY(xdma->dma_dev, xchan, &capacity);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't get DMA controller capacity.\n", __func__);
		return (-1);
	}

	for (;;) {
		if (xchan->xr_processed == xchan->xr_head) {
			/* All the requests processed. */
			break;
		}
		xr = &xchan->xr[xchan->xr_processed];

		switch (xr->type) {
		case XR_TYPE_MBUF:
			c = xdma_mbuf_defrag(xchan, xr);
			break;
		case XR_TYPE_BIO:
		case XR_TYPE_ADDR:
		default:
			c = 1;
		}

		if (capacity <= (c + n)) {
			/*
			 * No space yet available for the entire
			 * request in the DMA engine.
			 */
			break;
		}

		nsegs = xdma_sglist_prepare_one(xchan, xr, seg);
		if (nsegs == 0) {
			break;
		}

		xdma_sglist_add(&sg[n], seg, nsegs, xr);
		n += nsegs;

		xchan->xr_processed = xchan_next_req(xchan, xchan->xr_processed);
	}

	return (n);
}

int
xdma_queue_submit(xdma_channel_t *xchan)
{
	struct xdma_sglist *sg;
	xdma_controller_t *xdma;
	uint32_t sg_n;
	int ret;

	xdma = xchan->xdma;
	KASSERT(xdma != NULL, ("xdma is NULL"));

	sg = xchan->sg;

	if ((xchan->flags & XCHAN_BUFS_ALLOCATED) == 0) {
		device_printf(xdma->dev,
		    "%s: Can't submit SG transfer: no bufs\n",
		    __func__);
		return (-1);
	}

	XCHAN_LOCK(xchan);

	sg_n = xdma_sglist_prepare(xchan, sg);
	if (sg_n == 0) {
		/* Nothing to submit */
		XCHAN_UNLOCK(xchan);
		return (0);
	}

	/* Now submit xdma_sglist to DMA engine driver. */

	ret = XDMA_CHANNEL_SUBMIT_SG(xdma->dma_dev, xchan, sg, sg_n);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't submit SG transfer.\n", __func__);

		XCHAN_UNLOCK(xchan);

		return (-1);
	}

	XCHAN_UNLOCK(xchan);

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

	/* Deallocate bufs, if any. */
	xchan_bufs_free(xchan);

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
xchan_seg_done(xdma_channel_t *xchan,
    struct xdma_transfer_status *st)
{
	struct xdma_request *xr;
	xdma_controller_t *xdma;
	xchan_buf_t *b;

	xdma = xchan->xdma;

#if 0
	printf("%s: %d\n", __func__, idx);
#endif

	b = &xchan->bufs[xchan->buf_tail];
	xr = b->xr;

	atomic_subtract_int(&b->nsegs_left, 1);

	if (b->nsegs_left == 0) {
		if (xchan->caps & XCHAN_CAP_BUSDMA) {
			if (xr->direction == XDMA_MEM_TO_DEV) {
				bus_dmamap_sync(xchan->dma_tag_bufs, b->map, 
				    BUS_DMASYNC_POSTWRITE);
			} else {
				bus_dmamap_sync(xchan->dma_tag_bufs, b->map, 
				    BUS_DMASYNC_POSTREAD);
			}

			bus_dmamap_unload(xchan->dma_tag_bufs, b->map);
		}
		xr->status.error = st->error;
		xr->status.transferred = st->transferred;
		xr->done = 1;

		xchan->buf_tail = xchan_next_buf(xchan, xchan->buf_tail);
	}

	return (0);
}

int
xdma_callback(xdma_channel_t *xchan, xdma_transfer_status_t *status)
{
	struct xdma_intr_handler *ih_tmp;
	struct xdma_intr_handler *ih;
	xdma_controller_t *xdma;

	xdma = xchan->xdma;

	TAILQ_FOREACH_SAFE(ih, &xchan->ie_handlers, ih_next, ih_tmp) {
		if (ih->cb != NULL) {
			ih->cb(ih->cb_user, status);
		}
	}

	wakeup(xdma);

	return (0);
}

#ifdef FDT
/*
 * Notify the DMA driver we have machine-dependent data in FDT.
 */
static int
xdma_ofw_md_data(xdma_controller_t *xdma, pcell_t *cells, int ncells)
{
	uint32_t ret;

	ret = XDMA_OFW_MD_DATA(xdma->dma_dev,
	    cells, ncells, (void **)&xdma->data);

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

	mtx_init(&xdma->proc_mtx, "xDMA ofw controller", NULL, MTX_DEF);
	kproc_create(&xdma_task, xdma, &xdma->xdma_proc, 0, 0, "xdma drainer");

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

	kproc_shutdown(&xdma->xdma_proc, 0);
	mtx_destroy(&xdma->proc_mtx);

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
