/*-
 * Copyright (c) 2016-2018 Ruslan Bukin <br@bsdpad.com>
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

#define	XDMA_LOCK()			mtx_lock(&xdma_mtx)
#define	XDMA_UNLOCK()			mtx_unlock(&xdma_mtx)
#define	XDMA_ASSERT_LOCKED()		mtx_assert(&xdma_mtx, MA_OWNED)

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

		if (TAILQ_EMPTY(&xdma->channels))
			continue;

		TAILQ_FOREACH_SAFE(xchan, &xdma->channels, xchan_next, xchan_tmp)
			if (xchan->flags & XCHAN_TYPE_SG)
				xdma_queue_submit_sg(xchan);
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
	mtx_init(&xchan->mtx_qin_lock, "xDMA", NULL, MTX_DEF);
	mtx_init(&xchan->mtx_qout_lock, "xDMA", NULL, MTX_DEF);
	mtx_init(&xchan->mtx_bank_lock, "xDMA", NULL, MTX_DEF);
	mtx_init(&xchan->mtx_proc_lock, "xDMA", NULL, MTX_DEF);

	TAILQ_INIT(&xchan->bank);
	TAILQ_INIT(&xchan->queue_in);
	TAILQ_INIT(&xchan->queue_out);
	TAILQ_INIT(&xchan->processing);

#if 0
	/* Allocate memory for requests. */
	uint32_t xr_num;
	xr_num = 128;
	xchan->xr_num = xr_num;
	xchan_bank_init(xchan);
#endif

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
	KASSERT(xdma != NULL, ("xdma is NULL"));

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

	mtx_destroy(&xchan->mtx_lock);
	mtx_destroy(&xchan->mtx_qin_lock);
	mtx_destroy(&xchan->mtx_qout_lock);
	mtx_destroy(&xchan->mtx_bank_lock);
	mtx_destroy(&xchan->mtx_proc_lock);

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
	ih->cb = cb;
	ih->cb_user = arg;

	TAILQ_INSERT_TAIL(&xchan->ie_handlers, ih, ih_next);

	if (ihandler != NULL)
		*ihandler = ih;

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

int
xdma_request(xdma_channel_t *xchan, struct xdma_request *req)
{
	xdma_controller_t *xdma;
	int ret;

	xdma = xchan->xdma;

	KASSERT(xdma != NULL, ("xdma is NULL"));

	XCHAN_LOCK(xchan);
	ret = XDMA_CHANNEL_REQUEST(xdma->dma_dev, xchan, req);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't request a transfer.\n", __func__);
		XCHAN_UNLOCK(xchan);

		return (-1);
	}
	XCHAN_UNLOCK(xchan);

	return (0);
}

int
xdma_dequeue(xdma_channel_t *xchan, void **user,
    xdma_transfer_status_t *status)
{
	struct xdma_request *xr_tmp;
	struct xdma_request *xr;

	QUEUE_OUT_LOCK(xchan);
	TAILQ_FOREACH_SAFE(xr, &xchan->queue_out, xr_next, xr_tmp) {
		TAILQ_REMOVE(&xchan->queue_out, xr, xr_next);
		break;
	}
	QUEUE_OUT_UNLOCK(xchan);

	if (xr == NULL)
		return (-1);

	*user = xr->user;
	status->error = xr->status.error;
	status->transferred = xr->status.transferred;

	xchan_bank_put(xchan, xr);

	return (0);
}

int
xdma_enqueue(xdma_channel_t *xchan, uintptr_t src, uintptr_t dst,
    uint8_t src_width, uint8_t dst_width, bus_size_t len,
    enum xdma_direction dir, void *user)
{
	struct xdma_request *xr;
	xdma_controller_t *xdma;

	xdma = xchan->xdma;
	KASSERT(xdma != NULL, ("xdma is NULL"));

	xr = xchan_bank_get(xchan);
	if (xr == NULL)
		return (-1); /* No space is available. */

	xr->user = user;
	xr->direction = dir;
	xr->m = NULL;
	xr->bp = NULL;
	xr->len = len;
	xr->type = 0;
	xr->src_addr = src;
	xr->dst_addr = dst;
	xr->src_width = src_width;
	xr->dst_width = dst_width;

	QUEUE_IN_LOCK(xchan);
	TAILQ_INSERT_TAIL(&xchan->queue_in, xr, xr_next);
	QUEUE_IN_UNLOCK(xchan);

	return (0);
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

	XCHAN_LOCK(xchan);

	sg_n = 0;///xdma_sglist_prepare(xchan, sg);
	if (sg_n == 0) {
		/* Nothing to submit */
		XCHAN_UNLOCK(xchan);
		return (0);
	}

	/* Now submit xdma_sglist to DMA engine driver. */

	ret = XDMA_CHANNEL_SUBMIT(xdma->dma_dev, xchan, sg, sg_n);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't submit transfer.\n", __func__);

		XCHAN_UNLOCK(xchan);

		return (-1);
	}

	XCHAN_UNLOCK(xchan);

	return (0);
}

int
xdma_control(xdma_channel_t *xchan, enum xdma_command cmd)
{
	xdma_controller_t *xdma;
	int ret;

	xdma = xchan->xdma;
	KASSERT(xdma != NULL, ("xdma is NULL"));

	ret = XDMA_CHANNEL_CONTROL(xdma->dma_dev, xchan, cmd);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't process command.\n", __func__);
		return (-1);
	}

	return (0);
}

void
xdma_callback(xdma_channel_t *xchan, xdma_transfer_status_t *status)
{
	struct xdma_intr_handler *ih_tmp;
	struct xdma_intr_handler *ih;
	xdma_controller_t *xdma;

	xdma = xchan->xdma;
	KASSERT(xdma != NULL, ("xdma is NULL"));

	TAILQ_FOREACH_SAFE(ih, &xchan->ie_handlers, ih_next, ih_tmp)
		if (ih->cb != NULL)
			ih->cb(ih->cb_user, status);

	wakeup(xdma);
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
	if (node <= 0)
		device_printf(dev,
		    "%s called on not ofw based device.\n", __func__);

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
	xdma->dev = dev;
	xdma->dma_dev = dma_dev;

	TAILQ_INIT(&xdma->channels);

	xdma_ofw_md_data(xdma, cells, ncells);
	free(cells, M_OFWPROP);

	mtx_init(&xdma->proc_mtx, "xDMA ofw controller", NULL, MTX_DEF);
	error = kproc_create(&xdma_task, xdma, &xdma->xdma_proc, 0, 0, "xdma drainer");
	if (error) {
		device_printf(dev,
		    "%s failed to create kproc.\n", __func__);

		/* Cleanup */
		free(xdma, M_XDMA);

		return (NULL);
	}

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
