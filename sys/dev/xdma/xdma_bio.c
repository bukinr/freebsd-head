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

int
xdma_dequeue_bio(xdma_channel_t *xchan, struct bio **bp,
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

	*bp = xr->bp;
	status->error = xr->status.error;
	status->transferred = xr->status.transferred;
	xchan->xr_tail = xchan_next_req(xchan, xchan->xr_tail);
	atomic_subtract_int(&xchan->xr_count, 1);

	return (0);
}

int
xdma_enqueue_bio(xdma_channel_t *xchan, struct bio **bp,
    bus_addr_t addr, enum xdma_direction dir,
    uint8_t src_width, uint8_t dst_width)
{
	struct xdma_request *xr;
	xdma_controller_t *xdma;

	xdma = xchan->xdma;

	if (xchan->xr_count >= (xchan->xr_num - 1)) {
		/* No space is available yet. */
		return (-1);
	}

	xr = &xchan->xr[xchan->xr_head];
	xr->direction = dir;
	xr->bp = *bp;
	xr->type = XR_TYPE_BIO;

	xr->src_width = src_width;
	xr->dst_width = dst_width;

	if (dir == XDMA_MEM_TO_DEV) {
		xr->dst_addr = addr;
		xr->src_addr = 0;
	} else {
		xr->dst_addr = 0;
		xr->src_addr = addr;
	}
	xr->done = 0;
	xchan->xr_head = xchan_next_req(xchan, xchan->xr_head);
	atomic_add_int(&xchan->xr_count, 1);

	return (0);
}
