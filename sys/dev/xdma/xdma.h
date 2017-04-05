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
 *
 * $FreeBSD$
 */

#ifndef _DEV_XDMA_H_
#define _DEV_XDMA_H_

#include <sys/proc.h>

enum xdma_direction {
	XDMA_MEM_TO_MEM,
	XDMA_MEM_TO_DEV,
	XDMA_DEV_TO_MEM,
	XDMA_DEV_TO_DEV,
};

enum xdma_operation_type {
	XDMA_MEMCPY,
	XDMA_SG,
	XDMA_CYCLIC,
};

enum xdma_request_type {
	XR_TYPE_ADDR,
	XR_TYPE_MBUF,
	XR_TYPE_BIO,
};

enum xdma_command {
	XDMA_CMD_BEGIN,
	XDMA_CMD_PAUSE,
	XDMA_CMD_TERMINATE,
	XDMA_CMD_TERMINATE_ALL,
};

struct xdma_transfer_status {
	uint32_t	transferred;
	int		error;
};

typedef struct xdma_transfer_status xdma_transfer_status_t;

struct xdma_controller {
	device_t dev;		/* DMA consumer device_t. */
	device_t dma_dev;	/* A real DMA device_t. */
	void *data;		/* OFW MD part. */
	struct proc *xdma_proc;
	struct mtx proc_mtx;

	/* List of virtual channels allocated. */
	TAILQ_HEAD(xdma_channel_list, xdma_channel)	channels;
};

typedef struct xdma_controller xdma_controller_t;

struct xchan_buf {
	bus_dmamap_t			map;
	uint32_t			nsegs;
	uint32_t			nsegs_left;
	void				*cbuf;
};

/* SG type of transfer. */
struct xdma_request {
	struct mbuf			*m;
	struct bio			*bp;
	enum xdma_request_type		type;
	enum xdma_direction		direction;
	bus_addr_t			src_addr;	/* Physical address. */
	bus_addr_t			dst_addr;	/* Physical address. */
	uint8_t				src_width;
	uint8_t				dst_width;
	bus_size_t			len;
	xdma_transfer_status_t		status;
	void				*user;
	TAILQ_ENTRY(xdma_request)	xr_next;
	struct xchan_buf		buf;
};

/*
 * Cyclic/memcpy type of transfer.
 * Legacy configuration struct
 * TODO: replace with xdma_request.
 */
struct xdma_channel_config {
	enum xdma_direction	direction;
	uintptr_t		src_addr;	/* Physical address. */
	uintptr_t		dst_addr;	/* Physical address. */
	int			block_len;	/* In bytes. */
	int			block_num;	/* Count of blocks. */
	int			src_width;	/* In bytes. */
	int			dst_width;	/* In bytes. */
};

typedef struct xdma_channel_config xdma_config_t;

struct xdma_sglist {
	bus_addr_t			src_addr;
	bus_addr_t			dst_addr;
	size_t				len;
	uint8_t				src_width;
	uint8_t				dst_width;
	enum xdma_direction		direction;
	bool				first;
	bool				last;
};

struct xdma_channel {
	xdma_controller_t		*xdma;
	xdma_config_t			conf;

	uint32_t			flags;
#define	XCHAN_BUFS_ALLOCATED		(1 << 0)
#define	XCHAN_SGLIST_ALLOCATED		(1 << 1)
#define	XCHAN_CONFIGURED		(1 << 2)
#define	XCHAN_TYPE_CYCLIC		(1 << 3)
#define	XCHAN_TYPE_MEMCPY		(1 << 4)
#define	XCHAN_TYPE_FIFO			(1 << 5)
#define	XCHAN_TYPE_SG			(1 << 6)

	uint32_t			caps;
#define	XCHAN_CAP_BUSDMA		(1 << 0)
#define	XCHAN_CAP_BUSDMA_NOSEG		(1 << 1)

	/* A real hardware driver channel. */
	void				*chan;

	/* Interrupt handlers. */
	TAILQ_HEAD(, xdma_intr_handler)	ie_handlers;
	TAILQ_ENTRY(xdma_channel)	xchan_next;

	struct mtx			mtx_lock;
	struct mtx			mtx_qin_lock;
	struct mtx			mtx_qout_lock;
	struct mtx			mtx_bank_lock;
	struct mtx			mtx_proc_lock;

	/* Request queue. */
	bus_dma_tag_t			dma_tag_bufs;
	struct xdma_request		*xr_mem;
	uint32_t			xr_num;

	/* Bus dma tag options. */
	uint32_t			maxsegsize;
	uint32_t			maxnsegs;
	uint32_t			alignment;

	struct xdma_sglist		*sg;

	TAILQ_HEAD(, xdma_request)	bank;
	TAILQ_HEAD(, xdma_request)	queue_in;
	TAILQ_HEAD(, xdma_request)	queue_out;
	TAILQ_HEAD(, xdma_request)	processing;
	struct mtx			mtx_queue;
};

typedef struct xdma_channel xdma_channel_t;

/* xDMA controller ops */
xdma_controller_t *xdma_ofw_get(device_t dev, const char *prop);
int xdma_put(xdma_controller_t *xdma);

/* xDMA channel ops */
xdma_channel_t * xdma_channel_alloc(xdma_controller_t *, uint32_t caps);
int xdma_channel_free(xdma_channel_t *);

int xdma_prep_cyclic(xdma_channel_t *, enum xdma_direction,
    uintptr_t, uintptr_t, int, int, int, int);
int xdma_prep_memcpy(xdma_channel_t *, uintptr_t, uintptr_t, size_t len);
int xdma_prep_sg(xdma_channel_t *xchan, uint32_t, uint32_t, uint32_t, uint32_t);

int xchan_seg_done(xdma_channel_t *xchan, xdma_transfer_status_t *);

/* xchan queues operations */
int xdma_dequeue_mbuf(xdma_channel_t *xchan, struct mbuf **m, xdma_transfer_status_t *);
int xdma_enqueue_mbuf(xdma_channel_t *xchan, struct mbuf **m, uintptr_t addr,
    uint8_t, uint8_t, enum xdma_direction dir);
int xdma_dequeue_bio(xdma_channel_t *xchan, struct bio **bp, xdma_transfer_status_t *status);
int xdma_enqueue_bio(xdma_channel_t *xchan, struct bio **bp, bus_addr_t addr,
    uint8_t, uint8_t, enum xdma_direction dir);
int xdma_dequeue(xdma_channel_t *xchan, void **user, xdma_transfer_status_t *status);
int xdma_enqueue(xdma_channel_t *xchan, uintptr_t src, uintptr_t dst,
    uint8_t, uint8_t, bus_size_t, enum xdma_direction dir, void *);

int xdma_queue_submit(xdma_channel_t *xchan);

uint32_t xdma_mbuf_defrag(xdma_channel_t *xchan, struct xdma_request *xr);
uint32_t xdma_mbuf_chain_count(struct mbuf *m0);

/* Channel Control */
int xdma_begin(xdma_channel_t *xchan);
int xdma_pause(xdma_channel_t *xchan);
int xdma_terminate(xdma_channel_t *xchan);

/* Interrupt callback */
int xdma_setup_intr(xdma_channel_t *xchan, int (*cb)(void *, xdma_transfer_status_t *), void *arg, void **);
int xdma_teardown_intr(xdma_channel_t *xchan, struct xdma_intr_handler *ih);
int xdma_teardown_all_intr(xdma_channel_t *xchan);
int xdma_callback(struct xdma_channel *xchan, xdma_transfer_status_t *status);

int xchan_sglist_init(xdma_channel_t *xchan);
int xchan_sglist_free(xdma_channel_t *xchan);
int xdma_sglist_add(struct xdma_sglist *sg, struct bus_dma_segment *seg,
    uint32_t nsegs, struct xdma_request *xr);

struct xdma_intr_handler {
	int				(*cb)(void *cb_user, xdma_transfer_status_t *status);
	void				*cb_user;
	struct mtx			ih_lock;
	TAILQ_ENTRY(xdma_intr_handler)	ih_next;
};

static MALLOC_DEFINE(M_XDMA, "xdma", "xDMA framework");

struct xdma_request * xchan_bank_get(xdma_channel_t *xchan);
int xchan_bank_put(xdma_channel_t *xchan, struct xdma_request *xr);

#define	QUEUE_IN_LOCK(xchan)		mtx_lock(&(xchan)->mtx_qin_lock)
#define	QUEUE_IN_UNLOCK(xchan)		mtx_unlock(&(xchan)->mtx_qin_lock)
#define	QUEUE_IN_ASSERT_LOCKED(xchan)	mtx_assert(&(xchan)->mtx_qin_lock, MA_OWNED)

#define	QUEUE_OUT_LOCK(xchan)		mtx_lock(&(xchan)->mtx_qout_lock)
#define	QUEUE_OUT_UNLOCK(xchan)		mtx_unlock(&(xchan)->mtx_qout_lock)
#define	QUEUE_OUT_ASSERT_LOCKED(xchan)	mtx_assert(&(xchan)->mtx_qout_lock, MA_OWNED)

#define	QUEUE_BANK_LOCK(xchan)		mtx_lock(&(xchan)->mtx_bank_lock)
#define	QUEUE_BANK_UNLOCK(xchan)	mtx_unlock(&(xchan)->mtx_bank_lock)
#define	QUEUE_BANK_ASSERT_LOCKED(xchan)	mtx_assert(&(xchan)->mtx_bank_lock, MA_OWNED)

#define	QUEUE_PROC_LOCK(xchan)		mtx_lock(&(xchan)->mtx_proc_lock)
#define	QUEUE_PROC_UNLOCK(xchan)	mtx_unlock(&(xchan)->mtx_proc_lock)
#define	QUEUE_PROC_ASSERT_LOCKED(xchan)	mtx_assert(&(xchan)->mtx_proc_lock, MA_OWNED)

#endif /* !_DEV_XDMA_H_ */
