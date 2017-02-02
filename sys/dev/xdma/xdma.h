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

enum xdma_direction {
	XDMA_MEM_TO_MEM,
	XDMA_MEM_TO_DEV,
	XDMA_DEV_TO_MEM,
	XDMA_DEV_TO_DEV,
};

enum xdma_operation_type {
	XDMA_MEMCPY,
	XDMA_FIFO,
	XDMA_SG,
	XDMA_CYCLIC,
};

enum xdma_command {
	XDMA_CMD_BEGIN,
	XDMA_CMD_PAUSE,
	XDMA_CMD_TERMINATE,
	XDMA_CMD_TERMINATE_ALL,
};

struct xdma_transfer_status {
	int	error;
	int	total_copied;
	int	cnt_done;
};

typedef struct xdma_transfer_status xdma_transfer_status_t;

struct xdma_controller {
	device_t dev;		/* DMA consumer device_t. */
	device_t dma_dev;	/* A real DMA device_t. */
	void *data;		/* OFW MD part. */

	/* List of virtual channels allocated. */
	TAILQ_HEAD(xdma_channel_list, xdma_channel)	channels;
};

typedef struct xdma_controller xdma_controller_t;

struct xdma_mbuf_entry {
	struct mbuf			*m;
	TAILQ_ENTRY(xdma_mbuf_entry)	xm_next;
};

struct xdma_channel_config {
	enum xdma_direction	direction;
	uintptr_t		src_addr;	/* Physical address. */
	uintptr_t		dst_addr;	/* Physical address. */
	uint8_t			src_incr;
	uint8_t			dst_incr;
	int			block_len;	/* In bytes. */
	int			block_num;	/* Count of blocks. */
	int			src_width;	/* In bytes. */
	int			dst_width;	/* In bytes. */
};

typedef struct xdma_channel_config xdma_config_t;

struct xdma_descriptor {
	bus_addr_t			ds_addr;
	bus_size_t			ds_len;
	bus_dmamap_t			dma_map;
	void				*desc;
};

typedef struct xdma_descriptor xdma_descriptor_t;

struct xdma_sglist {
	vm_paddr_t			paddr;
	size_t				len;
	TAILQ_ENTRY(xdma_sglist)	sg_next;
};

TAILQ_HEAD(xdma_sglist_list, xdma_sglist);

struct xchan_bufmap {
	bus_dmamap_t	map;
	struct mbuf	*m;
};

struct xdma_channel {
	xdma_controller_t		*xdma;
	xdma_config_t			conf;

	uint8_t				flags;
#define	XCHAN_DESC_ALLOCATED		(1 << 0)
#define	XCHAN_CONFIGURED		(1 << 1)
#define	XCHAN_TYPE_CYCLIC		(1 << 2)
#define	XCHAN_TYPE_MEMCPY		(1 << 3)
#define	XCHAN_TYPE_FIFO			(1 << 4)
#define	XCHAN_TYPE_SG			(1 << 5)

	/* A real hardware driver channel. */
	void				*chan;

	/* Interrupt handlers. */
	TAILQ_HEAD(, xdma_intr_handler)	ie_handlers;

	/* Descriptors. */
	bus_dma_tag_t			dma_tag;
	xdma_descriptor_t		*descs;
	uint32_t			map_descr;
	uint8_t				map_err;

	/* Bufs */
	bus_dma_tag_t			dma_buf_tag;
	struct xchan_bufmap		*dma_buf_map;
	uint32_t			idx_count;
	uint32_t			idx_head;
	uint32_t			idx_tail;

	struct mtx			mtx_lock;

	TAILQ_ENTRY(xdma_channel)	xchan_next;

	struct mtx			mtx_qin_lock;
	struct mtx			mtx_qout_lock;

	TAILQ_HEAD(, xdma_mbuf_entry)	queue_in;
	TAILQ_HEAD(, xdma_mbuf_entry)	queue_out;
};

typedef struct xdma_channel xdma_channel_t;

/* xDMA controller alloc/free */
xdma_controller_t *xdma_ofw_get(device_t dev, const char *prop);
int xdma_put(xdma_controller_t *xdma);

xdma_channel_t * xdma_channel_alloc(xdma_controller_t *);
int xdma_channel_free(xdma_channel_t *);

int xdma_prep_cyclic(xdma_channel_t *, enum xdma_direction,
    uintptr_t, uintptr_t, int, int, int, int);
int xdma_prep_memcpy(xdma_channel_t *, uintptr_t, uintptr_t, size_t len);
int xdma_prep_fifo(xdma_channel_t *, uintptr_t, uintptr_t, size_t len, enum xdma_direction);
int xdma_prep_sg(xdma_channel_t *xchan, uintptr_t, uintptr_t, uint32_t, enum xdma_direction);
int xdma_desc_alloc(xdma_channel_t *, uint32_t, uint32_t);
int xdma_desc_free(xdma_channel_t *xchan);
int xdma_mark_done(xdma_channel_t *xchan, uint32_t idx, uint32_t len);
uint32_t xchan_next_idx(xdma_channel_t *xchan, uint32_t curidx);

int xdma_dequeue(xdma_channel_t *xchan, struct mbuf **m);
int xdma_enqueue(xdma_channel_t *xchan, struct mbuf **m);
int xdma_enqueue_submit(xdma_channel_t *xchan);
int xdma_enqueue_sync_pre(xdma_channel_t *xchan, uint32_t);
int xdma_enqueue_sync_post(xdma_channel_t *xchan, uint32_t);

/* Channel Control */
int xdma_begin(xdma_channel_t *xchan);
int xdma_pause(xdma_channel_t *xchan);
int xdma_terminate(xdma_channel_t *xchan);

/* Interrupt callback */
int xdma_setup_intr(xdma_channel_t *xchan, int (*cb)(void *, xdma_transfer_status_t *), void *arg, void **);
int xdma_teardown_intr(xdma_channel_t *xchan, struct xdma_intr_handler *ih);
int xdma_teardown_all_intr(xdma_channel_t *xchan);
int xdma_callback(struct xdma_channel *xchan, xdma_transfer_status_t *status);
void xdma_assert_locked(void);

struct xdma_intr_handler {
	int				(*cb)(void *cb_user, xdma_transfer_status_t *status);
	void				*cb_user;
	struct mtx			ih_lock;
	TAILQ_ENTRY(xdma_intr_handler)	ih_next;
};

#endif /* !_DEV_XDMA_H_ */
