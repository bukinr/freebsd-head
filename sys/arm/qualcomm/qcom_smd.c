/*-
 * Copyright (c) 2018 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kthread.h>
#include <sys/rman.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <machine/bus.h>

#include <dev/extres/clk/clk.h>
#include <dev/extres/hwreset/hwreset.h>
#include <dev/extres/regulator/regulator.h>
#include <dev/extres/syscon/syscon.h>

#include <dev/fdt/simplebus.h>
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

MALLOC_DEFINE(M_SMD, "SMD", "SMD");

#include "syscon_if.h" 

#include <arm/qualcomm/qcom_smd.h>
#include <arm/qualcomm/qcom_smem.h>
extern struct bus_space memmap_bus;

static struct ofw_compat_data compat_data[] = {
	{ "qcom,smd",		1 },
	{ NULL,			0 }
};

struct qcom_smd_softc {
	struct simplebus_softc	sc;
	device_t dev;
	phandle_t node;
	struct resource		*res;
	struct syscon		*syscon;
};

#define	SMD_ALLOC_TBL_COUNT	2
#define	SMD_ALLOC_TBL_SIZE	64

#define	SMD_CHANNEL_FLAGS_EDGE_MASK	0xff
#define	SMD_CHANNEL_FLAGS_STREAM	(1 << 8)
#define	SMD_CHANNEL_FLAGS_PACKET	(1 << 9)

static const struct {
	unsigned alloc_tbl_id;
	unsigned info_base_id;
	unsigned fifo_base_id;
} smem_items[SMD_ALLOC_TBL_COUNT] = {
	{
		.alloc_tbl_id = 13,
		.info_base_id = 14,
		.fifo_base_id = 338
	},
	{
		.alloc_tbl_id = 266,  
		.info_base_id = 138,
		.fifo_base_id = 202,
	},
};

struct qcom_smd_alloc_entry {
	uint8_t name[20];
	uint32_t cid;  
	uint32_t flags;
	uint32_t ref_count;
};

/*
 * Format of the smd_info smem items, for word aligned channels.
 */
struct smd_channel_info_word {
	uint32_t state;
	uint32_t fDSR;
	uint32_t fCTS;
	uint32_t fCD;
	uint32_t fRI;
	uint32_t fHEAD;
	uint32_t fTAIL;
	uint32_t fSTATE;
	uint32_t fBLOCKREADINTR;
	uint32_t tail;
	uint32_t head;
};

struct smd_channel_info_word_pair {
	struct smd_channel_info_word tx;
	struct smd_channel_info_word rx;
};

struct qcom_smd_channel {
	char *name;
	struct smd_channel_info_word_pair *info_word;
	size_t fifo_size;
	size_t info_size;
	void *tx_fifo;
};

/*
 * SMD channel states.
 */
enum smd_channel_state {
	SMD_CHANNEL_CLOSED,
	SMD_CHANNEL_OPENING,
	SMD_CHANNEL_OPENED,
	SMD_CHANNEL_FLUSHING,
	SMD_CHANNEL_CLOSING,
	SMD_CHANNEL_RESET,
	SMD_CHANNEL_RESET_OPENING
};

struct qcom_smd_edge {
	uint32_t remote_pid;
};

#if 0
static struct resource_spec qcom_smd_spec[] = {
	{ SYS_RES_IRQ,	0,	RF_ACTIVE },
	{ -1, 0 }
};
#endif

struct qcom_smd_softc *qcom_smd_sc;

struct qcom_smd_devinfo {
        struct ofw_bus_devinfo  di_dinfo;
        struct resource_list    di_rl;
};

static const struct ofw_bus_devinfo *
qcom_smd_get_devinfo(device_t bus __unused, device_t child)
{
        struct qcom_smd_devinfo *di;

        di = device_get_ivars(child);
        return (&di->di_dinfo);
}

static void
qcom_smd_channel_dump_info(struct smd_channel_info_word *info)
{

	printf("channel state %x\n", info->state);
	printf("channel fDSR %x\n", info->fDSR);
	printf("channel fCTS %x\n", info->fCTS);
	printf("channel fCD %x\n", info->fCD);
	printf("channel fRI %x\n", info->fRI);
	printf("channel fHEAD %x\n", info->fHEAD);
	printf("channel fTAIL %x\n", info->fTAIL);
	printf("channel fSTATE %x\n", info->fSTATE);
	printf("channel fBLOCKREADINTR %x\n", info->fBLOCKREADINTR);
	printf("channel tail %x\n", info->tail);
	printf("channel head %x\n", info->head);
}

static int
smd_intr(void *arg)  
{

	while (1)
		printf("%s\n", __func__);

	return (FILTER_HANDLED);
}

static int
qcom_smd_write_fifo(struct qcom_smd_channel *channel,
    void *data, size_t count)
{
	uint32_t head;
	uint32_t *dst;
	uint32_t *src;
	int i;

	printf("%s: len %ld\n", __func__, count);

	head = channel->info_word->tx.head;

	dst = (uint32_t *)((uint64_t)channel->tx_fifo + head);
	src = (uint32_t *)data;

	printf("%s: tx_fifo %lx data %lx\n", __func__, (uint64_t)dst, (uint64_t)src);

	for (i = 0; i < count/4; i++) {
		*dst++ = *src++;
	}
	//bcopy(data, (void *)(dst + head), count);
	//memcpy((void *)(dst + head), data, count);

	printf("write succeeded\n");

	head += count;
	head &= (channel->fifo_size - 1);
	channel->info_word->tx.head = head;
	wmb();

	return (0);
}

static void
qcom_smd_channel_reset(struct qcom_smd_softc *sc,
    struct qcom_smd_channel *channel)
{

	channel->info_word->tx.state = SMD_CHANNEL_CLOSED;
	channel->info_word->tx.fDSR = 0;
	channel->info_word->tx.fCTS = 0;
	channel->info_word->tx.fCD = 0;
	channel->info_word->tx.fRI = 0;
	channel->info_word->tx.fHEAD = 0;
	channel->info_word->tx.fTAIL = 0;
	channel->info_word->tx.fSTATE = 1;
	channel->info_word->tx.fBLOCKREADINTR = 1;
	//channel->info_word->tx.fBLOCKREADINTR = 0;
	channel->info_word->tx.head = 0;
	channel->info_word->rx.tail = 0;

	wmb();

	SYSCON_WRITE_4(sc->syscon, 0x8, 1);

	uint32_t reg;
	printf("Reading syscon\n");
	reg = SYSCON_READ_4(sc->syscon, 0x8);
	printf("syscon 0x8 == %x\n", reg);

	DELAY(100000);
}

static void
qcom_smd_channel_set_state(struct qcom_smd_softc *sc,
    struct qcom_smd_channel *channel, int state)
{
	bool is_open;

	if (state == SMD_CHANNEL_OPENED)
		is_open = 1;
	else
		is_open = 0;

	channel->info_word->tx.fDSR = is_open;
	channel->info_word->tx.fCTS = is_open;
	channel->info_word->tx.fCD = is_open;

	channel->info_word->tx.state = state;
	channel->info_word->tx.fSTATE = 1;

	wmb();

	SYSCON_WRITE_4(sc->syscon, 0x8, 1);
}

static void
qcom_scan_channels(struct qcom_smd_softc *sc, struct qcom_smd_channel *channel)
{
	struct qcom_smd_alloc_entry *entry;
	struct qcom_smd_alloc_entry *alloc_tbl;
	int tbl;
	int i;

	struct qcom_smd_edge edge;

	edge.remote_pid = QCOM_SMEM_HOST_ANY;

	uint32_t cid;
	uint32_t info_id;
	uint32_t fifo_id;
	uint32_t edge_id;
	void *info;
	void *fifo_base;

	for (tbl = 0; tbl < SMD_ALLOC_TBL_COUNT; tbl++) {
		alloc_tbl = qcom_smem_get(edge.remote_pid,
		    smem_items[tbl].alloc_tbl_id, NULL);
		for (i = 0; i < SMD_ALLOC_TBL_SIZE; i++) {
			entry = &alloc_tbl[i];
			if (!entry)
				continue;
			if (entry->ref_count == 0)
				continue;
			if (entry->name[0] == '\0')
				continue;

			edge_id = entry->flags & SMD_CHANNEL_FLAGS_EDGE_MASK;
			if (edge_id != 15)
				continue;

			printf("entry flags %x\n", entry->flags);
			printf("entry edge_id %d\n", entry->flags & SMD_CHANNEL_FLAGS_EDGE_MASK);
			printf("tbl %d channel %d name %s\n", tbl, i, entry->name);

			cid = entry->cid;
			info_id = smem_items[tbl].info_base_id + cid;
			fifo_id = smem_items[tbl].fifo_base_id + cid;

			qcom_smem_get(edge.remote_pid, fifo_id, &channel->fifo_size);
			printf("fifo size %ld\n", channel->fifo_size);

			info = qcom_smem_get(edge.remote_pid, info_id, &channel->info_size);
			printf("info size %ld\n", channel->info_size);
			if (channel->info_size != 2 * sizeof(struct smd_channel_info_word))
				panic("not right\n");
			channel->info_word = info;

			fifo_base = qcom_smem_get(edge.remote_pid, fifo_id, NULL);
			channel->tx_fifo = fifo_base;

			return;
		}
	}
	panic("not found\n");
}

void
qcom_smd_channel_open(void)
{
	struct qcom_smd_channel channel;
	struct qcom_smd_softc *sc;

	sc = qcom_smd_sc;

	printf("Resetting channel\n");

	qcom_scan_channels(sc, &channel);

	qcom_smd_channel_reset(sc, &channel);
	DELAY(100000);
	qcom_smd_channel_set_state(sc, &channel, SMD_CHANNEL_OPENING);
	DELAY(100000);
	qcom_smd_channel_set_state(sc, &channel, SMD_CHANNEL_OPENED);
	DELAY(100000);

	//while (1)
	//	qcom_smd_channel_dump_info(&channel.info_word->tx);
}

void
qcom_smd_send(void *data, size_t len)
{
	struct qcom_smd_softc *sc;

	printf("%s\n", __func__);

	sc = qcom_smd_sc;

	struct qcom_smd_channel channel;
	qcom_scan_channels(sc, &channel);

	channel.info_word->tx.fTAIL = 0;

	printf("Dump TX, channel\n");
	qcom_smd_channel_dump_info(&channel.info_word->tx);
	printf("Dump RX, channel\n");
	qcom_smd_channel_dump_info(&channel.info_word->rx);

	uint32_t hdr[5] = { len, };
	int tlen;
	tlen = sizeof(hdr) + len;
	qcom_smd_write_fifo(&channel, hdr, sizeof(hdr));
	qcom_smd_write_fifo(&channel, data, len);
	channel.info_word->tx.fHEAD = 1;

	wmb();

	printf("Dump TX, channel\n");
	qcom_smd_channel_dump_info(&channel.info_word->tx);
	printf("Dump RX, channel\n");
	qcom_smd_channel_dump_info(&channel.info_word->rx);

	if (sc->syscon != NULL) {
		SYSCON_WRITE_4(sc->syscon, 0x8, 1);
		SYSCON_WRITE_4(sc->syscon, 0x8, 0xffffffff);
		SYSCON_WRITE_4(sc->syscon, 0, 0xffffffff);
	} else
		panic("syscon is NULL\n");
}

static int
qcom_smd_probe(device_t dev)
{
	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "Qualcomm Shared Memory Device");

	return (BUS_PROBE_DEFAULT);
}

static int
qcom_smd_attach(device_t dev)
{
	struct qcom_smd_softc *sc;
	device_t gcdev;

	sc = device_get_softc(dev);

	qcom_smd_sc = sc;

	phandle_t node, child, grandchild;
	struct qcom_smd_devinfo *di;
	pcell_t addr_cells, size_cells;
	struct resource *res;
	int intr_rid;
	void *intr_ih;

	node = ofw_bus_get_node(dev);
	simplebus_init(dev, node);

	OF_getencprop(node, "#address-cells", &addr_cells,
	    sizeof(addr_cells));
	size_cells = 2;
	OF_getencprop(node, "#size-cells", &size_cells,   
	    sizeof(size_cells));

	struct resource_list		rl;
	struct resource_list_entry	*rle;
	int rlen;

	for (child = OF_child(node); child != 0;
	    child = OF_peer(child)) {

		if (OF_hasprop(child, "qcom,ipc") && syscon_get_by_ofw_property(dev, child,
		    "qcom,ipc", &sc->syscon) != 0) {
			device_printf(dev, "cannot get syscon driver handle\n");
			panic("a");
		}


		resource_list_init(&rl);
		ofw_bus_intr_to_rl(dev, child, &rl, &rlen);

		rle = resource_list_find(&rl, SYS_RES_IRQ, 0);
		if (rle == NULL)
			printf("failed to find SYS_RES_IRQ\n");
		if (rle->res == NULL)
			printf("rle->res is NULL\n");

		intr_rid = 0;
		printf("intr_rid %d, rle->start %ld, end %ld, count %ld\n",
		    intr_rid, rle->start, rle->end, rle->count);
		res = bus_alloc_resource(dev, SYS_RES_IRQ, &intr_rid,
		    rle->start, rle->end, rle->count, RF_ACTIVE);
		if (res == NULL) {
			printf("failed to alloc resource\n");
			panic("b");
		}

		if ((bus_setup_intr(dev, res, INTR_TYPE_MISC | INTR_MPSAFE,
		    smd_intr, NULL, sc, &intr_ih))) {
			device_printf(dev, "Cannot to register interrupt handler\n");
			panic("cant register interrupt\n");
		}

		for (grandchild = OF_child(child); grandchild != 0;
		    grandchild = OF_peer(grandchild)) {

			/* Allocate and populate devinfo. */
			di = malloc(sizeof(*di), M_SMD, M_WAITOK | M_ZERO);
 
			if (ofw_bus_gen_setup_devinfo(&di->di_dinfo, grandchild)) {
				panic("a");
			}

			/* Initialize and populate resource list. */
			resource_list_init(&di->di_rl);
			ofw_bus_reg_to_rl(gcdev, grandchild, addr_cells, size_cells,
			    &di->di_rl);

			/* Add newbus device for this FDT node */
			gcdev = device_add_child(dev, NULL, -1);
			if (gcdev == NULL)
				panic("here");

			device_set_ivars(gcdev, di);
		}
	}

	int ret;

	ret = bus_generic_attach(dev);
	if (ret)
		return (ret);

	return (0);
}

static device_method_t qcom_smd_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		qcom_smd_probe),
	DEVMETHOD(device_attach,	qcom_smd_attach),

	DEVMETHOD(ofw_bus_get_devinfo,	qcom_smd_get_devinfo),
	DEVMETHOD(ofw_bus_get_compat,   ofw_bus_gen_get_compat),
	DEVMETHOD(ofw_bus_get_model,	ofw_bus_gen_get_model),
	DEVMETHOD(ofw_bus_get_name,	ofw_bus_gen_get_name),
	DEVMETHOD(ofw_bus_get_node,	ofw_bus_gen_get_node),
	DEVMETHOD(ofw_bus_get_type,	ofw_bus_gen_get_type),

	DEVMETHOD_END
};

static driver_t qcom_smd_driver = {
	"qcom_smd",
	qcom_smd_methods,
	sizeof(struct qcom_smd_softc),
};

devclass_t qcom_smd_devclass;

EARLY_DRIVER_MODULE(qcom_smd, simplebus, qcom_smd_driver, qcom_smd_devclass,
    0, 0, BUS_PASS_INTERRUPT + BUS_PASS_ORDER_LAST);
MODULE_VERSION(qcom_smd, 1);
