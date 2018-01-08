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

#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <arm/qualcomm/qcom_smem.h>
extern struct bus_space memmap_bus;

static struct ofw_compat_data compat_data[] = {
	{ "qcom,smem",		1 },
	{ NULL,			0 }
};

struct qcom_smem_softc {
	struct resource		*res;
	bus_addr_t		smem;
};
struct qcom_smem_softc *qcom_smem_sc;

#if 0
static struct resource_spec qcom_smem_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ -1, 0 }
};
#endif

#define	SMEM_ITEM_COUNT		512
#define	AUX_BASE_MASK		0xfffffffc
#define	QCOM_SMEM_HOST_ANY	-1
#define	SMEM_MASTER_SBL_VERSION_INDEX   7
#define	SMEM_GLOBAL_HEAP_VERSION        11
#define	SMEM_GLOBAL_PART_VERSION        12

struct smem_proc_comm {
	uint32_t command;
	uint32_t status;
	uint32_t params[2];
};

struct smem_global_entry {
	uint32_t allocated;
	uint32_t offset;
	uint32_t size;
	uint32_t aux_base; /* bits 1:0 reserved */
};

struct smem_header {
	struct smem_proc_comm proc_comm[4];
	uint32_t version[32];
	uint32_t initialized;
	uint32_t free_offset;
	uint32_t available;
	uint32_t reserved;
	struct smem_global_entry toc[SMEM_ITEM_COUNT];
};

struct smem_region {
	uint32_t aux_base;
	void *virt_base;
	size_t size;
};


void *
qcom_smem_get(uint32_t host, uint32_t item, size_t *size)
{
	struct qcom_smem_softc *sc;
	struct smem_header *hdr;
	struct smem_global_entry *entry;
	//struct smem_region *area;
	//uint32_t aux_base;
	//int i;

	sc = qcom_smem_sc;

	hdr = (struct smem_header *)sc->smem;
	entry = &hdr->toc[item];

	//aux_base = entry->aux_base & AUX_BASE_MASK;

	if (host == QCOM_SMEM_HOST_ANY) {
		if (!entry->allocated)	
			return (NULL);

		if (size != NULL)
			*size = entry->size;

		return ((void *)((uint64_t)sc->smem + entry->offset));
#if 0
		for (i = 0; i < smem->num_regions; i++) {
			area = &smem->regions[i];
			if (area->aux_base == aux_base || !aux_base) {
				if (size != NULL)
					*size = entry->size;
				return (area->virt_base + entry->offset);
			}
		}
#endif
	}
		
	return (NULL);
}

static int
qcom_smem_probe(device_t dev)
{
	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "Qualcomm Shared Memory");

	return (BUS_PROBE_DEFAULT);
}

static int
qcom_smem_attach(device_t dev)
{
	struct qcom_smem_softc *sc;

	sc = device_get_softc(dev);

	qcom_smem_sc = sc;

	phandle_t node;
	phandle_t mem;
	uint64_t base;
	uint64_t size;
	int error;

	node = ofw_bus_get_node(dev);

	if (OF_searchencprop(node, "memory-region", &mem,
	    sizeof(mem)) == -1) {
		return (ENXIO);
	}

	error = fdt_regsize(OF_node_from_xref(mem), &base, &size);

	printf("attached, base %lx size %lx\n", base, size);

	bus_addr_t smem;
	//uint32_t reg;
	if (bus_space_map(&memmap_bus, base,
	    size, 0, &smem) != 0)
		panic("Couldn't map smem\n");
	printf("smem %lx\n", smem);

	sc->smem = smem;

	struct smem_header *hdr;
	uint32_t *versions;
	uint32_t item;
	uint32_t sbl_version;

	hdr = (struct smem_header *)smem;
	versions = hdr->version;
	sbl_version = versions[SMEM_MASTER_SBL_VERSION_INDEX];
	printf("sbl_version %d\n", sbl_version);
	if ((sbl_version >> 16) == SMEM_GLOBAL_PART_VERSION)
		printf("GLOBAL\n");
	if ((sbl_version >> 16) == SMEM_GLOBAL_HEAP_VERSION)
		printf("HEAP\n");

	item = 13; /* SMEM_CHANNEL_ALLOC_TBL */
	item = 14; /* SMEM_SMD_BASE_ID info_base_id */
	item = 138; /* SMEM_SMD_BASE_ID info_base_id */

	struct smem_global_entry *entry;
	entry = &hdr->toc[item];

	//entry->offset = hdr->free_offset;
	//TODO entry->size = 
	//entry->allocated = 1;

	printf("entry->allocated %d\n", entry->allocated);
	printf("entry->offset %x\n", entry->offset);
	printf("entry->size %d\n", entry->size);

	//reg = bus_space_read_4(&memmap_bus, smem, 0x0);
	//bus_space_unmap(&memmap_bus, smem, size);
	//printf("reg %x\n", reg);

	return (0);
}

static device_method_t qcom_smem_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		qcom_smem_probe),
	DEVMETHOD(device_attach,	qcom_smem_attach),

	DEVMETHOD_END
};

static driver_t qcom_smem_driver = {
	"qcom_smem",
	qcom_smem_methods,
	sizeof(struct qcom_smem_softc),
};

static devclass_t qcom_smem_devclass;

EARLY_DRIVER_MODULE(qcom_smem, simplebus, qcom_smem_driver, qcom_smem_devclass,
    0, 0, BUS_PASS_BUS + BUS_PASS_ORDER_MIDDLE);
MODULE_VERSION(qcom_smem, 1);
