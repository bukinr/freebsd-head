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

/* n25q flash driver */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_platform.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bio.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <geom/geom_disk.h>

#include <machine/bus.h>

#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus_subr.h>
#include <dev/ofw/openfirm.h>

#include <dev/flash/cqspi.h>

#include "qspi_if.h"

#define	FL_NONE			0x00
#define	FL_ERASE_4K		0x01
#define	FL_ERASE_32K		0x02
#define	FL_ENABLE_4B_ADDR	0x04
#define	FL_DISABLE_4B_ADDR	0x08

#define	CQSPI_SECTORSIZE	512

#define	READ4(_sc, _reg) bus_read_4((_sc)->res[0], _reg)
#define READ2(_sc, _reg) bus_read_2((_sc)->res[0], _reg)
#define READ1(_sc, _reg) bus_read_1((_sc)->res[0], _reg)
#define WRITE4(_sc, _reg, _val) bus_write_4((_sc)->res[0], _reg, _val)
#define WRITE2(_sc, _reg, _val) bus_write_2((_sc)->res[0], _reg, _val)
#define WRITE1(_sc, _reg, _val) bus_write_1((_sc)->res[0], _reg, _val)
#define READ_DATA_4(_sc, _reg) bus_read_4((_sc)->res[1], _reg)
#define READ_DATA_1(_sc, _reg) bus_read_1((_sc)->res[1], _reg)

struct n25q_flash_ident {
	const char	*name;
	uint8_t		manufacturer_id;
	uint16_t	device_id;
	unsigned int	sectorsize;
	unsigned int	sectorcount;
	unsigned int	flags;
};

struct n25q_softc {
	device_t	dev;
	uint8_t		sc_manufacturer_id;
	uint16_t	device_id;
	unsigned int	sc_sectorsize;
	struct mtx	sc_mtx;
	struct disk	*sc_disk;
	struct proc	*sc_p;
	struct bio_queue_head sc_bio_queue;
	unsigned int	sc_flags;

	struct resource		*res[3];
	bus_space_tag_t		bst;
	bus_space_handle_t	bsh;
	void			*ih;
	uint8_t			op_done;
};

#define	N25Q_LOCK(_sc)		mtx_lock(&(_sc)->sc_mtx)
#define	N25Q_UNLOCK(_sc)	mtx_unlock(&(_sc)->sc_mtx)
#define N25Q_LOCK_INIT(_sc)					\
	mtx_init(&_sc->sc_mtx, device_get_nameunit(_sc->dev),	\
	    "n25q", MTX_DEF)
#define N25Q_LOCK_DESTROY(_sc)	mtx_destroy(&_sc->sc_mtx);
#define N25Q_ASSERT_LOCKED(_sc)				\
	mtx_assert(&_sc->sc_mtx, MA_OWNED);
#define N25Q_ASSERT_UNLOCKED(_sc)				\
	mtx_assert(&_sc->sc_mtx, MA_NOTOWNED);

#if 0
static struct resource_spec n25q_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ -1, 0 }
};
#endif

static struct ofw_compat_data compat_data[] = {
	{ "n25q00aa",		1 },
	{ NULL,			0 },
};

/* disk routines */
static int n25q_open(struct disk *dp);
static int n25q_close(struct disk *dp);
static int n25q_ioctl(struct disk *, u_long, void *, int, struct thread *);
static void n25q_strategy(struct bio *bp);
static int n25q_getattr(struct bio *bp);
static void n25q_task(void *arg);

struct n25q_flash_ident flash_devices[] = {
	{ "n25q00", 0x20, 0xbb21, (64 * 1024), 2048, FL_NONE },
};

static void
n25q_intr(void *arg)
{
	struct n25q_softc *sc;
	uint32_t pending;

	sc = arg;

	pending = READ4(sc, CQSPI_IRQSTAT);

#if 1
	printf("%s: IRQSTAT %x\n", __func__, pending);
#endif
	if (pending & (IRQMASK_INDOPDONE | IRQMASK_INDXFRLVL | IRQMASK_INDSRAMFULL)) {
		//printf("op_done\n");
		sc->op_done = 1;
	}
	WRITE4(sc, CQSPI_IRQSTAT, pending);
}

static uint8_t
n25q_get_status(device_t dev)
{
#if 0
	uint8_t txBuf[2], rxBuf[2];
	struct spi_command cmd;
	int err;

	memset(&cmd, 0, sizeof(cmd));
	memset(txBuf, 0, sizeof(txBuf));
	memset(rxBuf, 0, sizeof(rxBuf));

	txBuf[0] = CMD_READ_STATUS;
	cmd.tx_cmd = txBuf;
	cmd.rx_cmd = rxBuf;
	cmd.rx_cmd_sz = 2;
	cmd.tx_cmd_sz = 2;
	err = 0; //SPIBUS_TRANSFER(device_get_parent(dev), dev, &cmd);
	return (rxBuf[1]);
#endif
	return (0);
}

static void
n25q_wait_for_device_ready(device_t dev)
{

	while ((n25q_get_status(dev) & STATUS_WIP))
		continue;
}

static struct n25q_flash_ident*
n25q_get_device_ident(struct n25q_softc *sc)
{
#if 0
	device_t dev;
	uint8_t txBuf[8], rxBuf[8];
	struct spi_command cmd;
	uint8_t manufacturer_id;
	uint16_t dev_id;
	int err, i;

	dev = sc->dev;

	memset(&cmd, 0, sizeof(cmd));
	memset(txBuf, 0, sizeof(txBuf));
	memset(rxBuf, 0, sizeof(rxBuf));

	txBuf[0] = CMD_READ_IDENT;
	cmd.tx_cmd = &txBuf;
	cmd.rx_cmd = &rxBuf;
	/*
	 * Some compatible devices has extended two-bytes ID
	 * We'll use only manufacturer/deviceid atm
	 */
	cmd.tx_cmd_sz = 4;
	cmd.rx_cmd_sz = 4;
	err = 0; //SPIBUS_TRANSFER(device_get_parent(dev), dev, &cmd);
	if (err)
		return (NULL);

	manufacturer_id = rxBuf[1];
	dev_id = (rxBuf[2] << 8) | (rxBuf[3]);

	for (i = 0; 
	    i < nitems(flash_devices); i++) {
		if ((flash_devices[i].manufacturer_id == manufacturer_id) &&
		    (flash_devices[i].device_id == dev_id))
			return &flash_devices[i];
	}

	printf("Unknown SPI flash device. Vendor: %02x, device id: %04x\n",
	    manufacturer_id, dev_id);
#endif

	return (NULL);
}

static void
n25q_set_writable(device_t dev, int writable)
{
#if 0
	uint8_t txBuf[1], rxBuf[1];
	struct spi_command cmd;
	int err;

	printf("%s\n", __func__);

	memset(&cmd, 0, sizeof(cmd));
	memset(txBuf, 0, sizeof(txBuf));
	memset(rxBuf, 0, sizeof(rxBuf));

	txBuf[0] = writable ? CMD_WRITE_ENABLE : CMD_WRITE_DISABLE;
	cmd.tx_cmd = txBuf;
	cmd.rx_cmd = rxBuf;
	cmd.rx_cmd_sz = 1;
	cmd.tx_cmd_sz = 1;
	err = 0; //SPIBUS_TRANSFER(device_get_parent(dev), dev, &cmd);
#endif
}

static void
n25q_erase_cmd(device_t dev, off_t sector, uint8_t ecmd)
{
#if 0
	struct n25q_softc *sc;
	uint8_t txBuf[5], rxBuf[5];
	struct spi_command cmd;
	int err;

	printf("%s\n", __func__);

	sc = device_get_softc(dev);

	n25q_wait_for_device_ready(dev);
	n25q_set_writable(dev, 1);

	memset(&cmd, 0, sizeof(cmd));
	memset(txBuf, 0, sizeof(txBuf));
	memset(rxBuf, 0, sizeof(rxBuf));

	txBuf[0] = ecmd;
	cmd.tx_cmd = txBuf;
	cmd.rx_cmd = rxBuf;
	if (sc->sc_flags & FL_ENABLE_4B_ADDR) {
		cmd.rx_cmd_sz = 5;
		cmd.tx_cmd_sz = 5;
		txBuf[1] = ((sector >> 24) & 0xff);
		txBuf[2] = ((sector >> 16) & 0xff);
		txBuf[3] = ((sector >> 8) & 0xff);
		txBuf[4] = (sector & 0xff);
	} else {
		cmd.rx_cmd_sz = 4;
		cmd.tx_cmd_sz = 4;
		txBuf[1] = ((sector >> 16) & 0xff);
		txBuf[2] = ((sector >> 8) & 0xff);
		txBuf[3] = (sector & 0xff);
	}
	err = 0; //SPIBUS_TRANSFER(device_get_parent(dev), dev, &cmd);
#endif
}

static int
n25q_write(device_t dev, struct bio *bp, off_t offset, caddr_t data, off_t count)
{
#if 0
	struct n25q_softc *sc;
	uint8_t txBuf[8], rxBuf[8];
	struct spi_command cmd;
	off_t write_offset;
	long bytes_to_write, bytes_writen;
	device_t pdev;
	int err = 0;

	printf("%s\n", __func__);

	pdev = device_get_parent(dev);
	sc = device_get_softc(dev);

	if (sc->sc_flags & FL_ENABLE_4B_ADDR) {
		cmd.tx_cmd_sz = 5;
		cmd.rx_cmd_sz = 5;
	} else {
		cmd.tx_cmd_sz = 4;
		cmd.rx_cmd_sz = 4;
	}

	bytes_writen = 0;
	write_offset = offset;

	/*
	 * Use the erase sectorsize here since blocks are fully erased
	 * first before they're written to.
	 */
	if (count % sc->sc_sectorsize != 0 || offset % sc->sc_sectorsize != 0)
		return (EIO);

	/*
	 * Assume here that we write per-sector only 
	 * and sector size should be 256 bytes aligned
	 */
	KASSERT(write_offset % FLASH_PAGE_SIZE == 0,
	    ("offset for BIO_WRITE is not page size (%d bytes) aligned",
		FLASH_PAGE_SIZE));

	/*
	 * Maximum write size for CMD_PAGE_PROGRAM is 
	 * FLASH_PAGE_SIZE, so split data to chunks 
	 * FLASH_PAGE_SIZE bytes eash and write them
	 * one by one
	 */
	while (bytes_writen < count) {
		/*
		 * If we crossed sector boundary - erase next sector
		 */
		if (((offset + bytes_writen) % sc->sc_sectorsize) == 0)
			n25q_erase_cmd(dev, offset + bytes_writen, CMD_SECTOR_ERASE);

		txBuf[0] = CMD_PAGE_PROGRAM;
		if (sc->sc_flags & FL_ENABLE_4B_ADDR) {
			txBuf[1] = ((write_offset >> 24) & 0xff);
			txBuf[2] = ((write_offset >> 16) & 0xff);
			txBuf[3] = ((write_offset >> 8) & 0xff);
			txBuf[4] = (write_offset & 0xff);
		} else {
			txBuf[1] = ((write_offset >> 16) & 0xff);
			txBuf[2] = ((write_offset >> 8) & 0xff);
			txBuf[3] = (write_offset & 0xff);
		}

		bytes_to_write = MIN(FLASH_PAGE_SIZE,
		    count - bytes_writen);
		cmd.tx_cmd = txBuf;
		cmd.rx_cmd = rxBuf;
		cmd.tx_data = data + bytes_writen;
		cmd.tx_data_sz = bytes_to_write;
		cmd.rx_data = data + bytes_writen;
		cmd.rx_data_sz = bytes_to_write;

		/*
		 * Eash completed write operation resets WEL 
		 * (write enable latch) to disabled state,
		 * so we re-enable it here 
		 */
		n25q_wait_for_device_ready(dev);
		n25q_set_writable(dev, 1);

		err = 0; //SPIBUS_TRANSFER(pdev, dev, &cmd);
		if (err)
			break;

		bytes_writen += bytes_to_write;
		write_offset += bytes_to_write;
	}

	return (err);
#endif
	return (0);
}

static int
n25q_read(device_t dev, struct bio *bp, off_t offset, caddr_t data, off_t count)
{
	struct n25q_softc *sc;
	device_t pdev;
	uint32_t reg;

	pdev = device_get_parent(dev);
	sc = device_get_softc(dev);

	//printf("%s: offset 0x%llx count %lld bytes\n", __func__, offset, count);
	sc->op_done = 0;

	/*
	 * Enforce the disk read sectorsize not the erase sectorsize.
	 * In this way, smaller read IO is possible,dramatically
	 * speeding up filesystem/geom_compress access.
	 */
	if (count % sc->sc_disk->d_sectorsize != 0
	    || offset % sc->sc_disk->d_sectorsize != 0) {
		printf("EIO\n");
		return (EIO);
	}

	//printf("qspi cmd read\n");
	QSPI_READ(pdev, dev, bp, offset, data, count);
	//printf("qspi cmd read done\n");

	return (0);

	reg = (2 << 0); //numsglreqbytes
	reg |= (2 << 8); //numburstreqbytes
	WRITE4(sc, CQSPI_DMAPER, reg);
	WRITE4(sc, CQSPI_INDRDWATER, 4);

	//reg = (2 << 0); //numsglreqbytes
	//reg |= (2 << 8); //numburstreqbytes
	//WRITE4(sc, CQSPI_DMAPER, reg);
	//WRITE4(sc, CQSPI_INDRDWATER, 64);

	WRITE4(sc, CQSPI_INDRD, INDRD_IND_OPS_DONE_STATUS);
	WRITE4(sc, CQSPI_INDRD, 0);

	WRITE4(sc, CQSPI_INDRDCNT, count);
	WRITE4(sc, CQSPI_INDRDSTADDR, offset);

	reg = (CMD_FAST_READ << DEVRD_RDOPCODE_S);
	reg |= (0 << DEVRD_DUMMYRDCLKS_S);
	reg |= (0 << 16); //data width
	reg |= (0 << 12); //addr width
	reg |= (0 <<  8); //inst width
	reg |= (0 << 20); //enmodebits

	//reg = READ4(sc, CQSPI_DEVRD);
	//reg &= ~(0xff << DEVRD_RDOPCODE_S);
	//reg |= (CMD_FAST_READ << DEVRD_RDOPCODE_S);

	reg = (0 << DEVRD_DUMMYRDCLKS_S);
	reg |= (2 << 16); //data width
	reg |= (0 << 12); //addr width
	reg |= (0 <<  8); //inst width
	reg |= (1 << 20); //enmodebits
	reg |= (CMD_READ_4B_QUAD_OUTPUT << DEVRD_RDOPCODE_S);
	WRITE4(sc, CQSPI_DEVRD, reg);

	WRITE4(sc, CQSPI_MODEBIT, 0xff);

	reg = READ4(sc, CQSPI_IRQMASK);
	reg |= (IRQMASK_INDOPDONE | IRQMASK_INDXFRLVL | IRQMASK_INDSRAMFULL);
	//WRITE4(sc, CQSPI_IRQMASK, reg);

	sc->op_done = 0;

#if 0
	uint32_t *addr;
	int i;
	int n;
	uint32_t cnt;
	addr = (uint32_t *)data;

	WRITE4(sc, CQSPI_INDRD, INDRD_START);

	n = 0;
	while (n < (count / 4)) {
		cnt = READ4(sc, CQSPI_SRAMFILL) & 0xffff;
		for (i = 0; i < cnt; i++) {
			addr[n++] = READ_DATA_4(sc, 0);
		}
	}

	while ((READ4(sc, CQSPI_INDRD) & INDRD_IND_OPS_DONE_STATUS) == 0)
		;

	WRITE4(sc, CQSPI_INDRD, INDRD_IND_OPS_DONE_STATUS);
	WRITE4(sc, CQSPI_IRQSTAT, 0);
#else
	//xdma_enqueue(sc->xchan_rx, 0xffa00000, (uintptr_t)data, count, XDMA_DEV_TO_MEM, bp);
	//xdma_enqueue_bio(sc->xchan_rx, &bp, 0xffa00000, XDMA_DEV_TO_MEM);
	//xdma_queue_submit(sc->xchan_rx);

	WRITE4(sc, CQSPI_INDRD, INDRD_START);
#endif

	return (0);

#if 0
	txBuf[0] = CMD_FAST_READ;
	if (sc->sc_flags & FL_ENABLE_4B_ADDR) {
		cmd.tx_cmd_sz = 6;
		cmd.rx_cmd_sz = 6;

		txBuf[1] = ((offset >> 24) & 0xff);
		txBuf[2] = ((offset >> 16) & 0xff);
		txBuf[3] = ((offset >> 8) & 0xff);
		txBuf[4] = (offset & 0xff);
		/* Dummy byte */
		txBuf[5] = 0;
	} else {
		cmd.tx_cmd_sz = 5;
		cmd.rx_cmd_sz = 5;

		txBuf[1] = ((offset >> 16) & 0xff);
		txBuf[2] = ((offset >> 8) & 0xff);
		txBuf[3] = (offset & 0xff);
		/* Dummy byte */
		txBuf[4] = 0;
	}

	cmd.tx_cmd = txBuf;
	cmd.rx_cmd = rxBuf;
	cmd.tx_data = data;
	cmd.tx_data_sz = count;
	cmd.rx_data = data;
	cmd.rx_data_sz = count;

	err = 0; //SPIBUS_TRANSFER(pdev, dev, &cmd);

	return (err);
#endif
}

static int
n25q_set_4b_mode(device_t dev, uint8_t command)
{
#if 0
	uint8_t txBuf[1], rxBuf[1];
	struct spi_command cmd;
	device_t pdev;
	int err;

	memset(&cmd, 0, sizeof(cmd));
	memset(txBuf, 0, sizeof(txBuf));
	memset(rxBuf, 0, sizeof(rxBuf));

	pdev = device_get_parent(dev);

	cmd.tx_cmd_sz = cmd.rx_cmd_sz = 1;

	cmd.tx_cmd = txBuf;
	cmd.rx_cmd = rxBuf;

	txBuf[0] = command;

	err = 0; //SPIBUS_TRANSFER(pdev, dev, &cmd);

	n25q_wait_for_device_ready(dev);

	return (err);
#endif
	return (0);
}

static int
n25q_probe(device_t dev)
{
	int i;

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	/* First try to match the compatible property to the compat_data */
	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 1)
		goto found;

	/*
	 * Next, try to find a compatible device using the names in the
	 * flash_devices structure
	 */
	for (i = 0; i < nitems(flash_devices); i++)
		if (ofw_bus_is_compatible(dev, flash_devices[i].name))
			goto found;

	return (ENXIO);
found:
	device_set_desc(dev, "Quad SPI Flash Controller");

	return (0);
}

static int
n25q_cmd(struct n25q_softc *sc, uint8_t cmd, uint32_t len)
{
	uint32_t reg;

	printf("%s: %x\n", __func__, cmd);
	//printf("datardlo before %x\n", READ4(sc, CQSPI_FLASHCMDRDDATALO));

	reg = (cmd << FLASHCMD_CMDOPCODE_S);
	reg |= ((len - 1) << FLASHCMD_NUMRDDATABYTES_S);
	reg |= FLASHCMD_ENRDDATA;
	WRITE4(sc, CQSPI_FLASHCMD, reg);

	reg |= FLASHCMD_EXECCMD;
	WRITE4(sc, CQSPI_FLASHCMD, reg);

	int timeout;
	int i;

	timeout = 1000;
	for (i = timeout; i > 0; i--) {
		if ((READ4(sc, CQSPI_FLASHCMD) & FLASHCMD_CMDEXECSTAT) == 0) {
			break;
		}
	}
	if (i == 0) {
		printf("cmd timed out\n");
	}
	//printf("i %d\n", i);

	//printf("cmd %x\n", READ4(sc, CQSPI_FLASHCMD));
	//printf("datardlo %x\n", READ4(sc, CQSPI_FLASHCMDRDDATALO));
	//printf("datardup %x\n", READ4(sc, CQSPI_FLASHCMDRDDATAUP));

	uint32_t data;

	data = READ4(sc, CQSPI_FLASHCMDRDDATALO);

	switch (len) {
	case 4:
		return (data);
	case 3:
		return (data & 0xffffff);
	case 2:
		return (data & 0xffff);
	case 1:
		return (data & 0xff);
	default:
		return (0);
	}

	return (0);
}

static int
n25q_attach(device_t dev)
{
	struct n25q_flash_ident *ident;
	struct n25q_softc *sc;
	//uint32_t caps;
	//int error;

	sc = device_get_softc(dev);
	sc->dev = dev;
	printf("%s: dev %p\n", __func__, dev);

	//if (bus_alloc_resources(dev, n25q_spec, sc->res)) {
	//	device_printf(dev, "could not allocate resources\n");
	//	return (ENXIO);
	//}

	/* Memory interface */
	//sc->bst = rman_get_bustag(sc->res[0]);
	//sc->bsh = rman_get_bushandle(sc->res[0]);

	N25Q_LOCK_INIT(sc);

	if (0 == 1) {
		ident = n25q_get_device_ident(sc);
	}
	ident = &flash_devices[0];
	if (ident == NULL)
		return (ENXIO);

	n25q_wait_for_device_ready(sc->dev);

	sc->sc_disk = disk_alloc();
	sc->sc_disk->d_open = n25q_open;
	sc->sc_disk->d_close = n25q_close;
	sc->sc_disk->d_strategy = n25q_strategy;
	sc->sc_disk->d_getattr = n25q_getattr;
	sc->sc_disk->d_ioctl = n25q_ioctl;
	sc->sc_disk->d_name = "flash/qspi";
	sc->sc_disk->d_drv1 = sc;
	sc->sc_disk->d_maxsize = DFLTPHYS;
	sc->sc_disk->d_sectorsize = CQSPI_SECTORSIZE;
	sc->sc_disk->d_mediasize = (ident->sectorsize * ident->sectorcount);
	sc->sc_disk->d_unit = device_get_unit(sc->dev);
	sc->sc_disk->d_dump = NULL;
	/* Sectorsize for erase operations */
	sc->sc_sectorsize =  ident->sectorsize;
	sc->sc_flags = ident->flags;

	if (sc->sc_flags & FL_ENABLE_4B_ADDR)
		n25q_set_4b_mode(dev, CMD_ENTER_4B_MODE);

	if (sc->sc_flags & FL_DISABLE_4B_ADDR)
		n25q_set_4b_mode(dev, CMD_EXIT_4B_MODE);

        /* NB: use stripesize to hold the erase/region size for RedBoot */
	sc->sc_disk->d_stripesize = ident->sectorsize;

	disk_create(sc->sc_disk, DISK_VERSION);
	bioq_init(&sc->sc_bio_queue);

	kproc_create(&n25q_task, sc, &sc->sc_p, 0, 0, "task: n25q flash");
	device_printf(sc->dev, "%s, sector %d bytes, %d sectors\n", 
	    ident->name, ident->sectorsize, ident->sectorcount);

	return (0);
}

static int
n25q_detach(device_t dev)
{

	return (EIO);
}

static int
n25q_open(struct disk *dp)
{

	return (0);
}

static int
n25q_close(struct disk *dp)
{

	return (0);
}

static int
n25q_ioctl(struct disk *dp, u_long cmd, void *data,
    int fflag, struct thread *td)
{

	return (EINVAL);
}

static void
n25q_strategy(struct bio *bp)
{
	struct n25q_softc *sc;

	sc = (struct n25q_softc *)bp->bio_disk->d_drv1;

	N25Q_LOCK(sc);
	bioq_disksort(&sc->sc_bio_queue, bp);
	wakeup(sc);
	N25Q_UNLOCK(sc);
}

static int
n25q_getattr(struct bio *bp)
{
	struct n25q_softc *sc;
	device_t dev;

	if (bp->bio_disk == NULL || bp->bio_disk->d_drv1 == NULL) {
		return (ENXIO);
	}

	sc = bp->bio_disk->d_drv1;
	dev = sc->dev;

	if (strcmp(bp->bio_attribute, "SPI::device") == 0) {
		if (bp->bio_length != sizeof(dev)) {
			return (EFAULT);
		}
		bcopy(&dev, bp->bio_data, sizeof(dev));
		return (0);
	}

	return (-1);
}

static void
n25q_task(void *arg)
{
	struct n25q_softc *sc;
	struct bio *bp;
	device_t dev;

	sc = (struct n25q_softc *)arg;

	dev = sc->dev;

	for (;;) {
		N25Q_LOCK(sc);

		//printf("Task\n");

		do {
			bp = bioq_first(&sc->sc_bio_queue);
			if (bp == NULL) {
				msleep(sc, &sc->sc_mtx, PRIBIO, "jobqueue", hz);
			}
		} while (bp == NULL);

		bioq_remove(&sc->sc_bio_queue, bp);
		N25Q_UNLOCK(sc);

		switch (bp->bio_cmd) {
		case BIO_READ:
			bp->bio_error = n25q_read(dev, bp, bp->bio_offset, 
			    bp->bio_data, bp->bio_bcount);
			break;
		case BIO_WRITE:
			bp->bio_error = EINVAL;
			break;
			bp->bio_error = n25q_write(dev, bp, bp->bio_offset, 
			    bp->bio_data, bp->bio_bcount);
			break;
		default:
			bp->bio_error = EINVAL;
		}

#if 0
		N25Q_LOCK(sc);
		while (sc->op_done == 0) {
			msleep(sc->xdma_rx, &sc->sc_mtx, PRIBIO, "jobqueue", hz/2);
		}
		N25Q_UNLOCK(sc);
#endif

#if 1
		//printf("bio done\n");
		biodone(bp);
#endif
	}
}

static devclass_t n25q_devclass;

static device_method_t n25q_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		n25q_probe),
	DEVMETHOD(device_attach,	n25q_attach),
	DEVMETHOD(device_detach,	n25q_detach),

	{ 0, 0 }
};

static driver_t n25q_driver = {
	"n25q",
	n25q_methods,
	sizeof(struct n25q_softc),
};

DRIVER_MODULE(n25q, simplebus, n25q_driver, n25q_devclass, 0, 0);
