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

/* Cadence Quad SPI Flash Controller driver. */

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

struct cqspi_flash_ident {
	const char	*name;
	uint8_t		manufacturer_id;
	uint16_t	device_id;
	unsigned int	sectorsize;
	unsigned int	sectorcount;
	unsigned int	flags;
};

struct cqspi_softc {
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

#define	CQSPI_LOCK(_sc)		mtx_lock(&(_sc)->sc_mtx)
#define	CQSPI_UNLOCK(_sc)	mtx_unlock(&(_sc)->sc_mtx)
#define CQSPI_LOCK_INIT(_sc)					\
	mtx_init(&_sc->sc_mtx, device_get_nameunit(_sc->dev),	\
	    "cqspi", MTX_DEF)
#define CQSPI_LOCK_DESTROY(_sc)	mtx_destroy(&_sc->sc_mtx);
#define CQSPI_ASSERT_LOCKED(_sc)				\
	mtx_assert(&_sc->sc_mtx, MA_OWNED);
#define CQSPI_ASSERT_UNLOCKED(_sc)				\
	mtx_assert(&_sc->sc_mtx, MA_NOTOWNED);

static struct resource_spec cqspi_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ SYS_RES_MEMORY,	1,	RF_ACTIVE },
	{ SYS_RES_IRQ,		0,	RF_ACTIVE },
	{ -1, 0 }
};

static struct ofw_compat_data compat_data[] = {
	{ "cdns,qspi-nor",	1 },
	{ NULL,			0 },
};

/* disk routines */
static int cqspi_open(struct disk *dp);
static int cqspi_close(struct disk *dp);
static int cqspi_ioctl(struct disk *, u_long, void *, int, struct thread *);
static void cqspi_strategy(struct bio *bp);
static int cqspi_getattr(struct bio *bp);
static void cqspi_task(void *arg);

struct cqspi_flash_ident flash_devices[] = {
	{ "n25q00", 0x20, 0xbb21, (64 * 1024), 2048, FL_NONE },
};

static void
cqspi_intr(void *arg)
{
	struct cqspi_softc *sc;
	uint32_t pending;

	sc = arg;

	pending = READ4(sc, CQSPI_IRQSTAT);

	//printf("%s: IRQSTAT %x\n", __func__, pending);
	if (pending & (IRQMASK_INDOPDONE | IRQMASK_INDXFRLVL | IRQMASK_INDSRAMFULL)) {
		//printf("op_done\n");
		sc->op_done = 1;
	}
	WRITE4(sc, CQSPI_IRQSTAT, pending);
}

static uint8_t
cqspi_get_status(device_t dev)
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
cqspi_wait_for_device_ready(device_t dev)
{

	while ((cqspi_get_status(dev) & STATUS_WIP))
		continue;
}

static struct cqspi_flash_ident*
cqspi_get_device_ident(struct cqspi_softc *sc)
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
cqspi_set_writable(device_t dev, int writable)
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
cqspi_erase_cmd(device_t dev, off_t sector, uint8_t ecmd)
{
#if 0
	struct cqspi_softc *sc;
	uint8_t txBuf[5], rxBuf[5];
	struct spi_command cmd;
	int err;

	printf("%s\n", __func__);

	sc = device_get_softc(dev);

	cqspi_wait_for_device_ready(dev);
	cqspi_set_writable(dev, 1);

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
cqspi_write(device_t dev, off_t offset, caddr_t data, off_t count)
{
#if 0
	struct cqspi_softc *sc;
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
			cqspi_erase_cmd(dev, offset + bytes_writen, CMD_SECTOR_ERASE);

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
		cqspi_wait_for_device_ready(dev);
		cqspi_set_writable(dev, 1);

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
cqspi_read(device_t dev, off_t offset, caddr_t data, off_t count)
{
	struct cqspi_softc *sc;
	device_t pdev;
	uint32_t reg;

	pdev = device_get_parent(dev);
	sc = device_get_softc(dev);

	//printf("%s: offset 0x%llx count %lld bytes\n", __func__, offset, count);

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

	WRITE4(sc, CQSPI_INDRD, INDRD_IND_OPS_DONE_STATUS);
	WRITE4(sc, CQSPI_INDRD, 0);

	WRITE4(sc, CQSPI_INDRDWATER, 4);
	WRITE4(sc, CQSPI_INDRDCNT, count);

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

	WRITE4(sc, CQSPI_INDRDSTADDR, offset);
	WRITE4(sc, CQSPI_INDRD, INDRD_START);

	uint32_t *addr;
	int i;
	int n;
	uint32_t cnt;
	addr = (uint32_t *)data;

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
cqspi_set_4b_mode(device_t dev, uint8_t command)
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

	cqspi_wait_for_device_ready(dev);

	return (err);
#endif
	return (0);
}

static int
cqspi_probe(device_t dev)
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
cqspi_cmd(struct cqspi_softc *sc, uint8_t cmd, uint32_t len)
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
cqspi_attach(device_t dev)
{
	struct cqspi_softc *sc;
	struct cqspi_flash_ident *ident;

	sc = device_get_softc(dev);
	sc->dev = dev;

	if (bus_alloc_resources(dev, cqspi_spec, sc->res)) {
		device_printf(dev, "could not allocate resources\n");
		return (ENXIO);
	}

	/* Memory interface */
	sc->bst = rman_get_bustag(sc->res[0]);
	sc->bsh = rman_get_bushandle(sc->res[0]);

	/* Setup interrupt handlers */
	if (bus_setup_intr(sc->dev, sc->res[2], INTR_TYPE_BIO | INTR_MPSAFE,
	    NULL, cqspi_intr, sc, &sc->ih)) {
		device_printf(sc->dev, "Unable to setup intr\n");
		return (ENXIO);
	}

	printf("Module ID %x\n", READ4(sc, CQSPI_MODULEID));
	printf("cfg %x\n", READ4(sc, CQSPI_CFG));

	uint32_t reg;

	/* Disable controller */
	reg = READ4(sc, CQSPI_CFG);
	reg &= ~(CFG_EN);
	WRITE4(sc, CQSPI_CFG, reg);

	reg = READ4(sc, CQSPI_DEVSZ);
	//printf("devsz %x\n", reg);
	reg |= 3;
	WRITE4(sc, CQSPI_DEVSZ, reg);

	//WRITE4(sc, CQSPI_REMAPADDR, 0);
	//WRITE4(sc, CQSPI_SRAMPART, 128/2);

	reg = READ4(sc, CQSPI_CFG);
	/* Configure baud rate */
	reg &= ~(CFG_BAUD_M);
	reg |= CFG_BAUD4;
	//reg |= (1 << 16) | (1 << 7); // DIRECT mode
	//reg |= CFG_ENDMA;
	//reg |= (1 << 2) | (1 << 1);
	WRITE4(sc, CQSPI_CFG, reg);

	reg = (3 << DELAY_NSS_S);
	reg |= (3 << DELAY_BTWN_S);
	reg |= (1 << DELAY_AFTER_S);
	reg |= (1 << DELAY_INIT_S);

	reg = (3 << DELAY_NSS_S);
	reg |= (3  << DELAY_BTWN_S);
	reg |= (1 << DELAY_AFTER_S);
	reg |= (1 << DELAY_INIT_S);
	WRITE4(sc, CQSPI_DELAY, reg);

	READ4(sc, CQSPI_RDDATACAP);
	reg &= ~(RDDATACAP_DELAY_M);
	reg |= (1 << RDDATACAP_DELAY_S);
	WRITE4(sc, CQSPI_RDDATACAP, reg);

	/* Enable controller */
	reg = READ4(sc, CQSPI_CFG);
	reg |= (CFG_EN);
	WRITE4(sc, CQSPI_CFG, reg);

	reg = cqspi_cmd(sc, CMD_READ_IDENT, 4);
	printf("Ident %x\n", reg);

	reg = cqspi_cmd(sc, CMD_READ_STATUS, 2);
	printf("Status %x\n", reg);

	printf("Enter 4b mode\n");
	cqspi_cmd(sc, CMD_ENTER_4B_MODE, 1);

	//printf("Exit 4b mode\n");
	//cqspi_cmd(sc, CMD_EXIT_4B_MODE, 1);

	printf("Nvconf\n");
	reg = cqspi_cmd(sc, CMD_READ_NVCONF_REG, 2);
	printf("NVCONF %x\n", reg);

	printf("Conf\n");
	reg = cqspi_cmd(sc, CMD_READ_CONF_REG, 1);
	printf("CONF %x\n", reg);

	printf("FSR\n");
	reg = cqspi_cmd(sc, CMD_READ_FSR, 1);
	printf("FSR %x\n", reg);

	CQSPI_LOCK_INIT(sc);

	if (0 == 1) {
		ident = cqspi_get_device_ident(sc);
	}
	ident = &flash_devices[0];
	if (ident == NULL)
		return (ENXIO);

	cqspi_wait_for_device_ready(sc->dev);

	sc->sc_disk = disk_alloc();
	sc->sc_disk->d_open = cqspi_open;
	sc->sc_disk->d_close = cqspi_close;
	sc->sc_disk->d_strategy = cqspi_strategy;
	sc->sc_disk->d_getattr = cqspi_getattr;
	sc->sc_disk->d_ioctl = cqspi_ioctl;
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
		cqspi_set_4b_mode(dev, CMD_ENTER_4B_MODE);

	if (sc->sc_flags & FL_DISABLE_4B_ADDR)
		cqspi_set_4b_mode(dev, CMD_EXIT_4B_MODE);

        /* NB: use stripesize to hold the erase/region size for RedBoot */
	sc->sc_disk->d_stripesize = ident->sectorsize;

	disk_create(sc->sc_disk, DISK_VERSION);
	bioq_init(&sc->sc_bio_queue);

	kproc_create(&cqspi_task, sc, &sc->sc_p, 0, 0, "task: cqspi flash");
	device_printf(sc->dev, "%s, sector %d bytes, %d sectors\n", 
	    ident->name, ident->sectorsize, ident->sectorcount);

	return (0);
}

static int
cqspi_detach(device_t dev)
{

	return (EIO);
}

static int
cqspi_open(struct disk *dp)
{

	return (0);
}

static int
cqspi_close(struct disk *dp)
{

	return (0);
}

static int
cqspi_ioctl(struct disk *dp, u_long cmd, void *data,
    int fflag, struct thread *td)
{

	return (EINVAL);
}

static void
cqspi_strategy(struct bio *bp)
{
	struct cqspi_softc *sc;

	sc = (struct cqspi_softc *)bp->bio_disk->d_drv1;

	CQSPI_LOCK(sc);
	bioq_disksort(&sc->sc_bio_queue, bp);
	wakeup(sc);
	CQSPI_UNLOCK(sc);
}

static int
cqspi_getattr(struct bio *bp)
{
	struct cqspi_softc *sc;
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
cqspi_task(void *arg)
{
	struct cqspi_softc *sc;
	struct bio *bp;
	device_t dev;

	sc = (struct cqspi_softc *)arg;

	dev = sc->dev;

	for (;;) {
		CQSPI_LOCK(sc);

		do {
			bp = bioq_first(&sc->sc_bio_queue);
			if (bp == NULL)
				msleep(sc, &sc->sc_mtx, PRIBIO, "jobqueue", 0);
		} while (bp == NULL);

		bioq_remove(&sc->sc_bio_queue, bp);
		CQSPI_UNLOCK(sc);

		switch (bp->bio_cmd) {
		case BIO_READ:
			bp->bio_error = cqspi_read(dev, bp->bio_offset, 
			    bp->bio_data, bp->bio_bcount);
			break;
		case BIO_WRITE:
			bp->bio_error = cqspi_write(dev, bp->bio_offset, 
			    bp->bio_data, bp->bio_bcount);
			break;
		default:
			bp->bio_error = EINVAL;
		}

		biodone(bp);
	}
}

static devclass_t cqspi_devclass;

static device_method_t cqspi_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		cqspi_probe),
	DEVMETHOD(device_attach,	cqspi_attach),
	DEVMETHOD(device_detach,	cqspi_detach),

	{ 0, 0 }
};

static driver_t cqspi_driver = {
	"cqspi",
	cqspi_methods,
	sizeof(struct cqspi_softc),
};

DRIVER_MODULE(cqspi, simplebus, cqspi_driver, cqspi_devclass, 0, 0);
