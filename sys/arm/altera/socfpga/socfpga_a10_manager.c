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

/*
 * Altera FPGA Manager.
 * Chapter 4, Arria 10 Hard Processor System Technical Reference Manual
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/rman.h>
#include <sys/timeet.h>
#include <sys/timetc.h>
#include <sys/conf.h>
#include <sys/uio.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <machine/bus.h>
#include <machine/cpu.h>
#include <machine/intr.h>

#include <arm/altera/socfpga/socfpga_common.h>

#define	IMGCFG_STAT			0x80
#define	 F2S_PR_ERROR			(1 << 11)
#define	 F2S_PR_DONE			(1 << 10)
#define	 F2S_PR_READY			(1 << 9)
#define	 F2S_MSEL_S			16
#define	 F2S_MSEL_M			(0x7 << F2S_MSEL_S)
#define	 F2S_NCONFIG_PIN		(1 << 12)
#define	 F2S_CONDONE_OE			(1 << 7)
#define	 F2S_NSTATUS_PIN		(1 << 4)
#define	 F2S_CONDONE_PIN		(1 << 6)
#define	 F2S_USERMODE			(1 << 2)
#define	IMGCFG_CTRL_00			0x70
#define	 S2F_CONDONE_OE			(1 << 24)
#define	 S2F_NSTATUS_OE			(1 << 16)
#define	 CTRL_00_NCONFIG		(1 << 8)
#define	 CTRL_00_NENABLE_CONDONE	(1 << 2)
#define	 CTRL_00_NENABLE_NSTATUS	(1 << 1)
#define	 CTRL_00_NENABLE_NCONFIG	(1 << 0)
#define	IMGCFG_CTRL_01			0x74
#define	 CTRL_01_S2F_NCE		(1 << 24)
#define	 CTRL_01_S2F_PR_REQUEST		(1 << 16)
#define	 CTRL_01_S2F_NENABLE_CONFIG	(1 << 0)
#define	IMGCFG_CTRL_02			0x78
#define	 CTRL_02_CFGWIDTH_16		(0 << 24)
#define	 CTRL_02_CFGWIDTH_32		(1 << 24)
#define	 CTRL_02_EN_CFG_DATA		(1 << 8)
#define	 CTRL_02_EN_CFG_CTRL		(1 << 0)

/* FPGA Manager Module Registers */
#define	FPGAMGR_STAT		0x0	/* Status Register */
#define	 STAT_MSEL_MASK		0x1f
#define	 STAT_MSEL_SHIFT	3
#define	 STAT_MODE_SHIFT	0
#define	 STAT_MODE_MASK		0x7
#define	FPGAMGR_CTRL		0x4	/* Control Register */
#define	 CTRL_AXICFGEN		(1 << 8)
#define	 CTRL_CDRATIO_MASK	0x3
#define	 CTRL_CDRATIO_SHIFT	6
#define	 CTRL_CFGWDTH_MASK	1
#define	 CTRL_CFGWDTH_SHIFT	9
#define	 CTRL_NCONFIGPULL	(1 << 2)
#define	 CTRL_NCE		(1 << 1)
#define	 CTRL_EN		(1 << 0)
#define	FPGAMGR_DCLKCNT		0x8	/* DCLK Count Register */
#define	FPGAMGR_DCLKSTAT	0xC	/* DCLK Status Register */
#define	FPGAMGR_GPO		0x10	/* General-Purpose Output Register */
#define	FPGAMGR_GPI		0x14	/* General-Purpose Input Register */
#define	FPGAMGR_MISCI		0x18	/* Miscellaneous Input Register */

/* Configuration Monitor (MON) Registers */
#define	GPIO_INTEN		0x830	/* Interrupt Enable Register */
#define	GPIO_INTMASK		0x834	/* Interrupt Mask Register */
#define	GPIO_INTTYPE_LEVEL	0x838	/* Interrupt Level Register */
#define	GPIO_INT_POLARITY	0x83C	/* Interrupt Polarity Register */
#define	GPIO_INTSTATUS		0x840	/* Interrupt Status Register */
#define	GPIO_RAW_INTSTATUS	0x844	/* Raw Interrupt Status Register */
#define	GPIO_PORTA_EOI		0x84C	/* Clear Interrupt Register */
#define	 PORTA_EOI_NS		(1 << 0)
#define	GPIO_EXT_PORTA		0x850	/* External Port A Register */
#define	 EXT_PORTA_CDP		(1 << 10) /* Configuration done */
#define	GPIO_LS_SYNC		0x860	/* Synchronization Level Register */
#define	GPIO_VER_ID_CODE	0x86C	/* GPIO Version Register */
#define	GPIO_CONFIG_REG2	0x870	/* Configuration Register 2 */
#define	GPIO_CONFIG_REG1	0x874	/* Configuration Register 1 */

#define	MSEL_PP16_FAST_NOAES_NODC	0x0
#define	MSEL_PP16_FAST_AES_NODC		0x1
#define	MSEL_PP16_FAST_AESOPT_DC	0x2
#define	MSEL_PP16_SLOW_NOAES_NODC	0x4
#define	MSEL_PP16_SLOW_AES_NODC		0x5
#define	MSEL_PP16_SLOW_AESOPT_DC	0x6
#define	MSEL_PP32_FAST_NOAES_NODC	0x8
#define	MSEL_PP32_FAST_AES_NODC		0x9
#define	MSEL_PP32_FAST_AESOPT_DC	0xa
#define	MSEL_PP32_SLOW_NOAES_NODC	0xc
#define	MSEL_PP32_SLOW_AES_NODC		0xd
#define	MSEL_PP32_SLOW_AESOPT_DC	0xe

#define	CFGWDTH_16	0
#define	CFGWDTH_32	1

#define	CDRATIO_1	0
#define	CDRATIO_2	1
#define	CDRATIO_4	2
#define	CDRATIO_8	3

#define	FPGAMGR_MODE_POWEROFF	0x0
#define	FPGAMGR_MODE_RESET	0x1
#define	FPGAMGR_MODE_CONFIG	0x2
#define	FPGAMGR_MODE_INIT	0x3
#define	FPGAMGR_MODE_USER	0x4

int wcnt = 0;
int nopf = 0;

struct fpgamgr_a10_softc {
	struct resource		*res[2];
	bus_space_tag_t		bst_data;
	bus_space_handle_t	bsh_data;
	struct cdev		*mgr_cdev;
	device_t		dev;
};

static struct resource_spec fpgamgr_a10_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ SYS_RES_MEMORY,	1,	RF_ACTIVE },
	{ -1, 0 }
};

static int fpga_wait_dclk_pulses(struct fpgamgr_a10_softc *sc, int npulses);

static int
fpgamgr_a10_state_get(struct fpgamgr_a10_softc *sc)
{
	int reg;

	reg = READ4(sc, FPGAMGR_STAT);
	reg >>= STAT_MODE_SHIFT;
	reg &= STAT_MODE_MASK;

	return reg;
}

static int
fpgamgr_a10_state_wait(struct fpgamgr_a10_softc *sc, int state)
{
	int tout;

	tout = 1000;
	while (tout > 0) {
		if (fpgamgr_a10_state_get(sc) == state)
			break;
		tout--;
		DELAY(10);
	}
	if (tout == 0) {
		return (1);
	}

	return (0);
}

static int
fpga_open(struct cdev *dev, int flags __unused,
    int fmt __unused, struct thread *td __unused)
{
	struct fpgamgr_a10_softc *sc;
	//struct cfgmgr_mode *mode;
	int msel;
	int reg;

	sc = dev->si_drv1;

	wcnt = 0;
	nopf = 0;

	printf("%s\n", __func__);

/* Step 1 */
	reg = READ4(sc, IMGCFG_STAT);
	if ((reg & F2S_USERMODE) == 0) {
		device_printf(sc->dev, "Invalid mode\n");
		return (ENXIO);
	};

/* Step 2 */
	reg = READ4(sc, IMGCFG_STAT);
	msel = (reg & F2S_MSEL_M) >> F2S_MSEL_S;
	if ((msel != 0) && (msel != 1)) {
		device_printf(sc->dev, "Invalid msel %d\n", msel);
		return (ENXIO);
	};

	reg = READ4(sc, IMGCFG_STAT);
	if ((reg & F2S_NCONFIG_PIN) == 0) {
		device_printf(sc->dev, "nconfig is low\n");
		return (ENXIO);
	}

	if ((reg & F2S_NSTATUS_PIN) == 0) {
		device_printf(sc->dev, "nstatus is low\n");
		return (ENXIO);
	}

/* Step 2 */
	reg = READ4(sc, IMGCFG_CTRL_02);
	reg &= ~CTRL_02_CFGWIDTH_32;
	WRITE4(sc, IMGCFG_CTRL_02, reg);

/* Step 3 */

	reg = READ4(sc, IMGCFG_CTRL_02);
	reg &= ~(0x3 << 16); //cdratio 1
	//reg |= (0x1 << 16); //cdratio 2
	//reg |= (0x2 << 16); //cdratio 4
	//reg |= (0x3 << 16); //cdratio 8
	WRITE4(sc, IMGCFG_CTRL_02, reg);

/* Step 4 */

	reg = READ4(sc, IMGCFG_CTRL_01);
	reg |= CTRL_01_S2F_NENABLE_CONFIG;
	WRITE4(sc, IMGCFG_CTRL_01, reg);

	/* c */
	reg = READ4(sc, IMGCFG_CTRL_02);
	reg |= CTRL_02_EN_CFG_CTRL;
	WRITE4(sc, IMGCFG_CTRL_02, reg);

	/* d */
	reg = READ4(sc, IMGCFG_CTRL_00);
	//reg &= ~S2F_CONDONE_OE;
	//reg &= ~S2F_NSTATUS_OE;
	reg |= CTRL_00_NCONFIG;
	reg |= CTRL_00_NENABLE_NSTATUS;
	reg |= CTRL_00_NENABLE_CONDONE;
	reg |= CTRL_00_NENABLE_NCONFIG;
	WRITE4(sc, IMGCFG_CTRL_00, reg);

/* Step 5 */
	reg = READ4(sc, IMGCFG_CTRL_01);
	reg &= ~CTRL_01_S2F_NENABLE_CONFIG;
	WRITE4(sc, IMGCFG_CTRL_01, reg);

#if 0
	/* a */
	reg = READ4(sc, IMGCFG_CTRL_01);
	reg &= ~CTRL_01_S2F_PR_REQUEST;
	WRITE4(sc, IMGCFG_CTRL_01, reg);

	reg = READ4(sc, IMGCFG_CTRL_00);
	reg |= CTRL_00_NCONFIG;
	WRITE4(sc, IMGCFG_CTRL_00, reg);

	/* b */
	reg = READ4(sc, IMGCFG_CTRL_01);
	reg &= ~CTRL_01_S2F_NCE;
	WRITE4(sc, IMGCFG_CTRL_01, reg);
#endif

	fpga_wait_dclk_pulses(sc, 0x100);


/* Step 7 */
	reg = READ4(sc, IMGCFG_CTRL_01);
	reg |= CTRL_01_S2F_PR_REQUEST;
	WRITE4(sc, IMGCFG_CTRL_01, reg);


/* Step 6 */

	fpga_wait_dclk_pulses(sc, 0x7ff);

	int tout;
	tout = 10;
	while (tout--) {
		reg = READ4(sc, IMGCFG_STAT);
		if (reg & F2S_PR_ERROR) {
			device_printf(sc->dev, "pr error on open\n");
			return (ENXIO);
		}
		if (reg & F2S_PR_READY) {
			break;
		}
	}
	if (tout == 0) {
		device_printf(sc->dev, "tout\n");
		return (ENXIO);
	}

	printf("%s: done, imgcfg stat %x\n", __func__, READ4(sc, IMGCFG_STAT));
	printf("%s: imgctrl00 %x\n", __func__, READ4(sc, IMGCFG_CTRL_00));
	printf("%s: imgctrl01 %x\n", __func__, READ4(sc, IMGCFG_CTRL_01));
	printf("%s: imgctrl02 %x\n", __func__, READ4(sc, IMGCFG_CTRL_02));

#if 0
	/* step 5 */
	reg = READ4(sc, IMGCFG_CTRL_01);
	reg |= CTRL_01_S2F_NCE;
	reg &= ~CTRL_01_S2F_PR_REQUEST;
	WRITE4(sc, IMGCFG_CTRL_01, reg);

	//reg = ~CTRL_01_S2F_NCE;
	//reg |= CTRL_01_S2F_NENABLE_CONFIG;
	//WRITE4(sc, IMGCFG_CTRL_01, reg);

	reg = READ4(sc, IMGCFG_CTRL_02);
	reg &= ~CTRL_02_EN_CFG_DATA;
	reg &= ~CTRL_02_EN_CFG_CTRL;
	WRITE4(sc, IMGCFG_CTRL_02, reg);

	//reg = CTRL_00_NENABLE_NCONFIG | CTRL_00_NENABLE_NSTATUS;
	//reg |= CTRL_00_NENABLE_CONDONE | CTRL_00_NCONFIG;

	reg = READ4(sc, IMGCFG_CTRL_00);
	reg |= CTRL_00_NCONFIG;
	WRITE4(sc, IMGCFG_CTRL_00, reg);

	reg = READ4(sc, IMGCFG_CTRL_00);
	reg &= ~S2F_CONDONE_OE;
	reg &= ~S2F_NSTATUS_OE;
	WRITE4(sc, IMGCFG_CTRL_00, reg);

	/* step 6 */
	reg = READ4(sc, IMGCFG_CTRL_01);
	reg &= ~CTRL_01_S2F_NENABLE_CONFIG;
	WRITE4(sc, IMGCFG_CTRL_01, reg);

	reg = READ4(sc, IMGCFG_CTRL_00);
	reg &= ~CTRL_00_NENABLE_NCONFIG;
	WRITE4(sc, IMGCFG_CTRL_00, reg);

	/* step 7 */
	reg = READ4(sc, IMGCFG_CTRL_00);
	reg |= CTRL_00_NENABLE_NSTATUS;
	reg |= CTRL_00_NENABLE_CONDONE;
	WRITE4(sc, IMGCFG_CTRL_00, reg);

	/* step 8 */
	reg = READ4(sc, IMGCFG_CTRL_01);
	reg &= ~CTRL_01_S2F_NCE;
	WRITE4(sc, IMGCFG_CTRL_01, reg);

	//socfpga_a10_gen_dclks(sc, 256);
	//fpga_wait_dclk_pulses(sc, 256);

	/* step 9 */
	reg = READ4(sc, IMGCFG_STAT);
	if ((reg & F2S_NCONFIG_PIN) == 0) {
		device_printf(sc->dev, "nconfig is low\n");
		return (ENXIO);
	}

	if ((reg & F2S_NSTATUS_PIN) == 0) {
		device_printf(sc->dev, "nstatus is low\n");
		return (ENXIO);
	}

	/* step 10 */
	//fpga_reset(sc);

	//socfpga_a10_gen_dclks(sc, 2047);
	fpga_wait_dclk_pulses(sc, 0x7ff);

	/* step 11 */
	reg = READ4(sc, IMGCFG_CTRL_02);
	reg |= CTRL_02_EN_CFG_DATA;
	reg |= CTRL_02_EN_CFG_CTRL;
	WRITE4(sc, IMGCFG_CTRL_02, reg);

	msel = READ4(sc, FPGAMGR_STAT);
	msel >>= STAT_MSEL_SHIFT;
	msel &= STAT_MSEL_MASK;

	mode = NULL;
	for (i = 0; cfgmgr_modes[i].msel != -1; i++) {
		if (msel == cfgmgr_modes[i].msel) {
			mode = &cfgmgr_modes[i];
			break;
		}
	}
	if (mode == NULL) {
		device_printf(sc->dev, "Can't configure: unknown mode\n");
		return (ENXIO);
	}

	reg = READ4(sc, FPGAMGR_CTRL);
	reg &= ~(CTRL_CDRATIO_MASK << CTRL_CDRATIO_SHIFT);
	reg |= (mode->cdratio << CTRL_CDRATIO_SHIFT);
	reg &= ~(CTRL_CFGWDTH_MASK << CTRL_CFGWDTH_SHIFT);
	reg |= (mode->cfgwdth << CTRL_CFGWDTH_SHIFT);
	reg &= ~(CTRL_NCE);
	WRITE4(sc, FPGAMGR_CTRL, reg);

	/* Enable configuration */
	reg = READ4(sc, FPGAMGR_CTRL);
	reg |= (CTRL_EN);
	WRITE4(sc, FPGAMGR_CTRL, reg);

	/* Reset FPGA */
	reg = READ4(sc, FPGAMGR_CTRL);
	reg |= (CTRL_NCONFIGPULL);
	WRITE4(sc, FPGAMGR_CTRL, reg);

	/* Wait reset state */
	if (fpgamgr_a10_state_wait(sc, FPGAMGR_MODE_RESET)) {
		device_printf(sc->dev, "Can't get RESET state\n");
		return (ENXIO);
	}

	/* Release from reset */
	reg = READ4(sc, FPGAMGR_CTRL);
	reg &= ~(CTRL_NCONFIGPULL);
	WRITE4(sc, FPGAMGR_CTRL, reg);

	if (fpgamgr_a10_state_wait(sc, FPGAMGR_MODE_CONFIG)) {
		device_printf(sc->dev, "Can't get CONFIG state\n");
		return (ENXIO);
	}

	/* Clear nSTATUS edge interrupt */
	WRITE4(sc, GPIO_PORTA_EOI, PORTA_EOI_NS);

	/* Enter configuration state */
	reg = READ4(sc, FPGAMGR_CTRL);
	reg |= (CTRL_AXICFGEN);
	WRITE4(sc, FPGAMGR_CTRL, reg);
#endif

	return (0);
}

static int
fpga_wait_dclk_pulses(struct fpgamgr_a10_softc *sc, int npulses)
{
	int tout;

	/* Clear done bit, if any */
	if (READ4(sc, FPGAMGR_DCLKSTAT) != 0)
		WRITE4(sc, FPGAMGR_DCLKSTAT, 0x1);

	/* Request DCLK pulses */
	WRITE4(sc, FPGAMGR_DCLKCNT, npulses);

	/* Wait finish */
	tout = 1000;
	while (tout > 0) {
		if (READ4(sc, FPGAMGR_DCLKSTAT) == 1) {
			WRITE4(sc, FPGAMGR_DCLKSTAT, 0x1);
			break;
		}
		tout--;
		DELAY(10);
	}
	if (tout == 0) {
		printf("tout on dclkpulses\n");
		return (1);
	}

	printf("no tout on dclkpulses: %d\n", tout);

	return (0);
}

static int
fpga_close(struct cdev *dev, int flags __unused,
    int fmt __unused, struct thread *td __unused)
{
	struct fpgamgr_a10_softc *sc;
	int reg;

	sc = dev->si_drv1;

	printf("%s: imgcfg stat %x\n", __func__, READ4(sc, IMGCFG_STAT));

	int tout;
	tout = 10;
	while (tout--) {
		reg = READ4(sc, IMGCFG_STAT);
		if (reg & F2S_PR_ERROR) {
			device_printf(sc->dev, "pr error on close, tout %d\n", tout);
			//return (ENXIO);
		}
		if (reg & F2S_PR_DONE) {
			break;
		}
	}
	if (tout == 0) {
		device_printf(sc->dev, "tout on close\n");
		//return (ENXIO);
	}

	reg = READ4(sc, IMGCFG_CTRL_01);
	reg &= ~CTRL_01_S2F_PR_REQUEST;
	WRITE4(sc, IMGCFG_CTRL_01, reg);

	fpga_wait_dclk_pulses(sc, 256);

	reg = READ4(sc, IMGCFG_CTRL_02);
	reg &= ~CTRL_02_EN_CFG_CTRL;
	WRITE4(sc, IMGCFG_CTRL_02, reg);

	reg = READ4(sc, IMGCFG_CTRL_01);
	reg |= CTRL_01_S2F_NCE;
	WRITE4(sc, IMGCFG_CTRL_01, reg);

	reg = READ4(sc, IMGCFG_CTRL_01);
	reg |= CTRL_01_S2F_NENABLE_CONFIG;
	WRITE4(sc, IMGCFG_CTRL_01, reg);

	reg = READ4(sc, IMGCFG_STAT);
	if ((reg & F2S_USERMODE) == 0) {
		device_printf(sc->dev, "usermode\n");
		return (ENXIO);
	};

	if ((reg & F2S_CONDONE_PIN) == 0) {
		device_printf(sc->dev, "err 2\n");
		return (ENXIO);
	};

	if ((reg & F2S_NSTATUS_PIN) == 0) {
		device_printf(sc->dev, "err 3\n");
		return (ENXIO);
	};

#if 0
	reg = READ4(sc, GPIO_EXT_PORTA);
	if ((reg & EXT_PORTA_CDP) == 0) {
		device_printf(sc->dev, "Err: configuration failed\n");
		return (ENXIO);
	}

	/* Exit configuration state */
	reg = READ4(sc, FPGAMGR_CTRL);
	reg &= ~(CTRL_AXICFGEN);
	WRITE4(sc, FPGAMGR_CTRL, reg);

	/* Wait dclk pulses */
	if (fpga_wait_dclk_pulses(sc, 4)) {
		device_printf(sc->dev, "Can't proceed 4 dclk pulses\n");
		return (ENXIO);
	}

	if (fpgamgr_a10_state_wait(sc, FPGAMGR_MODE_USER)) {
		device_printf(sc->dev, "Can't get USER mode\n");
		return (ENXIO);
	}

	/* Disable configuration */
	reg = READ4(sc, FPGAMGR_CTRL);
	reg &= ~(CTRL_EN);
	WRITE4(sc, FPGAMGR_CTRL, reg);
#endif

	return (0);
}

static int
fpga_write(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct fpgamgr_a10_softc *sc;
	uint32_t buffer;

	sc = dev->si_drv1;

	/* Device supports 4-byte writes only. */

	if (READ4(sc, IMGCFG_STAT) & F2S_PR_ERROR) {
		if (nopf == 0) {
			printf("%s: err on write, wcnt %d\n", __func__, wcnt);
			nopf = 1;
		}
	}

	while (uio->uio_resid >= 4) {
		uiomove(&buffer, 4, uio);
		bus_space_write_4(sc->bst_data, sc->bsh_data,
		    0x0, buffer);
		wcnt++;
	}

	switch (uio->uio_resid) {
	case 3:
		uiomove(&buffer, 3, uio);
		buffer &= 0xffffff;
		bus_space_write_4(sc->bst_data, sc->bsh_data,
		    0x0, buffer);
		break;
	case 2:
		uiomove(&buffer, 2, uio);
		buffer &= 0xffff;
		bus_space_write_4(sc->bst_data, sc->bsh_data,
		    0x0, buffer);
		break;
	case 1:
		uiomove(&buffer, 1, uio);
		buffer &= 0xff;
		bus_space_write_4(sc->bst_data, sc->bsh_data,
		    0x0, buffer);
		break;
	default:
		break;
	};

	return (0);
}

static int
fpga_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{

	return (0);
}

static struct cdevsw fpga_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	fpga_open,
	.d_close =	fpga_close,
	.d_write =	fpga_write,
	.d_ioctl =	fpga_ioctl,
	.d_name =	"FPGA Manager",
};

static int
fpgamgr_a10_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (!ofw_bus_is_compatible(dev, "altr,socfpga-a10-fpga-mgr"))
		return (ENXIO);

	device_set_desc(dev, "FPGA Manager");
	return (BUS_PROBE_DEFAULT);
}

static int
fpgamgr_a10_attach(device_t dev)
{
	struct fpgamgr_a10_softc *sc;

	sc = device_get_softc(dev);
	sc->dev = dev;

	if (bus_alloc_resources(dev, fpgamgr_a10_spec, sc->res)) {
		device_printf(dev, "could not allocate resources\n");
		return (ENXIO);
	}

	/* Memory interface */
	sc->bst_data = rman_get_bustag(sc->res[1]);
	sc->bsh_data = rman_get_bushandle(sc->res[1]);

	sc->mgr_cdev = make_dev(&fpga_cdevsw, 0, UID_ROOT, GID_WHEEL,
	    0600, "fpga%d", device_get_unit(sc->dev));

	if (sc->mgr_cdev == NULL) {
		device_printf(dev, "Failed to create character device.\n");
		return (ENXIO);
	}

	sc->mgr_cdev->si_drv1 = sc;

	return (0);
}

static device_method_t fpgamgr_a10_methods[] = {
	DEVMETHOD(device_probe,		fpgamgr_a10_probe),
	DEVMETHOD(device_attach,	fpgamgr_a10_attach),
	{ 0, 0 }
};

static driver_t fpgamgr_a10_driver = {
	"fpgamgr_a10",
	fpgamgr_a10_methods,
	sizeof(struct fpgamgr_a10_softc),
};

static devclass_t fpgamgr_a10_devclass;

DRIVER_MODULE(fpgamgr_a10, simplebus, fpgamgr_a10_driver, fpgamgr_a10_devclass, 0, 0);
