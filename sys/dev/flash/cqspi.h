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
 *
 * $FreeBSD$
 */

#ifndef _CQSPI_H_
#define _CQSPI_H_

#define	CQSPI_CFG		0x00	/* QSPI Configuration */
#define	 CFG_ENDMA		(1 << 15)
#define	 CFG_IDLE		(1 << 31)
#define	 CFG_BAUD_S		19
#define	 CFG_BAUD_M		(0xf << CFG_BAUD_S)
#define	 CFG_BAUD2		(0 << CFG_BAUD_S)
#define	 CFG_BAUD4		(1 << CFG_BAUD_S)
#define	 CFG_BAUD6		(2 << CFG_BAUD_S)
#define	 CFG_BAUD8		(3 << CFG_BAUD_S)
#define	 CFG_BAUD10		(4 << CFG_BAUD_S)
#define	 CFG_BAUD12		(5 << CFG_BAUD_S)
#define	 CFG_BAUD14		(6 << CFG_BAUD_S)
#define	 CFG_BAUD16		(7 << CFG_BAUD_S)
#define	 CFG_BAUD18		(8 << CFG_BAUD_S)
#define	 CFG_BAUD20		(9 << CFG_BAUD_S)
#define	 CFG_BAUD22		(10 << CFG_BAUD_S)
#define	 CFG_BAUD24		(11 << CFG_BAUD_S)
#define	 CFG_BAUD26		(12 << CFG_BAUD_S)
#define	 CFG_BAUD28		(13 << CFG_BAUD_S)
#define	 CFG_BAUD30		(14 << CFG_BAUD_S)
#define	 CFG_BAUD32		(0xf << CFG_BAUD_S)
#define	 CFG_EN			(1 << 0)
#define	CQSPI_DEVRD		0x04	/* Device Read Instruction Configuration */
#define	 DEVRD_DUMMYRDCLKS_S	24
#define	 DEVRD_RDOPCODE_S	0
#define	CQSPI_DEVWR		0x08	/* Device Write Instruction Configuration */
#define	CQSPI_DELAY		0x0C	/* QSPI Device Delay Register */
#define	 DELAY_NSS_S		24
#define	 DELAY_BTWN_S		16
#define	 DELAY_AFTER_S		8
#define	 DELAY_INIT_S		0
#define	CQSPI_RDDATACAP		0x10	/* Read Data Capture Register */
#define	 RDDATACAP_DELAY_S	1
#define	 RDDATACAP_DELAY_M	(0xf << RDDATACAP_DELAY_S)
#define	CQSPI_DEVSZ		0x14	/* Device Size Configuration Register */
#define	 DEVSZ_NUMADDRBYTES_S	0
#define	 DEVSZ_NUMADDRBYTES_M	(0xf << DEVSZ_NUMADDRBYTES_S)
#define	CQSPI_SRAMPART		0x18	/* SRAM Partition Configuration Register */
#define	CQSPI_INDADDRTRIG	0x1C	/* Indirect AHB Address Trigger Register */
#define	CQSPI_DMAPER		0x20	/* DMA Peripheral Configuration Register */
#define	CQSPI_REMAPADDR		0x24	/* Remap Address Register */
#define	CQSPI_MODEBIT		0x28	/* Mode Bit Configuration */
#define	CQSPI_SRAMFILL		0x2C	/* SRAM Fill Register */
#define	CQSPI_TXTHRESH		0x30	/* TX Threshold Register */
#define	CQSPI_RXTHRESH		0x34	/* RX Threshold Register */
#define	CQSPI_IRQSTAT		0x40	/* Interrupt Status Register */
#define	CQSPI_IRQMASK		0x44	/* Interrupt Mask */
#define	 IRQMASK_INDSRAMFULL	(1 << 12)
#define	 IRQMASK_INDXFRLVL	(1 << 6)
#define	 IRQMASK_INDOPDONE	(1 << 2)
#define	CQSPI_LOWWRPROT		0x50	/* Lower Write Protection */
#define	CQSPI_UPPWRPROT		0x54	/* Upper Write Protection */
#define	CQSPI_WRPROT		0x58	/* Write Protection Control Register */
#define	CQSPI_INDRD		0x60	/* Indirect Read Transfer Control Register */
#define	 INDRD_IND_OPS_DONE_STATUS	(1 << 5)
#define	 INDRD_START		(1 << 0)
#define	CQSPI_INDRDWATER	0x64	/* Indirect Read Transfer Watermark Register */
#define	CQSPI_INDRDSTADDR	0x68	/* Indirect Read Transfer Start Address Register */
#define	CQSPI_INDRDCNT		0x6C	/* Indirect Read Transfer Number Bytes Register */
#define	CQSPI_INDWR		0x70	/* Indirect Write Transfer Control Register */
#define	CQSPI_INDWRWATER	0x74	/* Indirect Write Transfer Watermark Register */
#define	CQSPI_INDWRSTADDR	0x78	/* Indirect Write Transfer Start Address Register */
#define	CQSPI_INDWRCNT		0x7C	/* Indirect Write Transfer Number Bytes Register */
#define	CQSPI_FLASHCMD		0x90	/* Flash Command Control Register */
#define	 FLASHCMD_NUMADDRBYTES_S	16
#define	 FLASHCMD_NUMRDDATABYTES_S	20
#define	 FLASHCMD_NUMRDDATABYTES_M	(0x7 << FLASHCMD_NUMRDDATABYTES_S)
#define	 FLASHCMD_ENCMDADDR	(1 << 19)
#define	 FLASHCMD_ENRDDATA	(1 << 23)
#define	 FLASHCMD_CMDOPCODE_S	24
#define	 FLASHCMD_CMDOPCODE_M	(0xff << FLASHCMD_CMDOPCODE_S)
#define	 FLASHCMD_CMDEXECSTAT	(1 << 1) /* Command execution in progress. */
#define	 FLASHCMD_EXECCMD	(1 << 0) /* Execute the command. */
#define	CQSPI_FLASHCMDADDR	0x94	/* Flash Command Address Registers */
#define	CQSPI_FLASHCMDRDDATALO	0xA0	/* Flash Command Read Data Register (Lower) */
#define	CQSPI_FLASHCMDRDDATAUP	0xA4	/* Flash Command Read Data Register (Upper) */
#define	CQSPI_FLASHCMDWRDATALO	0xA8	/* Flash Command Write Data Register (Lower) */
#define	CQSPI_FLASHCMDWRDATAUP	0xAC	/* Flash Command Write Data Register (Upper) */
#define	CQSPI_MODULEID		0xFC	/* Module ID Register */

#define	CMD_READ_4B_QUAD_OUTPUT	0x6C

//remove below
/*
 * Commands 
 */
#define CMD_WRITE_ENABLE	0x06
#define CMD_WRITE_DISABLE	0x04
#define CMD_READ_IDENT		0x9F
#define CMD_READ_STATUS		0x05
#define CMD_WRITE_STATUS	0x01
#define CMD_READ		0x03
#define CMD_FAST_READ		0x0B
#define CMD_PAGE_PROGRAM	0x02
#define CMD_SECTOR_ERASE	0xD8
#define CMD_BULK_ERASE		0xC7
#define	CMD_BLOCK_4K_ERASE	0x20
#define	CMD_BLOCK_32K_ERASE	0x52
#define	CMD_ENTER_4B_MODE	0xB7
#define	CMD_EXIT_4B_MODE	0xE9

#define	CMD_READ_NVCONF_REG	0xB5
#define	CMD_READ_CONF_REG	0x85
#define	CMD_READ_FSR		0x70

/*
 * Status register flags
 */
#define	STATUS_SRWD	(1 << 7)
#define	STATUS_BP2	(1 << 4)
#define	STATUS_BP1	(1 << 3)
#define	STATUS_BP0	(1 << 2)
#define	STATUS_WEL	(1 << 1)
#define	STATUS_WIP	(1 << 0)

#define	FLASH_PAGE_SIZE	256

#endif /* !_CQSPI_H_ */
