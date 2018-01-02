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
 *
 * $FreeBSD$
 */

#define	TRCPRGCTLR	0x004 /* Trace Programming Control Register */
#define	TRCPROCSELR	0x008 /* Trace PE Select Control Register */
#define	TRCSTATR	0x00C /* Trace Trace Status Register */
#define	TRCCONFIGR	0x010 /* Trace Trace Configuration Register */
#define	TRCAUXCTLR	0x018 /* Trace Auxiliary Control Register */
#define	TRCEVENTCTL0R	0x020 /* Trace Event Control 0 Register */
#define	TRCEVENTCTL1R	0x024 /* Trace Event Control 1 Register */
#define	TRCSTALLCTLR	0x02C /* Trace Stall Control Register */
#define	TRCTSCTLR	0x030 /* Trace Global Timestamp Control Register */
#define	TRCSYNCPR	0x034 /* Trace Synchronization Period Register */
#define	TRCCCCTLR	0x038 /* Trace Cycle Count Control Register */
#define	TRCBBCTLR	0x03C /* Trace Branch Broadcast Control Register */
#define	TRCTRACEIDR	0x040 /* Trace Trace ID Register */
#define	TRCQCTLR	0x044 /* Trace Q Element Control Register */
#define	TRCVICTLR	0x080 /* Trace ViewInst Main Control Register */
#define	TRCVIIECTLR	0x084 /* Trace ViewInst Include/Exclude Control Register */
#define	TRCVISSCTLR	0x088 /* Trace ViewInst Start/Stop Control Register */
#define	TRCVIPCSSCTLR	0x08C /* Trace ViewInst Start/Stop PE Comparator Control Register */
#define	TRCVDCTLR	0x0A0 /* Trace ViewData Main Control Register */
#define	TRCVDSACCTLR	0x0A4 /* Trace ViewData Include/Exclude Single Address Comparator Control Register */
#define	TRCVDARCCTLR	0x0A8 /* Trace ViewData Include/Exclude Address Range Comparator Control Register */
#define	TRCSEQEVR(n)	(0x100 + (n) * 0x4)	/* Trace Sequencer State Transition Control Register [n=0-2] */
#define	TRCSEQRSTEVR	0x118 /* Trace Sequencer Reset Control Register */
#define	TRCSEQSTR	0x11C /* Trace Sequencer State Register */
#define	TRCEXTINSELR	0x120 /* Trace External Input Select Register */
#define	TRCCNTRLDVR(n)	(0x140 + (n) * 0x4) /* 32 Trace Counter Reload Value Register [n=0-3] */
#define	TRCCNTCTLR(n)	(0x150 + (n) * 0x4) /* 32 Trace Counter Control Register [n=0-3] */
#define	TRCCNTVR(n)	(0x160 + (n) * 0x4) /* 32 Trace Counter Value Register [n=0-3] */
#define	TRCIDR8		0x180 /* Trace ID Register 8 */
#define	TRCIDR9s	0x184 /* Trace ID Register 9 */
#define	TRCIDR10	0x188 /* Trace ID Register 10 */
#define	TRCIDR11	0x18C /* Trace ID Register 11 */
#define	TRCIDR12	0x190 /* Trace ID Register 12 */
#define	TRCIDR13	0x194 /* Trace ID Register 13 */
#define	TRCIMSPEC(n)	(0x1C0 + (n) * 0x4)	/* Trace IMPLEMENTATION DEFINED register [n=0-7] */
#define	TRCIDR0		0x1E0 /* Trace ID Register 0 */
#define	TRCIDR1		0x1E4 /* Trace ID Register 1 */
#define	TRCIDR2		0x1E8 /* Trace ID Register 2 */
#define	TRCIDR3		0x1EC /* Trace ID Register 3 */
#define	TRCIDR4		0x1F0 /* Trace ID Register 4 */
#define	TRCIDR5		0x1F4 /* Trace ID Register 5 */
#define	TRCIDR6		0x1F8 /* Trace ID Register 6 */
#define	TRCIDR7		0x1FC /* Trace ID Register 7 */
#define	TRCRSCTLR(n)	(0x200 + (n) * 0x4) /* Trace Resource Selection Control Register [n=2-31] */
#define	TRCSSCCR(n)	(0x280 + (n) * 0x4) /* Trace Single-shot Comparator Control Register [n=0-7] */
#define	TRCSSCSR(n)	(0x2A0 + (n) * 0x4) /* Trace Single-shot Comparator Status Register [n=0-7] */
#define	TRCSSPCICR(n)	(0x2C0 + (n) * 0x4) /* Trace Single-shot PE Comparator Input Control Register [n=0-7] */
#define	TRCOSLAR	0x300 /* Management OS Lock Access Register */
#define	TRCOSLSR	0x304 /* Management OS Lock Status Register */
#define	TRCPDCR		0x310 /* Management PowerDown Control Register */
#define	TRCPDSR		0x314 /* Management PowerDown Status Register */
#define	TRCACVR(n)	(0x400 + (n) * 0x8) /* Trace Address Comparator Value Register [n=0-15] */
#define	TRCACATR(n)	(0x480 + (n) * 0x8) /* Trace Address Comparator Access Type Register [n=0-15] */
#define	TRCDVCVR(n)	(0x500 + (n) * 0x8) /* Trace Data Value Comparator Value Register [n=0-7] */
#define	TRCDVCMR(n)	(0x580 + (n) * 0x8) /* Trace Data Value Comparator Mask Register [n=0-7] */
#define	TRCCIDCVR(n)	(0x600 + (n) * 0x8) /* Trace Context ID Comparator Value Register [n=0-7] */
#define	TRCVMIDCVR(n)	(0x640 + (n) * 0x8) /* Trace Virtual context identifier Comparator Value Register [n=0-7] */
#define	TRCCIDCCTLR0	0x680 /* Trace Context ID Comparator Control Register 0 */
#define	TRCCIDCCTLR1	0x684 /* Trace Context ID Comparator Control Register 1 */
#define	TRCVMIDCCTLR0	0x688 /* Trace Virtual context identifier Comparator Control Register 0 */
#define	TRCVMIDCCTLR1	0x68C /* Trace Virtual context identifier Comparator Control Register 1 */
#define	TRCITCTRL	0xF00 /* Management Integration Mode Control register */
#define	TRCCLAIMSET	0xFA0 /* Trace Claim Tag Set register */
#define	TRCCLAIMCLR	0xFA4 /* Trace Claim Tag Clear register */
#define	TRCDEVAFF0	0xFA8 /* Management Device Affinity register 0 */
#define	TRCDEVAFF1	0xFAC /* Management Device Affinity register 1 */
#define	TRCLAR		0xFB0 /* Management Software Lock Access Register */
#define	TRCLSR		0xFB4 /* Management Software Lock Status Register */
#define	TRCAUTHSTATUS	0xFB8 /* Management Authentication Status register */
#define	TRCDEVARCH	0xFBC /* Management Device Architecture register */
#define	TRCDEVID	0xFC8 /* Management Device ID register */
#define	TRCDEVTYPE	0xFCC /* Management Device Type register */
#define	TRCPIDR4	0xFD0 /* Management Peripheral ID4 Register */
#define	TRCPIDR(n)	(0xFE0 + (n) * 0x4)	/* Management Peripheral IDn Register [n=0-3] */
#define	TRCPIDR567(n)	(0xFD4 + ((n) - 5) * 0x4) /*  Management Peripheral ID5 to Peripheral ID7 Registers */
#define	TRCCIDR(n)	(0xFF0 + (n) * 0x4)	/* Management Component IDn Register [n=0-4] */
