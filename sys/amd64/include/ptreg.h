/*-
 * Copyright (c) 2017 Ruslan Bukin <br@bsdpad.com>
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

/* Machine-defined variables. */

#ifndef _MACHINE_PTREG_H_
#define _MACHINE_PTREG_H_

#define	S0_EAX_SUBLEAF_MAX_S	0
#define	S0_EAX_SUBLEAF_MAX_M	(0xffffffff << S0_EAX_SUBLEAF_MAX_S)
#define	S0_EBX_CR3		(1 << 0)	/* CR3 Filtering Support */
#define	S0_EBX_PSB		(1 << 1)	/* Configurable PSB and Cycle-Accurate Mode Supported */
#define	S0_EBX_IPF		(1 << 2)	/* IP Filtering and TraceStop supported */
#define	S0_EBX_MTC		(1 << 3)	/* MTC Supported */
#define	S0_EBX_PRW		(1 << 4)	/* PTWRITE Supported */
#define	S0_EBX_PWR		(1 << 5)	/* Power Event Trace Supported */
#define	S0_ECX_TOPA		(1 << 0)	/* ToPA Output Supported */
#define	S0_ECX_TOPA_MULTI	(1 << 1)	/* ToPA Tables Allow Multiple Output Entries */
#define	S0_ECX_SINGLE		(1 << 2)	/* Single-Range Output Supported */
#define	S0_ECX_TT_OUT		(1 << 3)	/* Output to Trace Transport Subsystem Supported */
#define	S0_ECX_LIP		(1 << 31)	/* 31 IP Payloads are LIP */
#define	S1_EAX_NADDR_S		0	/* Number of Address Ranges */
#define	S1_EAX_NADDR_M		(0x7 << S1_EAX_NADDR_S)
#define	S1_EAX_MTC_BITMAP_S	16	/* 31:16  Bitmap of supported MTC Period Encodings */
#define	S1_EAX_MTC_BITMAP_M	(0xffff << S1_EAX_MTC_BITMAP_S)
#define	S1_EBX_CT_BITMAP_S	0	/* Bitmap of supported Cycle Threshold values */
#define	S1_EBX_CT_BITMAP_M	(0xffff << S1_EBX_CT_BITMAP_S)
#define	S1_EBX_PFE_BITMAP_S	16	/* Bitmap of supported Configurable PSB Frequency encoding */
#define	S1_EBX_PFE_BITMAP_M	(0xffff << S1_EBX_PFE_BITMAP_S)

#define	TOPA_SIZE_S	6
#define	TOPA_SIZE_M	(0xf << TOPA_SIZE_S)
#define	TOPA_SIZE_4K	(0 << TOPA_SIZE_S)
#define	TOPA_SIZE_8K	(1 << TOPA_SIZE_S)
#define	TOPA_SIZE_16K	(2 << TOPA_SIZE_S)
#define	TOPA_SIZE_32K	(3 << TOPA_SIZE_S)
#define	TOPA_SIZE_64K	(4 << TOPA_SIZE_S)
#define	TOPA_SIZE_128K	(5 << TOPA_SIZE_S)
#define	TOPA_SIZE_256K	(6 << TOPA_SIZE_S)
#define	TOPA_SIZE_512K	(7 << TOPA_SIZE_S)
#define	TOPA_SIZE_1M	(8 << TOPA_SIZE_S)
#define	TOPA_SIZE_2M	(9 << TOPA_SIZE_S)
#define	TOPA_SIZE_4M	(10 << TOPA_SIZE_S)
#define	TOPA_SIZE_8M	(11 << TOPA_SIZE_S)
#define	TOPA_SIZE_16M	(12 << TOPA_SIZE_S)
#define	TOPA_SIZE_32M	(13 << TOPA_SIZE_S)
#define	TOPA_SIZE_64M	(14 << TOPA_SIZE_S)
#define	TOPA_SIZE_128M	(15 << TOPA_SIZE_S)
#define	TOPA_STOP	(1 << 4)
#define	TOPA_INT	(1 << 2)
#define	TOPA_END	(1 << 0)

#endif /* !_MACHINE_PTREG_H_ */
