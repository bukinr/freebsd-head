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

#ifndef _MACHINE_SGX_H_
#define _MACHINE_SGX_H_

#define	SIGSTRUCT_SIZE	1808
#define	EINITTOKEN_SIZE	304

struct secinfo {
	uint64_t flags;
#define	SECINFO_FLAGS_PT_S	8	/* Page type shift */
#define	SECINFO_FLAGS_PT_M	(0xff << SECINFO_FLAGS_PT_S)
	uint64_t reserved[7];
} __aligned(128);

struct page_info {
	uint64_t linaddr;
	uint64_t srcpge;
	union {
		uint64_t secinfo;
		uint64_t pcmd;
	};
	uint64_t secs;
} __aligned(32);

struct secs_attr {
	uint8_t		reserved1: 1;
	uint8_t		debug: 1;
	uint8_t		mode64bit: 1;
	uint8_t		reserved2: 1;
	uint8_t		provisionkey: 1;
	uint8_t		einittokenkey: 1;
	uint8_t		reserved3: 2;
	uint8_t		reserved4[7];
	uint64_t	xfrm;			/* X-Feature Request Mask */
};

/*
 * 2.7 SGX Enclave Control Structure (SECS)
 * The SECS data structure requires 4K-Bytes alignment.
 */
struct secs {
	uint64_t	size;
	uint64_t	base;
	uint32_t	ssa_frame_size;
	uint32_t	misc_select;
	uint8_t		reserved1[24];
	struct secs_attr attributes;
	uint8_t		mr_enclave[32];
	uint8_t		reserved2[32];
	uint8_t		mr_signer[32];
	uint8_t		reserved3[96];
	uint16_t	isv_prod_id;
	uint16_t	isv_svn;
	uint8_t		reserved4[3836];
};

/*
 * 2.8 Thread Control Structure (TCS)
 * Each executing thread in the enclave is associated with a
 * Thread Control Structure. It requires 4K-Bytes alignment.
 */
struct tcs {
	uint64_t	state;
	uint64_t	flags;
	uint64_t	ossa;
	uint32_t	cssa;
	uint32_t	nssa;
	uint64_t	oentry;
	uint64_t	aep;
	uint64_t	ofsbasgx;
	uint64_t	ogsbasgx;
	uint32_t	fslimit;
	uint32_t	gslimit;
	uint64_t	reserved[503];
};

#endif /* !_MACHINE_SGX_H_ */
