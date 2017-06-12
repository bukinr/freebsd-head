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

#ifndef _AMD64_SGX_SGX_H_
#define _AMD64_SGX_SGX_H_

#define	SGX_MAGIC	0xA4
#define	SGX_IOC_ENCLAVE_CREATE \
	_IOR(SGX_MAGIC, 0x00, struct sgx_enclave_create)
#define	SGX_IOC_ENCLAVE_ADD_PAGE \
	_IOR(SGX_MAGIC, 0x01, struct sgx_enclave_add_page)
#define	SGX_IOC_ENCLAVE_INIT \
	_IOR(SGX_MAGIC, 0x02, struct sgx_enclave_init)

#define	SIGSTRUCT_SIZE	1808
#define	EINITTOKEN_SIZE	304

/* Error codes */
#define	SGX_SUCCESS		0
#define	SGX_UNMASKED_EVENT	128

struct sgx_enclave_create {
	uint64_t	src;
} __packed;

struct sgx_enclave_add_page {
	uint64_t	addr;
	uint64_t	src;
	uint64_t	secinfo;
	uint16_t	mrmask;
} __packed;

struct sgx_enclave_init {
	uint64_t	addr;
	uint64_t	sigstruct;
	uint64_t	einittoken;
} __packed;

enum {
	ECREATE	= 0x0,
	EADD	= 0x1,
	EINIT	= 0x2,
	EREMOVE	= 0x3,
	EDGBRD	= 0x4,
	EDGBWR	= 0x5,
	EEXTEND	= 0x6,
	ELDU	= 0x8,
	EBLOCK	= 0x9,
	EPA	= 0xA,
	EWB	= 0xB,
	ETRACK	= 0xC,
};

enum {
	PT_SECS = 0x00,
	PT_TCS  = 0x01,
	PT_REG  = 0x02,
	PT_VA   = 0x03,
	PT_TRIM = 0x04,
};

struct page_info {
	uint64_t linaddr;
	uint64_t srcpge;
	union {
		uint64_t secinfo;
		uint64_t pcmd;
	};
	uint64_t secs;
} __aligned(32);

struct out_regs {
	uint32_t oeax;
	uint64_t orbx;
	uint64_t orcx;
	uint64_t ordx;
};

#define __encls(cmd, tmp, rbx, rcx, rdx)		\
	__asm __volatile(				\
		".byte 0x0f, 0x01, 0xcf"		\
		:"=a"(tmp.oeax),			\
		 "=b"(tmp.orbx),			\
		 "=c"(tmp.orcx),			\
		 "=d"(tmp.ordx)				\
		:"a"((uint32_t)cmd),			\
		 "b"(rbx),				\
		 "c"(rcx),				\
		 "d"(rdx)				\
		:"memory");

static inline u_long
__ecreate(struct page_info *pginfo, void *secs)
{
	struct out_regs tmp;

	__encls(ECREATE, tmp, pginfo, secs, 0);

	return (tmp.oeax);
}

static inline u_long
__eadd(struct page_info *pginfo, void *epc)
{
	struct out_regs tmp;

	__encls(EADD, tmp, pginfo, epc, 0);

	return (tmp.oeax);
}

static inline int
__einit(void *sigstruct, void *secs, void *einittoken)
{
	struct out_regs tmp;

	__encls(EINIT, tmp, sigstruct, secs, einittoken);

	return (tmp.oeax);
}

static inline int
__eextend(void *secs, void *epc)
{
	struct out_regs tmp;

	__encls(EEXTEND, tmp, secs, epc, 0);

	return (tmp.oeax);
}

static inline int
__epa(void *epc)
{
	struct out_regs tmp;
	uint64_t rbx;

	rbx = PT_VA;

	__encls(EPA, tmp, rbx, epc, 0);

	return (tmp.oeax);
}

static inline int
__eldu(uint64_t rbx, uint64_t rcx,
    uint64_t rdx)
{
	struct out_regs tmp;

	__encls(ELDU, tmp, rbx, rcx, rdx);

	return (tmp.oeax);
}

static inline int
__eremove(void *epc)
{
	struct out_regs tmp;

	__encls(EREMOVE, tmp, 0, epc, 0);

	return (tmp.oeax);
}

#define	SECINFO_FLAGS_PT_S	8
#define	SECINFO_FLAGS_PT_M	(0xff << SECINFO_FLAGS_PT_S)

struct secinfo {
	uint64_t flags;
	uint64_t reserved[7];
} __attribute__((aligned(128)));

/*
 * 2.7 SGX ENCLAVE CONTROL STRUCTURE (SECS)
 * The SECS data structure requires 4K-Bytes alignment.
 */

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

#endif /* !_AMD64_SGX_SGX_H_ */
