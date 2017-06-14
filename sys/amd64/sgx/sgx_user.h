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

#ifndef _AMD64_SGX_SGX_USER_H_
#define _AMD64_SGX_SGX_USER_H_

#define	SGX_MAGIC	0xA4
#define	SGX_IOC_ENCLAVE_CREATE \
	_IOR(SGX_MAGIC, 0x00, struct sgx_enclave_create)
#define	SGX_IOC_ENCLAVE_ADD_PAGE \
	_IOR(SGX_MAGIC, 0x01, struct sgx_enclave_add_page)
#define	SGX_IOC_ENCLAVE_INIT \
	_IOR(SGX_MAGIC, 0x02, struct sgx_enclave_init)

/* Error codes. */
#define	SGX_SUCCESS			0
#define	SGX_INVALID_SIG_STRUCT		1	/* EINIT */
#define	SGX_INVALID_ATTRIBUTE		2	/* EINIT, EGETKEY */
#define	SGX_BLSTATE			3	/* EBLOCK */
#define	SGX_INVALID_MEASUREMENT		4	/* EINIT */
#define	SGX_NOTBLOCKABLE		5	/* EBLOCK */
#define	SGX_PG_INVLD			6	/* EBLOCK */
#define	SGX_LOCKFAIL			7	/* EBLOCK, EMODPR, EMODT */
#define	SGX_INVALID_SIGNATURE		8	/* EINIT */
#define	SGX_MAC_COMPARE_FAIL		9	/* ELDB, ELDU */
#define	SGX_PAGE_NOT_BLOCKED		10	/* EWB */
#define	SGX_NOT_TRACKED			11	/* EWB, EACCEPT */
#define	SGX_VA_SLOT_OCCUPIED		12	/* EWB */
#define	SGX_CHILD_PRESENT		13	/* EWB, EREMOVE */
#define	SGX_ENCLAVE_ACT			14	/* EREMOVE */
#define	SGX_ENTRYEPOCH_LOCKED		15	/* EBLOCK */
#define	SGX_INVALID_EINIT_TOKEN		16	/* EINIT */
#define	SGX_PREV_TRK_INCMPL		17	/* ETRACK */
#define	SGX_PG_IS_SECS			18	/* EBLOCK */
#define	SGX_PAGE_ATTRIBUTES_MISMATCH	19	/* EACCEPT, EACCEPTCOPY */
#define	SGX_PAGE_NOT_MODIFIABLE		20	/* EMODPR, EMODT */
#define	SGX_INVALID_CPUSVN		32	/* EINIT, EGETKEY */
#define	SGX_INVALID_ISVSVN		64	/* EGETKEY */
#define	SGX_UNMASKED_EVENT		128	/* EINIT */
#define	SGX_INVALID_KEYNAME		256	/* EGETKEY */

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

#endif /* !_AMD64_SGX_SGX_USER_H_ */
