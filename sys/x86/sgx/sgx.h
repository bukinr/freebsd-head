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

#ifndef _X86_SGX_SGX_H_
#define _X86_SGX_SGX_H_

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

struct secinfo_flags {
	uint8_t r:1;
	uint8_t w:1;
	uint8_t x:1; 
	uint8_t pending:1;
	uint8_t modified:1;
	uint8_t reserved1:3;
	uint8_t page_type;
	uint8_t reserved2[6]; 
};

struct secinfo {
	struct secinfo_flags flags;
	uint8_t reserved[56];
};

struct page_info {
	uint64_t linaddr;
	uint64_t srcpge;
	union {
		uint64_t secinfo;
		uint64_t pcmd;
	};
	uint64_t secs;
} __attribute__((aligned(32)));

struct out_regs {
	uint32_t oeax;
	uint64_t orbx;
	uint64_t orcx;
	uint64_t ordx;
};

#define	SIGSTRUCT_SIZE	1808
#define	EINITTOKEN_SIZE	304

#if 0
#define __encls(rax, rbx, rcx, rdx...)  \
        ({                              \
        int ret;                        \
        __asm __volatile("1: .byte 0x0f, 0x01, 0xcf;\n\t"   \
                     " xor %%eax,%%eax;\n"              \
                     "2: \n"                                    \
                     ".section .fixup,\"ax\"\n"                 \
                     "3: mov $-1,%%eax\n"                       \
                     "   jmp 2b\n"                              \
                     ".previous\n"                              \
                     : "=a"(ret), "=b"(rbx), "=c"(rcx)          \
                     : "a"(rax), "b"(rbx), "c"(rcx), rdx        \
                     : "memory");                               \
        ret;    \
        })

static inline u_long
__ecreate(struct page_info *pginfo, void *secs)
{

	__encls(ECREATE, pginfo, secs, "d"(0));

	return (0);
}

#else
#define __encls(cmd, tmp, rbx, rcx, rdx)		\
	__asm __volatile(				\
		".byte 0x0f, 0x01, 0xcf\n\t"		\
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

	printf("%s: %x %lx %lx %lx\n",
	    __func__, tmp.oeax, tmp.orbx, tmp.orcx, tmp.ordx);

	return (tmp.oeax);
}

static inline u_long
__eadd(struct page_info *pginfo, void *epc)
{

	struct out_regs tmp;

	__encls(EADD, tmp, pginfo, epc, 0);

	printf("%s: %x %lx %lx %lx\n",
	    __func__, tmp.oeax, tmp.orbx, tmp.orcx, tmp.ordx);

	return (tmp.oeax);
}
#endif

#endif /* !_X86_SGX_SGX_H_ */
