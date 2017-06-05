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

#if 0
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

struct sgx_einittoken {
	uint32_t	valid;
	uint8_t		reserved1[206];
	uint16_t	isvsvnle;
	uint8_t		reserved2[92];
} __attribute__((aligned(512)));
#endif

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

typedef struct _attributes_t
{
    uint64_t      flags;
    uint64_t      xfrm;
} sgx_attributes_t;

#define SGX_HASH_SIZE        32              /* SHA256 */
#define SGX_MAC_SIZE         16              /* Message Authentication Code - 16 bytes */

#define SGX_REPORT_DATA_SIZE    64

typedef struct _sgx_measurement_t
{
    uint8_t                 m[SGX_HASH_SIZE];
} sgx_measurement_t;

#define SGX_KEYID_SIZE    32
#define SGX_CPUSVN_SIZE   16

typedef struct _sgx_cpu_svn_t
{
    uint8_t                        svn[SGX_CPUSVN_SIZE];
} sgx_cpu_svn_t;

typedef struct _sgx_key_id_t
{
    uint8_t                        id[SGX_KEYID_SIZE];
} sgx_key_id_t;

typedef uint32_t    sgx_misc_select_t;
typedef uint8_t             sgx_mac_t[SGX_MAC_SIZE];
typedef uint16_t            sgx_prod_id_t;
typedef uint16_t                   sgx_isv_svn_t;

typedef struct _launch_body_t
{
   uint32_t              valid;            /* (  0) 0 = Invalid, 1 = Valid */
   uint32_t              reserved1[11];    /* (  4) must be zero */
   sgx_attributes_t      attributes;       /* ( 48) ATTRIBUTES of Enclave */
   sgx_measurement_t     mr_enclave;       /* ( 64) MRENCLAVE of Enclave */
   uint8_t               reserved2[32];    /* ( 96) */
   sgx_measurement_t     mr_signer;        /* (128) MRSIGNER of Enclave */
   uint8_t               reserved3[32];    /* (160) */
} launch_body_t;

typedef struct _launch_t {
  launch_body_t          body;
  sgx_cpu_svn_t          cpu_svn_le;       /* (192) Launch Enclave's CPUSVN */
  uint16_t               isv_prod_id_le;   /* (208) Launch Enclave's ISVPRODID */
  uint16_t               isv_svn_le;       /* (210) Launch Enclave's ISVSVN */
  uint8_t                reserved2[24];    /* (212) Must be 0 */
  sgx_misc_select_t      masked_misc_select_le; /* (236) */
  sgx_attributes_t       attributes_le;    /* (240) ATTRIBUTES of Launch Enclave */
  sgx_key_id_t           key_id;           /* (256) Value for key wear-out protection */
  sgx_mac_t              mac;              /* (288) CMAC using Launch Token Key */
} einittoken_t;

/*SECS data structure*/
typedef struct _secs_t
{
    uint64_t                    size;           /* (  0) Size of the enclave in bytes */
    void			*base;	// 64 bit only, 32 requires padding
    uint32_t                    ssa_frame_size; /* ( 16) size of 1 SSA frame in pages */
    sgx_misc_select_t           misc_select;    /* ( 20) Which fields defined in SSA.MISC */
#define SECS_RESERVED1_LENGTH 24
    uint8_t                     reserved1[SECS_RESERVED1_LENGTH];  /* ( 24) reserved */
    sgx_attributes_t            attributes;     /* ( 48) ATTRIBUTES Flags Field */
    sgx_measurement_t           mr_enclave;     /* ( 64) Integrity Reg 0 - Enclave measurement */
#define SECS_RESERVED2_LENGTH 32
    uint8_t                     reserved2[SECS_RESERVED2_LENGTH];  /* ( 96) reserved */
    sgx_measurement_t           mr_signer;      /* (128) Integrity Reg 1 - Enclave signing key */
#define SECS_RESERVED3_LENGTH 96
    uint8_t                     reserved3[SECS_RESERVED3_LENGTH];  /* (160) reserved */
    sgx_prod_id_t               isv_prod_id;    /* (256) product ID of enclave */
    sgx_isv_svn_t               isv_svn;        /* (258) Security Version of the Enclave */
#define SECS_RESERVED4_LENGTH 3836
    uint8_t                     reserved4[SECS_RESERVED4_LENGTH];/* (260) reserved */
} secs_t;

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

	//printf("%s: %x %lx %lx %lx\n",
	//    __func__, tmp.oeax, tmp.orbx, tmp.orcx, tmp.ordx);

	return (tmp.oeax);
}

static inline u_long
__eadd(struct page_info *pginfo, void *epc)
{

	struct out_regs tmp;

	__encls(EADD, tmp, pginfo, epc, 0);

	//printf("%s: %x %lx %lx %lx\n",
	//    __func__, tmp.oeax, tmp.orbx, tmp.orcx, tmp.ordx);

	return (tmp.oeax);
}

static inline int
__einit(void *sigstruct, void *secs, einittoken_t *einittoken)
{
	struct out_regs tmp;

	__encls(EINIT, tmp, sigstruct, secs, einittoken);

	//printf("%s: %x %lx %lx %lx\n",
	//    __func__, tmp.oeax, tmp.orbx, tmp.orcx, tmp.ordx);

	return (tmp.oeax);
}

static inline int
__eextend(void *secs, void *epc)
{
	struct out_regs tmp;

	__encls(EEXTEND, tmp, secs, epc, 0);

	//printf("%s: %x %lx %lx %lx\n",
	//    __func__, tmp.oeax, tmp.orbx, tmp.orcx, tmp.ordx);

	return (tmp.oeax);
}

static inline int
__epa(void *epc)
{
	struct out_regs tmp;
	unsigned long rbx;

	rbx = PT_VA;

	__encls(EPA, tmp, rbx, epc, 0);

	return (tmp.oeax);
}

static inline int
__eldu(unsigned long rbx, unsigned long rcx,
    unsigned long rdx)
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

#endif /* !_X86_SGX_SGX_H_ */
