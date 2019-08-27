/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018 Andrew Turner
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

#ifndef	_MACHINE_SMCCC_H_
#define	_MACHINE_SMCCC_H_

struct arm_smccc_res {
	uint64_t a0;
	uint64_t a1;
	uint64_t a2;
	uint64_t a3;
};

#define	SMCCC_VERSION_MAJOR(ver)	(((ver) >> 16) & 0x7fff)
#define	SMCCC_VERSION_MINOR(ver)	((ver) & 0xffff)

#define	SMCCC_FUNC_ID(type, call_conv, range, func)	\
	(((type) << 31) |				\
	 ((call_conv) << 30) |				\
	 (((range) & 0x3f) << 24) |				\
	 ((func) & 0xffff))

#define	SMCCC_YIELDING_CALL	0
#define	SMCCC_FAST_CALL		1

#define	SMCCC_32BIT_CALL	0
#define	SMCCC_64BIT_CALL	1

#define	SMCCC_ARM_ARCH_CALLS		0
#define	SMCCC_CPU_SERVICE_CALLS		1
#define	SMCCC_SIP_SERVICE_CALLS		2
#define	SMCCC_OEM_SERVICE_CALLS		3
#define	SMCCC_STD_SECURE_SERVICE_CALLS	4
#define	SMCCC_STD_HYP_SERVICE_CALLS	5
#define	SMCCC_VENDOR_HYP_SERVICE_CALLS	6

uint64_t arm_smccc_smc(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t, struct arm_smccc_res *res);
uint64_t arm_smccc_hvc(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t, struct arm_smccc_res *res);

#endif /* !_MACHINE_SMCCC_H_ */
