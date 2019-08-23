/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Ruslan Bukin <br@bsdpad.com>
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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

#ifndef	_ARM64_INTEL_INTEL_SMC_H_
#define	_ARM64_INTEL_INTEL_SMC_H_

#include <dev/psci/smccc.h>

/*
 * Intel SiP return values.
 */
#define	INTEL_SIP_SMC_STATUS_OK				0
#define	INTEL_SIP_SMC_FPGA_CONFIG_STATUS_BUSY		1
#define	INTEL_SIP_SMC_FPGA_CONFIG_STATUS_REJECTED	2
#define	INTEL_SIP_SMC_FPGA_CONFIG_STATUS_ERROR		4
#define	INTEL_SIP_SMC_REG_ERROR				5
#define	INTEL_SIP_SMC_RSU_ERROR				7

/*
 * Intel SiP calls.
 */
#define	INTEL_SIP_SMC_STD_CALL(func)				\
    SMCCC_FUNC_ID(SMCCC_YIELDING_CALL, SMCCC_64BIT_CALL,	\
	SMCCC_SIP_SERVICE_CALLS, (func))
#define	INTEL_SIP_SMC_FAST_CALL(func)				\
    SMCCC_FUNC_ID(SMCCC_FAST_CALL, SMCCC_64BIT_CALL,		\
	SMCCC_SIP_SERVICE_CALLS, (func))

#define	INTEL_SIP_SMC_FUNCID_FPGA_CONFIG_START			1
#define	INTEL_SIP_SMC_FUNCID_FPGA_CONFIG_WRITE			2
#define	INTEL_SIP_SMC_FUNCID_FPGA_CONFIG_COMPLETED_WRITE	3
#define	INTEL_SIP_SMC_FUNCID_FPGA_CONFIG_ISDONE			4
#define	INTEL_SIP_SMC_FUNCID_FPGA_CONFIG_GET_MEM		5
#define	INTEL_SIP_SMC_FUNCID_FPGA_CONFIG_LOOPBACK		6
#define	INTEL_SIP_SMC_FUNCID_REG_READ				7
#define	INTEL_SIP_SMC_FUNCID_REG_WRITE				8
#define	INTEL_SIP_SMC_FUNCID_REG_UPDATE				9
#define	INTEL_SIP_SMC_FUNCID_RSU_STATUS				11
#define	INTEL_SIP_SMC_FUNCID_RSU_UPDATE				12

#define	INTEL_SIP_SMC_FPGA_CONFIG_START			\
    INTEL_SIP_SMC_FAST_CALL(INTEL_SIP_SMC_FUNCID_FPGA_CONFIG_START)
#define	INTEL_SIP_SMC_FPGA_CONFIG_WRITE			\
    INTEL_SIP_SMC_STD_CALL(INTEL_SIP_SMC_FUNCID_FPGA_CONFIG_WRITE)
#define	INTEL_SIP_SMC_FPGA_CONFIG_COMPLETED_WRITE	\
    INTEL_SIP_SMC_FAST_CALL(INTEL_SIP_SMC_FUNCID_FPGA_CONFIG_COMPLETED_WRITE)
#define	INTEL_SIP_SMC_FPGA_CONFIG_ISDONE		\
    INTEL_SIP_SMC_FAST_CALL(INTEL_SIP_SMC_FUNCID_FPGA_CONFIG_ISDONE)
#define	INTEL_SIP_SMC_FPGA_CONFIG_GET_MEM		\
    INTEL_SIP_SMC_FAST_CALL(INTEL_SIP_SMC_FUNCID_FPGA_CONFIG_GET_MEM)
#define	INTEL_SIP_SMC_FPGA_CONFIG_LOOPBACK		\
    INTEL_SIP_SMC_FAST_CALL(INTEL_SIP_SMC_FUNCID_FPGA_CONFIG_LOOPBACK)
#define	INTEL_SIP_SMC_REG_READ				\
    INTEL_SIP_SMC_FAST_CALL(INTEL_SIP_SMC_FUNCID_REG_READ)
#define	INTEL_SIP_SMC_REG_WRITE				\
    INTEL_SIP_SMC_FAST_CALL(INTEL_SIP_SMC_FUNCID_REG_WRITE)
#define	INTEL_SIP_SMC_REG_UPDATE			\
    INTEL_SIP_SMC_FAST_CALL(INTEL_SIP_SMC_FUNCID_REG_UPDATE)
#define	INTEL_SIP_SMC_RSU_STATUS			\
    INTEL_SIP_SMC_FAST_CALL(INTEL_SIP_SMC_FUNCID_RSU_STATUS)
#define	INTEL_SIP_SMC_RSU_UPDATE			\
    INTEL_SIP_SMC_FAST_CALL(INTEL_SIP_SMC_FUNCID_RSU_UPDATE)

struct arm_smccc_res {
	uint64_t a0;
	uint64_t a1;
	uint64_t a2;
	uint64_t a3;
};

uint64_t arm_smccc_smc(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t, struct arm_smccc_res *res);
uint64_t arm_smccc_hvc(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t, struct arm_smccc_res *res);
typedef uint64_t (*intel_smc_callfn_t)(uint64_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
    struct arm_smccc_res *res);

#endif /* _ARM64_INTEL_INTEL_SMC_H_ */
