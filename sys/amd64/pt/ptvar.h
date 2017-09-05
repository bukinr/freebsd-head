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

#ifndef _AMD64_PT_PTVAR_H_
#define _AMD64_PT_PTVAR_H_

extern int (*pt_intr)(int _cpu, struct trapframe *_frame);

#define	PT_CPUID			0x14

#ifndef LOCORE
static MALLOC_DEFINE(M_PT, "pt", "PT driver");

struct pt_vm_handle {
	struct pt_softc		*sc;
	vm_object_t		mem;
	vm_size_t		size;
	void *			base;
};

struct pt_softc {
	uint64_t			base;
	uint64_t			size;
	vm_page_t			page;
	uint64_t			*topa;
	uint64_t			*topa_addr;
	struct thread			*td;
	struct mtx			proc_mtx;
	struct proc			*pt_proc;
	int				wakeup;
	bool				proc_terminate;

	struct cdev			*pt_cdev;
	struct mtx			mtx_encls;
	struct mtx			mtx;
	uint64_t			epc_base;
	uint64_t			epc_size;
	struct vmem			*vmem_epc;
	uint32_t			npages;
	uint64_t			enclave_size_max;
	uint8_t				state;
#define	PT_STATE_RUNNING		(1 << 0)
};
#endif /* !LOCORE */

#endif /* !_AMD64_PT_PTVAR_H_ */
