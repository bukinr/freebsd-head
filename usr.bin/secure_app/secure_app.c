/*
 * Copyright (c) 1980, 1987, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/mman.h>
#include <sys/uio.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>
#include <wctype.h>

#include <gelf.h>

#define	round_up(x,y) (((x) + (y) - 1) & ~((y)-1))
#define	round_down(x,y) ((x) & ~((y)-1))

#include "sgx_user.h"

static int
build_secs(void *p, struct secs *m_secs, uint64_t enclave_base_addr __unused, uint64_t enclave_size)
{
	struct secs_attr *attributes;

	memset(m_secs, 0, sizeof(struct secs));
	m_secs->base = (uint64_t)p; //enclave_base_addr;
	m_secs->size = enclave_size;
	m_secs->misc_select = 0;
	m_secs->ssa_frame_size = 8;

	attributes = &m_secs->attributes;
	attributes->mode64bit = 1;
	attributes->xfrm = 0x3;

#if 0
	void *p;
	//p = mmap(NULL, m_secs->size * 2, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, fd, 0);
	p = mmap(NULL, m_secs->size * 2, 0, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		printf("mmap failed\n");
		return (-1);
	}

	printf("p is %lx\n", (uint64_t)p);
	printf("*p is %hhx\n", *(uint8_t *)p);
	//*(uint64_t *)p = 1;
#endif

	return (0);
}

static int
enclave_create(int fd, struct secs *m_secs)
{
	uint64_t data;
	int err;

	data = (uint64_t)m_secs;
	err = ioctl(fd, SGX_IOC_ENCLAVE_CREATE, &data);

	printf("test fd %d err %d\n", fd, err);

	return (0);
}

int
main(int argc, char *argv[])
{
	struct secs m_secs;
	char *filename;
	GElf_Phdr phdr;
	GElf_Ehdr ehdr;
	Elf *e;
	int fd;
	size_t n;
	int i;
	int fd_app;
	void *secs_base;
	void *p;

	fd = open("/dev/isgx", O_RDONLY);
	if (fd < 0) {
		printf("Can't open /dev/isgx\n");
		return (1);
	}

	secs_base = mmap(NULL, 2 * 1024 * 1024, 0, MAP_SHARED, fd, 0);
	if (secs_base == MAP_FAILED) {
		printf("mmap failed: err %d\n", errno);
		return (-1);
	}
	printf("secs_base is %lx\n", (uint64_t)secs_base);

	//return (0);

	if (argc < 2) {
		printf("supply a binary pls\n");
		return (1);
	}
	filename = argv[1];
	printf("filename %s\n", filename);

	fd_app = open(filename, O_RDONLY, 0);
	if (fd_app < 0) {
		printf("Can't open %s\n", filename);
		return (1);
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		printf("Elf library init failed\n");
		return (1);
	}
	e = elf_begin(fd_app, ELF_C_READ, NULL);
	if (e == NULL) {
		printf("elf_begin failed\n");
		return (1);
	}
	if (elf_kind(e) != ELF_K_ELF) {
		printf("elf is not elf\n");
		return (1);
	}

	if (gelf_getehdr(e, &ehdr) == NULL) {
		printf("gelf_getehdr failed\n");
		return (1);
	}

	printf("Entry %lx\n", ehdr.e_entry);

	if (elf_getphdrnum(e, &n) != 0) {
		printf("elf_getphdrnum failed\n");
		return (1);
	}

	printf("n segments %zu\n", n);

	void *base_addr;
	void *entry;
	uint64_t entry_offset;
	unsigned long start, fdataend, fend, mend;
	int pflags;
	int cnt;

	cnt = 0;
	
	for (i = 0; i < (int)n; i++) {
		if (gelf_getphdr(e, i, &phdr) != &phdr) {
			printf("Failed to get segment phdr\n");
			return (1);
		}
		if (phdr.p_type != PT_LOAD) {
			continue;
		}

		printf("pt_load seg found %d\n", i);
		cnt += 1;

		if (cnt > 1) {
			printf("add support\n");
			return (1);
		}

		start = round_down(phdr.p_vaddr, PAGE_SIZE);
		mend = round_up(phdr.p_vaddr + phdr.p_memsz, PAGE_SIZE);
		fend  = round_up(phdr.p_vaddr + phdr.p_filesz, PAGE_SIZE);
		fdataend = phdr.p_vaddr + phdr.p_filesz;

		pflags = 0;
		if (phdr.p_flags & PF_R) {
			pflags |= PROT_READ;
		}
		if (phdr.p_flags & PF_W) {
			pflags |= PROT_WRITE;
		}
		if (phdr.p_flags & PF_X) {
			pflags |= PROT_EXEC;
		}
		pflags |= PROT_WRITE;

		//p = mmap(0, mend-start, pflags, MAP_PRIVATE | MAP_ANONYMOUS | MAP_ALIGNED(8192),
		p = mmap(0, 4096*2, pflags, MAP_PRIVATE | MAP_ANONYMOUS | MAP_ALIGNED(13),
		    -1, 0);
		if (p == NULL) {
			printf("mmap failed\n");
			return (1);
		}
		printf("p %lx, len %ld\n", (uint64_t)p, mend-start);

		base_addr = p;
		entry = (void *)(ehdr.e_entry + (unsigned long)p - start);
		printf("base_addr %lx entry %lx\n", (uint64_t)base_addr, (uint64_t)entry);

		entry_offset = (uint64_t)entry-(uint64_t)base_addr;
		printf("entry offs %lx\n", entry_offset);

	}
	uint64_t enclave_base_addr;
	uint64_t enclave_size;
	int tls_npages;
	struct tcs *tcs;

	enclave_base_addr = (uint64_t)base_addr;
	enclave_size = 4096*2; //at least two pages

	tcs = aligned_alloc(PAGE_SIZE, sizeof(struct tcs));
	memset(tcs, 0, sizeof(struct tcs));

	tcs->flags = 0;
	//tcs->ossa =
	tcs->fslimit = PAGE_SIZE - 1;
	tcs->gslimit = PAGE_SIZE - 1;

	tcs->ofsbasgx = 0;
	tcs->ogsbasgx = tcs->ofsbasgx + tcs->fslimit + 1;
	tcs->nssa = 2;
	tcs->cssa = 0;
	tls_npages = ((tcs->fslimit + 1) + (tcs->gslimit + 1)) / 4096;
	tcs->oentry = ((tls_npages) * PAGE_SIZE) + entry_offset;

	build_secs(secs_base, &m_secs, enclave_base_addr, enclave_size);

	enclave_create(fd, &m_secs);
	//enclave_add_page(secs, tcs);

	pid_t pid;
	pid = fork();

	char *my_argv[4];
	my_argv[0] = strdup("/bin/sleep");
	my_argv[1] = strdup("10");
	my_argv[2] = NULL;
	my_argv[3] = NULL;

	if (pid == 0) {
		/* child */
		//sleep(20);
		//printf("child exit\n");
		printf("child go to sleep 10\n");
		execve("/bin/sleep", my_argv, NULL);
	} else {
		/* parent */
		printf("parent go to sleep 10\n");
		execve("/bin/sleep", my_argv, NULL);
	}

	return (0);
}
