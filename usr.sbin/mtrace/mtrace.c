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
#include <libipt/intel-pt.h>

#define	round_up(x,y) (((x) + (y) - 1) & ~((y)-1))
#define	round_down(x,y) ((x) & ~((y)-1))

#define	PT_MAGIC	0xA5

struct pt_test {
	uint64_t	test;
};

#define	PT_IOC_TEST \
	_IOW(PT_MAGIC, 0x00, struct pt_test)

int
main(int argc __unused, char *argv[] __unused)
{
	void *base;
	int error;
	int fd;

	fd = open("/dev/ipt", O_RDWR);
	if (fd < 0) {
		printf("Can't open /dev/ipt\n");
		return (1);
	}

	base = mmap(NULL, 2 * 1024 * 1024, PROT_READ, MAP_SHARED, fd, 0);
	//base = mmap(NULL, 2 * 1024 * 1024, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, fd, 0);
	if (base == MAP_FAILED) {
		printf("mmap failed: err %d\n", errno);
		return (-1);
	}
	printf("base is %lx\n", (uint64_t)base);
	uint64_t *addr;
	addr = (uint64_t *)base;

	//printf("*base %lx\n", addr[0]);
	//addr[0] = 1;
	//printf("*base %lx\n", addr[0]);

	struct pt_test data;
	pid_t pid;
	char *my_argv[4];

	//my_argv[0] = strdup("/bin/sleep");
	//my_argv[1] = strdup("0");
	my_argv[0] = strdup("/home/br/test");
	my_argv[1] = NULL; //strdup("-a");
	my_argv[2] = NULL;
	my_argv[3] = NULL;

	pid = fork();

	if (pid == 0) {
		/* Child */
		error = ioctl(fd, PT_IOC_TEST, &data);
		//while (1);
		execve("/home/br/test", my_argv, NULL);
	} else {
		/* Parent */
		//error = ioctl(fd, PT_IOC_TEST, &data);
		sleep(2);
		printf("while loop\n");
		while (1)
			printf("%lx %lx %lx %lx %lx\n", addr[0], addr[1], addr[2], addr[3], addr[4]);
	}

	struct pt_packet_decoder *decoder;
	struct pt_config config;

	memset(&config, 0, sizeof(config));
	pt_config_init(&config);
	decoder = pt_pkt_alloc_decoder(&config);

	return (0);
}
