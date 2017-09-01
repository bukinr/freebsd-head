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
#include <inttypes.h>
#include <unistd.h>
#include <wchar.h>
#include <wctype.h>

#include <gelf.h>

#include <libipt/pt_cpu.h>
#include <libipt/pt_last_ip.h>
#include <libipt/pt_time.h>
#include <libipt/pt_compiler.h>
#include <libipt/intel-pt.h>

#define	round_up(x,y) (((x) + (y) - 1) & ~((y)-1))
#define	round_down(x,y) ((x) & ~((y)-1))

#define	PT_MAGIC	0xA5

struct pt_test {
	uint64_t	test;
};

#define	PT_IOC_TEST \
	_IOW(PT_MAGIC, 0x00, struct pt_test)

#define print_field(field, ...)					\
	do {							\
		/* Avoid partial overwrites. */			\
		memset(field, 0, sizeof(field));		\
		snprintf(field, sizeof(field), __VA_ARGS__);	\
	} while (0)

static uint64_t
sext(uint64_t val, uint8_t sign)
{
	uint64_t signbit, mask;

	signbit = 1ull << (sign - 1);
	mask = ~0ull << sign;

	return val & signbit ? val | mask : val & ~mask;
}


struct ptdump_buffer {
	char offset[17];
	char opcode[10];
	union {
		char standard[25];
		char extended[48];
	} payload;
};

static int
print_tnt_payload(struct ptdump_buffer *buffer, uint64_t offset __unused,
    const struct pt_packet_tnt *packet)
{

	uint64_t tnt;
	uint8_t bits;
	char *begin, *end;

	bits = packet->bit_size;
	tnt = packet->payload;
	begin = buffer->payload.extended;
	end = begin + bits;

	if (sizeof(buffer->payload.extended) < bits) {
		/* Truncating tnt payload */
		end = begin + sizeof(buffer->payload.extended);
	}

	for (; begin < end; ++begin, --bits)
		*begin = tnt & (1ull << (bits - 1)) ? '!' : '.';

	return (0);
}

static int
print_ip_payload(struct ptdump_buffer *buffer, uint64_t offset __unused,
    const struct pt_packet_ip *packet)
{

	switch (packet->ipc) {
	case pt_ipc_suppressed:
		print_field(buffer->payload.standard, "%x: ????????????????",
			    pt_ipc_suppressed);
		return 0;

	case pt_ipc_update_16:
		//printf("%s: %lx\n", __func__, packet->ip);
		print_field(buffer->payload.standard, "%x: ????????????%04"
			    PRIx64, pt_ipc_update_16, packet->ip);
		return 0;

	case pt_ipc_update_32:
		print_field(buffer->payload.standard, "%x: ????????%08"
			    PRIx64, pt_ipc_update_32, packet->ip);
		return 0;

	case pt_ipc_update_48:
		print_field(buffer->payload.standard, "%x: ????%012"
			    PRIx64, pt_ipc_update_48, packet->ip);
		return 0;

	case pt_ipc_sext_48:
		print_field(buffer->payload.standard, "%x: %016" PRIx64,
			    pt_ipc_sext_48, sext(packet->ip, 48));
		return 0;

	case pt_ipc_full:
		print_field(buffer->payload.standard, "%x: %016" PRIx64,
			    pt_ipc_full, packet->ip);
		return 0;
	default:
		printf("unknown ipc\n");
	}

	print_field(buffer->payload.standard, "%x: %016" PRIx64,
	    packet->ipc, packet->ip);
}

static int
init_ipt(void *base)
{
	struct pt_packet_decoder *decoder;
	struct pt_config config;
	int error;

	memset(&config, 0, sizeof(config));
	pt_config_init(&config);

	error = pt_cpu_read(&config.cpu);
	printf("err %d\n", error);
	error = pt_cpu_errata(&config.errata, &config.cpu);
	printf("err %d\n", error);

	//config->begin = buffer;
	//config->end = buffer + size;
	config.begin = (uint8_t *)base;
	config.end = (uint8_t *)((uint64_t)base + (2*1024*1024));

	decoder = pt_pkt_alloc_decoder(&config);
	if (decoder == NULL)
		printf("Can't allocate decoder\n");
	else
		printf("Decoder allocated\n");

	//error = pt_pkt_sync_set(decoder, 0ull);
	error = pt_pkt_sync_forward(decoder);

	uint64_t offset;
	struct pt_packet packet;
	struct ptdump_buffer buffer;
	const char *sep;

	sep = "";

	while (1) {
		error = pt_pkt_get_offset(decoder, &offset);
		if (error < 0)
			break;
		//printf("err %d, offset 0x%lx\n", error, offset);

		error = pt_pkt_next(decoder, &packet, sizeof(packet));
		if (error < 0)
			break;
		//printf("err %d, packet.type %d\n", error, packet.type);


		memset(&buffer, 0, sizeof(buffer));
		//print_field(buffer.offset, "%016" PRIx64, offset);

		switch (packet.type) {
		case ppt_psb:
			print_field(buffer.opcode, "psb");
			break;
		case ppt_psbend:
			print_field(buffer.opcode, "psbend");
			break;
		case ppt_pad:
			continue;
			print_field(buffer.opcode, "pad");
			break;
		case ppt_fup:
			continue;
			print_field(buffer.opcode, "fup");
			break;
		case ppt_tip:
			print_field(buffer.opcode, "tip");
			print_ip_payload(&buffer, offset, &packet.payload.ip);
			break;
		case ppt_tip_pge:
			print_field(buffer.opcode, "tip_pge");
			print_ip_payload(&buffer, offset, &packet.payload.ip);
			break;
		case ppt_tip_pgd:
			print_field(buffer.opcode, "tip_pgd");
			print_ip_payload(&buffer, offset, &packet.payload.ip);
			break;
		case ppt_mode:
			print_field(buffer.opcode, "mode");
			break;
		case ppt_tsc:
			print_field(buffer.opcode, "tsc");
			print_field(buffer.payload.standard, "%" PRIx64,
			    packet.payload.tsc.tsc);
			break;
		case ppt_cbr:
			print_field(buffer.opcode, "cbr");
			break;
		case ppt_tnt_8:
			continue;
			print_field(buffer.opcode, "tnt.8");
			print_tnt_payload(&buffer, offset, &packet.payload.tnt);
			break;
		case ppt_tnt_64:
			continue;
			print_field(buffer.opcode, "tnt.64");
			print_tnt_payload(&buffer, offset, &packet.payload.tnt);
			break;
		default:
			printf("unknown packet %d\n", packet.type);
			break;
		}

		printf("%s%s: ", sep, buffer.opcode);
		//printf(" %s\n", buffer.payload.extended);
		printf(" %s\n", buffer.payload.standard);
	}

	return (0);
}

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

		init_ipt(base);

		printf("while loop\n");
		while (1);
		//printf("%lx %lx %lx %lx %lx\n", addr[0], addr[1], addr[2], addr[3], addr[4]);
	}

	return (0);
}
