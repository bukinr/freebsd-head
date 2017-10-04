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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");
 
#include <sys/param.h>
#include <sys/cpuset.h>
#include <sys/event.h>
#include <sys/queue.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/ttycom.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <assert.h>
#include <curses.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <kvm.h>
#include <libgen.h>
#include <limits.h>
#include <math.h>
#include <pmc.h>
#include <pmclog.h>
#include <regex.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <gelf.h>
#include <inttypes.h>

#include <machine/pt.h>

#include <libpmcstat.h>
//#include "pmcstat_log.h"
//#include "pmcstat.h"
#include "hwtrace_pt.h"

#include <pmc.h>

#include <libipt/pt_cpu.h>
#include <libipt/pt_last_ip.h>
#include <libipt/pt_time.h>
#include <libipt/pt_compiler.h>
#include <libipt/intel-pt.h>

#define	round_up(x,y) (((x) + (y) - 1) & ~((y)-1))
#define	round_down(x,y) ((x) & ~((y)-1))

#define print_field(field, ...)					\
	do {							\
		/* Avoid partial overwrites. */			\
		memset(field, 0, sizeof(field));		\
		snprintf(field, sizeof(field), __VA_ARGS__);	\
	} while (0)

struct mtrace_data {
	uint64_t ip;
	int cpu;
	struct pmcstat_process *pp;
};

static struct trace_cpu {
	uint32_t cycle;
	uint64_t offset;
	struct mtrace_data mdata;
	uint32_t bufsize;
	void *base;
	int fd;
} trace_cpus[4];

#if 0
static int mtrace_kq;
static void
sigusr1(int sig __unused)
{

	printf("signal\n");
}
#endif

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

static void
symbol_lookup(struct mtrace_data *mdata)
{
	struct pmcstat_pcmap *map;
	struct pmcstat_image *image;
	uint64_t newpc;
	struct pmcstat_symbol *sym;
	uint64_t ip;

	if (mdata->ip & (1UL << 47))
		ip = mdata->ip | 0xffffUL << 48;
	else
		ip = mdata->ip;

	map = pmcstat_process_find_map(mdata->pp, ip);
	if (map != NULL) {
		image = map->ppm_image;
		newpc = ip - (map->ppm_lowpc +
			(image->pi_vaddr - image->pi_start));
		sym = pmcstat_symbol_search(image, newpc);
		if (sym)
			printf("cpu%d: 0x%lx %s\n", mdata->cpu,
			    ip,
			    pmcstat_string_unintern(sym->ps_name));
#if 0
		else
			printf("cpu%d: 0x%lx not found, newpc %lx\n", mdata->cpu,
			    ip, newpc);
#endif
	}

#if 0
	else {
		printf("cpu%d: 0x%lx .\n", mdata->cpu, ip);
		//printf("map not found, pp %lx, ip %lx\n", (uint64_t)mdata->pp, >ip);
		//return (12);
	}
#endif

	//printf("ok\n");
}

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
print_ip_payload(struct mtrace_data *mdata, struct ptdump_buffer *buffer,
    uint64_t offset __unused, const struct pt_packet_ip *packet)
{

	switch (packet->ipc) {
	case pt_ipc_suppressed:
		print_field(buffer->payload.standard, "%x: ????????????????",
			    pt_ipc_suppressed);
		return 0;

	case pt_ipc_update_16:

		mdata->ip &= ~0xffff;
		mdata->ip |= (packet->ip & 0xffff);

		symbol_lookup(mdata);
		print_field(buffer->payload.standard, "%x: %016"
			    PRIx64, pt_ipc_update_16, mdata->ip);
		return (0);

		//printf("%s: %lx\n", __func__, packet->ip);
		print_field(buffer->payload.standard, "%x: ????????????%04"
			    PRIx64, pt_ipc_update_16, packet->ip);
		return 0;

	case pt_ipc_update_32:
		mdata->ip &= ~0xffffffffUL;
		mdata->ip |= (packet->ip & 0xffffffff);

		symbol_lookup(mdata);
		print_field(buffer->payload.standard, "%x: %016"
			    PRIx64, pt_ipc_update_32, mdata->ip);
		return (0);

		print_field(buffer->payload.standard, "%x: ????????%08"
			    PRIx64, pt_ipc_update_32, packet->ip);
		return 0;

	case pt_ipc_update_48:
		mdata->ip &= ~0xffffffffffffUL;
		mdata->ip |= (packet->ip & 0xffffffffffff);
		symbol_lookup(mdata);
		print_field(buffer->payload.standard, "%x: %016"
			    PRIx64, pt_ipc_update_48, mdata->ip);
		return (0);
		print_field(buffer->payload.standard, "%x: ????%012"
			    PRIx64, pt_ipc_update_48, packet->ip);
		return 0;

	case pt_ipc_sext_48:
		mdata->ip &= ~0xffffffffffffUL;
		mdata->ip |= (packet->ip & 0xffffffffffff);
		symbol_lookup(mdata);
		print_field(buffer->payload.standard, "%x: %016"
			    PRIx64, pt_ipc_sext_48, mdata->ip);
		return (0);
		print_field(buffer->payload.standard, "%x: %016" PRIx64,
			    pt_ipc_sext_48, sext(packet->ip, 48));
		return 0;

	case pt_ipc_full:
		mdata->ip = packet->ip;
		symbol_lookup(mdata);
		print_field(buffer->payload.standard, "%x: %016"
			    PRIx64, pt_ipc_update_16, mdata->ip);
		return (0);
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
dump_packets(struct mtrace_data *mdata, struct pt_packet_decoder *decoder,
    const struct pt_config *config __unused)
{
	uint64_t offset;
	struct pt_packet packet;
	struct ptdump_buffer buffer;
	const char *sep;
	int error;

	printf("%s\n", __func__);

	sep = "";

	while (1) {
		error = pt_pkt_get_offset(decoder, &offset);
		if (error < 0) {
			printf("err %d, offset 0x%lx\n", error, offset);
			break;
		}

		error = pt_pkt_next(decoder, &packet, sizeof(packet));
		if (error < 0) {
			printf("err %d, packet.type %d\n", error, packet.type);
			break;
		}

		memset(&buffer, 0, sizeof(buffer));

		//print_field(buffer.offset, "%016" PRIx64, offset);

		switch (packet.type) {
		case ppt_psb:
			continue;
			print_field(buffer.opcode, "psb");
			break;
		case ppt_psbend:
			continue;
			print_field(buffer.opcode, "psbend");
			break;
		case ppt_pad:
			continue;
			print_field(buffer.opcode, "pad");
			break;
		case ppt_fup:
			print_field(buffer.opcode, "fup");
			print_ip_payload(mdata, &buffer, offset, &packet.payload.ip);
			break;
		case ppt_tip:
			print_field(buffer.opcode, "tip");
			print_ip_payload(mdata, &buffer, offset, &packet.payload.ip);
			break;
		case ppt_tip_pge:
			print_field(buffer.opcode, "tip_pge");
			print_ip_payload(mdata, &buffer, offset, &packet.payload.ip);
			break;
		case ppt_tip_pgd:
			print_field(buffer.opcode, "tip_pgd");
			print_ip_payload(mdata, &buffer, offset, &packet.payload.ip);
			break;
		case ppt_mode:
			continue;
			print_field(buffer.opcode, "mode");
			break;
		case ppt_tsc:
			continue;
			print_field(buffer.opcode, "tsc");
			print_field(buffer.payload.standard, "%" PRIx64,
			    packet.payload.tsc.tsc);
			break;
		case ppt_tma:
			continue;
			print_field(buffer.opcode, "tma");
			break;
		case ppt_mtc:
			continue;
			print_field(buffer.opcode, "mtc");
			break;
		case ppt_cbr:
			continue;
			print_field(buffer.opcode, "cbr");
			break;
		case ppt_pip:
			continue;
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
			continue;
			break;
		}
#if 0
		printf("%s%s: ", sep, buffer.opcode);
		//printf(" %s\n", buffer.payload.extended);
		printf(" %s\n", buffer.payload.standard);
#endif
	}

	return (0);
}

static int
init_ipt(struct mtrace_data *mdata, uint64_t base,
    uint64_t start, uint64_t end)
{
	struct pt_packet_decoder *decoder;
	struct pt_config config;
	int error;

	printf("%s\n", __func__);

	memset(&config, 0, sizeof(config));
	pt_config_init(&config);

	error = pt_cpu_read(&config.cpu);
	//printf("err %d\n", error);
	error = pt_cpu_errata(&config.errata, &config.cpu);
	//printf("err %d\n", error);

	config.begin = (uint8_t *)(base + start);
	config.end = (uint8_t *)(base + end);

	printf("%s: begin %lx end %lx\n", __func__, (uint64_t)config.begin, (uint64_t)config.end);

	decoder = pt_pkt_alloc_decoder(&config);
	if (decoder == NULL) {
		printf("Can't allocate decoder\n");
		return (-1);
	}

	//error = pt_pkt_sync_set(decoder, 0ull);
	error = pt_pkt_sync_forward(decoder);

	//struct ptdump_tracking tracking;
	//ptdump_tracking_init(&tracking);

	while (1) {
		error = dump_packets(mdata, decoder, &config);
		if (error == 0) {
			//printf(",");
			break;
		}

		error = pt_pkt_sync_forward(decoder);
		if (error < 0) {
			if (error == -pte_eos)
				return (0);
		}

		//ptdump_tracking_reset(tracking);
	}

	return (0);
}

int
pmc_ipt_init(uint32_t cpu)
{
	struct trace_cpu *cc;
	char filename[16];
	struct mtrace_data *mdata;

	printf("%s: cpu %d\n", __func__, cpu);

	cc = &trace_cpus[cpu];
	mdata = &cc->mdata;
	mdata->ip = 0;
	mdata->cpu = cpu;

	sprintf(filename, "/dev/pmc%d", cpu);

#if 0
	printf("%s: cpu %d: fd open\n", __func__, cpu);
#endif

	cc->fd = open(filename, O_RDWR);
	if (cc->fd < 0) {
		printf("Can't open %s\n", filename);
		return (-1);
	}

	cc->bufsize = 256 * 1024 * 1024;
	cc->cycle = 0;
	cc->offset = 0;

#if 0
	printf("%s: cpu %d: mmap\n", __func__, cpu);
#endif

	cc->base = mmap(NULL, cc->bufsize, PROT_READ, MAP_SHARED, cc->fd, 0);
	if (cc->base == MAP_FAILED) {
		printf("mmap failed: err %d\n", errno);
		return (-1);
	}

	return (0);
}

int
ipt_process(struct pmcstat_process *pp, uint32_t cpu, uint32_t cycle, uint64_t offset)
{
	struct mtrace_data *mdata;
	struct trace_cpu *cc;

	cc = &trace_cpus[cpu];

#if 0
	printf("pp is %lx\n", (uint64_t)pp);
#endif

	mdata = &cc->mdata;
	mdata->pp = pp;

#if 1
	printf("%s: cpu %d, cycle %d, offset %ld\n",
	    __func__, cpu, cycle, offset);
#endif

	if (offset == cc->offset)
		return (0);

	if (cycle == cc->cycle) {
		if (offset > cc->offset) {
			init_ipt(mdata, (uint64_t)cc->base, cc->offset, offset);
			cc->offset = offset;
		} else if (offset < cc->offset) {
			printf("panic: offset %lx cc->offset %lx\n", offset, cc->offset);
			return (-1);
		}
	} else if (cycle > cc->cycle) {
		if ((cycle - cc->cycle) > 1)
			err(EXIT_FAILURE, "cpu%d: trace is too fast, machine cycle %d, mtrace cycle %d",
			    cpu, cycle, cc->cycle);
		init_ipt(mdata, (uint64_t)cc->base, cc->offset, cc->bufsize);
		cc->offset = 0;
		cc->cycle += 1;
		init_ipt(mdata, (uint64_t)cc->base, cc->offset, offset);
		cc->offset = offset;
	}

	return (0);
}
