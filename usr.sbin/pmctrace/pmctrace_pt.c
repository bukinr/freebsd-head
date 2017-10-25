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

#include <machine/pt.h>

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

#include <libpmcstat.h>

#include "pmctrace_pt.h"

#include <libipt/pt_cpu.h>
#include <libipt/pt_last_ip.h>
#include <libipt/pt_time.h>
#include <libipt/pt_compiler.h>
#include <libipt/intel-pt.h>

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

static struct pmcstat_symbol *
symbol_lookup(struct mtrace_data *mdata)
{
	struct pmcstat_image *image;
	struct pmcstat_symbol *sym;
	struct pmcstat_pcmap *map;
	uint64_t newpc;
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
		return (sym);
	} else {
#if 0
		printf("cpu%d: 0x%lx .\n", mdata->cpu, ip);
		//printf("map not found, pp %lx, ip %lx\n", (uint64_t)mdata->pp, >ip);
#endif
	}

	return (NULL);
}

static int
print_tnt_payload(struct mtrace_data *mdata, uint64_t offset __unused,
    const struct pt_packet_tnt *packet)
{
	char payload[48];
	uint64_t tnt;
	uint8_t bits;
	char *begin;
	char *end;

	bits = packet->bit_size;
	tnt = packet->payload;
	begin = &payload[0];
	end = begin + bits;

	if (sizeof(payload) < bits)
		end = begin + sizeof(payload);

	for (; begin < end; ++begin, --bits)
		*begin = tnt & (1ull << (bits - 1)) ? '!' : '.';

	printf("cpu%d: TNT %s\n", mdata->cpu, payload);

	return (0);
}

static int
print_ip_payload(struct mtrace_data *mdata, uint64_t offset __unused,
    const struct pt_packet_ip *packet)
{
	struct pmcstat_symbol *sym;

	switch (packet->ipc) {
	case pt_ipc_suppressed:
		break;
	case pt_ipc_update_16:
		mdata->ip &= ~0xffff;
		mdata->ip |= (packet->ip & 0xffff);
		break;
	case pt_ipc_update_32:
		mdata->ip &= ~0xffffffffUL;
		mdata->ip |= (packet->ip & 0xffffffff);
		break;
	case pt_ipc_update_48:
		mdata->ip &= ~0xffffffffffffUL;
		mdata->ip |= (packet->ip & 0xffffffffffff);
		break;
	case pt_ipc_sext_48:
		mdata->ip &= ~0xffffffffffffUL;
		mdata->ip |= (packet->ip & 0xffffffffffff);
		symbol_lookup(mdata);
	case pt_ipc_full:
		mdata->ip = packet->ip;
		break;
	default:
		printf("unknown ipc: %d\n", packet->ipc);
		return (0);
	}

	sym = symbol_lookup(mdata);
	if (sym)
		printf("cpu%d:  IP 0x%lx %s\n", mdata->cpu, mdata->ip, pmcstat_string_unintern(sym->ps_name));

#if 0
		else
			printf("cpu%d: 0x%lx not found, image->pi_vaddr %lx, image->pi_start %lx, map->ppm_lowpc %lx, pc %lx, newpc %lx\n",
			    mdata->cpu, ip, image->pi_vaddr, image->pi_start, map->ppm_lowpc, mdata->ip, newpc);
#endif

	return (0);
}

static int
dump_packets(struct mtrace_data *mdata, struct pt_packet_decoder *decoder,
    const struct pt_config *config __unused)
{
	struct pt_packet packet;
	uint64_t offset;
	int error;

	while (1) {
		error = pt_pkt_get_offset(decoder, &offset);
		if (error < 0) {
			//printf("err %d, offset 0x%lx\n", error, offset);
			break;
		}

		error = pt_pkt_next(decoder, &packet, sizeof(packet));
		if (error < 0) {
			//printf("err %d, packet.type %d\n", error, packet.type);
			break;
		}

		switch (packet.type) {
		case ppt_invalid:
		case ppt_unknown:
		case ppt_pad:
		case ppt_psb:
		case ppt_psbend:
			break;
		case ppt_fup:
		case ppt_tip:
		case ppt_tip_pge:
		case ppt_tip_pgd:
			print_ip_payload(mdata, offset, &packet.payload.ip);
			break;
		case ppt_tnt_8:
		case ppt_tnt_64:
			print_tnt_payload(mdata, offset, &packet.payload.tnt);
			break;
		case ppt_mode:
		case ppt_pip:
		case ppt_vmcs:
		case ppt_cbr:
			break;
		case ppt_tsc:
			printf("cpu%d: TSC %ld\n", mdata->cpu, packet.payload.tsc.tsc);
			break;
		case ppt_tma:
			break;
		case ppt_mtc:
			printf("cpu%d: MTC %x\n", mdata->cpu, packet.payload.mtc.ctc);
			break;
		case ppt_cyc:
		case ppt_stop:
		case ppt_ovf:
		case ppt_mnt:
		case ppt_exstop:
		case ppt_mwait:
		case ppt_pwre:
		case ppt_pwrx:
		case ppt_ptw:
		default:
			break;
		}
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

#if 0
	printf("%s\n", __func__);
#endif

	memset(&config, 0, sizeof(config));
	pt_config_init(&config);

	error = pt_cpu_read(&config.cpu);
	//printf("err %d\n", error);
	error = pt_cpu_errata(&config.errata, &config.cpu);
	//printf("err %d\n", error);

	config.begin = (uint8_t *)(base + start);
	config.end = (uint8_t *)(base + end);

#if 0
	printf("%s: begin %lx end %lx\n", __func__, (uint64_t)config.begin, (uint64_t)config.end);
#endif

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
ipt_process(struct pmcstat_process *pp, uint32_t cpu,
    uint32_t cycle, uint64_t offset)
{
	struct mtrace_data *mdata;
	struct trace_cpu *cc;

	cc = &trace_cpus[cpu];

#if 0
	printf("pp is %lx\n", (uint64_t)pp);
#endif

	mdata = &cc->mdata;
	mdata->pp = pp;

#if 0
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
