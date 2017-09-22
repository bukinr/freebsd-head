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
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/signal.h>
#include <sys/types.h>

#include <signal.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <sysexits.h>
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

#include <pmc.h>
#include <libpmcstat.h>

#include <machine/pt.h>

#define	round_up(x,y) (((x) + (y) - 1) & ~((y)-1))
#define	round_down(x,y) ((x) & ~((y)-1))

#define print_field(field, ...)					\
	do {							\
		/* Avoid partial overwrites. */			\
		memset(field, 0, sizeof(field));		\
		snprintf(field, sizeof(field), __VA_ARGS__);	\
	} while (0)

static int mtrace_kq;

#if 0
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

struct mtrace_data {
	uint64_t ip;
	struct pmcstat_process *pp;
};

struct ptdump_buffer {
	char offset[17];
	char opcode[10];
	union {
		char standard[25];
		char extended[48];
	} payload;
};

static void
symbol_lookup(struct pmcstat_process *pp, uint64_t instr)
{
	struct pmcstat_pcmap *map;
	struct pmcstat_image *image;
	uint64_t newpc;
	struct pmcstat_symbol *sym;

	map = pmcstat_process_find_map(pp, instr);
	if (map != NULL) {
		image = map->ppm_image;
		newpc = instr - (map->ppm_lowpc +
			(image->pi_vaddr - image->pi_start));
		sym = pmcstat_symbol_search(image, newpc);
		if (sym)
			printf("FUNC: %s\n", pmcstat_string_unintern(sym->ps_name));
	} else {
		//printf("map not found\n");
		//return (12);
	}

	printf("ok\n");
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
		symbol_lookup(mdata->pp, mdata->ip);
		print_field(buffer->payload.standard, "%x: %016"
			    PRIx64, pt_ipc_update_16, mdata->ip);
		return (0);

		//printf("%s: %lx\n", __func__, packet->ip);
		print_field(buffer->payload.standard, "%x: ????????????%04"
			    PRIx64, pt_ipc_update_16, packet->ip);
		return 0;

	case pt_ipc_update_32:
		mdata->ip &= ~0xffffffff;
		mdata->ip |= (packet->ip & 0xffffffff);
		symbol_lookup(mdata->pp, mdata->ip);
		print_field(buffer->payload.standard, "%x: %016"
			    PRIx64, pt_ipc_update_32, mdata->ip);
		return (0);

		print_field(buffer->payload.standard, "%x: ????????%08"
			    PRIx64, pt_ipc_update_32, packet->ip);
		return 0;

	case pt_ipc_update_48:
		mdata->ip &= ~0xffffffffffff;
		mdata->ip |= (packet->ip & 0xffffffffffff);
		symbol_lookup(mdata->pp, mdata->ip);
		print_field(buffer->payload.standard, "%x: %016"
			    PRIx64, pt_ipc_update_48, mdata->ip);
		return (0);
		print_field(buffer->payload.standard, "%x: ????%012"
			    PRIx64, pt_ipc_update_48, packet->ip);
		return 0;

	case pt_ipc_sext_48:
		mdata->ip &= ~0xffffffffffff;
		mdata->ip |= (packet->ip & 0xffffffffffff);
		symbol_lookup(mdata->pp, mdata->ip);
		print_field(buffer->payload.standard, "%x: %016"
			    PRIx64, pt_ipc_sext_48, mdata->ip);
		return (0);
		print_field(buffer->payload.standard, "%x: %016" PRIx64,
			    pt_ipc_sext_48, sext(packet->ip, 48));
		return 0;

	case pt_ipc_full:
		mdata->ip = packet->ip;
		symbol_lookup(mdata->pp, mdata->ip);
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
		//printf(".");

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

		printf("%s%s: ", sep, buffer.opcode);
		//printf(" %s\n", buffer.payload.extended);
		printf(" %s\n", buffer.payload.standard);
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

	memset(&config, 0, sizeof(config));
	pt_config_init(&config);

	error = pt_cpu_read(&config.cpu);
	//printf("err %d\n", error);
	error = pt_cpu_errata(&config.errata, &config.cpu);
	//printf("err %d\n", error);

	config.begin = (uint8_t *)(base + start);
	config.end = (uint8_t *)(base + end);

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

static int
decode_data(struct pmcstat_process *pp, int fd, void *base, uint32_t bufsize)
{
	struct pt_test data;
	uint64_t curptr;
	uint64_t cycle;
	int error;
	struct mtrace_data mdata;

	cycle = 0;
	curptr = 0;

	mdata.pp = pp;

	while (1) {
		error = ioctl(fd, PT_IOC_PTR, &data);
#if 0
		printf("data.cycle %ld, cycle %ld, data.ptr %lx, curptr %lx\n",
		    data.cycle, cycle, data.ptr, curptr);
#endif
		if (data.ptr == curptr)
			continue;

		if (data.cycle == cycle) {
			if (data.ptr > curptr) {
				init_ipt(&mdata, (uint64_t)base, curptr, data.ptr);
				curptr = data.ptr;
			} else if (data.ptr < curptr) {
				printf("panic: data.ptr %lx curptr %lx\n", data.ptr, curptr);
				return (-1);
			}
		} else if (data.cycle > cycle) {
			if ((data.cycle - cycle) > 1)
				err(EXIT_FAILURE, "trace is too fast, machine cycle %ld, mtrace cycle %ld",
				    data.cycle, cycle);
			init_ipt(&mdata, (uint64_t)base, curptr, bufsize);
			curptr = 0;
			cycle += 1;
			init_ipt(&mdata, (uint64_t)base, curptr, data.ptr);
			curptr = data.ptr;
		}
	}

	return (0);
}

static void
help(const char *name)
{

	printf("usage: %s [<options>] <binary>[:<from>[-<to>]\n\n", name);
	printf("options:\n");
	printf("  --help|-h                 this text.\n");
	printf("  --retc                    enable ret compression.\n");
}

int
main(int argc, char *argv[])
{
	void *base;
	int error;
	int fd;
	int bufsize;
	int app_mode;
	const char *app_filename;
	struct stat sb;
	struct pt_drv_config config;
	int i;

	app_mode = 0;

#if 0
	int option;
	while ((option = getopt(argc, argv,
	    "a:")) != -1)
		switch (option) {
		case 'a':
			app_mode = 1;
			if (stat(optarg, &sb) < 0)
				err(EX_OSERR, "ERROR: Cannot stat \"%s\"",
				    optarg);
			app_filename = optarg;
			break;
		default:
			break;
		};
#endif

	for (i = 1; i < argc; i++) {

		if (strncmp(argv[i], "-", 1) != 0) {
			app_mode = 1;
			app_filename = argv[i];
			if (stat(app_filename, &sb) < 0)
				err(EX_OSERR, "ERROR: Cannot stat \"%s\"",
				    app_filename);
			//if (i < (argc - 1))
			//	return usage(argv[0]);
			//break;
		}
#if 0
		if (strcmp(argv[i], "--app") == 0) {
			app_mode = 1;
			app_filename = argv[i];
			if (stat(app_filename, &sb) < 0)
				err(EX_OSERR, "ERROR: Cannot stat \"%s\"",
				    app_filename);
		}
#endif

		if (strcmp(argv[i], "--retc") == 0) {
			config.retc = 1;
		}
	}

	if (app_mode == 0) {
		/* The only mode supported yet */
		help(argv[0]);

		errx(EX_USAGE, "ERROR: illegal usage.");

		return (1);
	}

	fd = open("/dev/ipt", O_RDWR);
	if (fd < 0) {
		printf("Can't open /dev/ipt\n");
		return (1);
	}

	bufsize = 128 * 1024 * 1024;

	base = mmap(NULL, bufsize, PROT_READ, MAP_SHARED, fd, 0);
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

	pid_t pid;
	char *my_argv[4];

	my_argv[0] = strdup(app_filename);
	my_argv[1] = NULL;
	my_argv[2] = NULL;
	my_argv[3] = NULL;

#if 0
	int ret;
#endif

	struct pmcstat_image *image;
	struct pmcstat_process *pp;
	pmcstat_interned_string image_path;

	if ((pp = malloc(sizeof(*pp))) == NULL)
		err(EX_OSERR, "ERROR: Cannot allocate pid descriptor");

	//pp->pp_pid = pid;
	pp->pp_isactive = 1;

	TAILQ_INIT(&pp->pp_map);

	//LIST_INSERT_HEAD(&pmcstat_process_hash[hash], pp, pp_next);

	//libc
	//uint64_t libstart;
	image_path = pmcstat_string_intern("/lib/libc.so.7");
	//image = pmcstat_image_from_path(image_path, 0);
	//libstart = 0x3c3a0 - image->pi_entry;
	//pmcstat_image_link(pp, image, libstart);
	pmcstat_process_exec(pp, image_path, 0x3c3a0);

	image_path = pmcstat_string_intern(app_filename);
	pmcstat_process_exec(pp, image_path, 0x4004a0);

	image = pmcstat_image_from_path(image_path, 0);
	//pmcstat_image_get_elf_params(image);

	struct pmcstat_symbol *sym;
	//sym = pmcstat_symbol_search(image, 0x400740);
	//sym = pmcstat_symbol_search(image, 0x740);
	sym = pmcstat_symbol_search(image, 0xbc1);
	printf("sym %lx\n", (uint64_t)sym);
	if (sym != NULL)
		printf("sym name %s\n", pmcstat_string_unintern(sym->ps_name));

	//map = pmcstat_process_find_map(pp, 0x000000080060cfa0);

	if ((mtrace_kq = kqueue()) < 0)
		printf("can't allocate kqueue\n");

	pid = fork();
	if (pid == 0) {
		/* Child */
		error = ioctl(fd, PT_IOC_CONFIG, &config);
		execve(app_filename, my_argv, NULL);
	} else {
		/* Parent */
#if 0
		struct kevent kev;
		struct kevent tkev;

		(void)signal(SIGUSR1, sigusr1);
		EV_SET(&kev, SIGUSR1, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
		if (kevent(mtrace_kq, &kev, 1, NULL, 0, NULL) < 0)
			printf("can't register kevent\n");
		printf("kevent registered\n");

		uint64_t offset;
		offset = 0;

		ret = kevent(mtrace_kq, NULL, 0, &tkev, 1, NULL);
		if (ret == -1) {
			err(EXIT_FAILURE, "kevent wait");
		} else if (ret > 0) {
		}
#endif

		decode_data(pp, fd, base, bufsize);
	}

	return (0);
}
