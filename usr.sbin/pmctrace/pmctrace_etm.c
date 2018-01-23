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

#include <libpmcstat.h>

#include "pmctrace.h"
#include "pmctrace_etm.h"


#define	PMCTRACE_ETM_DEBUG
//#undef	PMCTRACE_ETM_DEBUG

#ifdef	PMCTRACE_ETM_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

#if 0
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
	} else
		dprintf("cpu%d: 0x%lx map not found\n", mdata->cpu, ip);

	return (NULL);
}
#endif

static int
etm_process_chunk(struct mtrace_data *mdata __unused, uint64_t base __unused,
    uint64_t start __unused, uint64_t end __unused)
{

	dprintf("%s\n", __func__);

	return (0);
}

int
etm_process(struct trace_cpu *tc, struct pmcstat_process *pp,
    uint32_t cpu, uint32_t cycle, uint64_t offset,
    uint32_t flags)
{
	struct mtrace_data *mdata;

	mdata = &tc->mdata;
	mdata->pp = pp;
	mdata->flags = flags;

	dprintf("%s: cpu %d, cycle %d, offset %ld\n",
	    __func__, cpu, cycle, offset);

	dprintf("tc->base %lx\n", *(uint64_t *)tc->base);
	if (offset == tc->offset)
		return (0);

	if (cycle == tc->cycle) {
		if (offset > tc->offset) {
			etm_process_chunk(mdata, (uint64_t)tc->base, tc->offset, offset);
			tc->offset = offset;
		} else if (offset < tc->offset) {
			err(EXIT_FAILURE, "cpu%d: offset already processed %lx %lx",
			    cpu, offset, tc->offset);
		}
	} else if (cycle > tc->cycle) {
		if ((cycle - tc->cycle) > 1)
			err(EXIT_FAILURE, "cpu%d: trace buffers fills up faster than"
			    " we can process it (%d/%d). Consider setting trace filters",
			    cpu, cycle, tc->cycle);
		etm_process_chunk(mdata, (uint64_t)tc->base, tc->offset, tc->bufsize);
		tc->offset = 0;
		tc->cycle += 1;
		etm_process_chunk(mdata, (uint64_t)tc->base, tc->offset, offset);
		tc->offset = offset;
	}

	return (0);
}
