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
#include <sys/event.h>
#include <sys/cpuset.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/signal.h>
#include <sys/types.h>

#include <assert.h>
#include <signal.h>
#include <ctype.h>
#include <curses.h>
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
#include "hwtrace_pt.h"

static struct pmcstat_args args;
static int pmcstat_sockpair[NSOCKPAIRFD];
static int pmcstat_kq;
static struct pmcstat_process *pmcstat_kernproc;
static int pmcstat_npmcs;
static int pmcstat_mergepmc;

/*
 * All image descriptors are kept in a hash table.
 */
struct pmcstat_image_hash_list pmcstat_image_hash[PMCSTAT_NHASH];

/*
 * All process descriptors are kept in a hash table.
 */
struct pmcstat_process_hash_list pmcstat_process_hash[PMCSTAT_NHASH];

static struct pmc_plugins plugins[] = {};

static int
pmcstat_log_pt(struct pmcstat_ev *ev)
{
	struct pmcstat_process *pp;
	struct pmcstat_target *pt;
	pmc_value_t offset;
	pmc_value_t cycle;
	int i;

	STAILQ_FOREACH(ev, &args.pa_events, ev_next) {
		for (i = 0; i < 4; i++) {
			pmc_read_trace(i, ev->ev_pmcid, &cycle, &offset);
#if 1
			printf("cpu %d cycle %lx offset %lx\n", i, cycle, offset);
#endif

			pt = SLIST_FIRST(&args.pa_targets);
			if (pt != NULL) {
				pp = pmcstat_process_lookup(pt->pt_pid, 0);
				//printf("pid %d\n", pt->pt_pid);
			} else {
				pp = pmcstat_kernproc;
			}
			if (pp)
				ipt_process(pp, i, cycle, offset);
#if 0
			else
				printf("pp not found\n");
#endif
		}
	}

	return (0);
}

/*
 * Convert a hwpmc(4) log to profile information.  A system-wide
 * callgraph is generated if FLAG_DO_CALLGRAPHS is set.  gmon.out
 * files usable by gprof(1) are created if FLAG_DO_GPROF is set.
 */

static void
hwtrace_start_pmcs(void)
{
	struct pmcstat_ev *ev;

	STAILQ_FOREACH(ev, &args.pa_events, ev_next) {

	    assert(ev->ev_pmcid != PMC_ID_INVALID);

	    if (pmc_start(ev->ev_pmcid) < 0) {
	        warn("ERROR: Cannot start pmc 0x%x \"%s\"",
		    ev->ev_pmcid, ev->ev_name);
		//pmcstat_cleanup();
		exit(EX_OSERR);
	    }
	}
}

int
main(int argc, char *argv[])
{
	struct pmcstat_ev *ev;
	//char *app_filename;
	//struct stat sb;
	int user_mode;
	int option;
	cpuset_t cpumask;
	struct kevent kev;
	int c;
	int i;

	STAILQ_INIT(&args.pa_events);
	SLIST_INIT(&args.pa_targets);
	CPU_ZERO(&cpumask);

	while ((option = getopt(argc, argv,
	    "u:")) != -1)
		switch (option) {
		case 'u':
			user_mode = 1;
#if 0
			if (stat(optarg, &sb) < 0)
				err(EX_OSERR, "ERROR: Cannot stat \"%s\"",
				    optarg);
			app_filename = optarg;
#endif
			break;
		default:
			break;
		};

	args.pa_argc = (argc -= optind);
	args.pa_argv = (argv += optind);

	if ((ev = malloc(sizeof(*ev))) == NULL)
		errx(EX_SOFTWARE, "ERROR: Out of memory.");

	if (!user_mode)
		ev->ev_mode = PMC_MODE_ST;
	else
		ev->ev_mode = PMC_MODE_TT;

	ev->ev_spec = strdup("pt");
	if (ev->ev_spec == NULL)
		errx(EX_SOFTWARE, "ERROR: Out of memory.");

	//args.pa_required |= (FLAG_HAS_PIPE | FLAG_HAS_OUTPUT_LOGFILE);

	ev->ev_saved = 0LL;
	ev->ev_pmcid = PMC_ID_INVALID;

#if 0
	/* extract event name */
	c = strcspn(optarg, ", \t");
	ev->ev_name = malloc(c + 1);
	if (ev->ev_name == NULL)
		errx(EX_SOFTWARE, "ERROR: Out of memory.");
	(void) strncpy(ev->ev_name, optarg, c);
	*(ev->ev_name + c) = '\0';
#endif
	ev->ev_name = strdup("pt");

	if (!user_mode)
		ev->ev_cpu = CPU_FFS(&cpumask) - 1;
	else
		ev->ev_cpu = PMC_CPU_ANY;

	ev->ev_flags = 0;

	STAILQ_INSERT_TAIL(&args.pa_events, ev, ev_next);

	if (!user_mode) {
		CPU_CLR(ev->ev_cpu, &cpumask);
		pmcstat_clone_event_descriptor(ev, &cpumask, &args);
		CPU_SET(ev->ev_cpu, &cpumask);
	}

	for (i = 0; i < 4; i++)
		pmc_ipt_init(i);

	if (pmc_init() < 0)
		err(EX_UNAVAILABLE, "ERROR: Initialization of the pmc(3) library failed");

	pmcstat_initialize_logging(&pmcstat_kernproc,
	    &args, plugins, &pmcstat_npmcs, &pmcstat_mergepmc);

	STAILQ_FOREACH(ev, &args.pa_events, ev_next) {
		if (pmc_allocate(ev->ev_spec, ev->ev_mode,
			ev->ev_flags, ev->ev_cpu, &ev->ev_pmcid) < 0)
			err(EX_OSERR,
			    "ERROR: Cannot allocate %s-mode pmc with specification \"%s\"",
			    PMC_IS_SYSTEM_MODE(ev->ev_mode) ?
			    "system" : "process", ev->ev_spec);
	}

	if ((pmcstat_kq = kqueue()) < 0)
		err(EX_OSERR, "ERROR: Cannot allocate kqueue");

	pmcstat_create_process(pmcstat_sockpair, &args, pmcstat_kq);

	pmcstat_attach_pmcs(&args);
	hwtrace_start_pmcs();

	pmcstat_start_process(pmcstat_sockpair);

	EV_SET(&kev, 0, EVFILT_TIMER, EV_ADD, 0, 1000, NULL);
	if (kevent(pmcstat_kq, &kev, 1, NULL, 0, NULL) < 0)
		err(EX_OSERR, "ERROR: Cannot register kevent for timer");

	do {
		if ((c = kevent(pmcstat_kq, NULL, 0, &kev, 1, NULL)) <= 0) {
			if (errno != EINTR)
				err(EX_OSERR, "ERROR: kevent failed");
			else
				continue;
		}

#if 1
		printf("%s: pmcstat event: filter %d, ident %ld\n",
		    __func__, kev.filter, kev.ident);
#endif

		if (kev.flags & EV_ERROR)
			errc(EX_OSERR, kev.data, "ERROR: kevent failed");

		switch (kev.filter) {
		case EVFILT_TIMER:
			pmcstat_log_pt(ev);
			break;
		}
	} while (1);

	return (0);
}
