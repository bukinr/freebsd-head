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
#include <libgen.h>
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
#include <pmclog.h>
#include <libpmcstat.h>

#include <machine/pt.h>
#include "pmctrace_pt.h"

static struct pmcstat_args args;
static int pmcstat_sockpair[NSOCKPAIRFD];
static int pmcstat_kq;
static struct kevent kev;

static struct pmcstat_process *pmcstat_kernproc;
static int pmcstat_npmcs;
static int pmcstat_mergepmc;
static struct pmcstat_stats pmcstat_stats;
static int ps_samples_period;

/*
 * All image descriptors are kept in a hash table.
 */
struct pmcstat_image_hash_list pmcstat_image_hash[PMCSTAT_NHASH];

/*
 * All process descriptors are kept in a hash table.
 */
struct pmcstat_process_hash_list pmcstat_process_hash[PMCSTAT_NHASH];

struct pmcstat_pmcs pmcstat_pmcs = LIST_HEAD_INITIALIZER(pmcstat_pmcs);

static struct pmc_plugins plugins[] = {};

static int
pmcstat_pt_process(int cpuid, struct pmcstat_ev *ev)
{
	struct pmcstat_process *pp;
	struct pmcstat_target *pt;
	pmc_value_t offset;
	pmc_value_t cycle;

	pmc_read_trace(cpuid, ev->ev_pmcid, &cycle, &offset);
#if 0
	printf("cpu %d cycle %lx offset %lx\n", cpuid, cycle, offset);
#endif

	pt = SLIST_FIRST(&args.pa_targets);
	if (pt != NULL) {
		pp = pmcstat_process_lookup(pt->pt_pid, 0);
		//printf("pid %d\n", pt->pt_pid);
	} else {
		pp = pmcstat_kernproc;
	}
	if (pp)
		ipt_process(pp, cpuid, cycle, offset);
#if 0
	else
		printf("pp not found\n");
#endif

	return (0);
}

static int
pmcstat_log_pt(int user_mode)
{
	struct pmcstat_ev *ev;
	int i;

	if (user_mode) {
		ev = STAILQ_FIRST(&args.pa_events);
		for (i = 0; i < 4; i++) {
			pmcstat_pt_process(i, ev);
		}
	} else {
		STAILQ_FOREACH(ev, &args.pa_events, ev_next) {
			pmcstat_pt_process(ev->ev_cpu, ev);
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
pmctrace_start_pmcs(void)
{
	struct pmcstat_ev *ev;

	STAILQ_FOREACH(ev, &args.pa_events, ev_next) {
		printf("starting ev->ev_cpu %d\n", ev->ev_cpu);
		assert(ev->ev_pmcid != PMC_ID_INVALID);
		if (pmc_start(ev->ev_pmcid) < 0) {
			warn("ERROR: Cannot start pmc 0x%x \"%s\"",
			    ev->ev_pmcid, ev->ev_name);
			//pmcstat_cleanup();
			exit(EX_OSERR);
		}
	}
}

static int
pmctrace_open_logfile(void)
{
	int pipefd[2];

	/*
	 * process the log on the fly by reading it in
	 * through a pipe.
	 */
	if (pipe(pipefd) < 0)
		err(EX_OSERR, "ERROR: pipe(2) failed");

	if (fcntl(pipefd[READPIPEFD], F_SETFL, O_NONBLOCK) < 0)
		err(EX_OSERR, "ERROR: fcntl(2) failed");

	EV_SET(&kev, pipefd[READPIPEFD], EVFILT_READ, EV_ADD,
	    0, 0, NULL);

	if (kevent(pmcstat_kq, &kev, 1, NULL, 0, NULL) < 0)
		err(EX_OSERR, "ERROR: Cannot register kevent");

	args.pa_logfd = pipefd[WRITEPIPEFD];
	args.pa_flags |= FLAG_HAS_PIPE;
	//if ((args.pa_flags & FLAG_DO_TOP) == 0)
	//	args.pa_flags |= FLAG_DO_PRINT;
	args.pa_logparser = pmclog_open(pipefd[READPIPEFD]);

	if (pmc_configure_logfile(args.pa_logfd) < 0)
		err(EX_OSERR, "ERROR: Cannot configure log file");

	return (0);
}

static int
pmctrace_find_kernel(void)
{
	struct stat sb;
	char buffer[PATH_MAX];
	size_t len;
	char *tmp;

	/* Default to using the running system kernel. */
	len = 0;
	if (sysctlbyname("kern.bootfile", NULL, &len, NULL, 0) == -1)
		err(EX_OSERR, "ERROR: Cannot determine path of running kernel");
	args.pa_kernel = malloc(len);
	if (args.pa_kernel == NULL)
		errx(EX_SOFTWARE, "ERROR: Out of memory.");
	if (sysctlbyname("kern.bootfile", args.pa_kernel, &len, NULL, 0) == -1)
		err(EX_OSERR, "ERROR: Cannot determine path of running kernel");

	/*
	 * Check if 'kerneldir' refers to a file rather than a
	 * directory.  If so, use `dirname path` to determine the
	 * kernel directory.
	 */
	(void) snprintf(buffer, sizeof(buffer), "%s%s", args.pa_fsroot,
	    args.pa_kernel);
	if (stat(buffer, &sb) < 0)
		err(EX_OSERR, "ERROR: Cannot locate kernel \"%s\"",
		    buffer);
	if (!S_ISREG(sb.st_mode) && !S_ISDIR(sb.st_mode))
		errx(EX_USAGE, "ERROR: \"%s\": Unsupported file type.",
		    buffer);
	if (!S_ISDIR(sb.st_mode)) {
		tmp = args.pa_kernel;
		args.pa_kernel = strdup(dirname(args.pa_kernel));
		if (args.pa_kernel == NULL)
			errx(EX_SOFTWARE, "ERROR: Out of memory");
		free(tmp);
		(void) snprintf(buffer, sizeof(buffer), "%s%s",
		    args.pa_fsroot, args.pa_kernel);
		if (stat(buffer, &sb) < 0)
			err(EX_OSERR, "ERROR: Cannot stat \"%s\"",
			    buffer);
		if (!S_ISDIR(sb.st_mode))
			errx(EX_USAGE,
			    "ERROR: \"%s\" is not a directory.",
			    buffer);
	}

	return (0);
}

static void
pmctrace_setup_cpumask(cpuset_t *cpumask)
{
	cpuset_t rootmask;

	/*
	 * The initial CPU mask specifies the root mask of this process
	 * which is usually all CPUs in the system.
	 */
	if (cpuset_getaffinity(CPU_LEVEL_ROOT, CPU_WHICH_PID, -1,
	    sizeof(rootmask), &rootmask) == -1)
		err(EX_OSERR, "ERROR: Cannot determine the root set of CPUs");
	CPU_COPY(&rootmask, cpumask);
}

static int
pmctrace_ncpu(void)
{
	size_t ncpu_size;
	int error;
	int ncpu;

	ncpu_size = sizeof(ncpu);
	error = sysctlbyname("hw.ncpu", &ncpu, &ncpu_size, NULL, 0);
	if (error)
		return (-1);

	return (ncpu);
}

#if 0
static int
pmctrace_reconfig(uint32_t cpu, pmc_id_t pmc, ranges
int
pmc_trace_config(uint32_t cpu, pmc_id_t pmc,
    struct pmc_trace_filter_ip_range *ranges,
    uint32_t nranges)
#endif

int
main(int argc, char *argv[])
{
	struct pmcstat_ev *ev;
	//char *app_filename;
	int user_mode;
	int supervisor_mode;
	int option;
	int ncpu;
	cpuset_t cpumask;
	char *func_name;
	char *func_image;
	int c;
	int i;

	bzero(&args, sizeof(struct pmcstat_args));

	func_name = NULL;
	func_image = NULL;

	user_mode = 0;
	supervisor_mode = 0;

	STAILQ_INIT(&args.pa_events);
	SLIST_INIT(&args.pa_targets);
	CPU_ZERO(&cpumask);

	args.pa_fsroot = strdup("/");

	pmctrace_find_kernel();
	pmctrace_setup_cpumask(&cpumask);

	while ((option = getopt(argc, argv,
	    "u:s:i:f:")) != -1)
		switch (option) {
		case 'i':
			func_image = strdup(optarg);
			break;
		case 'f':
			func_name = strdup(optarg);
			break;
		case 'u':
		case 's':
			if ((ev = malloc(sizeof(struct pmcstat_ev))) == NULL)
				errx(EX_SOFTWARE, "ERROR: Out of memory.");
			if (option == 'u') {
				user_mode = 1;
				ev->ev_mode = PMC_MODE_TT;
				args.pa_flags |= FLAG_HAS_PROCESS_PMCS;
			} else {
				ev->ev_mode = PMC_MODE_ST;
				supervisor_mode = 1;
			}

			ev->ev_spec = strdup(optarg);
			if (ev->ev_spec == NULL)
				errx(EX_SOFTWARE, "ERROR: Out of memory.");

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

	if ((user_mode == 0 && supervisor_mode == 0) ||
	    (user_mode == 1 && supervisor_mode == 1))
		errx(EX_USAGE, "ERROR: specify -u or -s");

	if ((func_image == NULL && func_name != NULL) ||
	    (func_image != NULL && func_name == NULL))
		errx(EX_USAGE, "ERROR: specify both or neither -i and -f");

	args.pa_argc = (argc -= optind);
	args.pa_argv = (argv += optind);
	args.pa_cpumask = cpumask;

	if (user_mode && !argc)
		errx(EX_USAGE, "ERROR: user mode requires command to be specified");
	if (supervisor_mode && argc)
		errx(EX_USAGE, "ERROR: supervisor mode does not require command");

	printf("%s\n", __func__);

#if 0
	if ((ev = malloc(sizeof(*ev))) == NULL)
		errx(EX_SOFTWARE, "ERROR: Out of memory.");

	if (!user_mode)
		ev->ev_mode = PMC_MODE_ST;
	else {
		ev->ev_mode = PMC_MODE_TT;
		args.pa_flags |= FLAG_HAS_PROCESS_PMCS;
	}
#endif

	//ev->ev_spec = strdup("pt");
	//if (ev->ev_spec == NULL)
	//	errx(EX_SOFTWARE, "ERROR: Out of memory.");

	args.pa_required |= (FLAG_HAS_PIPE | FLAG_HAS_OUTPUT_LOGFILE);

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
	ev->ev_name = strdup("testname");

	if (!user_mode)
		ev->ev_cpu = CPU_FFS(&cpumask) - 1;
	else
		ev->ev_cpu = PMC_CPU_ANY;

	ev->ev_flags = 0;

	STAILQ_INSERT_TAIL(&args.pa_events, ev, ev_next);

	printf("%s\n", __func__);

	if (!user_mode) {
		CPU_CLR(ev->ev_cpu, &cpumask);
		pmcstat_clone_event_descriptor(ev, &cpumask, &args);
		CPU_SET(ev->ev_cpu, &cpumask);
	}

	ncpu = pmctrace_ncpu();
	if (ncpu < 0)
		errx(EX_SOFTWARE, "ERROR: Can't get cpus\n");

	for (i = 0; i < ncpu; i++)
		pmc_ipt_init(i);

	printf("%s\n", __func__);

	if (pmc_init() < 0)
		err(EX_UNAVAILABLE, "ERROR: Initialization of the pmc(3) library failed");

	if ((pmcstat_kq = kqueue()) < 0)
		err(EX_OSERR, "ERROR: Cannot allocate kqueue");

	pmctrace_open_logfile();

	STAILQ_FOREACH(ev, &args.pa_events, ev_next) {
		printf("pmc_allocate ev is %lx, ev->cpu %d\n", (uint64_t)ev, ev->ev_cpu);
		if (pmc_allocate(ev->ev_spec, ev->ev_mode,
			ev->ev_flags, ev->ev_cpu, &ev->ev_pmcid) < 0)
			err(EX_OSERR,
			    "ERROR: Cannot allocate %s-mode pmc with specification \"%s\"",
			    PMC_IS_SYSTEM_MODE(ev->ev_mode) ?
			    "system" : "process", ev->ev_spec);
	}

	EV_SET(&kev, 0, EVFILT_TIMER, EV_ADD, 0, 100, NULL);
	if (kevent(pmcstat_kq, &kev, 1, NULL, 0, NULL) < 0)
		err(EX_OSERR, "ERROR: Cannot register kevent for timer");

	pmcstat_initialize_logging(&pmcstat_kernproc,
	    &args, plugins, &pmcstat_npmcs, &pmcstat_mergepmc);

	int started;
	started = 0;

	if (user_mode) {
		pmcstat_create_process(pmcstat_sockpair, &args, pmcstat_kq);
		pmcstat_attach_pmcs(&args);
		if (func_name == NULL || func_image == NULL) {
			pmctrace_start_pmcs();
			started = 1;
		}
		pmcstat_start_process(pmcstat_sockpair);
	} else {
		if (func_name == NULL || func_image == NULL) {
			pmctrace_start_pmcs();
			started = 1;
		} else {
			ev = STAILQ_FIRST(&args.pa_events);
			STAILQ_FOREACH(ev, &args.pa_events, ev_next) {
				pmc_log_kmap(ev->ev_pmcid);
			}
		}
	}

	struct pmcstat_process *pp;
	struct pmcstat_symbol *sym;
	uintptr_t addr_start;
	uintptr_t addr_end;

	int running;
	int stopping;

	stopping = 0;
	running = 10;

	struct pmcstat_target *pt;

	struct pmc_trace_filter_ip_range ranges[16];

	do {
		if ((c = kevent(pmcstat_kq, NULL, 0, &kev, 1, NULL)) <= 0) {
			if (errno != EINTR)
				err(EX_OSERR, "ERROR: kevent failed");
			else
				continue;
		}

#if 0
		printf("%s: pmcstat event: filter %d, ident %ld\n",
		    __func__, kev.filter, kev.ident);
#endif

		if (kev.flags & EV_ERROR)
			errc(EX_OSERR, kev.data, "ERROR: kevent failed");

		switch (kev.filter) {
		case EVFILT_PROC:
			stopping = 1;
			break;
		case EVFILT_READ:
			printf("%s: read data available\n", __func__);
			args.pa_flags |= FLAG_DO_ANALYSIS;
			pmcstat_analyze_log(&args, plugins, &pmcstat_stats, pmcstat_kernproc,
			    pmcstat_mergepmc, &pmcstat_npmcs, &ps_samples_period);
			printf("%s: log analyzed\n", __func__);

			if (!user_mode)
				pp = pmcstat_kernproc;
			else {
				pt = SLIST_FIRST(&args.pa_targets);
				if (pt != NULL) {
					pp = pmcstat_process_lookup(pt->pt_pid, 0);
					if (pp == NULL) {
						printf("pp is NULL, pid %d\n", (uint32_t)pt->pt_pid);
						continue;
						exit(3);
					}
				} else
					exit(2);
			}

			pt = SLIST_FIRST(&args.pa_targets);
			if (func_name == NULL || func_image == NULL) {
				if (user_mode) {
					ev = STAILQ_FIRST(&args.pa_events);
					pmc_proc_unsuspend(ev->ev_pmcid, pt->pt_pid);
				}
				break;
			}

			printf("%s: name to addr\n", __func__);
			sym = pmcstat_name_to_addr(pp, func_image, func_name, &addr_start, &addr_end);
			printf("%s: name to addr done\n", __func__);
			if (sym) {
				printf("SYM addr start %lx end %lx\n", addr_start, addr_end);

				ranges[0].addra = addr_start;
				ranges[0].addrb = addr_end;

				if (user_mode) {
					ev = STAILQ_FIRST(&args.pa_events);
					for (i = 0; i < ncpu; i++)
						pmc_trace_config(i, ev->ev_pmcid, &ranges[0], 1);
				} else {
					STAILQ_FOREACH(ev, &args.pa_events, ev_next) {
						printf("cpu%d: trace config\n", ev->ev_cpu);
						pmc_trace_config(ev->ev_cpu, ev->ev_pmcid, &ranges[0], 1);
					}
				}

				if (started == 0) {
					started = 1;
					pmctrace_start_pmcs();
					printf("pmc started\n");
				}
			}

			if (user_mode) {
				ev = STAILQ_FIRST(&args.pa_events);
				pmc_proc_unsuspend(ev->ev_pmcid, pt->pt_pid);
			}

			break;
		case EVFILT_TIMER:
			pmc_flush_logfile();

			pp = pmcstat_kernproc;
			if (!user_mode && TAILQ_EMPTY(&pp->pp_map))
				break;

			pmcstat_log_pt(user_mode);

			if (stopping)
				running -= 1;
			break;
		}
	} while (running > 0);

	return (0);
}
