/*-
 * Copyright (c) 2005-2007, Joseph Koshy
 * Copyright (c) 2007 The FreeBSD Foundation
 * All rights reserved.
 *
 * Portions of this software were developed by A. Joseph Koshy under
 * sponsorship from the FreeBSD Foundation and Google, Inc.
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

/*
 * Transform a hwpmc(4) log into human readable form, and into
 * gprof(1) compatible profiles.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/cpuset.h>
#include <sys/gmon.h>
#include <sys/imgact_aout.h>
#include <sys/imgact_elf.h>
#include <sys/mman.h>
#include <sys/pmc.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <netinet/in.h>

#include <assert.h>
#include <curses.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libgen.h>
#include <limits.h>
#include <netdb.h>
#include <pmc.h>
#include <pmclog.h>
#include <sysexits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pmcstat.h"
#include "pmcstat_log.h"
#include "pmcstat_top.h"

#define	PMCSTAT_ALLOCATE		1

/*
 * PUBLIC INTERFACES
 *
 * pmcstat_initialize_logging()	initialize this module, called first
 * pmcstat_shutdown_logging()		orderly shutdown, called last
 * pmcstat_open_log()			open an eventlog for processing
 * pmcstat_process_log()		print/convert an event log
 * pmcstat_display_log()		top mode display for the log
 * pmcstat_close_log()			finish processing an event log
 *
 * IMPLEMENTATION NOTES
 *
 * We correlate each 'callchain' or 'sample' entry seen in the event
 * log back to an executable object in the system. Executable objects
 * include:
 * 	- program executables,
 *	- shared libraries loaded by the runtime loader,
 *	- dlopen()'ed objects loaded by the program,
 *	- the runtime loader itself,
 *	- the kernel and kernel modules.
 *
 * Each process that we know about is treated as a set of regions that
 * map to executable objects.  Processes are described by
 * 'pmcstat_process' structures.  Executable objects are tracked by
 * 'pmcstat_image' structures.  The kernel and kernel modules are
 * common to all processes (they reside at the same virtual addresses
 * for all processes).  Individual processes can have their text
 * segments and shared libraries loaded at process-specific locations.
 *
 * A given executable object can be in use by multiple processes
 * (e.g., libc.so) and loaded at a different address in each.
 * pmcstat_pcmap structures track per-image mappings.
 *
 * The sample log could have samples from multiple PMCs; we
 * generate one 'gmon.out' profile per PMC.
 *
 * IMPLEMENTATION OF GMON OUTPUT
 *
 * Each executable object gets one 'gmon.out' profile, per PMC in
 * use.  Creation of 'gmon.out' profiles is done lazily.  The
 * 'gmon.out' profiles generated for a given sampling PMC are
 * aggregates of all the samples for that particular executable
 * object.
 *
 * IMPLEMENTATION OF SYSTEM-WIDE CALLGRAPH OUTPUT
 *
 * Each active pmcid has its own callgraph structure, described by a
 * 'struct pmcstat_callgraph'.  Given a process id and a list of pc
 * values, we map each pc value to a tuple (image, symbol), where
 * 'image' denotes an executable object and 'symbol' is the closest
 * symbol that precedes the pc value.  Each pc value in the list is
 * also given a 'rank' that reflects its depth in the call stack.
 */

struct pmcstat_pmcs pmcstat_pmcs = LIST_HEAD_INITIALIZER(pmcstat_pmcs);

/*
 * All process descriptors are kept in a hash table.
 */
struct pmcstat_process_hash_list pmcstat_process_hash[PMCSTAT_NHASH];

struct pmcstat_stats pmcstat_stats; /* statistics */
static int ps_samples_period; /* samples count between top refresh. */

struct pmcstat_process *pmcstat_kernproc; /* kernel 'process' */

#include "pmcpl_gprof.h"
#include "pmcpl_callgraph.h"
#include "pmcpl_annotate.h"
#include "pmcpl_annotate_cg.h"
#include "pmcpl_calltree.h"

static struct pmc_plugins plugins[] = {
	{
		.pl_name		= "none",
	},
	{
		.pl_name		= "callgraph",
		.pl_init		= pmcpl_cg_init,
		.pl_shutdown		= pmcpl_cg_shutdown,
		.pl_process		= pmcpl_cg_process,
		.pl_topkeypress		= pmcpl_cg_topkeypress,
		.pl_topdisplay		= pmcpl_cg_topdisplay
	},
	{
		.pl_name		= "gprof",
		.pl_shutdown		= pmcpl_gmon_shutdown,
		.pl_process		= pmcpl_gmon_process,
		.pl_initimage		= pmcpl_gmon_initimage,
		.pl_shutdownimage	= pmcpl_gmon_shutdownimage,
		.pl_newpmc		= pmcpl_gmon_newpmc
	},
	{
		.pl_name		= "annotate",
		.pl_process		= pmcpl_annotate_process
	},
	{
		.pl_name		= "calltree",
		.pl_configure		= pmcpl_ct_configure,
		.pl_init		= pmcpl_ct_init,
		.pl_shutdown		= pmcpl_ct_shutdown,
		.pl_process		= pmcpl_ct_process,
		.pl_topkeypress		= pmcpl_ct_topkeypress,
		.pl_topdisplay		= pmcpl_ct_topdisplay
	},
	{
		.pl_name		= "annotate_cg",
		.pl_process		= pmcpl_annotate_cg_process
	},

	{
		.pl_name		= NULL
	}
};

static int pmcstat_mergepmc;

int pmcstat_pmcinfilter = 0; /* PMC filter for top mode. */
float pmcstat_threshold = 0.5; /* Cost filter for top mode. */

/*
 * Prototypes
 */

static void	pmcstat_pmcid_add(pmc_id_t _pmcid,
    pmcstat_interned_string _name);

static struct pmcstat_process *pmcstat_process_lookup(pid_t _pid,
    int _allocate);
static void pmcstat_string_initialize(void);
static void pmcstat_string_shutdown(void);
static void pmcstat_stats_reset(int _reset_global);

/*
 * PMC count.
 */
int pmcstat_npmcs;

/*
 * PMC Top mode pause state.
 */
static int pmcstat_pause;

static void
pmcstat_stats_reset(int reset_global)
{
	struct pmcstat_pmcrecord *pr;

	/* Flush PMCs stats. */
	LIST_FOREACH(pr, &pmcstat_pmcs, pr_next) {
		pr->pr_samples = 0;
		pr->pr_dubious_frames = 0;
	}
	ps_samples_period = 0;

	/* Flush global stats. */
	if (reset_global)
		bzero(&pmcstat_stats, sizeof(struct pmcstat_stats));
}

/*
 * Initialize the string interning facility.
 */

static void
pmcstat_string_initialize(void)
{
	int i;

	for (i = 0; i < PMCSTAT_NHASH; i++)
		LIST_INIT(&pmcstat_string_hash[i]);
}

/*
 * Destroy the string table, free'ing up space.
 */

static void
pmcstat_string_shutdown(void)
{
	int i;
	struct pmcstat_string *ps, *pstmp;

	for (i = 0; i < PMCSTAT_NHASH; i++)
		LIST_FOREACH_SAFE(ps, &pmcstat_string_hash[i], ps_next,
		    pstmp) {
			LIST_REMOVE(ps, ps_next);
			free(ps->ps_string);
			free(ps);
		}
}

/*
 * Unmap images in the range [start..end) associated with process
 * 'pp'.
 */

static void
pmcstat_image_unmap(struct pmcstat_process *pp, uintfptr_t start,
    uintfptr_t end)
{
	struct pmcstat_pcmap *pcm, *pcmtmp, *pcmnew;

	assert(pp != NULL);
	assert(start < end);

	/*
	 * Cases:
	 * - we could have the range completely in the middle of an
	 *   existing pcmap; in this case we have to split the pcmap
	 *   structure into two (i.e., generate a 'hole').
	 * - we could have the range covering multiple pcmaps; these
	 *   will have to be removed.
	 * - we could have either 'start' or 'end' falling in the
	 *   middle of a pcmap; in this case shorten the entry.
	 */
	TAILQ_FOREACH_SAFE(pcm, &pp->pp_map, ppm_next, pcmtmp) {
		assert(pcm->ppm_lowpc < pcm->ppm_highpc);
		if (pcm->ppm_highpc <= start)
			continue;
		if (pcm->ppm_lowpc >= end)
			return;
		if (pcm->ppm_lowpc >= start && pcm->ppm_highpc <= end) {
			/*
			 * The current pcmap is completely inside the
			 * unmapped range: remove it entirely.
			 */
			TAILQ_REMOVE(&pp->pp_map, pcm, ppm_next);
			free(pcm);
		} else if (pcm->ppm_lowpc < start && pcm->ppm_highpc > end) {
			/*
			 * Split this pcmap into two; curtail the
			 * current map to end at [start-1], and start
			 * the new one at [end].
			 */
			if ((pcmnew = malloc(sizeof(*pcmnew))) == NULL)
				err(EX_OSERR,
				    "ERROR: Cannot split a map entry");

			pcmnew->ppm_image = pcm->ppm_image;

			pcmnew->ppm_lowpc = end;
			pcmnew->ppm_highpc = pcm->ppm_highpc;

			pcm->ppm_highpc = start;

			TAILQ_INSERT_AFTER(&pp->pp_map, pcm, pcmnew, ppm_next);

			return;
		} else if (pcm->ppm_lowpc < start && pcm->ppm_highpc <= end)
			pcm->ppm_highpc = start;
		else if (pcm->ppm_lowpc >= start && pcm->ppm_highpc > end)
			pcm->ppm_lowpc = end;
		else
			assert(0);
	}
}

/*
 * Resolve file name and line number for the given address.
 */
int
pmcstat_image_addr2line(struct pmcstat_image *image, uintfptr_t addr,
    char *sourcefile, size_t sourcefile_len, unsigned *sourceline,
    char *funcname, size_t funcname_len)
{
	static int addr2line_warn = 0;

	char *sep, cmdline[PATH_MAX], imagepath[PATH_MAX];
	unsigned l;
	int fd;

	if (image->pi_addr2line == NULL) {
		/* Try default debug file location. */
		snprintf(imagepath, sizeof(imagepath),
		    "/usr/lib/debug/%s%s.debug",
		    args.pa_fsroot,
		    pmcstat_string_unintern(image->pi_fullpath));
		fd = open(imagepath, O_RDONLY);
		if (fd < 0) {
			/* Old kernel symbol path. */
			snprintf(imagepath, sizeof(imagepath), "%s%s.symbols",
			    args.pa_fsroot,
			    pmcstat_string_unintern(image->pi_fullpath));
			fd = open(imagepath, O_RDONLY);
			if (fd < 0) {
				snprintf(imagepath, sizeof(imagepath), "%s%s",
				    args.pa_fsroot,
				    pmcstat_string_unintern(
				        image->pi_fullpath));
			}
		}
		if (fd >= 0)
			close(fd);
		/*
		 * New addr2line support recursive inline function with -i
		 * but the format does not add a marker when no more entries
		 * are available.
		 */
		snprintf(cmdline, sizeof(cmdline), "addr2line -Cfe \"%s\"",
		    imagepath);
		image->pi_addr2line = popen(cmdline, "r+");
		if (image->pi_addr2line == NULL) {
			if (!addr2line_warn) {
				addr2line_warn = 1;
				warnx(
"WARNING: addr2line is needed for source code information."
				    );
			}
			return (0);
		}
	}

	if (feof(image->pi_addr2line) || ferror(image->pi_addr2line)) {
		warnx("WARNING: addr2line pipe error");
		pclose(image->pi_addr2line);
		image->pi_addr2line = NULL;
		return (0);
	}

	fprintf(image->pi_addr2line, "%p\n", (void *)addr);

	if (fgets(funcname, funcname_len, image->pi_addr2line) == NULL) {
		warnx("WARNING: addr2line function name read error");
		return (0);
	}
	sep = strchr(funcname, '\n');
	if (sep != NULL)
		*sep = '\0';

	if (fgets(sourcefile, sourcefile_len, image->pi_addr2line) == NULL) {
		warnx("WARNING: addr2line source file read error");
		return (0);
	}
	sep = strchr(sourcefile, ':');
	if (sep == NULL) {
		warnx("WARNING: addr2line source line separator missing");
		return (0);
	}
	*sep = '\0';
	l = atoi(sep+1);
	if (l == 0)
		return (0);
	*sourceline = l;
	return (1);
}

/*
 * Add a {pmcid,name} mapping.
 */

static void
pmcstat_pmcid_add(pmc_id_t pmcid, pmcstat_interned_string ps)
{
	struct pmcstat_pmcrecord *pr, *prm;

	/* Replace an existing name for the PMC. */
	prm = NULL;
	LIST_FOREACH(pr, &pmcstat_pmcs, pr_next)
		if (pr->pr_pmcid == pmcid) {
			pr->pr_pmcname = ps;
			return;
		} else if (pr->pr_pmcname == ps)
			prm = pr;

	/*
	 * Otherwise, allocate a new descriptor and call the
	 * plugins hook.
	 */
	if ((pr = malloc(sizeof(*pr))) == NULL)
		err(EX_OSERR, "ERROR: Cannot allocate pmc record");

	pr->pr_pmcid = pmcid;
	pr->pr_pmcname = ps;
	pr->pr_pmcin = pmcstat_npmcs++;
	pr->pr_samples = 0;
	pr->pr_dubious_frames = 0;
	pr->pr_merge = prm == NULL ? pr : prm;

	LIST_INSERT_HEAD(&pmcstat_pmcs, pr, pr_next);

	if (plugins[args.pa_pplugin].pl_newpmc != NULL)
		plugins[args.pa_pplugin].pl_newpmc(ps, pr);
	if (plugins[args.pa_plugin].pl_newpmc != NULL)
		plugins[args.pa_plugin].pl_newpmc(ps, pr);
}

/*
 * Given a pmcid in use, find its human-readable name.
 */

const char *
pmcstat_pmcid_to_name(pmc_id_t pmcid)
{
	struct pmcstat_pmcrecord *pr;

	LIST_FOREACH(pr, &pmcstat_pmcs, pr_next)
	    if (pr->pr_pmcid == pmcid)
		    return (pmcstat_string_unintern(pr->pr_pmcname));

	return NULL;
}

/*
 * Convert PMC index to name.
 */

const char *
pmcstat_pmcindex_to_name(int pmcin)
{
	struct pmcstat_pmcrecord *pr;

	LIST_FOREACH(pr, &pmcstat_pmcs, pr_next)
		if (pr->pr_pmcin == pmcin)
			return pmcstat_string_unintern(pr->pr_pmcname);

	return NULL;
}

/*
 * Return PMC record with given index.
 */

struct pmcstat_pmcrecord *
pmcstat_pmcindex_to_pmcr(int pmcin)
{
	struct pmcstat_pmcrecord *pr;

	LIST_FOREACH(pr, &pmcstat_pmcs, pr_next)
		if (pr->pr_pmcin == pmcin)
			return pr;

	return NULL;
}

/*
 * Get PMC record by id, apply merge policy.
 */

static struct pmcstat_pmcrecord *
pmcstat_lookup_pmcid(pmc_id_t pmcid)
{
	struct pmcstat_pmcrecord *pr;

	LIST_FOREACH(pr, &pmcstat_pmcs, pr_next) {
		if (pr->pr_pmcid == pmcid) {
			if (pmcstat_mergepmc)
				return pr->pr_merge;
			return pr;
		}
	}

	return NULL;
}

/*
 * Find the process descriptor corresponding to a PID.  If 'allocate'
 * is zero, we return a NULL if a pid descriptor could not be found or
 * a process descriptor process.  If 'allocate' is non-zero, then we
 * will attempt to allocate a fresh process descriptor.  Zombie
 * process descriptors are only removed if a fresh allocation for the
 * same PID is requested.
 */

static struct pmcstat_process *
pmcstat_process_lookup(pid_t pid, int allocate)
{
	uint32_t hash;
	struct pmcstat_pcmap *ppm, *ppmtmp;
	struct pmcstat_process *pp, *pptmp;

	hash = (uint32_t) pid & PMCSTAT_HASH_MASK;	/* simplicity wins */

	LIST_FOREACH_SAFE(pp, &pmcstat_process_hash[hash], pp_next, pptmp)
		if (pp->pp_pid == pid) {
			/* Found a descriptor, check and process zombies */
			if (allocate && pp->pp_isactive == 0) {
				/* remove maps */
				TAILQ_FOREACH_SAFE(ppm, &pp->pp_map, ppm_next,
				    ppmtmp) {
					TAILQ_REMOVE(&pp->pp_map, ppm,
					    ppm_next);
					free(ppm);
				}
				/* remove process entry */
				LIST_REMOVE(pp, pp_next);
				free(pp);
				break;
			}
			return (pp);
		}

	if (!allocate)
		return (NULL);

	if ((pp = malloc(sizeof(*pp))) == NULL)
		err(EX_OSERR, "ERROR: Cannot allocate pid descriptor");

	pp->pp_pid = pid;
	pp->pp_isactive = 1;

	TAILQ_INIT(&pp->pp_map);

	LIST_INSERT_HEAD(&pmcstat_process_hash[hash], pp, pp_next);
	return (pp);
}

int
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
#if 0
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
static int
pmcstat_analyze_log(void)
{
	uint32_t cpu, cpuflags;
	uintfptr_t pc;
	pid_t pid;
	struct pmcstat_image *image;
	struct pmcstat_process *pp, *ppnew;
	struct pmcstat_pcmap *ppm, *ppmtmp;
	struct pmclog_ev ev;
	struct pmcstat_pmcrecord *pmcr;
	pmcstat_interned_string image_path;
	struct pmcstat_target *pt;

	assert(args.pa_flags & FLAG_DO_ANALYSIS);

	if (elf_version(EV_CURRENT) == EV_NONE)
		err(EX_UNAVAILABLE, "Elf library initialization failed");

	while (pmclog_read(args.pa_logparser, &ev) == 0) {
		assert(ev.pl_state == PMCLOG_OK);

		switch (ev.pl_type) {
		case PMCLOG_TYPE_INITIALIZE:
			if ((ev.pl_u.pl_i.pl_version & 0xFF000000) !=
			    PMC_VERSION_MAJOR << 24 && args.pa_verbosity > 0)
				warnx(
"WARNING: Log version 0x%x does not match compiled version 0x%x.",
				    ev.pl_u.pl_i.pl_version, PMC_VERSION_MAJOR);
			break;

		case PMCLOG_TYPE_MAP_IN:
			/*
			 * Introduce an address range mapping for a
			 * userland process or the kernel (pid == -1).
			 *
			 * We always allocate a process descriptor so
			 * that subsequent samples seen for this
			 * address range are mapped to the current
			 * object being mapped in.
			 */
			pid = ev.pl_u.pl_mi.pl_pid;
			if (pid == -1)
				pp = pmcstat_kernproc;
			else
				pp = pmcstat_process_lookup(pid,
				    PMCSTAT_ALLOCATE);

			assert(pp != NULL);

			image_path = pmcstat_string_intern(ev.pl_u.pl_mi.
			    pl_pathname);
			image = pmcstat_image_from_path(image_path, pid == -1,
			    &args, plugins);
			if (image->pi_type == PMCSTAT_IMAGE_UNKNOWN)
				pmcstat_image_determine_type(image, &args);
			if (image->pi_type != PMCSTAT_IMAGE_INDETERMINABLE)
				pmcstat_image_link(pp, image,
				    ev.pl_u.pl_mi.pl_start);
			break;

		case PMCLOG_TYPE_MAP_OUT:
			/*
			 * Remove an address map.
			 */
			pid = ev.pl_u.pl_mo.pl_pid;
			if (pid == -1)
				pp = pmcstat_kernproc;
			else
				pp = pmcstat_process_lookup(pid, 0);

			if (pp == NULL)	/* unknown process */
				break;

			pmcstat_image_unmap(pp, ev.pl_u.pl_mo.pl_start,
			    ev.pl_u.pl_mo.pl_end);
			break;

		case PMCLOG_TYPE_PCSAMPLE:
			/*
			 * Note: the `PCSAMPLE' log entry is not
			 * generated by hpwmc(4) after version 2.
			 */

			/*
			 * We bring in the gmon file for the image
			 * currently associated with the PMC & pid
			 * pair and increment the appropriate entry
			 * bin inside this.
			 */
			pmcstat_stats.ps_samples_total++;
			ps_samples_period++;

			pc = ev.pl_u.pl_s.pl_pc;
			pp = pmcstat_process_lookup(ev.pl_u.pl_s.pl_pid,
			    PMCSTAT_ALLOCATE);

			/* Get PMC record. */
			pmcr = pmcstat_lookup_pmcid(ev.pl_u.pl_s.pl_pmcid);
			assert(pmcr != NULL);
			pmcr->pr_samples++;

			/*
			 * Call the plugins processing
			 * TODO: move pmcstat_process_find_map inside plugins
			 */

			if (plugins[args.pa_pplugin].pl_process != NULL)
				plugins[args.pa_pplugin].pl_process(
				    pp, pmcr, 1, &pc,
				    pmcstat_process_find_map(pp, pc) != NULL, 0);
			plugins[args.pa_plugin].pl_process(
			    pp, pmcr, 1, &pc,
			    pmcstat_process_find_map(pp, pc) != NULL, 0);
			break;

		case PMCLOG_TYPE_CALLCHAIN:
			pmcstat_stats.ps_samples_total++;
			ps_samples_period++;

			cpuflags = ev.pl_u.pl_cc.pl_cpuflags;
			cpu = PMC_CALLCHAIN_CPUFLAGS_TO_CPU(cpuflags);

			/* Filter on the CPU id. */
			if (!CPU_ISSET(cpu, &(args.pa_cpumask))) {
				pmcstat_stats.ps_samples_skipped++;
				break;
			}

			pp = pmcstat_process_lookup(ev.pl_u.pl_cc.pl_pid,
			    PMCSTAT_ALLOCATE);

			/* Get PMC record. */
			pmcr = pmcstat_lookup_pmcid(ev.pl_u.pl_cc.pl_pmcid);
			assert(pmcr != NULL);
			pmcr->pr_samples++;

			/*
			 * Call the plugins processing
			 */

			if (plugins[args.pa_pplugin].pl_process != NULL)
				plugins[args.pa_pplugin].pl_process(
				    pp, pmcr,
				    ev.pl_u.pl_cc.pl_npc,
				    ev.pl_u.pl_cc.pl_pc,
				    PMC_CALLCHAIN_CPUFLAGS_TO_USERMODE(cpuflags),
				    cpu);
			plugins[args.pa_plugin].pl_process(
			    pp, pmcr,
			    ev.pl_u.pl_cc.pl_npc,
			    ev.pl_u.pl_cc.pl_pc,
			    PMC_CALLCHAIN_CPUFLAGS_TO_USERMODE(cpuflags),
			    cpu);
			break;

		case PMCLOG_TYPE_PMCALLOCATE:
			/*
			 * Record the association pmc id between this
			 * PMC and its name.
			 */
			pmcstat_pmcid_add(ev.pl_u.pl_a.pl_pmcid,
			    pmcstat_string_intern(ev.pl_u.pl_a.pl_evname));
			break;

		case PMCLOG_TYPE_PMCALLOCATEDYN:
			/*
			 * Record the association pmc id between this
			 * PMC and its name.
			 */
			pmcstat_pmcid_add(ev.pl_u.pl_ad.pl_pmcid,
			    pmcstat_string_intern(ev.pl_u.pl_ad.pl_evname));
			break;

		case PMCLOG_TYPE_PROCEXEC:
			/*
			 * Change the executable image associated with
			 * a process.
			 */
			pp = pmcstat_process_lookup(ev.pl_u.pl_x.pl_pid,
			    PMCSTAT_ALLOCATE);

			/* delete the current process map */
			TAILQ_FOREACH_SAFE(ppm, &pp->pp_map, ppm_next, ppmtmp) {
				TAILQ_REMOVE(&pp->pp_map, ppm, ppm_next);
				free(ppm);
			}

			/*
			 * Associate this process image.
			 */
			image_path = pmcstat_string_intern(
				ev.pl_u.pl_x.pl_pathname);
			assert(image_path != NULL);
			pmcstat_process_exec(pp, image_path,
			    ev.pl_u.pl_x.pl_entryaddr, &args,
			    plugins, &pmcstat_stats);
			break;

		case PMCLOG_TYPE_PROCEXIT:

			/*
			 * Due to the way the log is generated, the
			 * last few samples corresponding to a process
			 * may appear in the log after the process
			 * exit event is recorded.  Thus we keep the
			 * process' descriptor and associated data
			 * structures around, but mark the process as
			 * having exited.
			 */
			pp = pmcstat_process_lookup(ev.pl_u.pl_e.pl_pid, 0);
			if (pp == NULL)
				break;
			pp->pp_isactive = 0;	/* mark as a zombie */
			break;

		case PMCLOG_TYPE_SYSEXIT:
			pp = pmcstat_process_lookup(ev.pl_u.pl_se.pl_pid, 0);
			if (pp == NULL)
				break;
			pp->pp_isactive = 0;	/* make a zombie */
			break;

		case PMCLOG_TYPE_PROCFORK:

			/*
			 * Allocate a process descriptor for the new
			 * (child) process.
			 */
			ppnew =
			    pmcstat_process_lookup(ev.pl_u.pl_f.pl_newpid,
				PMCSTAT_ALLOCATE);

			/*
			 * If we had been tracking the parent, clone
			 * its address maps.
			 */
			pp = pmcstat_process_lookup(ev.pl_u.pl_f.pl_oldpid, 0);
			if (pp == NULL)
				break;
			TAILQ_FOREACH(ppm, &pp->pp_map, ppm_next)
			    pmcstat_image_link(ppnew, ppm->ppm_image,
				ppm->ppm_lowpc);
			break;
		case PMCLOG_TYPE_TRACE:
			pt = SLIST_FIRST(&args.pa_targets);
			if (pt != NULL) {
				pp = pmcstat_process_lookup(pt->pt_pid, 0);
				printf("pid %d\n", pt->pt_pid);
			} else {
				pp = pmcstat_kernproc;
			}

			ipt_process(pp, ev.pl_u.pl_tr.pl_cpu, ev.pl_u.pl_tr.pl_cycle, ev.pl_u.pl_tr.pl_offset);
			break;

		default:	/* other types of entries are not relevant */
			break;
		}
	}

	if (ev.pl_state == PMCLOG_EOF)
		return (PMCSTAT_FINISHED);
	else if (ev.pl_state == PMCLOG_REQUIRE_DATA)
		return (PMCSTAT_RUNNING);

	err(EX_DATAERR,
	    "ERROR: event parsing failed (record %jd, offset 0x%jx)",
	    (uintmax_t) ev.pl_count + 1, ev.pl_offset);
}

/*
 * Print log entries as text.
 */

static int
pmcstat_print_log(void)
{
	struct pmclog_ev ev;
	uint32_t npc;

	while (pmclog_read(args.pa_logparser, &ev) == 0) {
		assert(ev.pl_state == PMCLOG_OK);
		switch (ev.pl_type) {
		case PMCLOG_TYPE_CALLCHAIN:
			PMCSTAT_PRINT_ENTRY("callchain",
			    "%d 0x%x %d %d %c", ev.pl_u.pl_cc.pl_pid,
			    ev.pl_u.pl_cc.pl_pmcid,
			    PMC_CALLCHAIN_CPUFLAGS_TO_CPU(ev.pl_u.pl_cc. \
				pl_cpuflags), ev.pl_u.pl_cc.pl_npc,
			    PMC_CALLCHAIN_CPUFLAGS_TO_USERMODE(ev.pl_u.pl_cc.\
			        pl_cpuflags) ? 'u' : 's');
			for (npc = 0; npc < ev.pl_u.pl_cc.pl_npc; npc++)
				PMCSTAT_PRINT_ENTRY("...", "%p",
				    (void *) ev.pl_u.pl_cc.pl_pc[npc]);
			break;
		case PMCLOG_TYPE_CLOSELOG:
			PMCSTAT_PRINT_ENTRY("closelog",);
			break;
		case PMCLOG_TYPE_DROPNOTIFY:
			PMCSTAT_PRINT_ENTRY("drop",);
			break;
		case PMCLOG_TYPE_INITIALIZE:
			PMCSTAT_PRINT_ENTRY("initlog","0x%x \"%s\"",
			    ev.pl_u.pl_i.pl_version,
			    pmc_name_of_cputype(ev.pl_u.pl_i.pl_arch));
			if ((ev.pl_u.pl_i.pl_version & 0xFF000000) !=
			    PMC_VERSION_MAJOR << 24 && args.pa_verbosity > 0)
				warnx(
"WARNING: Log version 0x%x != expected version 0x%x.",
				    ev.pl_u.pl_i.pl_version, PMC_VERSION);
			break;
		case PMCLOG_TYPE_MAP_IN:
			PMCSTAT_PRINT_ENTRY("map-in","%d %p \"%s\"",
			    ev.pl_u.pl_mi.pl_pid,
			    (void *) ev.pl_u.pl_mi.pl_start,
			    ev.pl_u.pl_mi.pl_pathname);
			break;
		case PMCLOG_TYPE_MAP_OUT:
			PMCSTAT_PRINT_ENTRY("map-out","%d %p %p",
			    ev.pl_u.pl_mo.pl_pid,
			    (void *) ev.pl_u.pl_mo.pl_start,
			    (void *) ev.pl_u.pl_mo.pl_end);
			break;
		case PMCLOG_TYPE_PCSAMPLE:
			PMCSTAT_PRINT_ENTRY("sample","0x%x %d %p %c",
			    ev.pl_u.pl_s.pl_pmcid,
			    ev.pl_u.pl_s.pl_pid,
			    (void *) ev.pl_u.pl_s.pl_pc,
			    ev.pl_u.pl_s.pl_usermode ? 'u' : 's');
			break;
		case PMCLOG_TYPE_PMCALLOCATE:
			PMCSTAT_PRINT_ENTRY("allocate","0x%x \"%s\" 0x%x",
			    ev.pl_u.pl_a.pl_pmcid,
			    ev.pl_u.pl_a.pl_evname,
			    ev.pl_u.pl_a.pl_flags);
			break;
		case PMCLOG_TYPE_PMCALLOCATEDYN:
			PMCSTAT_PRINT_ENTRY("allocatedyn","0x%x \"%s\" 0x%x",
			    ev.pl_u.pl_ad.pl_pmcid,
			    ev.pl_u.pl_ad.pl_evname,
			    ev.pl_u.pl_ad.pl_flags);
			break;
		case PMCLOG_TYPE_PMCATTACH:
			PMCSTAT_PRINT_ENTRY("attach","0x%x %d \"%s\"",
			    ev.pl_u.pl_t.pl_pmcid,
			    ev.pl_u.pl_t.pl_pid,
			    ev.pl_u.pl_t.pl_pathname);
			break;
		case PMCLOG_TYPE_PMCDETACH:
			PMCSTAT_PRINT_ENTRY("detach","0x%x %d",
			    ev.pl_u.pl_d.pl_pmcid,
			    ev.pl_u.pl_d.pl_pid);
			break;
		case PMCLOG_TYPE_PROCCSW:
			PMCSTAT_PRINT_ENTRY("cswval","0x%x %d %jd",
			    ev.pl_u.pl_c.pl_pmcid,
			    ev.pl_u.pl_c.pl_pid,
			    ev.pl_u.pl_c.pl_value);
			break;
		case PMCLOG_TYPE_PROCEXEC:
			PMCSTAT_PRINT_ENTRY("exec","0x%x %d %p \"%s\"",
			    ev.pl_u.pl_x.pl_pmcid,
			    ev.pl_u.pl_x.pl_pid,
			    (void *) ev.pl_u.pl_x.pl_entryaddr,
			    ev.pl_u.pl_x.pl_pathname);
			break;
		case PMCLOG_TYPE_PROCEXIT:
			PMCSTAT_PRINT_ENTRY("exitval","0x%x %d %jd",
			    ev.pl_u.pl_e.pl_pmcid,
			    ev.pl_u.pl_e.pl_pid,
			    ev.pl_u.pl_e.pl_value);
			break;
		case PMCLOG_TYPE_PROCFORK:
			PMCSTAT_PRINT_ENTRY("fork","%d %d",
			    ev.pl_u.pl_f.pl_oldpid,
			    ev.pl_u.pl_f.pl_newpid);
			break;
		case PMCLOG_TYPE_USERDATA:
			PMCSTAT_PRINT_ENTRY("userdata","0x%x",
			    ev.pl_u.pl_u.pl_userdata);
			break;
		case PMCLOG_TYPE_SYSEXIT:
			PMCSTAT_PRINT_ENTRY("exit","%d",
			    ev.pl_u.pl_se.pl_pid);
			break;
		case PMCLOG_TYPE_TRACE:
			PMCSTAT_PRINT_ENTRY("trace","cpu: %d, cycle: %d, offset: %ld",
			    ev.pl_u.pl_tr.pl_cpu,
			    ev.pl_u.pl_tr.pl_cycle,
			    ev.pl_u.pl_tr.pl_offset);
			break;
		default:
			printf("event %d\n", ev.pl_type);
			fprintf(args.pa_printfile, "unknown event (type %d).\n",
			    ev.pl_type);
		}
	}

	if (ev.pl_state == PMCLOG_EOF)
		return (PMCSTAT_FINISHED);
	else if (ev.pl_state == PMCLOG_REQUIRE_DATA)
		return (PMCSTAT_RUNNING);

	errx(EX_DATAERR,
	    "ERROR: event parsing failed (record %jd, offset 0x%jx, type %d, PMCLOG_TYPE_TRACE %d).",
	    (uintmax_t) ev.pl_count + 1, ev.pl_offset, ev.pl_type, PMCLOG_TYPE_TRACE);
	/*NOTREACHED*/
}

/*
 * Public Interfaces.
 */

/*
 * Close a logfile, after first flushing all in-module queued data.
 */

int
pmcstat_close_log(void)
{
	/* If a local logfile is configured ask the kernel to stop
	 * and flush data. Kernel will close the file when data is flushed
	 * so keep the status to EXITING.
	 */
	if (args.pa_logfd != -1) {
		if (pmc_close_logfile() < 0)
			err(EX_OSERR, "ERROR: logging failed");
	}

	return (args.pa_flags & FLAG_HAS_PIPE ? PMCSTAT_EXITING :
	    PMCSTAT_FINISHED);
}



/*
 * Open a log file, for reading or writing.
 *
 * The function returns the fd of a successfully opened log or -1 in
 * case of failure.
 */

int
pmcstat_open_log(const char *path, int mode)
{
	int error, fd, cfd;
	size_t hlen;
	const char *p, *errstr;
	struct addrinfo hints, *res, *res0;
	char hostname[MAXHOSTNAMELEN];

	errstr = NULL;
	fd = -1;

	/*
	 * If 'path' is "-" then open one of stdin or stdout depending
	 * on the value of 'mode'.
	 *
	 * If 'path' contains a ':' and does not start with a '/' or '.',
	 * and is being opened for writing, treat it as a "host:port"
	 * specification and open a network socket.
	 *
	 * Otherwise, treat 'path' as a file name and open that.
	 */
	if (path[0] == '-' && path[1] == '\0')
		fd = (mode == PMCSTAT_OPEN_FOR_READ) ? 0 : 1;
	else if (path[0] != '/' &&
	    path[0] != '.' && strchr(path, ':') != NULL) {

		p = strrchr(path, ':');
		hlen = p - path;
		if (p == path || hlen >= sizeof(hostname)) {
			errstr = strerror(EINVAL);
			goto done;
		}

		assert(hlen < sizeof(hostname));
		(void) strncpy(hostname, path, hlen);
		hostname[hlen] = '\0';

		(void) memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		if ((error = getaddrinfo(hostname, p+1, &hints, &res0)) != 0) {
			errstr = gai_strerror(error);
			goto done;
		}

		fd = -1;
		for (res = res0; res; res = res->ai_next) {
			if ((fd = socket(res->ai_family, res->ai_socktype,
			    res->ai_protocol)) < 0) {
				errstr = strerror(errno);
				continue;
			}
			if (mode == PMCSTAT_OPEN_FOR_READ) {
				if (bind(fd, res->ai_addr, res->ai_addrlen) < 0) {
					errstr = strerror(errno);
					(void) close(fd);
					fd = -1;
					continue;
				}
				listen(fd, 1);
				cfd = accept(fd, NULL, NULL);
				(void) close(fd);
				if (cfd < 0) {
					errstr = strerror(errno);
					fd = -1;
					break;
				}
				fd = cfd;
			} else {
				if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
					errstr = strerror(errno);
					(void) close(fd);
					fd = -1;
					continue;
				}
			}
			errstr = NULL;
			break;
		}
		freeaddrinfo(res0);

	} else if ((fd = open(path, mode == PMCSTAT_OPEN_FOR_READ ?
		    O_RDONLY : (O_WRONLY|O_CREAT|O_TRUNC),
		    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) < 0)
			errstr = strerror(errno);

  done:
	if (errstr)
		errx(EX_OSERR, "ERROR: Cannot open \"%s\" for %s: %s.", path,
		    (mode == PMCSTAT_OPEN_FOR_READ ? "reading" : "writing"),
		    errstr);

	return (fd);
}

/*
 * Process a log file in offline analysis mode.
 */

int
pmcstat_process_log(void)
{

	/*
	 * If analysis has not been asked for, just print the log to
	 * the current output file.
	 */
	if (args.pa_flags & FLAG_DO_PRINT)
		return (pmcstat_print_log());
	else
		return (pmcstat_analyze_log());
}

/*
 * Refresh top display.
 */

static void
pmcstat_refresh_top(void)
{
	int v_attrs;
	float v;
	char pmcname[40];
	struct pmcstat_pmcrecord *pmcpr;

	/* If in pause mode do not refresh display. */
	if (pmcstat_pause)
		return;

	/* Wait until PMC pop in the log. */
	pmcpr = pmcstat_pmcindex_to_pmcr(pmcstat_pmcinfilter);
	if (pmcpr == NULL)
		return;

	/* Format PMC name. */
	if (pmcstat_mergepmc)
		snprintf(pmcname, sizeof(pmcname), "[%s]",
		    pmcstat_string_unintern(pmcpr->pr_pmcname));
	else
		snprintf(pmcname, sizeof(pmcname), "%s.%d",
		    pmcstat_string_unintern(pmcpr->pr_pmcname),
		    pmcstat_pmcinfilter);

	/* Format samples count. */
	if (ps_samples_period > 0)
		v = (pmcpr->pr_samples * 100.0) / ps_samples_period;
	else
		v = 0.;
	v_attrs = PMCSTAT_ATTRPERCENT(v);

	PMCSTAT_PRINTBEGIN();
	PMCSTAT_PRINTW("PMC: %s Samples: %u ",
	    pmcname,
	    pmcpr->pr_samples);
	PMCSTAT_ATTRON(v_attrs);
	PMCSTAT_PRINTW("(%.1f%%) ", v);
	PMCSTAT_ATTROFF(v_attrs);
	PMCSTAT_PRINTW(", %u unresolved\n\n",
	    pmcpr->pr_dubious_frames);
	if (plugins[args.pa_plugin].pl_topdisplay != NULL)
		plugins[args.pa_plugin].pl_topdisplay();
	PMCSTAT_PRINTEND();
}

/*
 * Find the next pmc index to display.
 */

static void
pmcstat_changefilter(void)
{
	int pmcin;
	struct pmcstat_pmcrecord *pmcr;

	/*
	 * Find the next merge target.
	 */
	if (pmcstat_mergepmc) {
		pmcin = pmcstat_pmcinfilter;

		do {
			pmcr = pmcstat_pmcindex_to_pmcr(pmcstat_pmcinfilter);
			if (pmcr == NULL || pmcr == pmcr->pr_merge)
				break;

			pmcstat_pmcinfilter++;
			if (pmcstat_pmcinfilter >= pmcstat_npmcs)
				pmcstat_pmcinfilter = 0;

		} while (pmcstat_pmcinfilter != pmcin);
	}
}

/*
 * Top mode keypress.
 */

int
pmcstat_keypress_log(void)
{
	int c, ret = 0;
	WINDOW *w;

	w = newwin(1, 0, 1, 0);
	c = wgetch(w);
	wprintw(w, "Key: %c => ", c);
	switch (c) {
	case 'c':
		wprintw(w, "enter mode 'd' or 'a' => ");
		c = wgetch(w);
		if (c == 'd') {
			args.pa_topmode = PMCSTAT_TOP_DELTA;
			wprintw(w, "switching to delta mode");
		} else {
			args.pa_topmode = PMCSTAT_TOP_ACCUM;
			wprintw(w, "switching to accumulation mode");
		}
		break;
	case 'm':
		pmcstat_mergepmc = !pmcstat_mergepmc;
		/*
		 * Changing merge state require data reset.
		 */
		if (plugins[args.pa_plugin].pl_shutdown != NULL)
			plugins[args.pa_plugin].pl_shutdown(NULL);
		pmcstat_stats_reset(0);
		if (plugins[args.pa_plugin].pl_init != NULL)
			plugins[args.pa_plugin].pl_init();

		/* Update filter to be on a merge target. */
		pmcstat_changefilter();
		wprintw(w, "merge PMC %s", pmcstat_mergepmc ? "on" : "off");
		break;
	case 'n':
		/* Close current plugin. */
		if (plugins[args.pa_plugin].pl_shutdown != NULL)
			plugins[args.pa_plugin].pl_shutdown(NULL);

		/* Find next top display available. */
		do {
			args.pa_plugin++;
			if (plugins[args.pa_plugin].pl_name == NULL)
				args.pa_plugin = 0;
		} while (plugins[args.pa_plugin].pl_topdisplay == NULL);

		/* Open new plugin. */
		pmcstat_stats_reset(0);
		if (plugins[args.pa_plugin].pl_init != NULL)
			plugins[args.pa_plugin].pl_init();
		wprintw(w, "switching to plugin %s",
		    plugins[args.pa_plugin].pl_name);
		break;
	case 'p':
		pmcstat_pmcinfilter++;
		if (pmcstat_pmcinfilter >= pmcstat_npmcs)
			pmcstat_pmcinfilter = 0;
		pmcstat_changefilter();
		wprintw(w, "switching to PMC %s.%d",
		    pmcstat_pmcindex_to_name(pmcstat_pmcinfilter),
		    pmcstat_pmcinfilter);
		break;
	case ' ':
		pmcstat_pause = !pmcstat_pause;
		if (pmcstat_pause)
			wprintw(w, "pause => press space again to continue");
		break;
	case 'q':
		wprintw(w, "exiting...");
		ret = 1;
		break;
	default:
		if (plugins[args.pa_plugin].pl_topkeypress != NULL)
			if (plugins[args.pa_plugin].pl_topkeypress(c, w))
				ret = 1;
	}

	wrefresh(w);
	delwin(w);
	return ret;
}


/*
 * Top mode display.
 */

void
pmcstat_display_log(void)
{

	pmcstat_refresh_top();

	/* Reset everythings if delta mode. */
	if (args.pa_topmode == PMCSTAT_TOP_DELTA) {
		if (plugins[args.pa_plugin].pl_shutdown != NULL)
			plugins[args.pa_plugin].pl_shutdown(NULL);
		pmcstat_stats_reset(0);
		if (plugins[args.pa_plugin].pl_init != NULL)
			plugins[args.pa_plugin].pl_init();
	}

}

/*
 * Configure a plugins.
 */

void
pmcstat_pluginconfigure_log(char *opt)
{

	if (strncmp(opt, "threshold=", 10) == 0) {
		pmcstat_threshold = atof(opt+10);
	} else {
		if (plugins[args.pa_plugin].pl_configure != NULL) {
			if (!plugins[args.pa_plugin].pl_configure(opt))
				err(EX_USAGE,
				    "ERROR: unknown option <%s>.", opt);
		}
	}
}

/*
 * Initialize module.
 */

void
pmcstat_initialize_logging(void)
{
	int i;

	printf("%s\n", __func__);

	/* use a convenient format for 'ldd' output */
	if (setenv("LD_TRACE_LOADED_OBJECTS_FMT1","%o \"%p\" %x\n",1) != 0)
		err(EX_OSERR, "ERROR: Cannot setenv");

	/* Initialize hash tables */
	pmcstat_string_initialize();
	for (i = 0; i < PMCSTAT_NHASH; i++) {
		LIST_INIT(&pmcstat_image_hash[i]);
		LIST_INIT(&pmcstat_process_hash[i]);
	}

	/*
	 * Create a fake 'process' entry for the kernel with pid -1.
	 * hwpmc(4) will subsequently inform us about where the kernel
	 * and any loaded kernel modules are mapped.
	 */
	if ((pmcstat_kernproc = pmcstat_process_lookup((pid_t) -1,
		 PMCSTAT_ALLOCATE)) == NULL)
		err(EX_OSERR, "ERROR: Cannot initialize logging");

	/* PMC count. */
	pmcstat_npmcs = 0;

	/* Merge PMC with same name. */
	pmcstat_mergepmc = args.pa_mergepmc;

	/*
	 * Initialize plugins
	 */

	if (plugins[args.pa_pplugin].pl_init != NULL)
		plugins[args.pa_pplugin].pl_init();
	if (plugins[args.pa_plugin].pl_init != NULL)
		plugins[args.pa_plugin].pl_init();
}

/*
 * Shutdown module.
 */

void
pmcstat_shutdown_logging(void)
{
	int i;
	FILE *mf;
	struct pmcstat_image *pi, *pitmp;
	struct pmcstat_process *pp, *pptmp;
	struct pmcstat_pcmap *ppm, *ppmtmp;

	printf("%s\n", __func__);

	/* determine where to send the map file */
	mf = NULL;
	if (args.pa_mapfilename != NULL)
		mf = (strcmp(args.pa_mapfilename, "-") == 0) ?
		    args.pa_printfile : fopen(args.pa_mapfilename, "w");

	if (mf == NULL && args.pa_flags & FLAG_DO_GPROF &&
	    args.pa_verbosity >= 2)
		mf = args.pa_printfile;

	if (mf)
		(void) fprintf(mf, "MAP:\n");

	/*
	 * Shutdown the plugins
	 */

	if (plugins[args.pa_plugin].pl_shutdown != NULL)
		plugins[args.pa_plugin].pl_shutdown(mf);
	if (plugins[args.pa_pplugin].pl_shutdown != NULL)
		plugins[args.pa_pplugin].pl_shutdown(mf);

	for (i = 0; i < PMCSTAT_NHASH; i++) {
		LIST_FOREACH_SAFE(pi, &pmcstat_image_hash[i], pi_next,
		    pitmp) {
			if (plugins[args.pa_plugin].pl_shutdownimage != NULL)
				plugins[args.pa_plugin].pl_shutdownimage(pi);
			if (plugins[args.pa_pplugin].pl_shutdownimage != NULL)
				plugins[args.pa_pplugin].pl_shutdownimage(pi);

			free(pi->pi_symbols);
			if (pi->pi_addr2line != NULL)
				pclose(pi->pi_addr2line);
			LIST_REMOVE(pi, pi_next);
			free(pi);
		}

		LIST_FOREACH_SAFE(pp, &pmcstat_process_hash[i], pp_next,
		    pptmp) {
			TAILQ_FOREACH_SAFE(ppm, &pp->pp_map, ppm_next, ppmtmp) {
				TAILQ_REMOVE(&pp->pp_map, ppm, ppm_next);
				free(ppm);
			}
			LIST_REMOVE(pp, pp_next);
			free(pp);
		}
	}

	pmcstat_string_shutdown();

	/*
	 * Print errors unless -q was specified.  Print all statistics
	 * if verbosity > 1.
	 */
#define	PRINT(N,V) do {							\
		if (pmcstat_stats.ps_##V || args.pa_verbosity >= 2)	\
			(void) fprintf(args.pa_printfile, " %-40s %d\n",\
			    N, pmcstat_stats.ps_##V);			\
	} while (0)

	if (args.pa_verbosity >= 1 && (args.pa_flags & FLAG_DO_ANALYSIS)) {
		(void) fprintf(args.pa_printfile, "CONVERSION STATISTICS:\n");
		PRINT("#exec/a.out", exec_aout);
		PRINT("#exec/elf", exec_elf);
		PRINT("#exec/unknown", exec_indeterminable);
		PRINT("#exec handling errors", exec_errors);
		PRINT("#samples/total", samples_total);
		PRINT("#samples/unclaimed", samples_unknown_offset);
		PRINT("#samples/unknown-object", samples_indeterminable);
		PRINT("#samples/unknown-function", samples_unknown_function);
		PRINT("#callchain/dubious-frames", callchain_dubious_frames);
	}

	if (mf)
		(void) fclose(mf);
}
