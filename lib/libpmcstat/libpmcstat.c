/*-
 * Copyright (c) 2003-2008 Joseph Koshy
 * All rights reserved.
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

#include <sys/types.h>
#include <sys/cpuset.h>
#include <sys/event.h>
#include <sys/param.h>
#include <sys/endian.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/module.h>
#include <sys/pmc.h>
#include <sys/syscall.h>
#include <sys/queue.h>
#include <sys/imgact_aout.h>
#include <sys/imgact_elf.h>

#include <netinet/in.h>

#include <assert.h>
#include <ctype.h>
#include <curses.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <limits.h>
#include <netdb.h>
#include <pmc.h>
#include <pmclog.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sysexits.h>
#include <unistd.h>

#include "libpmcstat.h"

struct pmcstat_symbol *
pmcstat_name_to_addr(struct pmcstat_process *pp, const char *pi_name,
    const char *name, uintptr_t *addr_start, uintptr_t *addr_end)
{
	struct pmcstat_symbol *sym;
	struct pmcstat_image *image;
	struct pmcstat_pcmap *pcm;
	const char *name1;
	const char *name2;
	bool found;
	size_t i;

	found = 0;

	if (pp == NULL)
		return (NULL);

	TAILQ_FOREACH(pcm, &pp->pp_map, ppm_next) {
		image = pcm->ppm_image;
		if (image->pi_name == NULL)
			continue;
		name1 = pmcstat_string_unintern(image->pi_name);
		if (strcmp(name1, pi_name) == 0) {
			found = 1;
			break;
		}
	}

	if (!found || image->pi_symbols == NULL)
		return (NULL);

	found = 0;

	for (i = 0; i < image->pi_symcount; i++) {
		sym = &image->pi_symbols[i];
		name2 = pmcstat_string_unintern(sym->ps_name);
		if (strcmp(name2, name) == 0) {
			found = 1;
			break;
		}
	}

	if (!found)
		return (NULL);

	*addr_start = (image->pi_vaddr - image->pi_start +
	    pcm->ppm_lowpc + sym->ps_start);
	*addr_end = (image->pi_vaddr - image->pi_start +
	    pcm->ppm_lowpc + sym->ps_end);

	return (sym);
}

/*
 * Helper function.
 */

int
pmcstat_symbol_compare(const void *a, const void *b)
{
	const struct pmcstat_symbol *sym1, *sym2;

	sym1 = (const struct pmcstat_symbol *) a;
	sym2 = (const struct pmcstat_symbol *) b;

	if (sym1->ps_end <= sym2->ps_start)
		return (-1);
	if (sym1->ps_start >= sym2->ps_end)
		return (1);
	return (0);
}

/*
 * Map an address to a symbol in an image.
 */

struct pmcstat_symbol *
pmcstat_symbol_search(struct pmcstat_image *image, uintfptr_t addr)
{
	struct pmcstat_symbol sym;

	if (image->pi_symbols == NULL)
		return (NULL);

	sym.ps_name  = NULL;
	sym.ps_start = addr;
	sym.ps_end   = addr + 1;

	return (bsearch((void *) &sym, image->pi_symbols,
	    image->pi_symcount, sizeof(struct pmcstat_symbol),
	    pmcstat_symbol_compare));
}

/*
 * Add the list of symbols in the given section to the list associated
 * with the object.
 */
void
pmcstat_image_add_symbols(struct pmcstat_image *image, Elf *e,
    Elf_Scn *scn, GElf_Shdr *sh)
{
	int firsttime;
	size_t n, newsyms, nshsyms, nfuncsyms;
	struct pmcstat_symbol *symptr;
	char *fnname;
	GElf_Sym sym;
	Elf_Data *data;

	if ((data = elf_getdata(scn, NULL)) == NULL)
		return;

	/*
	 * Determine the number of functions named in this
	 * section.
	 */

	nshsyms = sh->sh_size / sh->sh_entsize;
	for (n = nfuncsyms = 0; n < nshsyms; n++) {
		if (gelf_getsym(data, (int) n, &sym) != &sym)
			return;
		if (GELF_ST_TYPE(sym.st_info) == STT_FUNC)
			nfuncsyms++;
	}

	if (nfuncsyms == 0)
		return;

	/*
	 * Allocate space for the new entries.
	 */
	firsttime = image->pi_symbols == NULL;
	symptr = reallocarray(image->pi_symbols,
	    image->pi_symcount + nfuncsyms, sizeof(*symptr));
	if (symptr == image->pi_symbols) /* realloc() failed. */
		return;
	image->pi_symbols = symptr;

	/*
	 * Append new symbols to the end of the current table.
	 */
	symptr += image->pi_symcount;

	for (n = newsyms = 0; n < nshsyms; n++) {
		if (gelf_getsym(data, (int) n, &sym) != &sym)
			return;
		if (GELF_ST_TYPE(sym.st_info) != STT_FUNC)
			continue;

		if (sym.st_shndx == STN_UNDEF)
			continue;

		if (!firsttime && pmcstat_symbol_search(image, sym.st_value))
			continue; /* We've seen this symbol already. */

		if ((fnname = elf_strptr(e, sh->sh_link, sym.st_name))
		    == NULL)
			continue;
#ifdef __arm__
		/* Remove spurious ARM function name. */
		if (fnname[0] == '$' &&
		    (fnname[1] == 'a' || fnname[1] == 't' ||
		    fnname[1] == 'd') &&
		    fnname[2] == '\0')
			continue;
#endif

		symptr->ps_name  = pmcstat_string_intern(fnname);
		symptr->ps_start = sym.st_value - image->pi_vaddr;
		symptr->ps_end   = symptr->ps_start + sym.st_size;

		symptr++;
		newsyms++;
	}

	image->pi_symcount += newsyms;
	if (image->pi_symcount == 0)
		return;

	assert(newsyms <= nfuncsyms);

	/*
	 * Return space to the system if there were duplicates.
	 */
	if (newsyms < nfuncsyms)
		image->pi_symbols = reallocarray(image->pi_symbols,
		    image->pi_symcount, sizeof(*symptr));

	/*
	 * Keep the list of symbols sorted.
	 */
	qsort(image->pi_symbols, image->pi_symcount, sizeof(*symptr),
	    pmcstat_symbol_compare);

	/*
	 * Deal with function symbols that have a size of 'zero' by
	 * making them extend to the next higher address.  These
	 * symbols are usually defined in assembly code.
	 */
	for (symptr = image->pi_symbols;
	     symptr < image->pi_symbols + (image->pi_symcount - 1);
	     symptr++)
		if (symptr->ps_start == symptr->ps_end)
			symptr->ps_end = (symptr+1)->ps_start;
}

/*
 * Intern a copy of string 's', and return a pointer to the
 * interned structure.
 */

pmcstat_interned_string
pmcstat_string_intern(const char *s)
{
	struct pmcstat_string *ps;
	const struct pmcstat_string *cps;
	int hash, len;

	if ((cps = pmcstat_string_lookup(s)) != NULL)
		return (cps);

	hash = pmcstat_string_compute_hash(s);
	len  = strlen(s);

	if ((ps = malloc(sizeof(*ps))) == NULL)
		err(EX_OSERR, "ERROR: Could not intern string");
	ps->ps_len = len;
	ps->ps_hash = hash;
	ps->ps_string = strdup(s);
	LIST_INSERT_HEAD(&pmcstat_string_hash[hash], ps, ps_next);
	return ((pmcstat_interned_string) ps);
}

const char *
pmcstat_string_unintern(pmcstat_interned_string str)
{
	const char *s;

	s = ((const struct pmcstat_string *) str)->ps_string;
	return (s);
}

/*
 * Compute a 'hash' value for a string.
 */

int
pmcstat_string_compute_hash(const char *s)
{
	unsigned hash;

	for (hash = 2166136261; *s; s++)
		hash = (hash ^ *s) * 16777619;

	return (hash & PMCSTAT_HASH_MASK);
}

pmcstat_interned_string
pmcstat_string_lookup(const char *s)
{
	struct pmcstat_string *ps;
	int hash, len;

	hash = pmcstat_string_compute_hash(s);
	len = strlen(s);

	LIST_FOREACH(ps, &pmcstat_string_hash[hash], ps_next)
	    if (ps->ps_len == len && ps->ps_hash == hash &&
		strcmp(ps->ps_string, s) == 0)
		    return (ps);
	return (NULL);
}

/*
 * Examine an ELF file to determine the size of its text segment.
 * Sets image->pi_type if anything conclusive can be determined about
 * this image.
 */

void
pmcstat_image_get_elf_params(struct pmcstat_image *image,
    struct pmcstat_args *args)
{
	int fd;
	size_t i, nph, nsh;
	const char *path, *elfbase;
	char *p, *endp;
	uintfptr_t minva, maxva;
	Elf *e;
	Elf_Scn *scn;
	GElf_Ehdr eh;
	GElf_Phdr ph;
	GElf_Shdr sh;
	enum pmcstat_image_type image_type;
	char buffer[PATH_MAX];

	assert(image->pi_type == PMCSTAT_IMAGE_UNKNOWN);

	image->pi_start = minva = ~(uintfptr_t) 0;
	image->pi_end = maxva = (uintfptr_t) 0;
	image->pi_type = image_type = PMCSTAT_IMAGE_INDETERMINABLE;
	image->pi_isdynamic = 0;
	image->pi_dynlinkerpath = NULL;
	image->pi_vaddr = 0;

	path = pmcstat_string_unintern(image->pi_execpath);
	assert(path != NULL);

	/*
	 * Look for kernel modules under FSROOT/KERNELPATH/NAME,
	 * and user mode executable objects under FSROOT/PATHNAME.
	 */
	if (image->pi_iskernelmodule)
		(void) snprintf(buffer, sizeof(buffer), "%s%s/%s",
		    args->pa_fsroot, args->pa_kernel, path);
	else
		(void) snprintf(buffer, sizeof(buffer), "%s%s",
		    args->pa_fsroot, path);

	e = NULL;
	if ((fd = open(buffer, O_RDONLY, 0)) < 0) {
		warnx("WARNING: Cannot open \"%s\".",
		    buffer);
		goto done;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		warnx("WARNING: failed to init elf\n");
		goto done;
	}

	if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
		warnx("WARNING: Cannot read \"%s\".",
		    buffer);
		goto done;
	}

	if (elf_kind(e) != ELF_K_ELF) {
		if (args->pa_verbosity >= 2)
			warnx("WARNING: Cannot determine the type of \"%s\".",
			    buffer);
		goto done;
	}

	if (gelf_getehdr(e, &eh) != &eh) {
		warnx(
		    "WARNING: Cannot retrieve the ELF Header for \"%s\": %s.",
		    buffer, elf_errmsg(-1));
		goto done;
	}

	if (eh.e_type != ET_EXEC && eh.e_type != ET_DYN &&
	    !(image->pi_iskernelmodule && eh.e_type == ET_REL)) {
		warnx("WARNING: \"%s\" is of an unsupported ELF type.",
		    buffer);
		goto done;
	}

	image_type = eh.e_ident[EI_CLASS] == ELFCLASS32 ?
	    PMCSTAT_IMAGE_ELF32 : PMCSTAT_IMAGE_ELF64;

	/*
	 * Determine the virtual address where an executable would be
	 * loaded.  Additionally, for dynamically linked executables,
	 * save the pathname to the runtime linker.
	 */
	if (eh.e_type == ET_EXEC) {
		if (elf_getphnum(e, &nph) == 0) {
			warnx(
"WARNING: Could not determine the number of program headers in \"%s\": %s.",
			    buffer,
			    elf_errmsg(-1));
			goto done;
		}
		for (i = 0; i < eh.e_phnum; i++) {
			if (gelf_getphdr(e, i, &ph) != &ph) {
				warnx(
"WARNING: Retrieval of PHDR entry #%ju in \"%s\" failed: %s.",
				    (uintmax_t) i, buffer, elf_errmsg(-1));
				goto done;
			}
			switch (ph.p_type) {
			case PT_DYNAMIC:
				image->pi_isdynamic = 1;
				break;
			case PT_INTERP:
				if ((elfbase = elf_rawfile(e, NULL)) == NULL) {
					warnx(
"WARNING: Cannot retrieve the interpreter for \"%s\": %s.",
					    buffer, elf_errmsg(-1));
					goto done;
				}
				image->pi_dynlinkerpath =
				    pmcstat_string_intern(elfbase +
				        ph.p_offset);
				break;
			case PT_LOAD:
				if ((ph.p_flags & PF_X) != 0 &&
				    (ph.p_offset & (-ph.p_align)) == 0)
					image->pi_vaddr = ph.p_vaddr & (-ph.p_align);
				break;
			}
		}
	}

	/*
	 * Get the min and max VA associated with this ELF object.
	 */
	if (elf_getshnum(e, &nsh) == 0) {
		warnx(
"WARNING: Could not determine the number of sections for \"%s\": %s.",
		    buffer, elf_errmsg(-1));
		goto done;
	}

	for (i = 0; i < nsh; i++) {
		if ((scn = elf_getscn(e, i)) == NULL ||
		    gelf_getshdr(scn, &sh) != &sh) {
			warnx(
"WARNING: Could not retrieve section header #%ju in \"%s\": %s.",
			    (uintmax_t) i, buffer, elf_errmsg(-1));
			goto done;
		}
		if (sh.sh_flags & SHF_EXECINSTR) {
			minva = min(minva, sh.sh_addr);
			maxva = max(maxva, sh.sh_addr + sh.sh_size);
		}
		if (sh.sh_type == SHT_SYMTAB || sh.sh_type == SHT_DYNSYM)
			pmcstat_image_add_symbols(image, e, scn, &sh);
	}

	image->pi_start = minva;
	image->pi_end   = maxva;
	image->pi_type  = image_type;
	image->pi_fullpath = pmcstat_string_intern(buffer);

	/* Build display name
	 */
	endp = buffer;
	for (p = buffer; *p; p++)
		if (*p == '/')
			endp = p+1;
	image->pi_name = pmcstat_string_intern(endp);

 done:
	(void) elf_end(e);
	if (fd >= 0)
		(void) close(fd);
	return;
}

/*
 * Locate an image descriptor given an interned path, adding a fresh
 * descriptor to the cache if necessary.  This function also finds a
 * suitable name for this image's sample file.
 *
 * We defer filling in the file format specific parts of the image
 * structure till the time we actually see a sample that would fall
 * into this image.
 */

struct pmcstat_image *
pmcstat_image_from_path(pmcstat_interned_string internedpath,
    int iskernelmodule, struct pmcstat_args *args,
    struct pmc_plugins *plugins)
{
	int hash;
	struct pmcstat_image *pi;

	hash = pmcstat_string_lookup_hash(internedpath);

	/* First, look for an existing entry. */
	LIST_FOREACH(pi, &pmcstat_image_hash[hash], pi_next)
	    if (pi->pi_execpath == internedpath &&
		  pi->pi_iskernelmodule == iskernelmodule)
		    return (pi);

	/*
	 * Allocate a new entry and place it at the head of the hash
	 * and LRU lists.
	 */
	pi = malloc(sizeof(*pi));
	if (pi == NULL)
		return (NULL);

	pi->pi_type = PMCSTAT_IMAGE_UNKNOWN;
	pi->pi_execpath = internedpath;
	pi->pi_start = ~0;
	pi->pi_end = 0;
	pi->pi_entry = 0;
	pi->pi_vaddr = 0;
	pi->pi_isdynamic = 0;
	pi->pi_iskernelmodule = iskernelmodule;
	pi->pi_dynlinkerpath = NULL;
	pi->pi_symbols = NULL;
	pi->pi_symcount = 0;
	pi->pi_addr2line = NULL;

	if (plugins[args->pa_pplugin].pl_initimage != NULL)
		plugins[args->pa_pplugin].pl_initimage(pi);
	if (plugins[args->pa_plugin].pl_initimage != NULL)
		plugins[args->pa_plugin].pl_initimage(pi);

	LIST_INSERT_HEAD(&pmcstat_image_hash[hash], pi, pi_next);

	return (pi);
}

int
pmcstat_string_lookup_hash(pmcstat_interned_string s)
{
	const struct pmcstat_string *ps;

	ps = (const struct pmcstat_string *) s;
	return (ps->ps_hash);
}

/*
 * Associate an ELF image with a process.
 */

void
pmcstat_process_elf_exec(struct pmcstat_process *pp,
    struct pmcstat_image *image, uintfptr_t entryaddr,
    struct pmcstat_args *args, struct pmc_plugins *plugins,
    struct pmcstat_stats *pmcstat_stats)
{
	uintmax_t libstart;
	struct pmcstat_image *rtldimage;

	assert(image->pi_type == PMCSTAT_IMAGE_ELF32 ||
	    image->pi_type == PMCSTAT_IMAGE_ELF64);

	/* Create a map entry for the base executable. */
	pmcstat_image_link(pp, image, image->pi_vaddr);

	/*
	 * For dynamically linked executables we need to determine
	 * where the dynamic linker was mapped to for this process,
	 * Subsequent executable objects that are mapped in by the
	 * dynamic linker will be tracked by log events of type
	 * PMCLOG_TYPE_MAP_IN.
	 */

	if (image->pi_isdynamic) {

		/*
		 * The runtime loader gets loaded just after the maximum
		 * possible heap address.  Like so:
		 *
		 * [  TEXT DATA BSS HEAP -->*RTLD  SHLIBS   <--STACK]
		 * ^					            ^
		 * 0				   VM_MAXUSER_ADDRESS

		 *
		 * The exact address where the loader gets mapped in
		 * will vary according to the size of the executable
		 * and the limits on the size of the process'es data
		 * segment at the time of exec().  The entry address
		 * recorded at process exec time corresponds to the
		 * 'start' address inside the dynamic linker.  From
		 * this we can figure out the address where the
		 * runtime loader's file object had been mapped to.
		 */
		rtldimage = pmcstat_image_from_path(image->pi_dynlinkerpath,
		    0, args, plugins);
		if (rtldimage == NULL) {
			warnx("WARNING: Cannot find image for \"%s\".",
			    pmcstat_string_unintern(image->pi_dynlinkerpath));
			pmcstat_stats->ps_exec_errors++;
			return;
		}

		if (rtldimage->pi_type == PMCSTAT_IMAGE_UNKNOWN)
			pmcstat_image_get_elf_params(rtldimage, args);

		if (rtldimage->pi_type != PMCSTAT_IMAGE_ELF32 &&
		    rtldimage->pi_type != PMCSTAT_IMAGE_ELF64) {
			warnx("WARNING: rtld not an ELF object \"%s\".",
			    pmcstat_string_unintern(image->pi_dynlinkerpath));
			return;
		}

		libstart = entryaddr - rtldimage->pi_entry;
		pmcstat_image_link(pp, rtldimage, libstart);
	}
}

/*
 * Record the fact that PC values from 'start' to 'end' come from
 * image 'image'.
 */

void
pmcstat_image_link(struct pmcstat_process *pp, struct pmcstat_image *image,
    uintfptr_t start)
{
	struct pmcstat_pcmap *pcm, *pcmnew;
	uintfptr_t offset;

	assert(image->pi_type != PMCSTAT_IMAGE_UNKNOWN &&
	    image->pi_type != PMCSTAT_IMAGE_INDETERMINABLE);

	warnx("Linking %s: start %lx\n", pmcstat_string_unintern(image->pi_execpath), start);
	if ((pcmnew = malloc(sizeof(*pcmnew))) == NULL)
		err(EX_OSERR, "ERROR: Cannot create a map entry");

	/*
	 * Adjust the map entry to only cover the text portion
	 * of the object.
	 */

	offset = start - image->pi_vaddr;
	pcmnew->ppm_lowpc  = image->pi_start + offset;
	pcmnew->ppm_highpc = image->pi_end + offset;
	pcmnew->ppm_image  = image;

	assert(pcmnew->ppm_lowpc < pcmnew->ppm_highpc);

	/* Overlapped mmap()'s are assumed to never occur. */
	TAILQ_FOREACH(pcm, &pp->pp_map, ppm_next)
	    if (pcm->ppm_lowpc >= pcmnew->ppm_highpc)
		    break;

	if (pcm == NULL)
		TAILQ_INSERT_TAIL(&pp->pp_map, pcmnew, ppm_next);
	else
		TAILQ_INSERT_BEFORE(pcm, pcmnew, ppm_next);
}

/*
 * Associate an AOUT image with a process.
 */

void
pmcstat_process_aout_exec(struct pmcstat_process *pp,
    struct pmcstat_image *image, uintfptr_t entryaddr)
{
	(void) pp;
	(void) image;
	(void) entryaddr;
	/* TODO Implement a.out handling */
}
/*
 * Determine whether a given executable image is an A.OUT object, and
 * if so, fill in its parameters from the text file.
 * Sets image->pi_type.
 */

void
pmcstat_image_get_aout_params(struct pmcstat_image *image,
    struct pmcstat_args *args)
{
	int fd;
	ssize_t nbytes;
	struct exec ex;
	const char *path;
	char buffer[PATH_MAX];

	path = pmcstat_string_unintern(image->pi_execpath);
	assert(path != NULL);

	if (image->pi_iskernelmodule)
		errx(EX_SOFTWARE,
		    "ERROR: a.out kernel modules are unsupported \"%s\"", path);

	(void) snprintf(buffer, sizeof(buffer), "%s%s",
	    args->pa_fsroot, path);

	if ((fd = open(buffer, O_RDONLY, 0)) < 0 ||
	    (nbytes = read(fd, &ex, sizeof(ex))) < 0) {
		if (args->pa_verbosity >= 2)
			warn("WARNING: Cannot determine type of \"%s\"",
			    path);
		image->pi_type = PMCSTAT_IMAGE_INDETERMINABLE;
		if (fd != -1)
			(void) close(fd);
		return;
	}

	(void) close(fd);

	if ((unsigned) nbytes != sizeof(ex) ||
	    N_BADMAG(ex))
		return;

	image->pi_type = PMCSTAT_IMAGE_AOUT;

	/* TODO: the rest of a.out processing */

	return;
}


/*
 * Given an image descriptor, determine whether it is an ELF, or AOUT.
 * If no handler claims the image, set its type to 'INDETERMINABLE'.
 */

void
pmcstat_image_determine_type(struct pmcstat_image *image,
    struct pmcstat_args *args)
{
	assert(image->pi_type == PMCSTAT_IMAGE_UNKNOWN);

	/* Try each kind of handler in turn */
	if (image->pi_type == PMCSTAT_IMAGE_UNKNOWN)
		pmcstat_image_get_elf_params(image, args);
	if (image->pi_type == PMCSTAT_IMAGE_UNKNOWN)
		pmcstat_image_get_aout_params(image, args);

	/*
	 * Otherwise, remember that we tried to determine
	 * the object's type and had failed.
	 */
	if (image->pi_type == PMCSTAT_IMAGE_UNKNOWN)
		image->pi_type = PMCSTAT_IMAGE_INDETERMINABLE;
}

/*
 * Associate an image and a process.
 */

void
pmcstat_process_exec(struct pmcstat_process *pp,
    pmcstat_interned_string path, uintfptr_t entryaddr,
    struct pmcstat_args *args, struct pmc_plugins *plugins,
    struct pmcstat_stats *pmcstat_stats)
{
	struct pmcstat_image *image;

	if ((image = pmcstat_image_from_path(path, 0,
	    args, plugins)) == NULL) {
		pmcstat_stats->ps_exec_errors++;
		return;
	}

	if (image->pi_type == PMCSTAT_IMAGE_UNKNOWN)
		pmcstat_image_determine_type(image, args);

	assert(image->pi_type != PMCSTAT_IMAGE_UNKNOWN);

	switch (image->pi_type) {
	case PMCSTAT_IMAGE_ELF32:
	case PMCSTAT_IMAGE_ELF64:
		pmcstat_stats->ps_exec_elf++;
		pmcstat_process_elf_exec(pp, image, entryaddr,
		    args, plugins, pmcstat_stats);
		break;

	case PMCSTAT_IMAGE_AOUT:
		pmcstat_stats->ps_exec_aout++;
		pmcstat_process_aout_exec(pp, image, entryaddr);
		break;

	case PMCSTAT_IMAGE_INDETERMINABLE:
		pmcstat_stats->ps_exec_indeterminable++;
		break;

	default:
		err(EX_SOFTWARE,
		    "ERROR: Unsupported executable type for \"%s\"",
		    pmcstat_string_unintern(path));
	}
}

/*
 * Find the map entry associated with process 'p' at PC value 'pc'.
 */

struct pmcstat_pcmap *
pmcstat_process_find_map(struct pmcstat_process *p, uintfptr_t pc)
{
	struct pmcstat_pcmap *ppm;

	TAILQ_FOREACH(ppm, &p->pp_map, ppm_next) {
		if (pc >= ppm->ppm_lowpc && pc < ppm->ppm_highpc)
			return (ppm);
		if (pc < ppm->ppm_lowpc)
			return (NULL);
	}

	return (NULL);
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
 * Find the process descriptor corresponding to a PID.  If 'allocate'
 * is zero, we return a NULL if a pid descriptor could not be found or
 * a process descriptor process.  If 'allocate' is non-zero, then we
 * will attempt to allocate a fresh process descriptor.  Zombie
 * process descriptors are only removed if a fresh allocation for the
 * same PID is requested.
 */

struct pmcstat_process *
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

/*
 * Initialize module.
 */

void
pmcstat_initialize_logging(struct pmcstat_process **pmcstat_kernproc,
    struct pmcstat_args *args, struct pmc_plugins *plugins,
    int *pmcstat_npmcs, int *pmcstat_mergepmc)
{
	struct pmcstat_process *pmcstat_kp;
	int i;

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
	if ((pmcstat_kp = pmcstat_process_lookup((pid_t) -1,
	    PMCSTAT_ALLOCATE)) == NULL)
		err(EX_OSERR, "ERROR: Cannot initialize logging");

	*pmcstat_kernproc = pmcstat_kp;

	/* PMC count. */
	*pmcstat_npmcs = 0;

	/* Merge PMC with same name. */
	*pmcstat_mergepmc = args->pa_mergepmc;

	/*
	 * Initialize plugins
	 */

	if (plugins[args->pa_pplugin].pl_init != NULL)
		plugins[args->pa_pplugin].pl_init();
	if (plugins[args->pa_plugin].pl_init != NULL)
		plugins[args->pa_plugin].pl_init();
}

/*
 * Shutdown module.
 */

void
pmcstat_shutdown_logging(struct pmcstat_args *args,
    struct pmc_plugins *plugins,
    struct pmcstat_stats *pmcstat_stats)
{
	struct pmcstat_image *pi, *pitmp;
	struct pmcstat_process *pp, *pptmp;
	struct pmcstat_pcmap *ppm, *ppmtmp;
	FILE *mf;
	int i;

	/* determine where to send the map file */
	mf = NULL;
	if (args->pa_mapfilename != NULL)
		mf = (strcmp(args->pa_mapfilename, "-") == 0) ?
		    args->pa_printfile : fopen(args->pa_mapfilename, "w");

	if (mf == NULL && args->pa_flags & FLAG_DO_GPROF &&
	    args->pa_verbosity >= 2)
		mf = args->pa_printfile;

	if (mf)
		(void) fprintf(mf, "MAP:\n");

	/*
	 * Shutdown the plugins
	 */

	if (plugins[args->pa_plugin].pl_shutdown != NULL)
		plugins[args->pa_plugin].pl_shutdown(mf);
	if (plugins[args->pa_pplugin].pl_shutdown != NULL)
		plugins[args->pa_pplugin].pl_shutdown(mf);

	for (i = 0; i < PMCSTAT_NHASH; i++) {
		LIST_FOREACH_SAFE(pi, &pmcstat_image_hash[i], pi_next,
		    pitmp) {
			if (plugins[args->pa_plugin].pl_shutdownimage != NULL)
				plugins[args->pa_plugin].pl_shutdownimage(pi);
			if (plugins[args->pa_pplugin].pl_shutdownimage != NULL)
				plugins[args->pa_pplugin].pl_shutdownimage(pi);

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
		if (pmcstat_stats->ps_##V || args->pa_verbosity >= 2)	\
			(void) fprintf(args->pa_printfile, " %-40s %d\n",\
			    N, pmcstat_stats->ps_##V);			\
	} while (0)

	if (args->pa_verbosity >= 1 && (args->pa_flags & FLAG_DO_ANALYSIS)) {
		(void) fprintf(args->pa_printfile, "CONVERSION STATISTICS:\n");
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

void
pmcstat_clone_event_descriptor(struct pmcstat_ev *ev, const cpuset_t *cpumask,
    struct pmcstat_args *args)
{
	int cpu;
	struct pmcstat_ev *ev_clone;

	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (!CPU_ISSET(cpu, cpumask))
			continue;

		if ((ev_clone = malloc(sizeof(*ev_clone))) == NULL)
			errx(EX_SOFTWARE, "ERROR: Out of memory");
		(void) memset(ev_clone, 0, sizeof(*ev_clone));

		ev_clone->ev_count = ev->ev_count;
		ev_clone->ev_cpu   = cpu;
		ev_clone->ev_cumulative = ev->ev_cumulative;
		ev_clone->ev_flags = ev->ev_flags;
		ev_clone->ev_mode  = ev->ev_mode;
		ev_clone->ev_name  = strdup(ev->ev_name);
		if (ev_clone->ev_name == NULL)
			errx(EX_SOFTWARE, "ERROR: Out of memory");
		ev_clone->ev_pmcid = ev->ev_pmcid;
		ev_clone->ev_saved = ev->ev_saved;
		ev_clone->ev_spec  = strdup(ev->ev_spec);
		if (ev_clone->ev_spec == NULL)
			errx(EX_SOFTWARE, "ERROR: Out of memory");

		STAILQ_INSERT_TAIL(&args->pa_events, ev_clone, ev_next);
	}
}

void
pmcstat_create_process(int *pmcstat_sockpair, struct pmcstat_args *args,
    int pmcstat_kq)
{
	char token;
	pid_t pid;
	struct kevent kev;
	struct pmcstat_target *pt;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pmcstat_sockpair) < 0)
		err(EX_OSERR, "ERROR: cannot create socket pair");

	switch (pid = fork()) {
	case -1:
		err(EX_OSERR, "ERROR: cannot fork");
		/*NOTREACHED*/

	case 0:		/* child */
		(void) close(pmcstat_sockpair[PARENTSOCKET]);

		/* Write a token to tell our parent we've started executing. */
		if (write(pmcstat_sockpair[CHILDSOCKET], "+", 1) != 1)
			err(EX_OSERR, "ERROR (child): cannot write token");

		/* Wait for our parent to signal us to start. */
		if (read(pmcstat_sockpair[CHILDSOCKET], &token, 1) < 0)
			err(EX_OSERR, "ERROR (child): cannot read token");
		(void) close(pmcstat_sockpair[CHILDSOCKET]);

		/* exec() the program requested */
		execvp(*args->pa_argv, args->pa_argv);
		/* and if that fails, notify the parent */
		kill(getppid(), SIGCHLD);
		err(EX_OSERR, "ERROR: execvp \"%s\" failed", *args->pa_argv);
		/*NOTREACHED*/

	default:	/* parent */
		(void) close(pmcstat_sockpair[CHILDSOCKET]);
		break;
	}

	/* Ask to be notified via a kevent when the target process exits. */
	EV_SET(&kev, pid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT, 0,
	    NULL);
	if (kevent(pmcstat_kq, &kev, 1, NULL, 0, NULL) < 0)
		err(EX_OSERR, "ERROR: cannot monitor child process %d", pid);

	if ((pt = malloc(sizeof(*pt))) == NULL)
		errx(EX_SOFTWARE, "ERROR: Out of memory.");

	pt->pt_pid = pid;
	SLIST_INSERT_HEAD(&args->pa_targets, pt, pt_next);

	/* Wait for the child to signal that its ready to go. */
	if (read(pmcstat_sockpair[PARENTSOCKET], &token, 1) < 0)
		err(EX_OSERR, "ERROR (parent): cannot read token");

	return;
}

/*
 * Do process profiling
 *
 * If a pid was specified, attach each allocated PMC to the target
 * process.  Otherwise, fork a child and attach the PMCs to the child,
 * and have the child exec() the target program.
 */

void
pmcstat_start_process(int *pmcstat_sockpair)
{
	/* Signal the child to proceed. */
	if (write(pmcstat_sockpair[PARENTSOCKET], "!", 1) != 1)
		err(EX_OSERR, "ERROR (parent): write of token failed");

	(void) close(pmcstat_sockpair[PARENTSOCKET]);
}

void
pmcstat_attach_pmcs(struct pmcstat_args *args)
{
	struct pmcstat_ev *ev;
	struct pmcstat_target *pt;
	int count;

	/* Attach all process PMCs to target processes. */
	count = 0;
	STAILQ_FOREACH(ev, &args->pa_events, ev_next) {
		if (PMC_IS_SYSTEM_MODE(ev->ev_mode))
			continue;
		SLIST_FOREACH(pt, &args->pa_targets, pt_next) {
			if (pmc_attach(ev->ev_pmcid, pt->pt_pid) == 0)
				count++;
			else if (errno != ESRCH)
				err(EX_OSERR,
"ERROR: cannot attach pmc \"%s\" to process %d",
				    ev->ev_name, (int)pt->pt_pid);
		}
	}

	if (count == 0)
		errx(EX_DATAERR, "ERROR: No processes were attached to.");
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
 * Get PMC record by id, apply merge policy.
 */

static struct pmcstat_pmcrecord *
pmcstat_lookup_pmcid(pmc_id_t pmcid, int pmcstat_mergepmc)
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
 * Add a {pmcid,name} mapping.
 */

static void
pmcstat_pmcid_add(pmc_id_t pmcid, pmcstat_interned_string ps,
    struct pmcstat_args *args, struct pmc_plugins *plugins,
    int *pmcstat_npmcs)
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
	pr->pr_pmcin = *pmcstat_npmcs++;
	pr->pr_samples = 0;
	pr->pr_dubious_frames = 0;
	pr->pr_merge = prm == NULL ? pr : prm;

	LIST_INSERT_HEAD(&pmcstat_pmcs, pr, pr_next);

	if (plugins[args->pa_pplugin].pl_newpmc != NULL)
		plugins[args->pa_pplugin].pl_newpmc(ps, pr);
	if (plugins[args->pa_plugin].pl_newpmc != NULL)
		plugins[args->pa_plugin].pl_newpmc(ps, pr);
}


/*
 * Convert a hwpmc(4) log to profile information.  A system-wide
 * callgraph is generated if FLAG_DO_CALLGRAPHS is set.  gmon.out
 * files usable by gprof(1) are created if FLAG_DO_GPROF is set.
 */
int
pmcstat_analyze_log(struct pmcstat_args *args,
    struct pmc_plugins *plugins,
    struct pmcstat_stats *pmcstat_stats,
    struct pmcstat_process *pmcstat_kernproc,
    int pmcstat_mergepmc,
    int *pmcstat_npmcs,
    int *ps_samples_period)
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

	assert(args->pa_flags & FLAG_DO_ANALYSIS);

	if (elf_version(EV_CURRENT) == EV_NONE)
		err(EX_UNAVAILABLE, "Elf library initialization failed");

	while (pmclog_read(args->pa_logparser, &ev) == 0) {
		assert(ev.pl_state == PMCLOG_OK);

		switch (ev.pl_type) {
		case PMCLOG_TYPE_INITIALIZE:
			if ((ev.pl_u.pl_i.pl_version & 0xFF000000) !=
			    PMC_VERSION_MAJOR << 24 && args->pa_verbosity > 0)
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
			    args, plugins);
			if (image->pi_type == PMCSTAT_IMAGE_UNKNOWN)
				pmcstat_image_determine_type(image, args);
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
			pmcstat_stats->ps_samples_total++;
			*ps_samples_period += 1;

			pc = ev.pl_u.pl_s.pl_pc;
			pp = pmcstat_process_lookup(ev.pl_u.pl_s.pl_pid,
			    PMCSTAT_ALLOCATE);

			/* Get PMC record. */
			pmcr = pmcstat_lookup_pmcid(ev.pl_u.pl_s.pl_pmcid, pmcstat_mergepmc);
			assert(pmcr != NULL);
			pmcr->pr_samples++;

			/*
			 * Call the plugins processing
			 * TODO: move pmcstat_process_find_map inside plugins
			 */

			if (plugins[args->pa_pplugin].pl_process != NULL)
				plugins[args->pa_pplugin].pl_process(
				    pp, pmcr, 1, &pc,
				    pmcstat_process_find_map(pp, pc) != NULL, 0);
			plugins[args->pa_plugin].pl_process(
			    pp, pmcr, 1, &pc,
			    pmcstat_process_find_map(pp, pc) != NULL, 0);
			break;

		case PMCLOG_TYPE_CALLCHAIN:
			pmcstat_stats->ps_samples_total++;
			*ps_samples_period += 1;

			cpuflags = ev.pl_u.pl_cc.pl_cpuflags;
			cpu = PMC_CALLCHAIN_CPUFLAGS_TO_CPU(cpuflags);

			/* Filter on the CPU id. */
			if (!CPU_ISSET(cpu, &(args->pa_cpumask))) {
				pmcstat_stats->ps_samples_skipped++;
				break;
			}

			pp = pmcstat_process_lookup(ev.pl_u.pl_cc.pl_pid,
			    PMCSTAT_ALLOCATE);

			/* Get PMC record. */
			pmcr = pmcstat_lookup_pmcid(ev.pl_u.pl_cc.pl_pmcid, pmcstat_mergepmc);
			assert(pmcr != NULL);
			pmcr->pr_samples++;

			/*
			 * Call the plugins processing
			 */

			if (plugins[args->pa_pplugin].pl_process != NULL)
				plugins[args->pa_pplugin].pl_process(
				    pp, pmcr,
				    ev.pl_u.pl_cc.pl_npc,
				    ev.pl_u.pl_cc.pl_pc,
				    PMC_CALLCHAIN_CPUFLAGS_TO_USERMODE(cpuflags),
				    cpu);
			plugins[args->pa_plugin].pl_process(
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
			    pmcstat_string_intern(ev.pl_u.pl_a.pl_evname),
			    args, plugins, pmcstat_npmcs);
			break;

		case PMCLOG_TYPE_PMCALLOCATEDYN:
			/*
			 * Record the association pmc id between this
			 * PMC and its name.
			 */
			pmcstat_pmcid_add(ev.pl_u.pl_ad.pl_pmcid,
			    pmcstat_string_intern(ev.pl_u.pl_ad.pl_evname),
			    args, plugins, pmcstat_npmcs);
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
			    ev.pl_u.pl_x.pl_entryaddr, args,
			    plugins, pmcstat_stats);
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
 * Close a logfile, after first flushing all in-module queued data.
 */

int
pmcstat_close_log(struct pmcstat_args *args)
{
	/* If a local logfile is configured ask the kernel to stop
	 * and flush data. Kernel will close the file when data is flushed
	 * so keep the status to EXITING.
	 */
	if (args->pa_logfd != -1) {
		if (pmc_close_logfile() < 0)
			err(EX_OSERR, "ERROR: logging failed");
	}

	return (args->pa_flags & FLAG_HAS_PIPE ? PMCSTAT_EXITING :
	    PMCSTAT_FINISHED);
}
