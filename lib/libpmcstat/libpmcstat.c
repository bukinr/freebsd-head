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
#include <sys/param.h>
#include <sys/endian.h>
#include <sys/module.h>
#include <sys/pmc.h>
#include <sys/syscall.h>
#include <sys/queue.h>
#include <sys/imgact_aout.h>
#include <sys/imgact_elf.h>

#include <netinet/in.h>

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <pmc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sysexits.h>
#include <unistd.h>

#include "libpmcstat.h"

/*
 * All image descriptors are kept in a hash table.
 */
struct pmcstat_image_hash_list pmcstat_image_hash[PMCSTAT_NHASH];


int
libpmcstat_test(void)
{

	return (0);
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

	printf("%s: path %s\n", __func__, pmcstat_string_unintern(image->pi_execpath));

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

	printf("nshmsyms %ld\n", nshsyms);

	for (n = newsyms = 0; n < nshsyms; n++) {
		if (gelf_getsym(data, (int) n, &sym) != &sym) {
			printf("%s: err 1\n", __func__);
			return;
		}
		if (GELF_ST_TYPE(sym.st_info) != STT_FUNC) {
			printf("%s: err 2\n", __func__);
			continue;
		}

		if (sym.st_shndx == STN_UNDEF) {
			printf("%s: err 3\n", __func__);
			continue;
		}

		if (!firsttime && pmcstat_symbol_search(image, sym.st_value)) {
			printf("%s: err 4\n", __func__);
			continue; /* We've seen this symbol already. */
		}

		if ((fnname = elf_strptr(e, sh->sh_link, sym.st_name))
		    == NULL) {
			printf("%s: err 5\n", __func__);
			continue;
		}
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

		printf("start %lx end %lx name %s image->pi_vaddr %lx\n",
		    symptr->ps_start, symptr->ps_end, fnname, image->pi_vaddr);

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
pmcstat_image_get_elf_params(struct pmcstat_image *image)
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

	printf("%s: %d\n", __func__, image->pi_iskernelmodule);

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
#if 0
	if (image->pi_iskernelmodule)
		(void) snprintf(buffer, sizeof(buffer), "%s%s/%s",
		    args.pa_fsroot, args.pa_kernel, path);
	else
		(void) snprintf(buffer, sizeof(buffer), "%s%s",
		    args.pa_fsroot, path);
#else
	/* TODO */
	if (image->pi_iskernelmodule)
		(void) snprintf(buffer, sizeof(buffer), "/boot/kernel/%s", path);
	else
		(void) snprintf(buffer, sizeof(buffer), "%s", path);
#endif

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
#if 0
		if (args.pa_verbosity >= 2)
#endif
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
    int iskernelmodule)
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

#if 0
	if (plugins[args.pa_pplugin].pl_initimage != NULL)
		plugins[args.pa_pplugin].pl_initimage(pi);
	if (plugins[args.pa_plugin].pl_initimage != NULL)
		plugins[args.pa_plugin].pl_initimage(pi);
#endif

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
    struct pmcstat_image *image, uintfptr_t entryaddr)
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
		rtldimage = pmcstat_image_from_path(image->pi_dynlinkerpath, 0);
		if (rtldimage == NULL) {
			warnx("WARNING: Cannot find image for \"%s\".",
			    pmcstat_string_unintern(image->pi_dynlinkerpath));
#if 0
			pmcstat_stats.ps_exec_errors++;
#endif
			return;
		}

		if (rtldimage->pi_type == PMCSTAT_IMAGE_UNKNOWN)
			pmcstat_image_get_elf_params(rtldimage);

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

	warnx("Linking %s\n", pmcstat_string_unintern(image->pi_execpath));
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
pmcstat_image_get_aout_params(struct pmcstat_image *image)
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

#if 0
	(void) snprintf(buffer, sizeof(buffer), "%s%s",
	    args.pa_fsroot, path);
#else
	(void) snprintf(buffer, sizeof(buffer), "%s", path);
#endif

	if ((fd = open(buffer, O_RDONLY, 0)) < 0 ||
	    (nbytes = read(fd, &ex, sizeof(ex))) < 0) {
#if 0
		if (args.pa_verbosity >= 2)
#endif
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
pmcstat_image_determine_type(struct pmcstat_image *image)
{
	assert(image->pi_type == PMCSTAT_IMAGE_UNKNOWN);

	/* Try each kind of handler in turn */
	if (image->pi_type == PMCSTAT_IMAGE_UNKNOWN)
		pmcstat_image_get_elf_params(image);
	if (image->pi_type == PMCSTAT_IMAGE_UNKNOWN)
		pmcstat_image_get_aout_params(image);

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
    pmcstat_interned_string path, uintfptr_t entryaddr)
{
	struct pmcstat_image *image;

	if ((image = pmcstat_image_from_path(path, 0)) == NULL) {
#if 0
		pmcstat_stats.ps_exec_errors++;
#endif
		return;
	}

	if (image->pi_type == PMCSTAT_IMAGE_UNKNOWN)
		pmcstat_image_determine_type(image);

	assert(image->pi_type != PMCSTAT_IMAGE_UNKNOWN);

	switch (image->pi_type) {
	case PMCSTAT_IMAGE_ELF32:
	case PMCSTAT_IMAGE_ELF64:
#if 0
		pmcstat_stats.ps_exec_elf++;
#endif
		pmcstat_process_elf_exec(pp, image, entryaddr);
		break;

	case PMCSTAT_IMAGE_AOUT:
#if 0
		pmcstat_stats.ps_exec_aout++;
#endif
		pmcstat_process_aout_exec(pp, image, entryaddr);
		break;

	case PMCSTAT_IMAGE_INDETERMINABLE:
#if 0
		pmcstat_stats.ps_exec_indeterminable++;
#endif
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
