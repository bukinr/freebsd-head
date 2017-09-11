#ifndef	_LIBPMCSTAT_H_
#define	_LIBPMCSTAT_H_

int libpmcstat_test(void);
int pmcstat_symbol_compare(const void *a, const void *b);

typedef const void *pmcstat_interned_string;

/*
 * Each function symbol tracked by pmcstat(8).
 */

struct pmcstat_symbol {
	pmcstat_interned_string ps_name;
	uint64_t	ps_start;
	uint64_t	ps_end;
};

#endif /* !_LIBPMCSTAT_H_ */
