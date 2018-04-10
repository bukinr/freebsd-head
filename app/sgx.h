typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

enum {
	ENCLU_EREPORT      = 0x00,
	ENCLU_EGETKEY      = 0x01, 
	ENCLU_EENTER       = 0x02,
	ENCLU_ERESUME      = 0x03,
	ENCLU_EEXIT        = 0x04,
	ENCLU_EACCEPT      = 0x05,
	ENCLU_EMODPE       = 0x06,
	ENCLU_EACCEPTCOPY  = 0x07
};

#define	NULL		((void *)0)
#define	__asm		__asm__
#define	__volatile	__volatile__

#define sgx_exit(ptr) {				\
	__asm __volatile("movl %0, %%eax\n\t"	\
		"movq %1, %%rbx\n\t"		\
		".byte 0x0F\n\t"		\
		".byte 0x01\n\t"		\
		".byte 0xd7\n\t"		\
		:				\
		:"a"((uint32_t)ENCLU_EEXIT),	\
		"b"((uint64_t)ptr));		\
};
