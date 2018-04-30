#define	UART_BASE	0x7f001000

typedef	unsigned int	uint32_t;
typedef	unsigned int	__uint32_t;

static __inline __uint32_t
__bswap32_var(__uint32_t _x)
{

        return ((_x >> 24) | ((_x >> 8) & 0xff00) | ((_x << 8) & 0xff0000) |
            ((_x << 24) & 0xff000000));
}

int
main(void)
{
	unsigned long *addr;

	addr = (unsigned long *)0xffffffffb0800000;

	*addr = 0x1515151515161616;

	*(volatile unsigned int *)(0x9000000000000000 | UART_BASE) = __bswap32_var(0x63);

	return (0);
}
