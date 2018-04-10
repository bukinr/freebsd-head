CFLAGS=-I/usr/include -static -nostdlib -nostartfiles -g -nostdinc -Wall -pedantic -Wno-unused-function

.c.o: Makefile
	gcc48 ${CFLAGS} -c -o ${.TARGET} ${.IMPSRC}

.S.o: Makefile
	gcc48 -c -D__ASSEMBLY__ -o ${.TARGET} ${.IMPSRC}

all:	app.o sgx-entry.o
	ld -T sgx.lds app.o sgx-entry.o -o app

clean:
	rm -f app app.o sgx-entry.o
