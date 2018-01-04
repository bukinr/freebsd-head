/*-
 * Copyright (c) 2016 Jared McNeill <jmcneill@invisible.ca>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

/*
 * Qualcomm Watchdog
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kthread.h>
#include <sys/rman.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <machine/bus.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <arm/qualcomm/qcom_wdog.h>

extern int uart_delay;

static struct ofw_compat_data compat_data[] = {
	{ "qcom,msm-wdog",			1 },
	{ NULL,					0 }
};

struct qcom_wdog_softc {
	struct resource		*res;
};
struct qcom_wdog_softc *qcom_wdog_sc;

static struct resource_spec qcom_wdog_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ -1, 0 }
};

static void
qcom_wdog_worker(void *arg)
{
	struct qcom_wdog_softc *sc;

	sc = (struct qcom_wdog_softc *)arg;

	while (1) {
		printf(".");
		bus_write_4(sc->res, 0x04, 1);
	}

	kproc_exit(0);
}

static int
qcom_wdog_probe(device_t dev)
{
	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "Qualcomm Watchdog");

	return (BUS_PROBE_DEFAULT);
}

void qcom_test(void);

void
qcom_test(void)
{
	//uint8_t *addr;

	printf("Start test\n");
	//addr = (uint8_t *)0xfff0000000000000ULL;
	//*(uint8_t *)addr = 1;

	//__asm __volatile("mov x8, #0x40000000");
	//__asm __volatile("mov x8, #0x3ffffff0");
	//__asm __volatile("mov x8, #0x200000");
	//__asm __volatile("mov x8, #0x1ffff0");
	//__asm __volatile("ldr x8, [x8]");

	__asm __volatile("mov x8, xzr");
	__asm __volatile("str xzr, [x8]");
	printf("End test\n");

	return;

	uint8_t *p;
	int len;

	len = 147;
	p = NULL;
	while(len-- > 0)
		*p++ = 0;
}

void
qcom_wdog_reset(void)
{
	struct qcom_wdog_softc *sc;

	sc = qcom_wdog_sc;

	printf(",");
	bus_write_4(sc->res, 0x04, 1);
}

static int
qcom_wdog_attach(device_t dev)
{
	struct qcom_wdog_softc *sc;
	struct proc *newp;

	sc = device_get_softc(dev);

	if (bus_alloc_resources(dev, qcom_wdog_spec, &sc->res) != 0) {
		device_printf(dev, "cannot allocate resources for device\n");
		return (ENXIO);
	}

	qcom_wdog_sc = sc;

	/* Disable watchdog */
	bus_write_4(sc->res, 0x8, 0);

	if (0 == 1)
		qcom_test();

	int i;

	//ptr = malloc(PAGE_SIZE, M_DEVBUF, M_NOWAIT);
	//bzero(ptr, PAGE_SIZE);
	//bzero((void *)ptr[0], PAGE_SIZE);
	//bzero((void *)0, PAGE_SIZE);

	//ptr = malloc(768*1024*1024, M_DEVBUF, M_NOWAIT);
	//bzero((void *)ptr, 768*1024*1024);
	//printf("ptr %lx\n", (uint64_t)ptr);
	//free(ptr, M_DEVBUF);

	//printf("test\n");
	//uint64_t val;
	//val = 0x80000000;
	//__asm __volatile("msr ttbr0_el1, %0" :: "r"(val));
	//printf("end\n");

#if 0
	uint64_t *ptr;
	int j;
	i = 0;
	ptr = malloc(16*1024*1024, M_DEVBUF, M_NOWAIT);
	while (1) {
		ptr[i] = (uint64_t)malloc(PAGE_SIZE, M_DEVBUF, M_NOWAIT);
		if (ptr[i] == 0) {
		//if (i == 1) {
			printf("no mem\n");
			for (j = 0; j < i; j++) {
				//printf("f %lx\n", (uint64_t)ptr);
				//printf("%lx\n", vtophys((void *)ptr[j]));
				bzero((void *)ptr[j], PAGE_SIZE);
				//printf("bzero ok\n");
				free((void *)ptr[j], M_DEVBUF);
				//printf("free ok\n");
			}
			break;
		}
		printf("%lx\n", (uint64_t)vtophys(ptr[i]));
		//if ((uint64_t)vtophys(ptr) >= 0xaf92b000 && (uint64_t)vtophys(ptr) < 0xb0000000)
		//	continue;
		bzero((void *)ptr[i], PAGE_SIZE);
		//bzero(ptr, PAGE_SIZE);
		i+=1;
	}
#endif

	return (0);

	while (1) {
		if (kproc_create(qcom_wdog_worker, (void*)sc, &newp, 0, 0,
		    "qcom wdog worker") != 0) {
			printf("Failed to create qcom_wdog_worker\n");
       		}
		kproc_shutdown(&newp, 0);
	}

	return (0);

	//uint64_t i;
	i = 0xffffffffUL;

	while (i--)
		bus_write_4(sc->res, 0x4, 1);

	return (0);

	while (1)
		__asm __volatile(
                	    "dsb sy \n"
                	    "wfi    \n");

	return (0);

#if 0
	while (1);
		bus_write_4(sc->res, 0x4, 1);
#endif

	
	bus_write_4(sc->res, 0x10, 12000);
	bus_write_4(sc->res, 0x14, 12000);
	bus_write_4(sc->res, 0x8, 1 | (1 << 1));

	printf("APCS_WDOG_SECURE: %x\n", bus_read_4(sc->res, 0x00));
	printf("APCS_WDOG_STATUS: %x\n", bus_read_4(sc->res, 0x0C));
	printf("APCS_WDOG_BARK_TIME: %x\n", bus_read_4(sc->res, 0x10));
	printf("APCS_WDOG_BITE_TIME: %x\n", bus_read_4(sc->res, 0x14));

	//return (0);

	return (0);
}

static device_method_t qcom_wdog_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		qcom_wdog_probe),
	DEVMETHOD(device_attach,	qcom_wdog_attach),

	DEVMETHOD_END
};

static driver_t qcom_wdog_driver = {
	"qcom_wdog",
	qcom_wdog_methods,
	sizeof(struct qcom_wdog_softc),
};

static devclass_t qcom_wdog_devclass;

//EARLY_DRIVER_MODULE(qcom_wdog, simplebus, qcom_wdog_driver, qcom_wdog_devclass,
//    0, 0, BUS_PASS_BUS + BUS_PASS_ORDER_MIDDLE);
DRIVER_MODULE(qcom_wdog, simplebus, qcom_wdog_driver, qcom_wdog_devclass,
    0, 0);
MODULE_VERSION(qcom_wdog, 1);
