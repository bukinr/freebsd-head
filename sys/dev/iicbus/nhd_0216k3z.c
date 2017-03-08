/*-
 * Copyright (c) 2003-2012 Broadcom Corporation
 * All Rights Reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY BROADCOM ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL BROADCOM OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/clock.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/rman.h>

#include <dev/iicbus/iiconf.h>
#include <dev/iicbus/iicbus.h>

#include "iicbus_if.h"
#include "clock_if.h"

#define	DS1374_RTC_COUNTER	0	/* counter (bytes 0-3) */

struct nhd_0216k3z_softc {
	uint32_t	sc_addr;
	device_t	sc_dev;
};

static int
nhd_0216k3z_write(device_t dev, uint32_t addr, uint8_t reg, uint8_t *data)
{
	int err;
	uint8_t prefix;

	prefix = 0xfe;
	struct iic_msg msg[3] = {
		{ addr, IIC_M_WR | IIC_M_NOSTOP, 1, &prefix },
		{ addr, IIC_M_WR | IIC_M_NOSTOP, 1, &reg },
		{ addr, IIC_M_WR, 1, data },
	};

	err = iicbus_transfer(dev, msg, 3);
	if (err != 0) {
		printf("%s: err: %d\n", __func__, err);
		return (-1);
	}

	return (0);
}

static int
nhd_0216k3z_write_font(device_t dev, uint32_t addr, uint8_t *data, uint32_t len)
{
	int err;

	struct iic_msg msg[1] = {
		{ addr, IIC_M_WR, len, data },
	};

	err = iicbus_transfer(dev, msg, 1);
	if (err != 0) {
		printf("%s: err: %d\n", __func__, err);
		return (-1);
	}

	return (0);
}

static int
nhd_0216k3z_probe(device_t dev)
{

	device_set_desc(dev, "NHD 0216k3z");

	return (0);
}

static int
nhd_0216k3z_attach(device_t dev)
{
	struct nhd_0216k3z_softc *sc;

	sc = device_get_softc(dev);

	if(sc == NULL) {
		printf("nhd_0216k3z_attach device_get_softc failed\n");
		return (0);
	}

	sc->sc_dev = dev;
	sc->sc_addr = iicbus_get_addr(dev);

	uint8_t data[32];
	uint32_t len;
	int i;

	data[0] = 0x8;
	nhd_0216k3z_write(dev, 0x28, 0x53, data);

	data[0] = 0x46;
	data[1] = 0x72;
	data[2] = 0x65;
	data[3] = 0x65;
	data[4] = 0x42;
	data[5] = 0x53;
	data[6] = 0x44;
	for (i = 7; i < 32; i++) {
		data[i] = 0x80;
	}


	data[0] = 0x48;
	data[1] = 0x69;
	data[2] = 0x80;
	data[3] = 0x54;
	data[4] = 0x68;
	data[5] = 0x65;
	data[6] = 0x6f;
	for (i = 7; i < 32; i++) {
		data[i] = 0x80;
	}


	len = 16;
	nhd_0216k3z_write_font(dev, 0x28, data, len);

	return (0);
}

static device_method_t nhd_0216k3z_methods[] = {
	DEVMETHOD(device_probe,		nhd_0216k3z_probe),
	DEVMETHOD(device_attach,	nhd_0216k3z_attach),

	DEVMETHOD_END
};

static driver_t nhd_0216k3z_driver = {
	"nhd_0216k3z",
	nhd_0216k3z_methods,
	sizeof(struct nhd_0216k3z_softc),
};
static devclass_t nhd_0216k3z_devclass;

DRIVER_MODULE(nhd_0216k3z, iicbus, nhd_0216k3z_driver, nhd_0216k3z_devclass, 0, 0);
MODULE_VERSION(nhd_0216k3z, 1);
MODULE_DEPEND(nhd_0216k3z, iicbus, 1, 1, 1);
