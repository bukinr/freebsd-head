/*-
 * Copyright (c) 2018 Ruslan Bukin <br@bsdpad.com>
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
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/rman.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <machine/bus.h>

#include <arm64/coresight/coresight.h>

extern struct coresight_device_list cs_devs;

static int
coresight_build_path_one(struct coresight_device *out, struct endpoint *out_endp)
{

	printf("%s\n", __func__);

	switch (out->dev_type) {
	//case CORESIGHT_ETMV4:
	//	out->ops->source_ops->enable(config);
	//	break;
	case CORESIGHT_ETR:
	case CORESIGHT_ETF:
		printf("enabling SINK ops\n");
		//out->ops->sink_ops->enable();
		break;
	case CORESIGHT_DYNAMIC_REPLICATOR:
	case CORESIGHT_FUNNEL:
		printf("enabling LINK ops\n");
		out->ops->link_ops->enable(out, out_endp);
		break;
	default:
		break;
	}

	printf("%s: done\n", __func__);

	return (0);
}

static int
coresight_build_path(struct coresight_device *cs_dev)
{
	struct coresight_device *out;
	struct endpoint *out_endp;
	struct endpoint *endp;

	out = cs_dev;
	do {
		endp = coresight_get_output_endpoint(out->pdata);
		if (endp == NULL)
			return (-1);

		out = coresight_get_output_device(endp, &out_endp);
		if (out == NULL)
			return (-2);

		coresight_build_path_one(out, out_endp);
	} while (out);

	return (0);
}

int
coresight_enable_etmv4(int cpu, struct etm_config *config)
{
	struct coresight_device *cs_dev;

	TAILQ_FOREACH(cs_dev, &cs_devs, link) {
		if (cs_dev->dev_type == CORESIGHT_ETMV4 &&
		    cs_dev->pdata->cpu == cpu) {
			printf("ETMv4 cs_dev found\n");

			coresight_build_path(cs_dev);

			cs_dev->ops->source_ops->enable(config);
			break;
		}
	}

	return (0);
}
