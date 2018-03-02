#ifndef _ARM64_CORESIGHT_CORESIGHT_H_
#define _ARM64_CORESIGHT_CORESIGHT_H_

#include <dev/ofw/openfirm.h>

#define CORESIGHT_ITCTRL        0xf00
#define CORESIGHT_CLAIMSET      0xfa0
#define CORESIGHT_CLAIMCLR      0xfa4
#define CORESIGHT_LAR           0xfb0
#define CORESIGHT_LSR           0xfb4
#define CORESIGHT_AUTHSTATUS    0xfb8
#define CORESIGHT_DEVID         0xfc8
#define CORESIGHT_DEVTYPE       0xfcc

#define CORESIGHT_UNLOCK        0xc5acce55

enum cs_dev_type {
	CORESIGHT_ETMV4,
	CORESIGHT_ETR,
	CORESIGHT_ETF,
	CORESIGHT_DYNAMIC_REPLICATOR,
	CORESIGHT_FUNNEL,
};

struct coresight_device {
	TAILQ_ENTRY(coresight_device) link;
	device_t dev;
	phandle_t node;
	enum cs_dev_type dev_type;
	struct coresight_ops *ops;
	struct coresight_platform_data *pdata;
};

struct endpoint {
	TAILQ_ENTRY(endpoint) link;
	phandle_t my_node;
	phandle_t their_node;
	phandle_t dev_node;
	boolean_t slave;
	int reg;
	struct coresight_device *cs_dev;
	LIST_ENTRY(endpoint) endplink;
};

struct coresight_platform_data {
	int cpu;
	int in_ports;
	int out_ports;
	struct mtx mtx_lock;
	TAILQ_HEAD(endpoint_list, endpoint) endpoints;
};

struct coresight_desc {
	struct coresight_platform_data *pdata;
	device_t dev;
	enum cs_dev_type dev_type;
	struct coresight_ops *ops;
};

TAILQ_HEAD(coresight_device_list, coresight_device);

#define	ETM_N_COMPRATOR		16

struct coresight_event {
	LIST_HEAD(, endpoint) endplist;

	uint64_t addr[ETM_N_COMPRATOR];
	uint32_t naddr;
	uint8_t excp_level;
	enum cs_dev_type src;
	enum cs_dev_type sink;

	int started;
	int cycle;
	uint32_t offset;
	uint32_t low;
	uint32_t high;
	uint32_t bufsize;
	uint32_t rrp;
	uint32_t rwp;
};

struct coresight_ops {
	int (*read)(struct coresight_device *out, struct endpoint *endp, struct coresight_event *event);
	int (*enable)(struct coresight_device *out, struct endpoint *endp, struct coresight_event *event);
	void (*disable)(struct coresight_device *out, struct endpoint *endp, struct coresight_event *event);
};

struct etm_config {
	uint64_t addr[ETM_N_COMPRATOR];
	uint32_t naddr;
	uint8_t excp_level;
};

struct coresight_platform_data * coresight_get_platform_data(device_t dev);
struct endpoint * coresight_get_output_endpoint(struct coresight_platform_data *pdata);
struct coresight_device * coresight_get_output_device(struct endpoint *endp, struct endpoint **);
int coresight_register(struct coresight_desc *desc);
int coresight_init_event(int cpu, struct coresight_event *event);
void coresight_enable(int cpu, struct coresight_event *event);
void coresight_disable(int cpu, struct coresight_event *event);
void coresight_read(int cpu, struct coresight_event *event);

#endif /* !_ARM64_CORESIGHT_CORESIGHT_H_ */
