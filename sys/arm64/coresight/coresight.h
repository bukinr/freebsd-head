#ifndef _ARM64_CORESIGHT_CORESIGHT_H_
#define _ARM64_CORESIGHT_CORESIGHT_H_

#include <dev/ofw/openfirm.h>

struct endpoint {
	TAILQ_ENTRY(endpoint) link;
	phandle_t my_node;
	phandle_t their_node;
	phandle_t dev_node;
	boolean_t slave;
	int reg;
};

struct coresight_platform_data {
	int cpu;
	int in_ports;
	int out_ports;
	struct mtx mtx_lock;
	TAILQ_HEAD(endpoint_list, endpoint) endpoints;
};

enum cs_dev_type {
	CORESIGHT_ETMV4,
	CORESIGHT_ETR,
	CORESIGHT_ETF,
	CORESIGHT_DYNAMIC_REPLICATOR,
	CORESIGHT_FUNNEL,
};

struct coresight_desc {
	struct coresight_platform_data *pdata;
	device_t dev;
	enum cs_dev_type dev_type;
	struct coresight_ops *ops;
};

struct coresight_device {
	TAILQ_ENTRY(coresight_device) link;
	device_t dev;
	phandle_t node;
	enum cs_dev_type dev_type;
	struct coresight_ops *ops;
	struct coresight_platform_data *pdata;
};

TAILQ_HEAD(coresight_device_list, coresight_device);

struct coresight_ops_sink {
	int (*enable)(void);
	void (*disable)(void);
};

struct coresight_ops_link {
	int (*enable)(struct coresight_device *out, struct endpoint *endp);
	void (*disable)(void);
};

struct coresight_ops_source {
	int (*enable)(void *);
	int (*disable)(void);
};

struct coresight_ops {
	struct coresight_ops_sink *sink_ops;
	struct coresight_ops_link *link_ops;
	struct coresight_ops_source *source_ops;
};

#define	ETM_N_COMPRATOR		16
struct etm_config {
	uint64_t addr[ETM_N_COMPRATOR];
	uint32_t naddr;
	uint8_t excp_level;
};

struct coresight_platform_data * coresight_get_platform_data(device_t dev);
struct endpoint * coresight_get_output_endpoint(struct coresight_platform_data *pdata);
struct coresight_device * coresight_get_output_device(struct endpoint *endp, struct endpoint **);
int coresight_register(struct coresight_desc *desc);
int coresight_enable_etmv4(int cpu, struct etm_config *);

#endif /* !_ARM64_CORESIGHT_CORESIGHT_H_ */
