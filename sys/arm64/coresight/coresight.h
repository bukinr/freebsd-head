#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

struct endpoint {
	TAILQ_ENTRY(endpoint) link;
	phandle_t node;
	boolean_t slave;
};

struct coresight_platform_data {
	int cpu;
	int in_ports;
	int out_ports;
	struct mtx mtx_lock;
	TAILQ_HEAD(endpoint_list, endpoint) endpoints;
};

struct coresight_platform_data * coresight_get_platform_data(device_t dev);
