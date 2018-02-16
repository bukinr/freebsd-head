#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

struct coresight_platform_data {
	int cpu;
};

int coresight_parse_port(phandle_t node);
int coresight_get_platform_data(device_t dev, struct coresight_platform_data *pdata);
