#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

struct coresight_platform_data {
	int cpu;
	int in_ports;
	int out_ports;
};

int coresight_get_platform_data(device_t dev, struct coresight_platform_data *pdata);
