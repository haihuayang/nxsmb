
#ifndef __networking__hxx__
#define __networking__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include <vector>
#include <string>
#include <sys/socket.h>
#include <stdint.h>
#include <net/if.h>

enum {
	X_FSCTL_NET_IFACE_RSS_CAPABLE = 0x00000001,
	X_FSCTL_NET_IFACE_RDMA_CAPABLE = 0x00000002,
};

struct x_iface_t {
	char name[IF_NAMESIZE];
	uint32_t if_index;
	int flags;
	uint32_t capability;
	uint64_t linkspeed;
	struct sockaddr_storage ip;
	struct sockaddr_storage netmask;
	struct sockaddr_storage bcast;
};

int x_probe_ifaces(std::vector<x_iface_t> &ifaces);
int x_interpret_iface(std::vector<x_iface_t> &ret, std::string token_str,
		const std::vector<x_iface_t> &probed_ifaces);

#endif /* __networking__hxx__ */

