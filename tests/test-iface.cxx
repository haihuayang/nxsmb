
#include "include/utils.hxx"
#include "include/networking.hxx"
#include <arpa/inet.h>
#include <stdio.h>

static const char *ss_tostr(const sockaddr_storage *ss, char *buf)
{
	return inet_ntop(ss->ss_family,
			ss->ss_family == AF_INET ?  (void *)&((const sockaddr_in *)ss)->sin_addr :
				(void *)&((const sockaddr_in6 *)ss)->sin6_addr,
			buf, INET6_ADDRSTRLEN);
}

static void output_ifaces(const std::vector<x_iface_t> &ifaces)
{
	for (const auto &iface: ifaces) {
		char addr_buf[INET6_ADDRSTRLEN];
		char netmask_buf[INET6_ADDRSTRLEN];
		char bcast_buf[INET6_ADDRSTRLEN];
		printf("#%d %s 0x%x %lu %s/%s/%s\n", iface.if_index,
				iface.name, iface.flags, iface.linkspeed,
				ss_tostr(&iface.ip, addr_buf),
				ss_tostr(&iface.netmask, netmask_buf),
				ss_tostr(&iface.bcast, bcast_buf));
	}
}

#define OUTPUT_IFACES(ifaces, fmt, ...) do { \
	printf(fmt "\n", ##__VA_ARGS__); \
	output_ifaces(ifaces); \
} while (0)

static void test_list_ifaces(char **tokens)
{
	std::vector<x_iface_t> ifaces;
	int err = x_probe_ifaces(ifaces);
	X_ASSERT(err == 0);
	OUTPUT_IFACES(ifaces, "Probed:");

	for (; *tokens; ++tokens) {
		std::vector<x_iface_t> matched;
		x_interpret_iface(matched, *tokens, ifaces);
		OUTPUT_IFACES(matched, "Match %s:", *tokens);
	}
}

int main(int argc, char **argv)
{
	test_list_ifaces(argv + 1);
	return 0;
}

