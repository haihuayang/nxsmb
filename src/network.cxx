#include "network.hxx"
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

int tcplisten(int port)
{
	int sock = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);

	X_ASSERT(sock >= 0);

	set_reuse(sock, 1);

	struct sockaddr_in6 sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons((unsigned short)port);
	X_ASSERT_SYSCALL(bind(sock, (struct sockaddr*) &sa, sizeof sa));

	set_tcpkeepalive(sock, 1);
	set_nbio(sock, 1);

	X_ASSERT_SYSCALL(listen(sock, 5));

	return sock;
}

std::string x_sockaddr_t::tostring() const
{
	char buf[INET6_ADDRSTRLEN + 16] = "";
	if (family == AF_INET) {
		snprintf(buf, sizeof buf, "%d.%d.%d.%d:%d",
			X_IPQUAD_BE(sin.sin_addr), ntohs(sin.sin_port));
	} else if (family == AF_INET6) {
		buf[0] = '[';
		size_t len = strlen(inet_ntop(AF_INET6, &sin6.sin6_addr, buf + 1, sizeof buf - 1));
		len += 1;
		snprintf(buf + len, sizeof buf - len, "]:%d",
				ntohs(sin6.sin6_port));
	} else {
		X_ASSERT(0);
	}

	return buf;
}

