
#ifndef __network__hxx__
#define __network__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

union x_sockaddr_t
{
	uint16_t family;
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;

	std::string tostring() const;
};

static inline void set_reuse(int s, int on)
{
	X_ASSERT_SYSCALL(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on));
}

static inline void set_tcpkeepalive(int s, int on)
{
	X_ASSERT_SYSCALL(setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on));
}

static inline void set_nbio(int s, unsigned long on)
{
	X_ASSERT_SYSCALL(ioctl(s, FIONBIO, &on));
}

int tcplisten(int port);


#endif /* __network__hxx__ */

