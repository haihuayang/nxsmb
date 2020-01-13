#include "network.hxx"
#include <netinet/in.h>
#include <string.h>

int tcplisten(int port)
{
	int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	X_ASSERT(sock >= 0);

	set_reuse(sock, 1);

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family      = AF_INET;
	sa.sin_port	= htons((unsigned short)port);
	X_ASSERT_SYSCALL(bind(sock, (struct sockaddr*) &sa, sizeof sa));

	set_tcpkeepalive(sock, 1);
	set_nbio(sock, 1);

	X_ASSERT_SYSCALL(listen(sock, 5));

	return sock;
}

 
