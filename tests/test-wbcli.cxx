
#define WINBINDD_SOCKET_DIR "/var/run/winbindd"
#define WINBINDD_SOCKET_PATH "/var/run/winbindd/pipe"

#include "include/xdefines.h"
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <stdio.h>

extern "C" {
#include "include/winbind_struct_protocol.h"
}

static void winbindd_init_request(struct winbindd_request *request,
		int request_type)
{
	request->length = sizeof(struct winbindd_request);
	request->cmd = (enum winbindd_cmd)request_type;
	request->pid = getpid();
}

static int winbind_open_pipe()
{
	struct sockaddr_un sun;
	sun.sun_family = AF_UNIX;
	size_t ret = snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", WINBINDD_SOCKET_PATH);
	X_ASSERT(ret < sizeof(sun.sun_path));
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	X_ASSERT(fd >= 0);
	
	/* TODO make_safe_fd */
	int err = connect(fd, (struct sockaddr *)&sun, sizeof(sun));
	X_ASSERT(err == 0);


	struct winbindd_request wbrequ;
	memset(&wbrequ, 0, sizeof wbrequ);

	winbindd_init_request(&wbrequ, WINBINDD_INTERFACE_VERSION);

	write(fd, &wbrequ, sizeof wbrequ);

	struct winbindd_response wbresp;

	read(fd, &wbresp, sizeof wbresp);

	return 0;
}

int main()
{
	winbind_open_pipe();
}

