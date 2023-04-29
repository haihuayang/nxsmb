
#include "smbd_volume.hxx"
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>


int x_smbd_volume_read_id(int vol_fd, uint16_t &vol_id)
{
	int fd = openat(vol_fd, "id", O_RDONLY);
	if (fd < 0) {
		X_LOG_ERR("cannot open volume id errno=%d", errno);
		return -errno;
	}
	uint16_t id;
	ssize_t ret = read(fd, &id, sizeof id);
	close(fd);
	if (ret != sizeof(id)) {
		X_LOG_ERR("cannot read volume id ret=%ld, errno=%d", ret, errno);
		return -errno;
	}

	vol_id = ntohs(id);

	return 0;
}

int x_smbd_volume_set_id(int vol_fd, uint16_t vol_id)
{
	int fd = openat(vol_fd, "id", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	X_ASSERT(fd >= 0);
	uint16_t id = htons(vol_id);
	write(fd, &vol_id, sizeof id);
	close(fd);
	return 0;
}

