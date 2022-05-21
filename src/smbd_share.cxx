
#include "smbd_share.hxx"
#include <fcntl.h>
#include <unistd.h>

static std::atomic<uint64_t> g_topdir_next_id = 0;
x_smbd_topdir_t::x_smbd_topdir_t()
		: /*smbd_share(s), */uuid(g_topdir_next_id++)
{
}

x_smbd_topdir_t::~x_smbd_topdir_t()
{
	if (fd != -1) {
		close(fd);
	}
}

std::shared_ptr<x_smbd_topdir_t> x_smbd_topdir_create(const std::string &path)
{
	/* TODO if the share is hosted by this node */
	int fd = open(path.c_str(), O_RDONLY);
	X_ASSERT(fd != -1);
	auto topdir = std::make_shared<x_smbd_topdir_t>();
	topdir->fd = fd;
	return topdir;
}
