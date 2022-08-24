
#include "smbd_share.hxx"
#include <fcntl.h>
#include <unistd.h>

static std::atomic<uint64_t> g_topdir_next_id = 0;
x_smbd_topdir_t::x_smbd_topdir_t(const x_smbd_object_ops_t *ops, int fd)
		: ops(ops), uuid(g_topdir_next_id++), fd(fd)
{
}

x_smbd_topdir_t::~x_smbd_topdir_t()
{
	if (fd != -1) {
		close(fd);
	}
}

std::shared_ptr<x_smbd_topdir_t> x_smbd_topdir_create(const std::string &path,
		const x_smbd_object_ops_t *ops)
{
	int fd = -1;
	if (path.size()) {
		fd = open(path.c_str(), O_RDONLY);
		X_ASSERT(fd != -1);
	}
	auto topdir = std::make_shared<x_smbd_topdir_t>(ops, fd);
	return topdir;
}
