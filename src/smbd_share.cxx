
#include "smbd_share.hxx"
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>

static std::atomic<uint64_t> g_topdir_next_id = 0;
x_smbd_topdir_t::x_smbd_topdir_t(const x_smbd_object_ops_t *ops, int fd,
		const x_smb2_uuid_t &volume_id)
	: ops(ops), uuid(g_topdir_next_id++), fd(fd), volume_id(volume_id)
{
}

x_smbd_topdir_t::~x_smbd_topdir_t()
{
	if (fd != -1) {
		close(fd);
	}
}

static x_smb2_uuid_t create_volume_id(const std::string &name)
{
	x_smb2_uuid_t uuid[4];
	SHA512_CTX sctx;
	SHA512_Init(&sctx);
	SHA512_Update(&sctx, name.data(), name.length());
	SHA512_Final((unsigned char *)&uuid[0], &sctx);
	return uuid[0];
}

std::shared_ptr<x_smbd_topdir_t> x_smbd_topdir_create(const std::string &path,
		const x_smbd_object_ops_t *ops,
		const std::string &volume_name)
{
	int fd = -1;
	if (path.size()) {
		fd = open(path.c_str(), O_RDONLY);
		X_ASSERT(fd != -1);
	}
	auto topdir = std::make_shared<x_smbd_topdir_t>(ops, fd,
			create_volume_id(volume_name));
	return topdir;
}
