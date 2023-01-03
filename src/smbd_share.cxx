
#include "smbd_share.hxx"
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <sys/stat.h>

static x_smb2_uuid_t create_volume_id(const std::string &name)
{
	x_smb2_uuid_t uuid[4];
	SHA512_CTX sctx;
	SHA512_Init(&sctx);
	SHA512_Update(&sctx, name.data(), name.length());
	SHA512_Final((unsigned char *)&uuid[0], &sctx);
	return uuid[0];
}

x_smbd_volume_t::x_smbd_volume_t(const std::string &n, const std::string &p,
		const std::string &on, const std::string &os,
		const x_smb2_uuid_t &vol_uuid,
		uint16_t vol_id, int rfd,
		x_smbd_durable_db_t *durable_db)
	: name(n), path(p), owner_node(on), owner_share(os)
	, volume_uuid(vol_uuid), volume_id(vol_id), rootdir_fd(rfd)
	, smbd_durable_db(durable_db)
{
}

x_smbd_volume_t::~x_smbd_volume_t()
{
	if (rootdir_fd != -1) {
		close(rootdir_fd);
	}
}

static int smbd_volume_read(int vol_fd,
		uint16_t &vol_id,
		int &rootdir_fd, x_smbd_durable_db_t *&durable_db)
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

	int rfd = openat(vol_fd, "root", O_RDONLY);
	if (rfd < 0) {
		X_LOG_ERR("cannot open rootdir, errno=%d", errno);
		return -errno;
	}

	struct stat st;
	X_ASSERT(fstat(rfd, &st) == 0);
	if (!S_ISDIR(st.st_mode)) {
		X_LOG_ERR("root is not directory");
		close(rfd);
		return -EINVAL;
	}

	int durable_fd = openat(vol_fd, "durable.db", O_RDWR | O_CREAT, 0644);
	X_ASSERT(durable_fd != 0);

	durable_db = x_smbd_durable_db_init(durable_fd,
			0x20000, 0x200000); /* TODO the number */

	vol_id = id;
	rootdir_fd = rfd;
	return 0;
}

std::shared_ptr<x_smbd_volume_t> x_smbd_volume_create(
		const std::string &name, const std::string &path,
		const std::string &owner_node, const std::string &owner_share)
{
	uint16_t vol_id = 0xffffu;
	int rootdir_fd = -1;
	x_smbd_durable_db_t *durable_db;

	if (!path.empty()) {
		int vol_fd = open(path.c_str(), O_RDONLY);
		if (vol_fd < 0) {
			X_LOG_ERR("cannot open volume %s, %d", name.c_str(), errno);
			return nullptr;
		}

		int ret = smbd_volume_read(vol_fd, vol_id, rootdir_fd, durable_db);
		close(vol_fd);
		if (ret < 0) {
			X_LOG_ERR("cannot read volume %s, %d", name.c_str(), -ret);
			return nullptr;
		}
	}

	X_LOG_NOTICE("add volume %s with '%s', '%s', '%s', 0x%x",
			name.c_str(), path.c_str(),
			owner_node.c_str(), owner_share.c_str(),
			vol_id);
	return std::make_shared<x_smbd_volume_t>(name, path, owner_node,
			owner_share, create_volume_id(name),
			vol_id, rootdir_fd, durable_db);
}

int x_smbd_volume_save_durable(x_smbd_volume_t &smbd_volume,
		uint64_t &id_persistent,
		const x_smbd_durable_t *durable)
{
	return x_smbd_durable_db_save(smbd_volume.smbd_durable_db,
			durable, sizeof *durable,
			smbd_volume.volume_id,
			id_persistent);
}

int x_smbd_volume_set_durable_timeout(x_smbd_volume_t &smbd_volume,
		uint64_t id_persistent, uint32_t timeout_sec)
{
	return x_smbd_durable_db_set_timeout(smbd_volume.smbd_durable_db,
			id_persistent, timeout_sec);
}
