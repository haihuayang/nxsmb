
#include "smbd_share.hxx"
#include "smbd_volume.hxx"
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <sys/stat.h>

#if 0
static x_smb2_uuid_t create_volume_id(const std::string &name)
{
	x_smb2_uuid_t uuid[4];
	SHA512_CTX sctx;
	SHA512_Init(&sctx);
	SHA512_Update(&sctx, name.data(), name.length());
	SHA512_Final((unsigned char *)&uuid[0], &sctx);
	return uuid[0];
}
#endif
x_smbd_volume_t::x_smbd_volume_t(const x_smb2_uuid_t &uuid,
		const std::string &name,
		std::u16string &&name_u16,
		const std::string &path,
		const std::string &owner_node)
	: uuid(uuid), name(name), name_u16(name_u16)
	, path(path), owner_node(owner_node)
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
	uint16_t id;
	int err = x_smbd_volume_read_id(vol_fd, id);
	if (err) {
		return err;
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
		const x_smb2_uuid_t &uuid,
		const std::string &name, std::u16string &&name_u16,
		const std::string &path, const std::string &owner_node)
{
	X_LOG_NOTICE("add volume '%s' node='%s', path='%s'",
			name.c_str(),
			owner_node.c_str(),
			path.c_str());
	return std::make_shared<x_smbd_volume_t>(uuid, name, std::move(name_u16),
			path, owner_node);
}

int x_smbd_volume_init(x_smbd_volume_t &smbd_volume)
{
	uint16_t vol_id = 0xffffu;
	int rootdir_fd = -1;
	x_smbd_durable_db_t *durable_db;

	if (!smbd_volume.path.empty()) {
		int vol_fd = open(smbd_volume.path.c_str(), O_RDONLY);
		if (vol_fd < 0) {
			X_LOG_ERR("cannot open volume %s, %d",
					smbd_volume.name.c_str(), errno);
			return -1;
		}

		int ret = smbd_volume_read(vol_fd, vol_id, rootdir_fd, durable_db);
		close(vol_fd);
		if (ret < 0) {
			X_LOG_ERR("cannot read volume %s, %d",
					smbd_volume.name.c_str(), -ret);
			return -1;
		}
	}

	X_LOG_NOTICE("volume '%s' with id=0x%x",
			smbd_volume.name.c_str(), vol_id);

	smbd_volume.rootdir_fd = rootdir_fd;
	smbd_volume.volume_id = vol_id;
	smbd_volume.smbd_durable_db = durable_db;
	return 0;
}

NTSTATUS x_smbd_volume_get_fd_path(std::string &path,
		const x_smbd_volume_t &smbd_volume,
		int fd)
{
	char file_path[PATH_MAX];
	char fd_path[64];
	snprintf(fd_path, sizeof fd_path, "/proc/self/fd/%d", fd);
	ssize_t ret = readlink(fd_path, file_path, PATH_MAX);
	if (ret >= PATH_MAX) {
		X_LOG_ERR("file_handle path too long");
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	X_ASSERT(ret > 0);
	file_path[ret] = '\0';
	if (strncmp(file_path, smbd_volume.path.c_str(),
				smbd_volume.path.length()) != 0) {
		X_LOG_ERR("file_handle path %s not under volume %s",
				file_path, smbd_volume.path.c_str());
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	if (strncmp(file_path + smbd_volume.path.length(), "/root/", 6) != 0) {
		X_LOG_ERR("file_handle path %s not under volume root",
				file_path);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	path = file_path + smbd_volume.path.length() + 6;
	return NT_STATUS_OK;
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
#if 0
struct smbd_durable_restorer_t : x_smbd_durable_db_visitor_t
{
	bool operator()(uint64_t id, uint32_t timeout,
			void *record, size_t size) override
	{
		const x_smbd_durable_t *durable = (x_smbd_durable_t *)record;
		printf("0x%lx %u 0x%lx 0x%x %s\n",
				id, timeout,
				durable->id_volatile,
				durable->access_mask,
				x_tostr(durable->owner).c_str());
		return false;
	}
};
#endif

struct smbd_open_restorer_t : x_smbd_durable_db_visitor_t
{
	smbd_open_restorer_t(std::shared_ptr<x_smbd_volume_t> &smbd_volume)
		: smbd_volume{smbd_volume}
	{
	}
	bool operator()(uint64_t id, uint32_t timeout,
			void *record, size_t size) override
	{
		x_smbd_durable_t *durable = (x_smbd_durable_t *)record;
		x_smbd_open_restore(smbd_volume, *durable);
		return false;
	}
	std::shared_ptr<x_smbd_volume_t> & smbd_volume;
};

int x_smbd_volume_restore_durable(std::shared_ptr<x_smbd_volume_t> &smbd_volume)
{
	smbd_open_restorer_t restore{smbd_volume};

	x_smbd_durable_db_traverse(smbd_volume->smbd_durable_db,
			restore);
	return 0;
}


