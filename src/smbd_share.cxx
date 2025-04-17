
#include "smbd_share.hxx"
#include "smbd_volume.hxx"
#include "smbd_open.hxx"
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
		uint16_t volume_id,
		const std::string &owner_node,
		const std::string &path,
		uint32_t allocation_roundup_size)
	: uuid(uuid)
	, owner_node(owner_node), path(path)
	, allocation_roundup_size(allocation_roundup_size)
	, volume_id(volume_id)
{
}

x_smbd_volume_t::~x_smbd_volume_t()
{
	if (smbd_durable_db) {
		x_smbd_durable_db_release(smbd_durable_db);
	}
	if (root_fd != -1) {
		close(root_fd);
	}
	// x_smbd_release_object(root_object);
}

std::shared_ptr<x_smbd_volume_t> x_smbd_volume_create(
		const x_smb2_uuid_t &uuid,
		uint16_t volume_id,
		const std::string &owner_node,
		const std::string &path,
		uint32_t allocation_roundup_size)
{
	X_LOG(CONF, NOTICE, "add volume %u '%s', path='%s'",
			volume_id, x_tostr(uuid).c_str(), path.c_str());
	return std::make_shared<x_smbd_volume_t>(uuid, volume_id,
			owner_node, path, allocation_roundup_size);
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
		X_LOG(CONF, ERR, "file_handle path too long");
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	X_ASSERT(ret > 0);
	file_path[ret] = '\0';
	if (strncmp(file_path, smbd_volume.path.c_str(),
				smbd_volume.path.length()) != 0) {
		X_LOG(CONF, ERR, "file_handle path %s not under volume %s",
				file_path, smbd_volume.path.c_str());
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	if (strncmp(file_path + smbd_volume.path.length(), "/root/", 6) != 0) {
		X_LOG(CONF, ERR, "file_handle path %s not under volume root",
				file_path);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	path = file_path + smbd_volume.path.length() + 6;
	return NT_STATUS_OK;
}

int x_smbd_volume_allocate_persistent(x_smbd_volume_t &smbd_volume,
		uint64_t *p_id_persistent, uint64_t id_volatile)
{
	uint64_t id;
	int err = x_smbd_durable_db_allocate_id(smbd_volume.smbd_durable_db,
			&id, id_volatile);
	if (err == 0) {
		*p_id_persistent = ((uint64_t)smbd_volume.volume_id) << 48 | id;
	}
	return err;
}

int x_smbd_volume_save_durable(x_smbd_volume_t &smbd_volume,
		uint64_t id_persistent,
		uint64_t id_volatile,
		const x_smbd_open_state_t &open_state,
		const x_smbd_lease_data_t &lease_data,
		const x_smbd_file_handle_t &file_handle)
{
	return x_smbd_durable_save(smbd_volume.smbd_durable_db,
			id_persistent,
			id_volatile,
			open_state, lease_data, file_handle);
}

int x_smbd_volume_update_durable_flags(x_smbd_volume_t &smbd_volume,
		uint64_t id_persistent,
		const x_smbd_open_state_t &open_state)
{
	return x_smbd_durable_update_flags(smbd_volume.smbd_durable_db,
			open_state.dhmode == x_smbd_dhmode_t::PERSISTENT,
			id_persistent,
			open_state.flags);
}

int x_smbd_volume_update_durable_locks(x_smbd_volume_t &smbd_volume,
		bool sync,
		uint64_t id_persistent,
		const std::vector<x_smb2_lock_element_t> &locks)
{
	return x_smbd_durable_update_locks(smbd_volume.smbd_durable_db,
			sync,
			id_persistent, locks);
}

int x_smbd_volume_disconnect_durable(x_smbd_volume_t &smbd_volume,
		bool sync,
		uint64_t id_persistent)
{
	return x_smbd_durable_disconnect(smbd_volume.smbd_durable_db,
			sync, id_persistent);
}

int x_smbd_volume_remove_durable(x_smbd_volume_t &smbd_volume,
		bool sync,
		uint64_t id_persistent)
{
	return x_smbd_durable_remove(smbd_volume.smbd_durable_db,
			sync, id_persistent);
}

int x_smbd_volume_restore_durable(std::shared_ptr<x_smbd_share_t> smbd_share,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume)
{
	x_smbd_durable_db_restore(smbd_share, smbd_volume,
			smbd_volume->smbd_durable_db,
			x_smbd_open_restore);
	return 0;
}


