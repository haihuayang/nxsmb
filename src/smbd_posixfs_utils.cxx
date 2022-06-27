
#include "smbd_posixfs_utils.hxx"
#include "misc.hxx"
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <attr/xattr.h>
extern "C" {
#include "samba/libcli/smb/smb_constants.h"
#include "samba/libcli/smb/smb2_constants.h"
}

int posixfs_dos_attr_get(int fd, dos_attr_t *dos_attr)
{
	ssize_t err = fgetxattr(fd, XATTR_DOS_ATTR, dos_attr, sizeof *dos_attr);
	// TODO int err = ioctl(fd, FS_IOC_GET_DOS_ATTR, &dos_attr);
	X_ASSERT(err == sizeof *dos_attr);
	return 0;
}

int posixfs_dos_attr_set(int fd, const dos_attr_t *dos_attr)
{
	int err = fsetxattr(fd, XATTR_DOS_ATTR, dos_attr, sizeof *dos_attr, 0);
	X_ASSERT(err == 0);
	return 0;
}

int posixfs_statex_get(int fd, posixfs_statex_t *statex)
{
	int err = fstat(fd, &statex->stat);
	X_ASSERT(err == 0);
	dos_attr_t dos_attr;
	posixfs_dos_attr_get(fd, &dos_attr);
	statex->birth_time = dos_attr.create_time;
	statex->file_attributes = dos_attr.file_attrs;

	return 0;
}

int posixfs_statex_getat(int dirfd, const char *name, posixfs_statex_t *statex)
{
	int fd = openat(dirfd, name, O_NOFOLLOW);
	if (fd < 0) {
		return -errno;
	}
	int err = posixfs_statex_get(fd, statex);
	close(fd);
	return err;
}

static int ntacl_get(int fd, std::vector<uint8_t> &out_data)
{
	ssize_t err = fgetxattr(fd, XATTR_NTACL, out_data.data(), out_data.size());
	if (err < 0) {
		return -errno;
	}
	out_data.resize(err);
	return 0;
}

static int ntacl_set(int fd, const std::vector<uint8_t> &out_data)
{
	int err = fsetxattr(fd, XATTR_NTACL, out_data.data(), out_data.size(), 0);
	X_ASSERT(err == 0);
	return 0;
}

int posixfs_get_ntacl_blob(int fd, std::vector<uint8_t> &blob)
{
	blob.resize(4096); // TODO
	return ntacl_get(fd, blob);
}

int posixfs_set_ntacl_blob(int fd, const std::vector<uint8_t> &blob)
{
	return ntacl_set(fd, blob);
}

NTSTATUS posixfs_get_sd(int fd, std::shared_ptr<idl::security_descriptor> &psd)
{
	std::vector<uint8_t> blob;
	int err = posixfs_get_ntacl_blob(fd, blob);
	if (err < 0) {
		return x_map_nt_error_from_unix(-err);
	}

	uint16_t hash_type;
	uint16_t version;
	std::array<uint8_t, idl::XATTR_SD_HASH_SIZE> hash;
	return parse_acl_blob(blob, psd, &hash_type, &version, hash);
}

void posixfs_post_create(int fd, uint32_t file_attrs, posixfs_statex_t *statex,
		const std::vector<uint8_t> &ntacl_blob)
{
	int err = fstat(fd, &statex->stat);
	X_ASSERT(err == 0);
	dos_attr_t dos_attr = {
		.attr_mask = DOS_SET_CREATE_TIME | DOS_SET_FILE_ATTR,
		.file_attrs = file_attrs,
		.create_time = statex->stat.st_mtim,
	};
	err = posixfs_dos_attr_set(fd, &dos_attr);
	X_ASSERT(err == 0);
	statex->file_attributes = file_attrs;
	statex->birth_time = statex->stat.st_mtim;
	if (!ntacl_blob.empty()) {
		posixfs_set_ntacl_blob(fd, ntacl_blob);
	}
}

int posixfs_create(int dirfd, bool is_dir, const char *path,
		posixfs_statex_t *statex,
		const std::vector<uint8_t> &ntacl_blob)
{
	int fd;
	if (is_dir) {
		int err = mkdirat(dirfd, path, 0777);
		if (err < 0) {
			return -errno;
		}
		fd = openat(dirfd, path, O_RDONLY);
		X_ASSERT(fd >= 0);
	} else {
		fd = openat(dirfd, path, O_RDWR | O_CREAT | O_EXCL, 0666);
		if (fd < 0) {
			return -errno;
		}
	}
	posixfs_post_create(fd, is_dir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_ARCHIVE,
			statex, ntacl_blob);
	return fd;
}


