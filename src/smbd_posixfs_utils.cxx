
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

#if 0
ssize_t posixfs_getxattr(int fd, const char *name, void *data, size_t size);
{
	ssize_t err = fgetxattr(fd, name, );
}
#endif
static int posixfs_dos_attr_get(int fd, dos_attr_t *dos_attr)
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

static void fill_statex(x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta,
		const struct stat &stat,
		const dos_attr_t &dos_attr)
{
	/* TODO for now we use st_dev as the fs id. st_dev can change in remounting,
	   should use fsid from statvfs
	 */
	object_meta->fsid = stat.st_dev;
	object_meta->inode = stat.st_ino;
	object_meta->creation = x_timespec_to_nttime(dos_attr.create_time);
	object_meta->last_access = x_timespec_to_nttime(stat.st_atim);
	object_meta->last_write = x_timespec_to_nttime(stat.st_mtim);
	object_meta->change = x_timespec_to_nttime(stat.st_ctim);
	stream_meta->end_of_file = S_ISDIR(stat.st_mode) ? 0 : stat.st_size;
	stream_meta->allocation_size = S_ISDIR(stat.st_mode) ? 0 :
		std::max(stat.st_blocks * 512, stat.st_size); /* TODO */
	object_meta->file_attributes = dos_attr.file_attrs;
	object_meta->nlink = stat.st_nlink;
}

int posixfs_statex_get(int fd, x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta)
{
	struct stat stat;
	int err = fstat(fd, &stat);
	X_ASSERT(err == 0);
	dos_attr_t dos_attr;
	posixfs_dos_attr_get(fd, &dos_attr);

	if (dos_attr.file_attrs & FILE_ATTRIBUTE_DIRECTORY) {
		X_ASSERT(S_ISDIR(stat.st_mode));
	} else {
		X_ASSERT(!S_ISDIR(stat.st_mode));
	}

	fill_statex(object_meta, stream_meta, stat, dos_attr);
	return 0;
}

int posixfs_statex_getat(int dirfd, const char *name,
		x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta)
{
	int fd = openat(dirfd, name, O_NOFOLLOW);
	if (fd < 0) {
		return -errno;
	}
	int err = posixfs_statex_get(fd, object_meta, stream_meta);
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

void posixfs_post_create(int fd, uint32_t file_attrs,
		x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta,
		const std::vector<uint8_t> &ntacl_blob)
{
	struct stat stat;
	int err = fstat(fd, &stat);
	X_ASSERT(err == 0);
	dos_attr_t dos_attr = {
		.attr_mask = DOS_SET_CREATE_TIME | DOS_SET_FILE_ATTR,
		.file_attrs = file_attrs,
		.create_time = stat.st_mtim,
	};
	err = posixfs_dos_attr_set(fd, &dos_attr);
	X_ASSERT(err == 0);

	fill_statex(object_meta, stream_meta, stat, dos_attr);
	if (!ntacl_blob.empty()) {
		posixfs_set_ntacl_blob(fd, ntacl_blob);
	}
}

/* TODO we can use file_attrs to indicate if it is a dir */
int posixfs_create(int dirfd, bool is_dir, const char *path,
		x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta,
		uint32_t file_attrs,
		uint64_t allocation_size,
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
	if (allocation_size && !is_dir) {
		int err = ftruncate(fd, allocation_size);
		if (err < 0) {
			int save_errno = errno;
			err = unlinkat(dirfd, path, is_dir ? AT_REMOVEDIR : 0);
			X_ASSERT(err == 0);
			return -save_errno;
		}
	}

	// file_attrs &= FILE_ATTRIBUTE_ALL_MASK;
	file_attrs &= SAMBA_ATTRIBUTES_MASK;
	if (is_dir) {
		file_attrs &= ~(uint32_t)FILE_ATTRIBUTE_ARCHIVE;
		file_attrs |= (uint32_t)FILE_ATTRIBUTE_DIRECTORY;
	} else {
		file_attrs |= (uint32_t)FILE_ATTRIBUTE_ARCHIVE;
		file_attrs &= ~(uint32_t)FILE_ATTRIBUTE_DIRECTORY;
	}
	/* TODO delete file if fail */
	posixfs_post_create(fd, file_attrs,
			object_meta, stream_meta, ntacl_blob);
	return fd;
}


