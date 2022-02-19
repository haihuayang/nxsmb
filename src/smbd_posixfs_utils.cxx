
#include "smbd_posixfs_utils.hxx"
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <attr/xattr.h>

int posixfs_dos_attr_get(int fd, dos_attr_t *dos_attr)
{
	int err = fgetxattr(fd, XATTR_DOS_ATTR, dos_attr, sizeof *dos_attr);
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
	int err = fgetxattr(fd, XATTR_NTACL, out_data.data(), out_data.size());
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


