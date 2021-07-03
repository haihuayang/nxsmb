
#include "smb2.hxx"
#include "smbd_vfs.hxx"
#include <sys/types.h>
#include <attr/xattr.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>


/* Attr Mask */
#define DOS_SET_CREATE_TIME   0x0001L
#define DOS_SET_FILE_ATTR     0x0002L
#define DOS_SET_SCAN_STAMP    0x0004L
#define DOS_SET_QUARANTINE    0x0008L
#define DOS_SET_UNQUARANTINE  0x0010L

#define FS_IOC_GET_DOS_ATTR             _IOR('t', 1, dos_attr_t)
#define FS_IOC_SET_DOS_ATTR             _IOW('t', 2, dos_attr_t)
typedef struct dos_attr_s {
	uint32_t attr_mask;
	uint32_t file_attrs;
	struct timespec create_time;
	char scan_stamp[32];
} dos_attr_t;

#define XATTR_DOS_ATTR "user.dos_attr"
#define XATTR_NTACL "security.NTACL"

static int dos_attr_get(int fd, dos_attr_t *dos_attr)
{
	int err = fgetxattr(fd, XATTR_DOS_ATTR, dos_attr, sizeof *dos_attr);
	// TODO int err = ioctl(fd, FS_IOC_GET_DOS_ATTR, &dos_attr);
	X_ASSERT(err == sizeof *dos_attr);
	return 0;
}

static int dos_attr_set(int fd, const dos_attr_t *dos_attr)
{
	int err = fsetxattr(fd, XATTR_DOS_ATTR, dos_attr, sizeof *dos_attr, 0);
	X_ASSERT(err == 0);
	return 0;
}

static int statex_get(int fd, x_smbd_statex_t *statex)
{
	int err = fstat(fd, &statex->stat);
	X_ASSERT(err == 0);
	dos_attr_t dos_attr;
	dos_attr_get(fd, &dos_attr);
	statex->birth_time = dos_attr.create_time;
	statex->file_attributes = dos_attr.file_attrs;

	return 0;
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

int x_smbd_vfs_get_ntacl_blob(int fd, std::vector<uint8_t> &blob)
{
	blob.resize(4096); // TODO
	return ntacl_get(fd, blob);
}

int x_smbd_vfs_set_ntacl_blob(int fd, const std::vector<uint8_t> &blob)
{
	return ntacl_set(fd, blob);
}

int x_smbd_vfs_get_statex(int dirfd, const char *name,
		x_smbd_statex_t *statex)
{
	int fd = openat(dirfd, name, O_NOFOLLOW);
	if (fd < 0) {
		return -errno;
	}

	statex_get(fd, statex);
	X_ASSERT(close(fd) == 0);
	return 0;
}
#if 0
int x_smbd_vfs_get_security(int fd, uint32_t buffer_size,
		uint32_t additional,
		std::vector<uint8_t> &out_data)
{
	if (buffer_size > 4 * 1024) {
		buffer_size = 4 * 1024;
	}
	out_data.resize(buffer_size);
	ntacl_get(fd, out_data);
	return 0;
}

int x_smbd_vfs_set_security(int fd,
		uint32_t additional,
		const std::vector<uint8_t> &out_data)
{

	X_ASSERT(out_data.size() <= 4 * 1024);
	ntacl_set(fd, out_data);
	return 0;
}
#endif
int x_smbd_vfs_open(const char *path, x_smbd_statex_t *statex)
{
	bool is_dir = false;
	int fd = open(path, O_RDWR);
	if (fd < 0) {
		if (errno != EISDIR) {
			return -errno;
		}
		fd = open(path, O_RDONLY);
		X_ASSERT(fd >= 0);
		is_dir = true;
	}

	statex_get(fd, statex);
	X_ASSERT(is_dir == S_ISDIR(statex->stat.st_mode));
	return fd;
}

/* FileAttributes (search attributes) field */
#define FILE_ATTRIBUTE_READONLY         0x0001L
#define FILE_ATTRIBUTE_HIDDEN           0x0002L
#define FILE_ATTRIBUTE_SYSTEM           0x0004L
#define FILE_ATTRIBUTE_VOLUME           0x0008L
#define FILE_ATTRIBUTE_DIRECTORY        0x0010L
#define FILE_ATTRIBUTE_ARCHIVE          0x0020L
#define FILE_ATTRIBUTE_DEVICE           0x0040L
#define FILE_ATTRIBUTE_NORMAL           0x0080L
#define FILE_ATTRIBUTE_TEMPORARY        0x0100L
#define FILE_ATTRIBUTE_SPARSE           0x0200L
#define FILE_ATTRIBUTE_REPARSE_POINT    0x0400L
#define FILE_ATTRIBUTE_COMPRESSED       0x0800L
#define FILE_ATTRIBUTE_OFFLINE          0x1000L
#define FILE_ATTRIBUTE_NONINDEXED       0x2000L
#define FILE_ATTRIBUTE_ENCRYPTED        0x4000L
#define FILE_ATTRIBUTE_ALL_MASK         0x7FFFL

static void post_create(int fd, uint32_t file_attrs, x_smbd_statex_t *statex,
		const std::vector<uint8_t> &ntacl_blob)
{
	int err = fstat(fd, &statex->stat);
	X_ASSERT(err == 0);
	dos_attr_t dos_attr = {
		.attr_mask = DOS_SET_CREATE_TIME | DOS_SET_FILE_ATTR,
		.file_attrs = file_attrs,
		.create_time = statex->stat.st_mtim,
	};
	err = dos_attr_set(fd, &dos_attr);
	X_ASSERT(err == 0);
	statex->file_attributes = file_attrs;
	statex->birth_time = statex->stat.st_mtim;
	ntacl_set(fd, ntacl_blob);
}
		
int x_smbd_vfs_create(bool is_dir, const char *path, x_smbd_statex_t *statex,
		const std::vector<uint8_t> &ntacl_blob)
{
	int fd;
	if (is_dir) {
		int err = mkdir(path, 0777);
		if (err < 0) {
			return -errno;
		}
		fd = open(path, O_RDONLY);
		X_ASSERT(fd >= 0);
	} else {
		fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0666);
		if (fd < 0) {
			return -errno;
		}
	}
	post_create(fd, is_dir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_ARCHIVE,
			statex, ntacl_blob);
	return fd;
}

static bool is_null_ntime(idl::NTTIME nt)
{
	return nt.val == 0 || nt.val == (uint64_t)-1;
}

int x_smbd_vfs_set_basic_info(int fd,
		uint32_t &notify_actions,
		const x_smb2_basic_info_t &basic_info,
		x_smbd_statex_t *statex)
{
	dos_attr_t dos_attr;
	memset(&dos_attr, 0, sizeof dos_attr);
	if (basic_info.file_attributes != 0) {
		dos_attr.attr_mask |= DOS_SET_FILE_ATTR;
		dos_attr.file_attrs = basic_info.file_attributes;
		notify_actions |= FILE_NOTIFY_CHANGE_ATTRIBUTES;
	}

	if (!is_null_ntime(basic_info.creation)) {
		dos_attr.attr_mask |= DOS_SET_CREATE_TIME;
		dos_attr.create_time = x_nttime_to_timespec(basic_info.creation);
		notify_actions |= FILE_NOTIFY_CHANGE_CREATION;
	}

	if (dos_attr.attr_mask != 0) {
		dos_attr_set(fd, &dos_attr);
	}

	struct timespec uts[2] = {
		{ 0, UTIME_OMIT },
		{ 0, UTIME_OMIT },
	};

	int count = 0;
	if (!is_null_ntime(basic_info.last_access)) {
		uts[0] = x_nttime_to_timespec(basic_info.last_access);
		notify_actions |= FILE_NOTIFY_CHANGE_LAST_ACCESS;
		++count;
	}

	if (!is_null_ntime(basic_info.last_write)) {
		uts[0] = x_nttime_to_timespec(basic_info.last_write);
		notify_actions |= FILE_NOTIFY_CHANGE_LAST_WRITE;
		++count;
	}

	if (count) {
		int err = futimens(fd, uts);
		X_TODO_ASSERT(err == 0);
	}
	
	statex_get(fd, statex);
	return 0;
}
