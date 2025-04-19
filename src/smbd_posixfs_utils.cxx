
#include "smbd_posixfs_utils.hxx"
#include "misc.hxx"
#include "include/nttime.hxx"
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <attr/xattr.h>
extern "C" {
}

#ifdef NXSMBD_MINERVA
#define MINORBITS       20
#define MINORMASK       ((1U << MINORBITS) - 1)

#define MAJOR(dev)      ((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)      ((unsigned int) ((dev) & MINORMASK))

#define encode_dev(x) makedev(MAJOR(x), MINOR(x))

static int minerva_zfsdev_fd = -1;
void x_smbd_posixfs_init_dev()
{
	/* set /sys/module/zfs/parameters/zfs_enable_inode_gen_in_atime to 0
	 * to use access time
	 */
	int zfsdev = open(ZFS_DEV_PATH, O_RDWR);
	X_ASSERT(zfsdev != -1);
	minerva_zfsdev_fd = zfsdev;
}

static void fill_statex(x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta,
		const zfs_ntnx_kstat_t kst,
		const dos_attr_t &dos_attr,
		uint64_t fsid)
{
	object_meta->fsid = fsid;
	object_meta->inode = kst.ino;
	object_meta->creation = dos_attr.create_time;
	object_meta->last_access = kst.atime;
	object_meta->last_write = kst.mtime;
	/* samba use mtime for change time */
	object_meta->change = kst.mtime;
	stream_meta->end_of_file = S_ISDIR(kst.mode) ? 0 : kst.size;
	stream_meta->allocation_size = S_ISDIR(kst.mode) ? 0 :
		std::max(uint64_t(kst.blocks) * 512, uint64_t(kst.size)); /* TODO */
	object_meta->file_attributes = dos_attr.file_attrs;
	object_meta->nlink = kst.nlink;
}

static int posixfs_statex_get_(int fd,
		const char *name,
		zfs_ntnx_kstat_t &kst,
		dos_attr_t &dos_attr,
		uint64_t &fsid,
		uint8_t *ntacl_buf, uint32_t *p_ntacl_buf_size)
{
	zfs_ntnx_attrex_tag_t tags[4], *ptag = tags;

	ptag->tag = ZFS_NTNX_ATTREX_TAG_STAT;
	ptag->size = sizeof(zfs_ntnx_kstat_t);
	ptag->data = (unsigned long)&kst;
	ptag++;

	ptag->tag = ZFS_NTNX_ATTREX_TAG_DOS_ATTR;
	ptag->size = sizeof(dos_attr_t);
	ptag->data = (unsigned long)&dos_attr;
	ptag++;

	ptag->tag = ZFS_NTNX_ATTREX_TAG_FSID;
	ptag->size = sizeof(uint64_t);
	ptag->data = 0;
	ptag++;

	if (ntacl_buf) {
		ptag->tag = ZFS_NTNX_ATTREX_TAG_XATTR_NTACL;
		ptag->size = *p_ntacl_buf_size;
		ptag->data = (unsigned long)ntacl_buf;
		ptag++;
	}

	int err = zfs_ntnx_ioc_attrex(minerva_zfsdev_fd, fd,
			AT_SYMLINK_NOFOLLOW,
			name, ZFS_NTNX_ATTREX_OP_GET,
			uint16_t(ptag - tags), tags);
	if (err < 0) {
		return -errno;
	}
	X_ASSERT(err == 0);

	if (dos_attr.file_attrs & X_SMB2_FILE_ATTRIBUTE_DIRECTORY) {
		X_ASSERT(S_ISDIR(kst.mode));
	} else {
		X_ASSERT(!S_ISDIR(kst.mode));
		if (!dos_attr.file_attrs) {
			dos_attr.file_attrs = X_SMB2_FILE_ATTRIBUTE_NORMAL;
		}
	}
	fsid = tags[2].data;
	if (ntacl_buf) {
		*p_ntacl_buf_size = tags[3].size;
	}
	return 0;
}

int posixfs_statex_get(int fd, x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta)
{
	zfs_ntnx_kstat_t kst;
	dos_attr_t dos_attr;
	uint64_t fsid;
	int err = posixfs_statex_get_(fd, nullptr, kst, dos_attr, fsid, nullptr, nullptr);
	X_ASSERT(err == 0);
	X_LOG(SMB, DBG, "posixfs_statex_get(%d) blocks=%llu size=%lu",
			fd, kst.blocks, kst.size);
	fill_statex(object_meta, stream_meta, kst, dos_attr, fsid);
	return 0;
}

int posixfs_statex_getat(int dirfd, const char *name,
		x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta,
		std::shared_ptr<idl::security_descriptor> *ppsd)
{
	zfs_ntnx_kstat_t kst;
	dos_attr_t dos_attr;
	uint64_t fsid;
	uint8_t ntacl_buf[0x10000], *ntacl_buf_ptr = nullptr;
	uint32_t ntacl_buf_size = 0;
	if (ppsd) {
		ntacl_buf_ptr = ntacl_buf;
		ntacl_buf_size = sizeof(ntacl_buf);
	}

	int err = posixfs_statex_get_(dirfd, name, kst, dos_attr, fsid, ntacl_buf_ptr,
			&ntacl_buf_size);
	if (err < 0) {
		return err;
	}
	if (ppsd) {
		uint16_t hash_type;
		uint16_t version;
		std::array<uint8_t, idl::XATTR_SD_HASH_SIZE> hash;
		parse_acl_blob(ntacl_buf, ntacl_buf_size, *ppsd, &hash_type,
				&version, hash);
	}
	fill_statex(object_meta, stream_meta, kst, dos_attr, fsid);
	return 0;
}

int posixfs_dos_attr_get(int fd, dos_attr_t *dos_attr)
{
	zfs_ntnx_attrex_tag_t tags[1], *ptag = tags;

	ptag->tag = ZFS_NTNX_ATTREX_TAG_DOS_ATTR;
	ptag->size = sizeof(dos_attr_t);
	ptag->data = (unsigned long)&dos_attr;
	ptag++;

	int err = zfs_ntnx_ioc_attrex(minerva_zfsdev_fd, fd,
			AT_SYMLINK_NOFOLLOW,
			nullptr, ZFS_NTNX_ATTREX_OP_GET,
			1, tags);
	X_ASSERT(err == 0);
	return 0;
}

int posixfs_dos_attr_set(int fd, const dos_attr_t *dos_attr)
{
	dos_attr_t tmp = *dos_attr;
	/* zfs does not support */
	tmp.file_attrs &= ~(X_SMB2_FILE_ATTRIBUTE_NORMAL
			| X_SMB2_FILE_ATTRIBUTE_ENCRYPTED
			| X_SMB2_FILE_ATTRIBUTE_TEMPORARY
			| X_SMB2_FILE_ATTRIBUTE_OFFLINE
			| X_SMB2_FILE_ATTRIBUTE_DIRECTORY);
	int err = zfs_ntnx_set_dos_attr(minerva_zfsdev_fd, fd, AT_SYMLINK_NOFOLLOW,
			nullptr, &tmp);
	X_ASSERT(err == 0);
	return 0;
}

void posixfs_post_create(int fd, uint32_t file_attrs,
		x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta,
		const std::vector<uint8_t> &ntacl_blob)
{
	zfs_ntnx_kstat_t kst;
	dos_attr_t dos_attr;
	uint64_t fsid;
	int err = posixfs_statex_get_(fd, nullptr, kst, dos_attr, fsid, nullptr, nullptr);
	X_ASSERT(err == 0);
	if (file_attrs != 0) {
		dos_attr.attr_mask = DOS_SET_CREATE_TIME | DOS_SET_FILE_ATTR,
		dos_attr.file_attrs = file_attrs;
		dos_attr.create_time = kst.mtime;
		int err = posixfs_dos_attr_set(fd, &dos_attr);
		X_ASSERT(err == 0);
	}

	fill_statex(object_meta, stream_meta, kst, dos_attr, fsid);
	if (!ntacl_blob.empty()) {
		posixfs_set_ntacl_blob(fd, ntacl_blob);
	}
}

#else
void x_smbd_posixfs_init_dev()
{
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
	X_LOG(SMB, DBG, "posixfs_statex_get(%d) blocks=%lu size=%lu",
			fd, stat.st_blocks, stat.st_size);
	dos_attr_t dos_attr;
	posixfs_dos_attr_get(fd, &dos_attr);

	if (dos_attr.file_attrs & X_SMB2_FILE_ATTRIBUTE_DIRECTORY) {
		X_ASSERT(S_ISDIR(stat.st_mode));
	} else {
		X_ASSERT(!S_ISDIR(stat.st_mode));
	}

	fill_statex(object_meta, stream_meta, stat, dos_attr);
	return 0;
}

int posixfs_statex_getat(int dirfd, const char *name,
		x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta,
		std::shared_ptr<idl::security_descriptor> *ppsd)
{
	int fd = openat(dirfd, name, O_NOFOLLOW);
	if (fd < 0) {
		return -errno;
	}
	int err = posixfs_statex_get(fd, object_meta, stream_meta);
	if (err == 0) {
		if (ppsd) {
			posixfs_get_sd(fd, *ppsd);
			/* TODO check return value */
		}
	}
	close(fd);
	return err;
}

void posixfs_post_create(int fd, uint32_t file_attrs,
		x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta,
		const std::vector<uint8_t> &ntacl_blob)
{
	struct stat stat;
	int err = fstat(fd, &stat);
	X_ASSERT(err == 0);
	if (S_ISDIR(stat.st_mode)) {
		file_attrs |= (uint32_t)X_SMB2_FILE_ATTRIBUTE_DIRECTORY;
	} else {
		file_attrs |= (uint32_t)X_SMB2_FILE_ATTRIBUTE_ARCHIVE;
		file_attrs &= ~(uint32_t)X_SMB2_FILE_ATTRIBUTE_DIRECTORY;
	}

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
#endif

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
	return parse_acl_blob(blob.data(), blob.size(), psd, &hash_type, &version, hash);
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

	/* it is incorrect to use ftruncate to set AlSi */
	if (false && allocation_size && !is_dir) {
		int err = ftruncate(fd, allocation_size);
		if (err < 0) {
			int save_errno = errno;
			err = unlinkat(dirfd, path, is_dir ? AT_REMOVEDIR : 0);
			X_ASSERT(err == 0);
			return -save_errno;
		}
	}

	/* TODO delete file if fail */
	file_attrs &= ~(X_SMB2_FILE_ATTRIBUTE_NORMAL);
	if (is_dir) {
		file_attrs |= X_SMB2_FILE_ATTRIBUTE_DIRECTORY;
	} else {
		file_attrs |= X_SMB2_FILE_ATTRIBUTE_ARCHIVE;
	}
	posixfs_post_create(fd, file_attrs,
			object_meta, stream_meta, ntacl_blob);
	if (!is_dir) {
		stream_meta->allocation_size = allocation_size;
	}
	return fd;
}


