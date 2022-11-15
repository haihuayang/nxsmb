
#ifndef __zfs_wrap__h__
#define __zfs_wrap__h__

#define MINERVA_USER_SPACE 1
#include <sys/types.h>
#include <stdint.h>

/* workaround a bug in sys/fs/zfs.h that { } does not match when __cplusplus is defined */
#ifdef __cplusplus
#define __cplusplus_save __cplusplus
#undef __cplusplus
#endif
#include <sys/fs/zfs.h>
#ifdef __cplusplus_save
#define __cplusplus __cplusplus_save
#undef __cplusplus_save
#endif

#include <sys/ioctl.h>

#define ZFS_DEV_PATH "/dev/zfs"

static inline int zfs_ntnx_ioc_attrex(
		int zfsdev,
		int dirfd,
		uint32_t lookup_flags,
		const char *filename, 
		uint8_t op,
		uint16_t tag_count,
		const zfs_ntnx_attrex_tag_t *tags)
{
	zfs_ntnx_attrex_arg_t arg = {
		.op = op,
		.tag_count = tag_count,
		.tags = (zfs_ntnx_attrex_tag_t *)tags,
		.dirfd = dirfd,
		.lookup_flags = lookup_flags,
		.filename = filename,
	};

	return ioctl(zfsdev, ZFS_IOC_ATTREX, &arg);
}

static inline int zfs_ntnx_set_dos_attr(int zfsdev, int dirfd, uint32_t lookup_flags,
		const char *filename, const dos_attr_t *dos_attr)
{
	zfs_ntnx_attrex_tag_t tags = {
		.tag = ZFS_NTNX_ATTREX_TAG_DOS_ATTR,
		.size = sizeof(dos_attr_t),
		.data = (unsigned long)dos_attr,
	};

	return zfs_ntnx_ioc_attrex(zfsdev, dirfd, lookup_flags, filename,
			ZFS_NTNX_ATTREX_OP_SET,
			1, &tags);
}

#endif /* __zfs_wrap__h__ */

