
#ifndef __smbd_posixfs_utils__hxx__
#define __smbd_posixfs_utils__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "samba/include/config.h"
#include "include/xdefines.h"
#include "smbd_file.hxx"
#include "smbd_ntacl.hxx"
#include <vector>
#include <sys/stat.h>
#include <stdint.h>
#include <memory>
extern "C" {
#include "samba/lib/util/samba_util.h"
#include "samba/libcli/util/ntstatus.h"
}

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
#define XATTR_TLD_PATH "user.tld_path"

// int posixfs_dos_attr_get(int fd, dos_attr_t *dos_attr);
int posixfs_dos_attr_set(int fd, const dos_attr_t *dos_attr);
int posixfs_statex_get(int fd, x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta);
int posixfs_statex_getat(int dirfd, const char *name, x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta);
int posixfs_get_ntacl_blob(int fd, std::vector<uint8_t> &blob);
int posixfs_set_ntacl_blob(int fd, const std::vector<uint8_t> &blob);
NTSTATUS posixfs_get_sd(int fd, std::shared_ptr<idl::security_descriptor> &psd);
void posixfs_post_create(int fd, uint32_t file_attrs, x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta,
		const std::vector<uint8_t> &ntacl_blob);
int posixfs_create(int dirfd, bool is_dir, const char *path,
		x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta,
		uint32_t file_attrs,
		uint64_t allocation_size,
		const std::vector<uint8_t> &ntacl_blob);


#endif /* __smbd_posixfs_utils__hxx__ */

