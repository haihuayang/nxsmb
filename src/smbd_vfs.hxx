
#ifndef __smbd_vfs__hxx__
#define __smbd_vfs__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
#include <stdint.h>
#include <sys/stat.h>
#include <time.h>
#include "include/librpc/ndr_smb.hxx"
#include "include/librpc/security.hxx"

struct x_smbd_statex_t
{
	x_smbd_statex_t() {
		stat.st_nlink = 0;
	}
	bool is_valid() const {
		return stat.st_nlink != 0;
	}
	void invalidate() {
		stat.st_nlink = 0;
	}

	uint64_t get_end_of_file() const {
		if (S_ISDIR(stat.st_mode)) {
			return 0;
		}
		return stat.st_size;
	}

	uint64_t get_allocation() const {
		if (S_ISDIR(stat.st_mode)) {
			return 0;
		}
		return stat.st_blocks * 512;
	}

	struct stat stat;
	struct timespec birth_time;
	uint32_t file_attributes;
};

struct x_smb2_basic_info_t
{
	idl::NTTIME creation;
	idl::NTTIME last_access;
	idl::NTTIME last_write;
	idl::NTTIME change;
	uint32_t file_attributes;
};

int x_smbd_vfs_set_basic_info(int fd,
		uint32_t &notify_actions,
		const x_smb2_basic_info_t &basic_info,
		x_smbd_statex_t *statex);

int x_smbd_vfs_create(bool is_dir, const char *path, x_smbd_statex_t *statex,
		const std::vector<uint8_t> &ntacl_blob);

int x_smbd_vfs_open(const char *path, x_smbd_statex_t *statex);
int x_smbd_vfs_get_statex(int dirfd, const char *name, x_smbd_statex_t *statex);
int x_smbd_vfs_get_ntacl_blob(int fd, std::vector<uint8_t> &blob);
int x_smbd_vfs_set_ntacl_blob(int fd, const std::vector<uint8_t> &blob);

#endif /* __smbd_vfs__hxx__ */

