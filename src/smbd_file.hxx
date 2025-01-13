
#ifndef __smbd_file__hxx__
#define __smbd_file__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "defines.hxx"
#include "smb2.hxx"
#include <fcntl.h>

struct x_smbd_object_meta_t
{
	bool isdir() const {
		return file_attributes & X_SMB2_FILE_ATTRIBUTE_DIRECTORY;
	}
	uint64_t fsid;
	uint64_t inode;
	uint64_t nlink = 0;
	struct timespec creation;
	struct timespec last_access;
	struct timespec last_write;
	struct timespec change;
	uint32_t file_attributes;
};

struct x_smbd_stream_meta_t
{
	uint64_t end_of_file;
	uint64_t allocation_size;
	bool delete_on_close = false;
};

struct x_smbd_file_handle_t
{
	int cmp(const x_smbd_file_handle_t &other) const
	{
		if (base.handle_type != other.base.handle_type) {
			return base.handle_type - other.base.handle_type;
		}
		if (base.handle_bytes != other.base.handle_bytes) {
			return int(base.handle_bytes - other.base.handle_bytes);
		}
		return memcmp(base.f_handle, other.base.f_handle, base.handle_bytes);
	}
	bool is_share_root() const { return base.handle_bytes == 0; }

	struct file_handle base;
	unsigned char f_handle[MAX_HANDLE_SZ];
};

void x_smbd_get_file_info(x_smb2_file_basic_info_t &info,
		const x_smbd_object_meta_t &object_meta);

void x_smbd_get_file_info(x_smb2_file_standard_info_t &info,
		const x_smbd_object_meta_t &object_meta,
		const x_smbd_stream_meta_t &stream_meta,
		uint32_t access_mask,
		uint32_t mode,
		uint64_t current_offset);

void x_smbd_get_file_info(x_smb2_file_all_info_t &info,
		const x_smbd_object_meta_t &object_meta,
		const x_smbd_stream_meta_t &stream_meta,
		uint32_t access_mask,
		uint32_t mode,
		uint64_t current_offset);

void x_smbd_get_file_info(x_smb2_file_network_open_info_t &info,
		const x_smbd_object_meta_t &object_meta,
		const x_smbd_stream_meta_t &stream_meta);

void x_smbd_get_file_info(x_smb2_file_compression_info_t &info,
		const x_smbd_stream_meta_t &stream_meta);

void x_smbd_get_file_info(x_smb2_file_attribute_tag_info_t &info,
		const x_smbd_object_meta_t &object_meta);

bool x_smbd_marshall_dir_entry(x_smb2_chain_marshall_t &marshall,
		const x_smbd_object_meta_t &object_meta,
		const x_smbd_stream_meta_t &stream_meta,
		const std::u16string &name, x_smb2_info_level_t info_level);


#endif /* __smbd_file__hxx__ */

