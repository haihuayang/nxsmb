
#ifndef __smbd_file__hxx__
#define __smbd_file__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "defines.hxx"
#include "smb2.hxx"

struct x_smbd_object_meta_t
{
	bool isdir() const {
		return file_attributes & X_SMB2_FILE_ATTRIBUTE_DIRECTORY;
	}
	uint64_t fsid;
	uint64_t inode;
	uint64_t nlink = 0;
	idl::NTTIME creation;
	idl::NTTIME last_access;
	idl::NTTIME last_write;
	idl::NTTIME change;
	uint32_t file_attributes;
};

struct x_smbd_stream_meta_t
{
	uint64_t end_of_file;
	uint64_t allocation_size;
	bool delete_on_close = false;
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

bool x_smbd_marshall_dir_entry(x_smb2_chain_marshall_t &marshall,
		const x_smbd_object_meta_t &object_meta,
		const x_smbd_stream_meta_t &stream_meta,
		const std::u16string &name, x_smb2_info_level_t info_level);


#endif /* __smbd_file__hxx__ */

