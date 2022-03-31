
#ifndef __smbd_open__hxx__
#define __smbd_open__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "defines.hxx"
#include "include/librpc/ndr_smb.hxx"
#include "smb2.hxx"

struct x_smb2_state_read_t
{
	uint8_t in_flags;
	uint32_t in_length;
	uint64_t in_offset;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	uint32_t in_minimum_count;

	std::vector<uint8_t> out_data;
};

struct x_smb2_state_write_t
{
	uint64_t in_offset;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	uint32_t in_flags;
	std::vector<uint8_t> in_data;

	uint32_t out_count;
	uint32_t out_remaining;
};

struct x_smb2_state_getinfo_t
{
	uint8_t  in_info_class;
	uint8_t  in_info_level;
	uint32_t in_output_buffer_length;
	uint32_t in_additional;
	uint32_t in_flags;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;

	std::vector<uint8_t> out_data;
};

struct x_smb2_state_setinfo_t
{
	uint8_t  in_info_class;
	uint8_t  in_info_level;
	uint32_t in_additional;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	std::vector<uint8_t> in_data;
};

struct x_smb2_state_qdir_t
{
	uint8_t in_info_level;
	uint8_t in_flags;
	uint32_t in_file_index;
	uint32_t in_output_buffer_length;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	std::u16string in_name;

	std::vector<uint8_t> out_data;
};

struct x_smb2_state_ioctl_t
{
	uint32_t ctl_code;
	uint32_t in_flags;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
	uint32_t in_max_input_length;
	uint32_t in_max_output_length;

	std::vector<uint8_t> in_data;
	std::vector<uint8_t> out_data;
};

struct x_smb2_state_notify_t
{
	// void done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ, NTSTATUS status);
	uint16_t in_flags;
	uint32_t in_output_buffer_length;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	uint32_t in_filter;

	std::vector<uint8_t> out_data;
};

struct x_smb2_state_lease_break_t
{
	uint8_t in_oplock_level;
	uint32_t in_flags;
	x_smb2_lease_key_t in_key;
	uint32_t in_state;
	uint64_t in_duration;
};

struct x_smb2_state_oplock_break_t
{
	uint8_t in_oplock_level;
	uint8_t out_oplock_level;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
};

struct x_smb2_state_close_t
{
	uint16_t in_struct_size;
	uint16_t in_flags;
	uint32_t in_reserved;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;

	uint16_t out_struct_size;
	uint16_t out_flags{0};
	uint32_t out_reserved{0};
	x_smb2_create_close_info_t out_info;
};

enum {
	X_SMB2_CONTEXT_FLAG_MXAC = 1,
	X_SMB2_CONTEXT_FLAG_QFID = 2,
};

struct x_smb2_state_create_t
{
	uint8_t oplock_level;
	uint32_t contexts{0};

	uint32_t in_impersonation_level;
	uint32_t in_desired_access;
	uint32_t in_file_attributes;
	uint32_t in_share_access;
	uint32_t in_create_disposition;
	uint32_t in_create_options;

	x_smb2_lease_t lease;

	std::u16string in_name;

	uint8_t out_create_flags;
	uint32_t out_create_action;
	uint32_t out_maximal_access{0};
	uint8_t out_qfid_info[32];
	x_smb2_create_close_info_t out_info;

	uint32_t granted_access{0}; // internally used
};

#endif /* __smbd_open__hxx__ */

