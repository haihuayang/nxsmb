
#ifndef __smb2_state__hxx__
#define __smb2_state__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "defines.hxx"
#include "smb2.hxx"
#include "include/librpc/security.hxx"

struct x_smb2_change_t
{
	uint32_t action;
	uint32_t filter;
	std::u16string path;
	std::u16string new_path;
};

struct x_smb2_state_read_t
{
	uint8_t in_flags;
	uint32_t in_length;
	uint64_t in_offset;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	uint32_t in_minimum_count;
#if 1
	~x_smb2_state_read_t() {
		if (out_buf) {
			x_buf_release(out_buf);
		}
	}
	x_buf_t *out_buf{};
	uint32_t out_buf_length;
#else
	std::unique_ptr<x_bufref_t> out_data;
#endif
};

struct x_smb2_state_write_t
{
	~x_smb2_state_write_t() {
		if (in_buf) {
			x_buf_release(in_buf);
		}
	}
	uint64_t in_offset;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	uint32_t in_flags;

	x_buf_t *in_buf{};
	uint32_t in_buf_offset;
	uint32_t in_buf_length;

	uint32_t out_count;
	uint32_t out_remaining;
};

struct x_smb2_lock_element_t
{
	uint64_t offset;
	uint64_t length;
	uint32_t flags;
	uint32_t unused;
};

struct x_smb2_state_lock_t
{
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	uint32_t in_lock_sequence_index;
	std::vector<x_smb2_lock_element_t> in_lock_elements;
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
	~x_smb2_state_ioctl_t() {
		if (in_buf) {
			x_buf_release(in_buf);
		}
		if (out_buf) {
			x_buf_release(out_buf);
		}
	}
	uint32_t ctl_code;
	uint32_t in_flags;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
	uint32_t in_max_input_length;
	uint32_t in_max_output_length;

	x_buf_t *in_buf{};
	uint32_t in_buf_offset;
	uint32_t in_buf_length{0};
	x_buf_t *out_buf{};
	uint32_t out_buf_length{0};
#if 0
	std::vector<uint8_t> in_data;
	std::vector<uint8_t> out_data;
#endif
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
	uint32_t in_flags;
	uint32_t in_state;
	x_smb2_lease_key_t in_key;
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
	X_SMB2_CONTEXT_FLAG_ALSI = 4,
};
#if 0
struct x_smb2_state_create_t
{
	uint8_t in_oplock_level;
	uint8_t out_oplock_level;
	uint32_t contexts{0};

	uint32_t in_impersonation_level;
	uint32_t in_desired_access;
	uint32_t in_file_attributes;
	uint32_t in_share_access;
	uint32_t in_create_disposition;
	uint32_t in_create_options;
	std::shared_ptr<idl::security_descriptor> in_security_descriptor;

	x_smb2_lease_t lease;
	uint64_t in_allocation_size{0};
	uint64_t in_timestamp{0};

	bool is_dollar_data = false;
	bool end_with_sep = false;
	std::u16string in_path;
	std::u16string in_ads_name;

	uint8_t out_create_flags;
	bool base_created = false;
	uint32_t out_create_action;
	uint32_t out_maximal_access{0};
	uint8_t out_qfid_info[32];
	x_smb2_create_close_info_t out_info;

	uint32_t granted_access{0}; // internally used

	x_smbd_object_t *smbd_object{};
	x_smbd_lease_t *smbd_lease{};
};
#endif

#endif /* __smb2_state__hxx__ */

