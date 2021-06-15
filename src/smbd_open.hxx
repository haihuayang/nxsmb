
#ifndef __smbd_open__hxx__
#define __smbd_open__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "smbd.hxx"

struct x_smb2_create_close_info_t
{
	idl::NTTIME out_create_ts;
	idl::NTTIME out_last_access_ts;
	idl::NTTIME out_last_write_ts;
	idl::NTTIME out_change_ts;
	uint64_t out_allocation_size{0};
	uint64_t out_end_of_file{0};
	uint32_t out_file_attributes{0};
};


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

struct x_smb2_state_find_t
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
	uint16_t in_flags;
	uint32_t in_output_buffer_length;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	uint32_t in_filter;

	std::vector<uint8_t> out_data;
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

struct x_smbd_open_ops_t
{
	NTSTATUS (*read)(x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_read_t> &state);
	NTSTATUS (*write)(x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_write_t> &state);
	NTSTATUS (*getinfo)(x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_getinfo_t> &state);
	NTSTATUS (*setinfo)(x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_setinfo_t> &state);
	NTSTATUS (*find)(x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_find_t> &state);
	NTSTATUS (*ioctl)(x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_ioctl_t> &state);
	NTSTATUS (*notify)(x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_notify_t> &state);
	NTSTATUS (*close)(x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_close_t> &state);
	void (*destroy)(x_smbd_open_t *smbd_open);
};

static inline NTSTATUS x_smbd_open_op_read(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_read_t> &state)
{
	return smbd_requ->smbd_open->ops->read(smbd_conn, smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_write(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_write_t> &state)
{
	return smbd_requ->smbd_open->ops->write(smbd_conn, smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_getinfo(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_getinfo_t> &state)
{
	return smbd_requ->smbd_open->ops->getinfo(smbd_conn, smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_setinfo(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_setinfo_t> &state)
{
	return smbd_requ->smbd_open->ops->setinfo(smbd_conn, smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_find(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_find_t> &state)
{
	return smbd_requ->smbd_open->ops->find(smbd_conn, smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_ioctl(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_ioctl_t> &state)
{
	return smbd_requ->smbd_open->ops->ioctl(smbd_conn, smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_notify(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_notify_t> &state)
{
	return smbd_requ->smbd_open->ops->notify(smbd_conn, smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_close(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state)
{
	return smbd_requ->smbd_open->ops->close(smbd_conn, smbd_requ, state);
}

struct x_smb2_state_create_t
{
	uint8_t in_oplock_level;
	uint32_t in_impersonation_level;
	uint32_t in_desired_access;
	uint32_t in_file_attributes;
	uint32_t in_share_access;
	uint32_t in_create_disposition;
	uint32_t in_create_options;

	std::u16string in_name;
	std::vector<uint8_t> in_context;

	uint8_t out_oplock_level;
	uint8_t out_create_flags;
	uint32_t out_create_action;
	x_smb2_create_close_info_t out_info;

	std::vector<uint8_t> out_context;
};

struct x_smbd_tcon_ops_t
{
	x_smbd_open_t *(*create)(x_smbd_tcon_t *smbd_tcon,
			NTSTATUS &status,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_create_t> &state);
};

static inline x_smbd_open_t *x_smbd_tcon_op_create(x_smbd_tcon_t *smbd_tcon,
		NTSTATUS &status,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	return smbd_tcon->ops->create(smbd_tcon, status, smbd_requ, state);
}



#endif /* __smbd_open__hxx__ */

