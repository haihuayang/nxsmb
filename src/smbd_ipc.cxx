
#include "smbd.hxx"

struct x_smbd_name_pipe_t
{
	x_smbd_open_t base;
	std::vector<uint8_t> write_data;
};

static inline x_smbd_name_pipe_t *from_smbd_open(x_smbd_open_t *smbd_open)
{
	return X_CONTAINER_OF(smbd_open, x_smbd_name_pipe_t, base);
}

static NTSTATUS x_smbd_name_pipe_write(x_smbd_open_t *smbd_open, const x_smb2_requ_write_t &requ,
		const uint8_t *data, x_smb2_resp_write_t &resp)
{
	x_smbd_name_pipe_t *name_pipe = from_smbd_open(smbd_open);
	resp.write_count = requ.data_length;
	resp.write_remaining = 0;
	return NT_STATUS_OK;
}

static NTSTATUS x_smbd_name_pipe_getinfo(x_smbd_open_t *smbd_open, const x_smb2_requ_getinfo_t &requ, std::vector<uint8_t> &output)
{
	/* SMB2_GETINFO_FILE, SMB2_FILE_STANDARD_INFO */
	if (requ.info_class == 0x01 && requ.info_level == 0x05) {
		/* only little endian */
		struct {
			uint64_t allocation_size;
			uint64_t end_of_file;
			uint32_t link_count;
			uint8_t delete_pending;
			uint8_t is_directory;
			uint16_t reserve;
		} standard_info = {
			4096, 0, 1, 1, 0, 0
		};
		output.assign((const uint8_t *)&standard_info, (const uint8_t *)(&standard_info + 1));
		return NT_STATUS_OK;
	} else {
		return NT_STATUS_NOT_SUPPORTED;
	}
}

static NTSTATUS x_smbd_name_pipe_close(x_smbd_open_t *smbd_open,
		const x_smb2_requ_close_t &requ, x_smb2_resp_close_t &resp)
{
	memset(&resp, 0, sizeof resp);
	resp.struct_size = 0x3c;
	return NT_STATUS_OK;
}

static void x_smbd_name_pipe_destroy(x_smbd_open_t *smbd_open)
{
	x_smbd_name_pipe_t *name_pipe = from_smbd_open(smbd_open);
	delete name_pipe;
}

static const x_smbd_open_ops_t x_smbd_name_pipe_ops = {
	nullptr, // x_smbd_name_pipe_read,
	x_smbd_name_pipe_write,
	x_smbd_name_pipe_getinfo,
	nullptr,
	x_smbd_name_pipe_close,
	x_smbd_name_pipe_destroy,
};

static inline x_smbd_name_pipe_t *x_smbd_name_pipe_create(std::shared_ptr<x_smbd_tcon_t> &smbd_tcon)
{
	x_smbd_name_pipe_t *name_pipe = new x_smbd_name_pipe_t;
	name_pipe->base.ops = &x_smbd_name_pipe_ops;
	name_pipe->base.smbd_tcon = smbd_tcon;
	return name_pipe;
}


static std::map<std::u16string, int> rpc_lookup;

static x_smbd_open_t *x_smbd_tcon_ipc_op_create(std::shared_ptr<x_smbd_tcon_t> &smbd_tcon,
		NTSTATUS &status, x_smb2_requ_create_t &requ_create)
{
	std::u16string in_name;
	in_name.reserve(requ_create.in_name.size());
	std::transform(std::begin(requ_create.in_name), std::end(requ_create.in_name),
			std::back_inserter(in_name), tolower);


	auto it = rpc_lookup.find(in_name);
	if (it == rpc_lookup.end()) {
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		return nullptr;
	}

	x_smbd_name_pipe_t *name_pipe = x_smbd_name_pipe_create(smbd_tcon);
	x_smbd_open_insert_local(&name_pipe->base);

	requ_create.out_create_ts.val = 0;
	requ_create.out_last_access_ts.val = 0;
	requ_create.out_last_write_ts.val = 0;
	requ_create.out_change_ts.val = 0;
	requ_create.out_allocation_size = 4096;
	requ_create.out_end_of_file = 0;
	requ_create.out_file_attributes = FILE_ATTRIBUTE_NORMAL;
	requ_create.out_oplock_level = 0;
	requ_create.out_create_flags = 0;
	requ_create.out_create_action = FILE_WAS_OPENED;

	//status = x_smbd_open_np_file(smbd_open);
	status = NT_STATUS_OK;
	return &name_pipe->base;
}

static const x_smbd_tcon_ops_t x_smbd_tcon_ipc_ops = {
	x_smbd_tcon_ipc_op_create,
};

void x_smbd_tcon_init_ipc(x_smbd_tcon_t *smbd_tcon)
{
	smbd_tcon->ops = &x_smbd_tcon_ipc_ops;
}

int x_smbd_ipc_init()
{
	rpc_lookup[u"srvsvc"] = 1;
	rpc_lookup[u"wkssvc"] = 1;
	return 0;
}

