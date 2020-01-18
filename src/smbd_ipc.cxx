
#include "smbd.hxx"

static std::map<std::u16string, int> rpc_lookup;

static x_smbd_open_t *x_smbd_tcon_ipc_op_create(x_smbd_tcon_t *smbd_tcon,
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

	x_smbd_open_t *smbd_open = x_smbd_open_create(smbd_tcon);

	requ_create.out_create_ts.val = 0;
	requ_create.out_last_access_ts.val = 0;
	requ_create.out_last_write_ts.val = 0;
	requ_create.out_change_ts.val = 0;
	requ_create.out_allocation_size = 4096;
	requ_create.out_end_of_file = 0;
	requ_create.out_oplock_level = 0;
	requ_create.out_create_flags = 0;
	requ_create.out_create_action = FILE_WAS_OPENED;

	//status = x_smbd_open_np_file(smbd_open);
	status = NT_STATUS_OK;
	return smbd_open;
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

