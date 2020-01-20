
#include "smbd.hxx"

static x_smbd_open_t *x_smbd_tcon_disk_op_create(std::shared_ptr<x_smbd_tcon_t>& smbd_tcon,
		NTSTATUS &status, x_smb2_requ_create_t &requ_create)
{
	X_TODO;
	return nullptr;
}

static const x_smbd_tcon_ops_t x_smbd_tcon_disk_ops = {
	x_smbd_tcon_disk_op_create,
};

void x_smbd_tcon_init_disk(x_smbd_tcon_t *smbd_tcon)
{
	smbd_tcon->ops = &x_smbd_tcon_disk_ops;
}

