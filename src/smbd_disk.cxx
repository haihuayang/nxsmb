
#include "smbd.hxx"

struct x_smbd_disk_file_t
{
	x_smbd_open_t base;
};

static NTSTATUS x_smbd_disk_file_read(x_smbd_open_t *smbd_open, const x_smb2_requ_read_t &requ,
			std::vector<uint8_t> &output)
{
	X_TODO;
}

static NTSTATUS x_smbd_disk_file_write(x_smbd_open_t *smbd_open,
		const x_smb2_requ_write_t &requ,
		const uint8_t *data, x_smb2_resp_write_t &resp)
{
	X_TODO;
}

static NTSTATUS x_smbd_disk_file_getinfo(x_smbd_open_t *smbd_open, const x_smb2_requ_getinfo_t &requ, std::vector<uint8_t> &output)
{
	X_TODO;
}

static NTSTATUS x_smbd_disk_file_ioctl(x_smbd_open_t *smbd_open,
		uint32_t ctl_code,
		const uint8_t *in_input_data,
		uint32_t in_input_size,
		uint32_t in_max_output,
		std::vector<uint8_t> &output)
{
	X_TODO;
}

static NTSTATUS x_smbd_disk_file_close(x_smbd_open_t *smbd_open,
		const x_smb2_requ_close_t &requ, x_smb2_resp_close_t &resp)
{
	X_TODO;
}


static void x_smbd_disk_file_destroy(x_smbd_open_t *smbd_open)
{
	X_TODO;
}

static const x_smbd_open_ops_t x_smbd_disk_file_ops = {
	x_smbd_disk_file_read,
	x_smbd_disk_file_write,
	x_smbd_disk_file_getinfo,
	nullptr,
	x_smbd_disk_file_ioctl,
	x_smbd_disk_file_close,
	x_smbd_disk_file_destroy,
};

static x_smbd_open_t *x_smbd_tcon_disk_op_create(std::shared_ptr<x_smbd_tcon_t>& smbd_tcon,
		NTSTATUS &status, x_smb2_requ_create_t &requ_create)
{
	x_smbd_disk_file_t *disk_file = new x_smbd_disk_file_t;
	disk_file->base.ops = &x_smbd_disk_file_ops;
	disk_file->base.smbd_tcon = smbd_tcon;
	return nullptr;
}

static const x_smbd_tcon_ops_t x_smbd_tcon_disk_ops = {
	x_smbd_tcon_disk_op_create,
};

void x_smbd_tcon_init_disk(x_smbd_tcon_t *smbd_tcon)
{
	smbd_tcon->ops = &x_smbd_tcon_disk_ops;
}

