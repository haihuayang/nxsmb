
#include "smbd_open.hxx"
#include "smbd_stats.hxx"

x_smbd_object_t::x_smbd_object_t(const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		long priv_data, uint64_t hash, const std::u16string &path)
	: smbd_volume(smbd_volume), priv_data(priv_data), hash(hash), path(path)
{
	X_SMBD_COUNTER_INC(object_create, 1);
}

x_smbd_object_t::~x_smbd_object_t()
{
	X_SMBD_COUNTER_INC(object_delete, 1);
}

x_smb2_state_create_t::~x_smb2_state_create_t()
{
	if (smbd_object) {
		x_smbd_object_release(smbd_object, smbd_stream);
	}
	if (smbd_lease) {
		x_smbd_lease_release(smbd_lease);
	}
}

