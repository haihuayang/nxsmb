
#include "smbd_open.hxx"
#include "smbd_stats.hxx"

x_smbd_object_t::x_smbd_object_t(const std::shared_ptr<x_smbd_topdir_t> &topdir,
		long priv_data)
	: topdir(topdir), priv_data(priv_data)
{
	X_SMBD_COUNTER_INC(object_create, 1);
}

x_smbd_object_t::~x_smbd_object_t()
{
	X_SMBD_COUNTER_INC(object_delete, 1);
}

