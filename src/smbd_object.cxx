
#include "smbd_open.hxx"
#include "smbd_stats.hxx"

x_smbd_object_t::x_smbd_object_t(const x_smbd_object_ops_t *ops) : ops(ops)
{
	X_SMBD_COUNTER_INC(object_create, 1);
}

x_smbd_object_t::~x_smbd_object_t()
{
	X_SMBD_COUNTER_INC(object_delete, 1);
}

