
#include "noded.hxx"
#include "nxfsd_stats.hxx"
#include "smbd_open.hxx"
#include "include/idtable.hxx"

std::ostream &x_noded_requ_t::tostr(std::ostream &os) const
{
	char buf[256];
	snprintf(buf, sizeof(buf), X_NODED_REQU_DBG_FMT, X_NODED_REQU_DBG_ARG(this));
	return os << buf;
}

x_noded_requ_t::x_noded_requ_t(x_noded_conn_t *noded_conn)
	: x_nxfsd_requ_t((x_nxfsd_conn_t *)noded_conn)
{
	X_NODED_COUNTER_INC_CREATE(noded_requ, 1);
}

x_noded_requ_t::~x_noded_requ_t()
{
	X_NODED_REQU_LOG(DBG, this, " freed");
	X_NODED_COUNTER_INC_DELETE(noded_requ, 1);
}

NTSTATUS x_noded_requ_init_open(x_noded_requ_t *noded_requ,
		uint64_t id_persistent, uint64_t id_volatile,
		bool modify_call)
{
	if (!noded_requ->smbd_open && !x_smb2_file_id_is_nul(id_persistent,
				id_volatile)) {
		noded_requ->smbd_open = x_smbd_open_lookup(
				id_persistent,
				id_volatile,
				nullptr);
	}

	if (noded_requ->smbd_open) {
		/*
		return x_noded_conn_dispatch_update_counts(noded_requ,
				modify_call);
		*/
		return NT_STATUS_OK;
	}

	if (/* noded_requ->is_compound_related() && */!NT_STATUS_IS_OK(noded_requ->status)) {
		X_NODED_REQU_RETURN_STATUS(noded_requ, noded_requ->status);
	} else {
		X_NODED_REQU_RETURN_STATUS(noded_requ, NT_STATUS_FILE_CLOSED);
	}
}

