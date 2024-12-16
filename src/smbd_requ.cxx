
#include "smbd.hxx"
#include "nxfsd_stats.hxx"
#include "smbd_open.hxx"
#include "smbd_replay.hxx"
#include "nxfsd_sched.hxx"

std::ostream &x_smbd_requ_t::tostr(std::ostream &os) const
{
	char buf[256];
	snprintf(buf, sizeof(buf), X_SMBD_REQU_DBG_FMT, X_SMBD_REQU_DBG_ARG(this));
	return os << buf;
}

x_smbd_requ_t::x_smbd_requ_t(x_smbd_conn_t *smbd_conn,
		x_in_buf_t &in_buf, uint32_t in_msgsize,
		bool encrypted)
	: x_nxfsd_requ_t((x_nxfsd_conn_t *)(smbd_conn), in_buf, in_msgsize)
	, encrypted(encrypted)
{
	X_NXFSD_COUNTER_INC_CREATE(smbd_requ, 1);
}

x_smbd_requ_t::~x_smbd_requ_t()
{
	X_SMBD_REQU_LOG(DBG, this, " freed");

	x_ref_dec_if(smbd_tcon);
	x_ref_dec_if(smbd_chan);
	x_ref_dec_if(smbd_sess);
	X_NXFSD_COUNTER_INC_DELETE(smbd_requ, 1);
}

NTSTATUS x_smbd_requ_init_open(x_smbd_requ_t *smbd_requ,
		uint64_t id_persistent, uint64_t id_volatile,
		bool modify_call)
{
	if (!smbd_requ->smbd_open && !x_smb2_file_id_is_nul(id_persistent,
				id_volatile)) {
		smbd_requ->smbd_open = x_smbd_open_lookup(
				id_persistent,
				id_volatile,
				smbd_requ->smbd_tcon);
	}

	if (smbd_requ->smbd_open) {
		return x_smbd_conn_dispatch_update_counts(smbd_requ,
				modify_call);
	}

	if (smbd_requ->is_compound_related() && !NT_STATUS_IS_OK(smbd_requ->status)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, smbd_requ->status);
	} else {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_FILE_CLOSED);
	}
}

struct smbd_lease_release_evt_t
{
	static void func(void *ctx_conn, x_fdevt_user_t *fdevt_user)
	{
		smbd_lease_release_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				smbd_lease_release_evt_t, base);
		x_smbd_lease_close(evt->smbd_lease);
		delete evt;
	}

	explicit smbd_lease_release_evt_t(x_smbd_lease_t *smbd_lease)
		: base(func), smbd_lease(smbd_lease)
	{
	}

	x_fdevt_user_t base;
	x_smbd_lease_t * const smbd_lease;
};

void x_smbd_schedule_release_lease(x_smbd_lease_t *smbd_lease)
{
	smbd_lease_release_evt_t *evt = new smbd_lease_release_evt_t(smbd_lease);
	x_nxfsd_schedule(&evt->base);
}

void x_smbd_schedule_wakeup_pending_requ_list(const x_tp_ddlist_t<requ_async_traits> &pending_requ_list)
{
	x_nxfsd_requ_t *nxfsd_requ;
	for (nxfsd_requ = pending_requ_list.get_front(); nxfsd_requ;
			nxfsd_requ = pending_requ_list.next(nxfsd_requ)) {
		x_nxfsd_requ_post_cancel(nxfsd_requ, x_nxfsd_requ_t::CANCEL_BY_CLOSE);
	}
}

struct smbd_notify_evt_t
{
	static void func(void *ctx_conn, x_fdevt_user_t *fdevt_user)
	{
		smbd_notify_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				smbd_notify_evt_t, base);
		x_smbd_notify_change(evt->smbd_object,
				evt->action,
				evt->filter,
				evt->ignore_lease_key,
				evt->client_guid,
				evt->path_base,
				evt->new_path_base);
		delete evt;
	}

	explicit smbd_notify_evt_t(x_smbd_object_t *parent_object,
			uint32_t action, uint32_t filter,
			const x_smb2_lease_key_t &ignore_lease_key,
			const x_smb2_uuid_t &client_guid,
			const std::u16string &path_base,
			const std::u16string &new_path_base)
		: base(func), smbd_object(parent_object)
		, action(action), filter(filter)
		, ignore_lease_key(ignore_lease_key)
		, client_guid(client_guid)
		, path_base(path_base)
		, new_path_base(new_path_base)
	{
		smbd_object->incref();
	}

	~smbd_notify_evt_t()
	{
		x_smbd_release_object(smbd_object);
	}

	x_fdevt_user_t base;
	x_smbd_object_t * const smbd_object;
	const uint32_t action;
	const uint32_t filter;
	const x_smb2_lease_key_t ignore_lease_key;
	const x_smb2_uuid_t client_guid;
	std::u16string path_base;
	std::u16string new_path_base;
};

static void x_smbd_schedule_notify_evt(x_smbd_object_t *parent_object,
		uint32_t action, uint32_t filter,
		const x_smb2_lease_key_t &ignore_lease_key,
		const x_smb2_uuid_t &client_guid,
		const std::u16string &path_base,
		const std::u16string &new_path_base)
{
	smbd_notify_evt_t *evt = new smbd_notify_evt_t(parent_object,
			action, filter, ignore_lease_key, client_guid,
			path_base, new_path_base);
	x_nxfsd_schedule(&evt->base);
}

void x_smbd_schedule_notify(
		uint32_t notify_action,
		uint32_t notify_filter,
		const x_smb2_lease_key_t &ignore_lease_key,
		const x_smb2_uuid_t &client_guid,
		x_smbd_object_t *parent_object,
		x_smbd_object_t *new_parent_object,
		const std::u16string &path_base,
		const std::u16string &new_path_base)
{
	if (!parent_object) {
		return;
	}

	if (new_parent_object) {
		X_ASSERT(notify_action == NOTIFY_ACTION_OLD_NAME);

		if (new_parent_object == parent_object) {
			x_smbd_schedule_notify_evt(parent_object,
					notify_action,
					notify_filter,
					ignore_lease_key,
					client_guid,
					path_base, new_path_base);
		} else {
			x_smbd_schedule_notify_evt(parent_object,
					NOTIFY_ACTION_REMOVED,
					notify_filter,
					ignore_lease_key,
					client_guid,
					path_base, u"");
			x_smbd_schedule_notify_evt(new_parent_object,
					NOTIFY_ACTION_ADDED,
					notify_filter,
					{},
					{},
					new_path_base, u"");
		}
	} else {
		X_ASSERT(new_path_base.empty());
		X_ASSERT(notify_action != NOTIFY_ACTION_OLD_NAME);
		x_smbd_schedule_notify_evt(parent_object,
				notify_action,
				notify_filter,
				ignore_lease_key,
				client_guid,
				path_base, new_path_base);
	}
}
