
#include "smbd.hxx"
#include "smbd_ctrl.hxx"
#include "smbd_stats.hxx"
#include "smbd_open.hxx"
#include "include/idtable.hxx"
#include "smbd_share.hxx"

using smbd_tcon_table_t = x_idtable_t<x_smbd_tcon_t, x_idtable_32_traits_t>;
static smbd_tcon_table_t *g_smbd_tcon_table;

struct x_smbd_tcon_t
{ 
	x_smbd_tcon_t(x_smbd_sess_t *smbd_sess,
			const std::shared_ptr<x_smbd_share_t> &share,
			const std::string &volume,
			uint32_t share_access)
		: tick_create(tick_now), share_access(share_access)
		, smbd_sess(x_smbd_ref_inc(smbd_sess)), smbd_share(share)
		, volume(volume)
       	{
		X_SMBD_COUNTER_INC(tcon_create, 1);
	}
	~x_smbd_tcon_t()
	{
		x_smbd_ref_dec(smbd_sess);
		X_SMBD_COUNTER_INC(tcon_delete, 1);
	}

	x_dlink_t sess_link; // protected by smbd_sess' mutex
	const x_tick_t tick_create;
	enum {
		S_ACTIVE,
		S_DONE,
	} state = S_ACTIVE;
	uint32_t tid;
	const uint32_t share_access;
	x_smbd_sess_t * const smbd_sess;
	const std::shared_ptr<x_smbd_share_t> smbd_share;
	const std::string volume;
	std::mutex mutex;
	x_ddlist_t open_list;
};

template <>
x_smbd_tcon_t *x_smbd_ref_inc(x_smbd_tcon_t *smbd_tcon)
{
	g_smbd_tcon_table->incref(smbd_tcon->tid);
	return smbd_tcon;
}

template <>
void x_smbd_ref_dec(x_smbd_tcon_t *smbd_tcon)
{
	g_smbd_tcon_table->decref(smbd_tcon->tid);
}

x_smbd_tcon_t *x_smbd_tcon_create(x_smbd_sess_t *smbd_sess, 
		const std::shared_ptr<x_smbd_share_t> &smbshare,
		const std::string &volume,
		uint32_t share_access)
{
	x_smbd_tcon_t *smbd_tcon = new x_smbd_tcon_t(smbd_sess, smbshare, volume, share_access);
	if (!g_smbd_tcon_table->store(smbd_tcon, smbd_tcon->tid)) {
		delete smbd_tcon;
		return nullptr;
	}
	if (!x_smbd_sess_link_tcon(smbd_sess, &smbd_tcon->sess_link)) {
		g_smbd_tcon_table->remove(smbd_tcon->tid);
		x_smbd_ref_dec(smbd_tcon);
		return nullptr;
	}
	x_smbd_ref_inc(smbd_tcon); // ref by smbd_sess list

	return smbd_tcon;
}

uint32_t x_smbd_tcon_get_id(const x_smbd_tcon_t *smbd_tcon)
{
	return smbd_tcon->tid;
}

bool x_smbd_tcon_access_check(const x_smbd_tcon_t *smbd_tcon, uint32_t desired_access)
{
	return (desired_access & ~smbd_tcon->share_access) == 0;
}

std::shared_ptr<x_smbd_user_t> x_smbd_tcon_get_user(const x_smbd_tcon_t *smbd_tcon)
{
	return x_smbd_sess_get_user(smbd_tcon->smbd_sess);
}

uint32_t x_smbd_tcon_get_share_access(const x_smbd_tcon_t *smbd_tcon)
{
	return smbd_tcon->share_access;
}

bool x_smbd_tcon_get_read_only(const x_smbd_tcon_t *smbd_tcon)
{
	return smbd_tcon->smbd_share->is_read_only();
}

bool x_smbd_tcon_get_durable_handle(const x_smbd_tcon_t *smbd_tcon)
{
	return smbd_tcon->smbd_share->support_durable_handle();
}

bool x_smbd_tcon_get_continuously_available(const x_smbd_tcon_t *smbd_tcon)
{
	return smbd_tcon->smbd_share->is_continuously_available();
}

bool x_smbd_tcon_get_abe(const x_smbd_tcon_t *smbd_tcon)
{
	return smbd_tcon->smbd_share->abe_enabled();
}

bool x_smbd_tcon_match(const x_smbd_tcon_t *smbd_tcon, const x_smbd_sess_t *smbd_sess, uint32_t tid)
{
	return smbd_tcon->smbd_sess == smbd_sess && smbd_tcon->tid == tid;
}

x_smbd_sess_t *x_smbd_tcon_get_sess(const x_smbd_tcon_t *smbd_tcon)
{
	return x_smbd_ref_inc(smbd_tcon->smbd_sess);
}

bool x_smbd_tcon_same_sess(const x_smbd_tcon_t *smbd_tcon1, const x_smbd_tcon_t *smbd_tcon2)
{
	return smbd_tcon1->smbd_sess == smbd_tcon2->smbd_sess;
}

std::shared_ptr<x_smbd_share_t> x_smbd_tcon_get_share(const x_smbd_tcon_t *smbd_tcon)
{
	return smbd_tcon->smbd_share;
}

x_smbd_tcon_t *x_smbd_tcon_lookup(uint32_t id, const x_smbd_sess_t *smbd_sess)
{
	auto [found, smbd_tcon] = g_smbd_tcon_table->lookup(id);
	if (!found) {
		return nullptr;
	}
	if (smbd_tcon->smbd_sess == smbd_sess) {
		return smbd_tcon;
	} else {
		g_smbd_tcon_table->decref(id);
		return nullptr;
	}
}

static bool smbd_save_durable(x_smbd_open_t *smbd_open,
		uint32_t durable_timeout_msec)
{
	X_LOG_DBG("save %p durable info to db", smbd_open);
	uint64_t id_persistent;
	const auto &file_handle = smbd_open->smbd_object->file_handle;
	X_ASSERT(file_handle.base.handle_bytes <= MAX_HANDLE_SZ);
	x_smbd_durable_t durable{smbd_open->id_volatile,
		smbd_open->open_state, smbd_open->smbd_object->file_handle};
	/* TODO lease */

	int ret = x_smbd_volume_save_durable(*smbd_open->smbd_object->smbd_volume,
			id_persistent, &durable);
	if (ret == 0) {
		smbd_open->id_persistent = id_persistent;
		smbd_open->dh_mode = x_smbd_open_t::DH_DURABLE;

		if (durable_timeout_msec == 0) {
			durable_timeout_msec = X_SMBD_DURABLE_TIMEOUT_MAX * 1000u;
		} else {
			durable_timeout_msec = std::min(
					durable_timeout_msec,
					X_SMBD_DURABLE_TIMEOUT_MAX * 1000u);
		}
		smbd_open->open_state.durable_timeout_msec = durable_timeout_msec;
		X_LOG_DBG("smbd_save_durable for %p 0x%lx 0x%lx",
				smbd_open, smbd_open->id_persistent,
				smbd_open->id_volatile);
		return true;
	} else {
		X_LOG_WARN("smbd_save_durable for %p 0x%lx failed, ret = %d",
				smbd_open,
				smbd_open->id_volatile, ret);
		return false;
	}
}

NTSTATUS x_smbd_tcon_op_create(x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	if (!x_smbd_open_has_space()) {
		X_LOG_WARN("too many opens, cannot allocate new");
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	NTSTATUS status;
	x_smbd_tcon_t *smbd_tcon = smbd_requ->smbd_tcon;

	if (!state->smbd_object) {
		std::shared_ptr<x_smbd_volume_t> smbd_volume;
		std::u16string path;
		long path_priv_data{};
		long open_priv_data{};
		status = smbd_tcon->smbd_share->resolve_path(
				smbd_volume, path, path_priv_data, open_priv_data,
				smbd_requ->in_smb2_hdr.flags & X_SMB2_HDR_FLAG_DFS,
				state->in_path.data(),
				state->in_path.data() + state->in_path.length(),
				smbd_tcon->volume);
		if (!NT_STATUS_IS_OK(status)) {
			X_LOG_WARN("resolve_path failed");
			return status;
		}
		X_LOG_DBG("resolve_path(%s) to %s, %ld, %ld",
				x_convert_utf16_to_utf8_safe(state->in_path).c_str(),
				x_convert_utf16_to_utf8_safe(path).c_str(),
				path_priv_data, open_priv_data);

		status = x_smbd_open_object(&state->smbd_object,
				&state->smbd_stream,
				smbd_volume, path, state->in_ads_name,
				path_priv_data, true);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		state->open_priv_data = open_priv_data;
	}

	/* changes may include many stream deletion */
	std::vector<x_smb2_change_t> changes;
	x_smbd_open_t *smbd_open = nullptr;
	/* TODO should we check the open limit before create the open */
	status = x_smbd_open_create(
			&smbd_open, smbd_requ,
			*smbd_tcon->smbd_share,
			state, changes);

	if (NT_STATUS_IS_OK(status)) {
		X_ASSERT(smbd_open);

		/* we do not support durable handle for ADS */
		if (!smbd_open->smbd_stream &&
				smbd_open->smbd_object->type == x_smbd_object_t::type_file) {
			if (state->in_contexts & X_SMB2_CONTEXT_FLAG_DH2Q) {
				uint32_t flags = 0;
				if ((state->in_dh_flags & X_SMB2_DHANDLE_FLAG_PERSISTENT) &&
						x_smbd_tcon_get_continuously_available(smbd_tcon)) {
					if (smbd_save_durable(smbd_open, state->in_dh_timeout)) {
						smbd_open->dh_mode = x_smbd_open_t::DH_PERSISTENT;
						flags = X_SMB2_DHANDLE_FLAG_PERSISTENT;
					}
				} else if (x_smbd_tcon_get_durable_handle(smbd_tcon)) {
					if (smbd_save_durable(smbd_open, state->in_dh_timeout)) {
						smbd_open->dh_mode = x_smbd_open_t::DH_DURABLE;
					}
				}
				if (smbd_open->dh_mode != x_smbd_open_t::DH_NONE) {
					state->out_contexts |= X_SMB2_CONTEXT_FLAG_DH2Q;
					state->dh2q_resp.timeout = smbd_open->open_state.durable_timeout_msec;
					state->dh2q_resp.flags = flags;
				}

			} else if (state->in_contexts & X_SMB2_CONTEXT_FLAG_DHNQ) {
				if (x_smbd_tcon_get_durable_handle(smbd_tcon) &&
						smbd_save_durable(smbd_open, 0)) {
					state->out_contexts |= X_SMB2_CONTEXT_FLAG_DHNQ;
				}
			}
		}

		/* if client access the open from other channel now, it does not have
		 * link into smbd_tcon, probably we should call x_smbd_open_store in the last
		 */
		{
			std::lock_guard<std::mutex> lock(smbd_tcon->mutex);
			if (smbd_tcon->state != x_smbd_tcon_t::S_ACTIVE) {
				std::unique_ptr<x_smb2_state_close_t> state;
				x_smbd_open_close(smbd_open, nullptr, state, changes, false);
				status = NT_STATUS_NETWORK_NAME_DELETED;
			} else {
				smbd_tcon->open_list.push_back(&smbd_open->tcon_link);
			}
		}
		if (NT_STATUS_IS_OK(status)) {
			x_smbd_ref_inc(smbd_open); // ref by smbd_tcon open_list
			smbd_requ->smbd_open = x_smbd_ref_inc(smbd_open);
		}

		x_smbd_notify_change(state->smbd_object->smbd_volume, changes);
	} else {
		X_ASSERT(!smbd_open);
	}

	return status;
}

NTSTATUS x_smbd_tcon_op_recreate(x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	x_smbd_tcon_t *smbd_tcon = smbd_requ->smbd_tcon;
	NTSTATUS status = NT_STATUS_OK;

	if (!x_smbd_tcon_get_durable_handle(smbd_tcon)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	}
	uint64_t id_persistent = state->in_dh_id_persistent;
	std::shared_ptr<x_smbd_volume_t> smbd_volume;
	x_smbd_durable_t *durable = x_smbd_share_lookup_durable(
			smbd_volume, smbd_requ->smbd_tcon->smbd_share,
			id_persistent);
	if (!durable) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	}

	uint64_t id_volatile = durable->id_volatile;

	x_smbd_open_t *smbd_open = x_smbd_open_reopen(status,
			id_persistent, id_volatile,
			smbd_tcon, *state);
	if (!smbd_open) {
		RETURN_OP_STATUS(smbd_requ, status);
	}

	/* if client access the open from other channel now, it does not have
	 * link into smbd_tcon, probably we should call x_smbd_open_store in the last
	 */
	{
		std::vector<x_smb2_change_t> changes;
		std::lock_guard<std::mutex> lock(smbd_tcon->mutex);
		if (smbd_tcon->state != x_smbd_tcon_t::S_ACTIVE) {
			std::unique_ptr<x_smb2_state_close_t> state;
			x_smbd_open_close(smbd_open, nullptr, state, changes, false);
			status = NT_STATUS_NETWORK_NAME_DELETED;
		} else {
			smbd_tcon->open_list.push_back(&smbd_open->tcon_link);
		}
	}

	if (NT_STATUS_IS_OK(status)) {
		smbd_requ->smbd_open = x_smbd_ref_inc(smbd_open);
	}
	/* TODO is other action possible */
	state->out_create_action = x_smb2_create_action_t::WAS_OPENED;
	state->out_oplock_level = smbd_open->open_state.oplock_level;
	return status;
}

static bool smbd_tcon_terminate(x_smbd_tcon_t *smbd_tcon, bool shutdown)
{
	std::unique_lock<std::mutex> lock(smbd_tcon->mutex);
	if (smbd_tcon->state == x_smbd_tcon_t::S_DONE) {
		/* this can happen if client logoff on one channel and
		 * tdis on another
		 */
		return false;
	}
	smbd_tcon->state = x_smbd_tcon_t::S_DONE;
	lock.unlock();

	g_smbd_tcon_table->remove(smbd_tcon->tid);
	x_smbd_ref_dec(smbd_tcon);

	std::vector<x_smb2_change_t> changes;
	x_dlink_t *link;
	lock.lock();
	while ((link = smbd_tcon->open_list.get_front()) != nullptr) {
		smbd_tcon->open_list.remove(link);
		lock.unlock();
		x_smbd_open_unlinked(link, smbd_tcon, changes, shutdown);
		lock.lock();
	}
	lock.unlock();

	// TODO get topdir, x_smbd_notify_change(topdir, changes);

	x_smbd_ref_dec(smbd_tcon); // ref by smbd_sess tcon_list
	return true;
}

void x_smbd_tcon_unlinked(x_dlink_t *link, x_smbd_sess_t *smbd_sess, bool shutdown)
{
	x_smbd_tcon_t *smbd_tcon = X_CONTAINER_OF(link, x_smbd_tcon_t, sess_link);
	smbd_tcon_terminate(smbd_tcon, shutdown);
}

bool x_smbd_tcon_disconnect(x_smbd_tcon_t *smbd_tcon)
{
	if (x_smbd_sess_unlink_tcon(smbd_tcon->smbd_sess, &smbd_tcon->sess_link)) {
		return smbd_tcon_terminate(smbd_tcon, false);
	}
	return false;
}

bool x_smbd_tcon_unlink_open(x_smbd_tcon_t *smbd_tcon, x_dlink_t *link)
{
	std::lock_guard<std::mutex> lock(smbd_tcon->mutex);
	if (link->is_valid()) {
		smbd_tcon->open_list.remove(link);
		return true;
	}
	return false;
}

int x_smbd_tcon_table_init(uint32_t count)
{
	g_smbd_tcon_table = new smbd_tcon_table_t(count);
	return 0;
}

std::string x_smbd_tcon_get_volume_label(const x_smbd_tcon_t *smbd_tcon)
{
	if (smbd_tcon->volume.empty()) {
		return smbd_tcon->smbd_share->name;
	} else {
		return smbd_tcon->volume;
	}
}

struct x_smbd_tcon_list_t : x_smbd_ctrl_handler_t
{
	x_smbd_tcon_list_t() : iter(g_smbd_tcon_table->iter_start()) {
	}
	bool output(std::string &data) override;
	smbd_tcon_table_t::iter_t iter;
};

bool x_smbd_tcon_list_t::output(std::string &data)
{
	std::ostringstream os;

	bool ret = g_smbd_tcon_table->iter_entry(iter, [&os](const x_smbd_tcon_t *smbd_tcon) {
			std::shared_ptr<x_smbd_share_t> smbshare = smbd_tcon->smbd_share;
			os << idl::x_hex_t<uint32_t>(smbd_tcon->tid) << ' '
			<< idl::x_hex_t<uint32_t>(smbd_tcon->share_access) << ' '
			<< smbshare->name << std::endl;
			return true;
		});
	if (ret) {
		data = os.str(); // TODO avoid copying
		return true;
	} else {
		return false;
	}
}

x_smbd_ctrl_handler_t *x_smbd_tcon_list_create()
{
	return new x_smbd_tcon_list_t;
}

