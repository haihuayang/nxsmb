
#include "smbd.hxx"
#include "smbd_open.hxx"
#include "smbd_conf.hxx"

namespace {

struct x_smbd_requ_state_notify_t
{
	uint16_t in_flags;
	uint32_t in_output_buffer_length;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	uint32_t in_filter;
	std::vector<std::pair<uint32_t, std::u16string>> out_notify_changes;
};

struct x_smbd_requ_notify_t : x_smbd_requ_t
{
	x_smbd_requ_notify_t(x_smbd_conn_t *smbd_conn)
		: x_smbd_requ_t(smbd_conn)
	{
		interim_timeout_ns = 0;
	}

	std::tuple<bool, bool, bool> get_properties() const override
	{
		return { true, true, false };
	}
	NTSTATUS process(void *ctx_conn) override;
	NTSTATUS done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status) override;
	NTSTATUS cancelled(void *ctx_conn, int reason) override
	{
		auto lock = std::lock_guard(smbd_open->smbd_object->mutex);
		smbd_open->pending_requ_list.remove(this);
		this->decref();
		return reason == x_nxfsd_requ_t::CANCEL_BY_CLIENT ?
			NT_STATUS_CANCELLED : NT_STATUS_NOTIFY_CLEANUP;
	}

	x_smbd_requ_state_notify_t state;
};

}

static NTSTATUS x_smb2_reply_notify(x_smbd_requ_t *smbd_requ,
		const x_smbd_requ_state_notify_t &state)
{
	/* TODO seem windows server remember in_output_buffer_length */
	uint32_t output_buffer_length = std::min(state.in_output_buffer_length,
			smbd_requ->smbd_open->notify_buffer_length);

	auto &out_buf = smbd_requ->get_requ_out_buf();
	out_buf.head = out_buf.tail = x_smb2_bufref_alloc(sizeof(x_smb2_notify_resp_t) +
			output_buffer_length);

	uint8_t *out_hdr = out_buf.head->get_data();
	auto out_body = (x_smb2_notify_resp_t *)(out_hdr + sizeof(x_smb2_header_t));
	uint8_t *out_dyn = (uint8_t *)(out_body + 1);

	size_t out_dyn_length = x_smb2_notify_marshall(state.out_notify_changes,
			out_dyn, output_buffer_length);
	NTSTATUS status;
	if (out_dyn_length == 0) {
		status = NT_STATUS_NOTIFY_ENUM_DIR;
	} else {
		status = NT_STATUS_OK;
	}
	out_buf.length = out_buf.head->length =
		x_convert_assert<uint32_t>(sizeof(x_smb2_header_t) +
				sizeof(x_smb2_notify_resp_t) + out_dyn_length);

	out_body->struct_size = X_H2LE16(sizeof(x_smb2_notify_resp_t) + 1);
	out_body->output_buffer_offset = X_H2LE16(sizeof(x_smb2_header_t) + sizeof(x_smb2_notify_resp_t));
	out_body->output_buffer_length = X_H2LE32(x_convert_assert<uint32_t>(out_dyn_length));

	return status;
}

static NTSTATUS smbd_open_notify(x_smbd_open_t *smbd_open,
		x_nxfsd_requ_t *nxfsd_requ,
		x_smbd_requ_state_notify_t &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto lock = std::lock_guard(smbd_object->mutex);

	if (smbd_object->sharemode.meta.delete_on_close) {
		return NT_STATUS_DELETE_PENDING;
	}

	X_LOG(SMB, DBG, "changes count %ld", smbd_open->notify_changes.size());
	state.out_notify_changes = std::move(smbd_open->notify_changes);
	if (!state.out_notify_changes.empty()) {
		return NT_STATUS_OK;
	} else if (nxfsd_requ->can_async()) {
		nxfsd_requ->incref();
		smbd_open->pending_requ_list.push_back(nxfsd_requ);
		return NT_STATUS_PENDING;
	} else {
		return NT_STATUS_INTERNAL_ERROR;
	}
}

NTSTATUS x_smbd_requ_notify_t::process(void *ctx_conn)
{
	if (!this->smbd_sess) {
		X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_USER_SESSION_DELETED);
	}

	X_SMBD_REQU_LOG(OP, this, " open=0x%lx,0x%lx filter=0x%x, length=%d",
			state.in_file_id_persistent, state.in_file_id_volatile,
			state.in_filter, state.in_output_buffer_length);

	if (!x_smbd_requ_verify_creditcharge(this,
				state.in_output_buffer_length)) {
		X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_INVALID_PARAMETER);
	}

	NTSTATUS status = x_smbd_requ_init_open(this,
			state.in_file_id_persistent,
			state.in_file_id_volatile,
			false);
	if (!NT_STATUS_IS_OK(status)) {
		X_SMBD_REQU_RETURN_STATUS(this, status);
	}

	auto smbd_open = this->smbd_open;
	if (x_smbd_open_is_data(smbd_open)) {
		X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_INVALID_PARAMETER);
	}

	if (!smbd_open->check_access_any(idl::SEC_DIR_LIST)) {
		X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_ACCESS_DENIED);
	}

	/* notify filter cannot be overwritten */
	if (smbd_open->notify_filter == 0) {
		smbd_open->notify_filter = state.in_filter | X_FILE_NOTIFY_CHANGE_VALID;
		smbd_open->notify_buffer_length = state.in_output_buffer_length;
		if (state.in_flags & X_SMB2_WATCH_TREE) {
			smbd_open->notify_filter |= X_FILE_NOTIFY_CHANGE_WATCH_TREE;
			++smbd_open->smbd_object->smbd_volume->watch_tree_cnt;
		}
	}

	return smbd_open_notify(smbd_open, this, state);
}

NTSTATUS x_smbd_requ_notify_t::done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status)
{
	X_SMBD_REQU_LOG(OP, this, " %s", x_ntstatus_str(status));
	if (status.ok()) {
		status = x_smb2_reply_notify(this, this->state);
	}
	return status;
}

NTSTATUS x_smb2_parse_NOTIFY(x_smbd_conn_t *smbd_conn, x_smbd_requ_t **p_smbd_requ,
		x_in_buf_t &in_buf)
{
	auto in_smb2_hdr = (const x_smb2_header_t *)(in_buf.get_data());

	if (in_buf.length < sizeof(x_smb2_header_t) + sizeof(x_smb2_notify_requ_t)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	auto in_body = (const x_smb2_notify_requ_t *)(in_smb2_hdr + 1);
	auto in_output_buffer_length = X_LE2H32(in_body->output_buffer_length);

	if (in_output_buffer_length > x_smbd_conn_get_negprot(smbd_conn).max_trans_size) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	auto requ = new x_smbd_requ_notify_t(smbd_conn);
	auto &state = requ->state;
	state.in_flags = X_LE2H16(in_body->flags);
	state.in_file_id_persistent = X_LE2H64(in_body->file_id_persistent);
	state.in_file_id_volatile = X_LE2H64(in_body->file_id_volatile);
	state.in_filter = X_LE2H32(in_body->filter);
	state.in_output_buffer_length = in_output_buffer_length;

	*p_smbd_requ = requ;
	return NT_STATUS_OK;
}

static x_smbd_requ_notify_t *get_pending_requ_notify(x_smbd_open_t *curr_open)
{
	x_nxfsd_requ_t *nxfsd_requ;
	for (nxfsd_requ = curr_open->pending_requ_list.get_front();
			nxfsd_requ;
			nxfsd_requ = curr_open->pending_requ_list.next(nxfsd_requ)) {
		auto requ_notify = dynamic_cast<x_smbd_requ_notify_t *>(nxfsd_requ);
		if (!requ_notify) {
			continue;
		}
		/* each open can have only one pending notify */
		if (requ_notify->set_processing()) {
			curr_open->pending_requ_list.remove(nxfsd_requ);
			return requ_notify;
		}
		break;
	}
	return nullptr;
}

static void x_smbd_object_notify_change(x_smbd_object_t *smbd_object,
		x_smbd_object_t **p_parent_object,
		uint32_t notify_action,
		uint32_t notify_filter,
		std::u16string &path,
		std::u16string &new_path,
		const x_smb2_lease_key_t &ignore_lease_key,
		const x_smb2_uuid_t &client_guid,
		bool recursive,
		bool last_level)
{
	/* TODO change to read lock */
	auto lock = std::lock_guard(smbd_object->mutex);
	auto &open_list = smbd_object->sharemode.open_list;
	x_smbd_open_t *curr_open;
	int count = 0;
	for (curr_open = open_list.get_front(); curr_open; curr_open = open_list.next(curr_open)) {
		++count;
		if (last_level && curr_open->smbd_lease) {
			x_smbd_open_break_lease(curr_open, &ignore_lease_key, &client_guid,
					X_SMB2_LEASE_ALL, 0, nullptr, false);
		}

		if (!(curr_open->notify_filter & notify_filter)) {
			continue;
		}
		if (!last_level && !(curr_open->notify_filter & X_FILE_NOTIFY_CHANGE_WATCH_TREE)) {
			continue;
		}
		bool orig_empty = curr_open->notify_changes.empty();
		curr_open->notify_changes.push_back(std::make_pair(notify_action, path));
		if (notify_action == NOTIFY_ACTION_OLD_NAME) {
			curr_open->notify_changes.push_back(std::make_pair(NOTIFY_ACTION_NEW_NAME,
						new_path));
		}

		if (!orig_empty) {
		       continue;
		}

		auto requ_notify = get_pending_requ_notify(curr_open);
		if (!requ_notify) {
			continue;
		}

		auto notify_changes = std::exchange(curr_open->notify_changes, {});
		/* TODO should we merge notify_changes? */
		X_ASSERT(requ_notify->state.out_notify_changes.empty());
		requ_notify->state.out_notify_changes = std::move(notify_changes);

		X_NXFSD_REQU_POST_DONE(requ_notify, NT_STATUS_OK);
	}
	if (recursive && smbd_object->parent_object) {
		smbd_object->parent_object->incref();
		*p_parent_object = smbd_object->parent_object;
		path = smbd_object->path_base + u'\\' + path;
		if (notify_action == NOTIFY_ACTION_OLD_NAME) {
			new_path = smbd_object->path_base + u'\\' + new_path;
		}
	}
}

void x_smbd_notify_change(
		x_smbd_object_t *smbd_object,
		uint32_t action,
		uint32_t filter,
		const x_smb2_lease_key_t &ignore_lease_key,
		const x_smb2_uuid_t &client_guid,
		std::u16string &path_base,
		std::u16string &new_path_base)
{
	x_smbd_object_t *parent_object = nullptr;
	bool recursive = (smbd_object->smbd_volume->watch_tree_cnt > 0);

	x_smbd_object_notify_change(smbd_object,
			&parent_object,
			action, filter,
			path_base, new_path_base,
			ignore_lease_key,
			client_guid,
			recursive,
			true);

	for (; parent_object; ) {
		smbd_object = parent_object;
		parent_object = nullptr;

		x_smbd_object_notify_change(smbd_object,
				&parent_object,
				action, filter,
				path_base, new_path_base,
				ignore_lease_key,
				client_guid,
				true,
				false);
		x_smbd_release_object(smbd_object);
	}
}

/* caller hold smbd_object->mutex */
void x_smbd_notify_post_deleting(x_smbd_open_t *smbd_open, NTSTATUS status)
{
	auto requ_notify = get_pending_requ_notify(smbd_open);
	if (!requ_notify) {
		return;
	}

	X_NXFSD_REQU_POST_DONE(requ_notify, status);
}

