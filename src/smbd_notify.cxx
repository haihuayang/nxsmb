
#include "smbd_open.hxx"

struct smd_notify_evt_t
{
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user)
	{
		smd_notify_evt_t *evt = X_CONTAINER_OF(fdevt_user, smd_notify_evt_t, base);
		x_smbd_requ_t *smbd_requ = evt->smbd_requ;
		X_LOG(SMB, DBG, "evt=%p, requ=%p, smbd_conn=%p", evt, smbd_requ, smbd_conn);

		auto state = smbd_requ->release_state<x_smbd_requ_state_notify_t>();
		X_ASSERT(state->out_notify_changes.empty());
		std::swap(state->out_notify_changes, evt->notify_changes);
		state->async_done(smbd_conn, smbd_requ, NT_STATUS_OK);
		delete evt;
	}

	smd_notify_evt_t(x_smbd_requ_t *requ,
			std::vector<std::pair<uint32_t, std::u16string>> &&changes)
		: base(func), smbd_requ(requ), notify_changes(changes)
	{
	}

	~smd_notify_evt_t()
	{
		x_ref_dec(smbd_requ);
	}

	x_fdevt_user_t base;
	x_smbd_requ_t * const smbd_requ;
	std::vector<std::pair<uint32_t, std::u16string>> notify_changes;
};

static void x_smbd_object_notify_change(x_smbd_object_t *smbd_object,
		x_smbd_object_t **p_parent_object,
		uint32_t notify_action,
		uint32_t notify_filter,
		std::u16string &path,
		std::u16string &new_path,
		const x_smb2_lease_key_t &ignore_lease_key,
		const x_smb2_uuid_t &client_guid,
		bool recursive,
		bool last_level,
		long open_priv_data)
{
	/* TODO change to read lock */
	auto lock = std::lock_guard(smbd_object->mutex);
	auto &open_list = smbd_object->sharemode.open_list;
	x_smbd_open_t *curr_open;
	int count = 0;
	for (curr_open = open_list.get_front(); curr_open; curr_open = open_list.next(curr_open)) {
		++count;
		if (curr_open->open_state.priv_data != open_priv_data) {
			continue;
		}

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

		x_smbd_requ_t *smbd_requ;
		for (smbd_requ = curr_open->pending_requ_list.get_front();
				smbd_requ;
				smbd_requ = curr_open->pending_requ_list.next(smbd_requ)) {
			if (smbd_requ->in_smb2_hdr.opcode == X_SMB2_OP_NOTIFY) {
				break;
			}
		}
		if (!smbd_requ) {
			continue;
		}

		auto notify_changes = std::exchange(curr_open->notify_changes, {});
		curr_open->pending_requ_list.remove(smbd_requ);

		X_SMBD_CHAN_POST_USER(smbd_requ->smbd_chan, 
				new smd_notify_evt_t(smbd_requ,
					std::move(notify_changes)));
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

void x_smbd_simple_notify_change(
		const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const std::u16string &path,
		const std::u16string &fullpath,
		const std::u16string *new_fullpath,
		uint32_t notify_action,
		uint32_t notify_filter,
		const x_smb2_lease_key_t &ignore_lease_key,
		const x_smb2_uuid_t &client_guid,
		bool last_level)
{
	X_TODO;
	/* decide later if we need the op_notify_change, previous it is for the dfs */
#if 0
	x_smbd_object_t *smbd_object = nullptr;
	NTSTATUS status = x_smbd_open_object(&smbd_object,
			smbd_volume, path, 0, false);
	if (!NT_STATUS_IS_OK(status)) {
		X_LOG(SMB, DBG, "skip notify %d,x%x '%s', '%s'", notify_action,
				notify_filter,
				x_str_todebug(path).c_str(),
				x_str_todebug(fullpath).c_str());
		return;
	}

	X_ASSERT(smbd_object);
	X_LOG(SMB, DBG, "notify object %d,x%x '%s', '%s'", notify_action,
			notify_filter,
			x_str_todebug(path).c_str(),
			x_str_todebug(fullpath).c_str());
	x_smbd_object_notify_change(smbd_object, notify_action, notify_filter,
			path.empty() ? 0: x_convert<uint32_t>(path.length() + 1),
			fullpath, new_fullpath,
			ignore_lease_key, client_guid,
			last_level, 0);

	x_smbd_release_object(smbd_object);
#endif
}
#if 0
static void notify_one_level(const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const std::u16string &path,
		const std::u16string &fullpath,
		const std::u16string *new_fullpath,
		uint32_t notify_action,
		uint32_t notify_filter,
		const x_smb2_lease_key_t &ignore_lease_key,
		const x_smb2_uuid_t &client_guid,
		bool last_level)
{
	smbd_volume->ops->notify_change(smbd_volume, path, fullpath, new_fullpath,
			notify_action, notify_filter,
			ignore_lease_key, client_guid, last_level);
}
#endif

void x_smbd_notify_change(
		x_smbd_object_t *smbd_object,
		uint32_t action,
		uint32_t filter,
		x_smb2_lease_key_t &ignore_lease_key,
		x_smb2_uuid_t &client_guid,
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
			true,
			0);

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
				false,
				0);
		x_smbd_release_object(smbd_object);
	}
}
