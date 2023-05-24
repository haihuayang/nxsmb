
#include "smbd_open.hxx"

struct smd_notify_evt_t
{
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user)
	{
		smd_notify_evt_t *evt = X_CONTAINER_OF(fdevt_user, smd_notify_evt_t, base);
		x_smbd_requ_t *smbd_requ = evt->smbd_requ;
		X_LOG_DBG("evt=%p, requ=%p, smbd_conn=%p", evt, smbd_requ, smbd_conn);

		auto state = smbd_requ->get_requ_state<x_smb2_state_notify_t>();
		state->out_notify_changes = std::move(evt->notify_changes);
		x_smbd_requ_async_done(smbd_conn, smbd_requ, NT_STATUS_OK);
		delete evt;
	}

	smd_notify_evt_t(x_smbd_requ_t *requ,
			std::vector<std::pair<uint32_t, std::u16string>> &&changes)
		: base(func), smbd_requ(requ), notify_changes(changes)
	{
	}

	~smd_notify_evt_t()
	{
		x_smbd_ref_dec(smbd_requ);
	}

	x_fdevt_user_t base;
	x_smbd_requ_t * const smbd_requ;
	std::vector<std::pair<uint32_t, std::u16string>> notify_changes;
};

void x_smbd_object_notify_change(x_smbd_object_t *smbd_object,
		uint32_t notify_action,
		uint32_t notify_filter,
		uint32_t prefix_length,
		const std::u16string &fullpath,
		const std::u16string *new_name_path,
		const x_smb2_lease_key_t &ignore_lease_key,
		bool last_level,
		long open_priv_data)
{
	std::u16string subpath;
	std::u16string new_subpath;
	/* TODO change to read lock */
	std::unique_lock<std::mutex> lock(smbd_object->mutex);
	auto &open_list = smbd_object->sharemode.open_list;
	x_smbd_open_t *curr_open;
	int count = 0;
	for (curr_open = open_list.get_front(); curr_open; curr_open = open_list.next(curr_open)) {
		++count;
		if (curr_open->open_state.priv_data != open_priv_data) {
			continue;
		}

		if (last_level && curr_open->smbd_lease) {
			x_smbd_open_break_lease(curr_open, &ignore_lease_key, 0);
		}

		if (!(curr_open->notify_filter & notify_filter)) {
			continue;
		}
		if (!last_level && !(curr_open->notify_filter & X_FILE_NOTIFY_CHANGE_WATCH_TREE)) {
			continue;
		}
		if (subpath.empty()) {
			if (prefix_length == 0) {
				subpath = fullpath;
				if (new_name_path) {
					new_subpath = *new_name_path;
				}
			} else {
				subpath = fullpath.substr(prefix_length);
				if (new_name_path) {
					new_subpath = new_name_path->substr(prefix_length);
				}
			}
		}
		bool orig_empty = curr_open->notify_changes.empty();
		curr_open->notify_changes.push_back(std::make_pair(notify_action, subpath));
		if (new_name_path) {
			curr_open->notify_changes.push_back(std::make_pair(NOTIFY_ACTION_NEW_NAME,
						new_subpath));
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

		auto notify_changes = std::move(curr_open->notify_changes);
		curr_open->pending_requ_list.remove(smbd_requ);
		lock.unlock();

		X_SMBD_CHAN_POST_USER(smbd_requ->smbd_chan, 
				new smd_notify_evt_t(smbd_requ,
					std::move(notify_changes)));
		lock.lock();
	}
}

void x_smbd_simple_notify_change(
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const std::u16string &path,
		const std::u16string &fullpath,
		const std::u16string *new_fullpath,
		uint32_t notify_action,
		uint32_t notify_filter,
		const x_smb2_lease_key_t &ignore_lease_key,
		bool last_level)
{
	x_smbd_object_t *smbd_object = nullptr;
	x_smbd_stream_t *smbd_stream = nullptr;
	NTSTATUS status = x_smbd_open_object(&smbd_object, &smbd_stream,
			smbd_volume, path, std::u16string(), 0, false);
	if (!NT_STATUS_IS_OK(status)) {
		X_LOG_DBG("skip notify %d,x%x '%s', '%s'", notify_action,
				notify_filter,
				x_str_todebug(path).c_str(),
				x_str_todebug(fullpath).c_str());
		return;
	}

	X_ASSERT(smbd_object);
	X_LOG_DBG("notify object %d,x%x '%s', '%s'", notify_action,
			notify_filter,
			x_str_todebug(path).c_str(),
			x_str_todebug(fullpath).c_str());
	x_smbd_object_notify_change(smbd_object, notify_action, notify_filter,
			path.empty() ? 0: x_convert<uint32_t>(path.length() + 1),
			fullpath, new_fullpath, ignore_lease_key, last_level, 0);

	x_smbd_object_release(smbd_object, nullptr);
}

static void notify_one_level(std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const std::u16string &path,
		const std::u16string &fullpath,
		const std::u16string *new_fullpath,
		uint32_t notify_action,
		uint32_t notify_filter,
		const x_smb2_lease_key_t &ignore_lease_key,
		bool last_level)
{
	smbd_volume->ops->notify_change(smbd_volume, path, fullpath, new_fullpath,
			notify_action, notify_filter,
			ignore_lease_key, last_level);
}

static void notify_change(std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		uint32_t notify_action,
		uint32_t notify_filter,
		const std::u16string &path,
		const std::u16string *new_path,
		const x_smb2_lease_key_t &ignore_lease_key)
{
	bool watch_tree = smbd_volume->watch_tree_cnt > 0;
	std::size_t curr_pos = 0, last_sep_pos = 0;
	for (;;) {
		auto found = path.find('\\', curr_pos);
		if (found == std::string::npos) {
			break;
		}
		
		if (watch_tree) {
			notify_one_level(smbd_volume,
					path.substr(0, last_sep_pos),
					path, new_path,
					notify_action, notify_filter,
					ignore_lease_key,
					false);
		}
		last_sep_pos = found;
		curr_pos = found + 1;
	}

	notify_one_level(smbd_volume,
			path.substr(0, last_sep_pos),
			path, new_path,
			notify_action, notify_filter,
			ignore_lease_key,
			true);
}

void x_smbd_notify_change(std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const std::vector<x_smb2_change_t> &changes)
{
	for (const auto &change: changes) {
		if (change.action == NOTIFY_ACTION_OLD_NAME) {
			X_ASSERT(!change.new_path.empty());

			auto old_sep = change.path.rfind(u'\\');
			auto new_sep = change.new_path.rfind(u'\\');

			bool same_parent = (old_sep == new_sep) &&
				(old_sep == std::u16string::npos ||
				 change.path.compare(0, old_sep, change.new_path,
					 0, new_sep) == 0);

			if (same_parent) {
				notify_change(smbd_volume, change.action, change.filter,
						change.path, &change.new_path,
						change.ignore_lease_key);
			} else {
				notify_change(smbd_volume, NOTIFY_ACTION_REMOVED, change.filter,
						change.path, nullptr,
						change.ignore_lease_key);
				notify_change(smbd_volume, NOTIFY_ACTION_ADDED, change.filter,
						change.new_path, nullptr,
						change.ignore_lease_key);
			}
			if (new_sep != std::u16string::npos) {
				/* Windows server also notify dest parent dir modified */
				notify_change(smbd_volume, NOTIFY_ACTION_MODIFIED,
						FILE_NOTIFY_CHANGE_LAST_WRITE,
						change.new_path.substr(0, new_sep),
						nullptr, x_smb2_lease_key_t{});
			}
		} else {
			notify_change(smbd_volume, change.action, change.filter,
					change.path, nullptr,
					change.ignore_lease_key);
		}
	}
}


