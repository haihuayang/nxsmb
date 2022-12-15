
#include "smbd_open.hxx"

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

static bool is_same_parent(const std::u16string &old_path, const std::u16string &new_path)
{
	auto old_sep = old_path.rfind(u'\\');
	auto new_sep = new_path.rfind(u'\\');
	if (old_sep != new_sep) {
	       return false;
	}
	return old_sep == std::u16string::npos || old_path.compare(0, old_sep,
			new_path, 0, new_sep) == 0;
}

void x_smbd_notify_change(std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const std::vector<x_smb2_change_t> &changes)
{
	for (const auto &change: changes) {
		if (change.action == NOTIFY_ACTION_OLD_NAME) {
			X_ASSERT(!change.new_path.empty());
			if (is_same_parent(change.path, change.new_path)) {
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
		} else {
			notify_change(smbd_volume, change.action, change.filter,
					change.path, nullptr,
					change.ignore_lease_key);
		}
	}
}


