
#include "smbd_open.hxx"

static void notify_one_level(std::shared_ptr<x_smbd_topdir_t> &topdir,
		const std::u16string &path,
		const std::u16string &fullpath,
		const std::u16string *new_fullpath,
		uint32_t notify_action,
		uint32_t notify_filter,
		bool last_level)
{
	NTSTATUS status;
	x_smbd_object_t *smbd_object = topdir->ops->open_object(&status,
			topdir, path, 0, false);
	if (!smbd_object) {
		return;
	}

	x_smbd_object_notify_change(smbd_object, notify_action, notify_filter,
			fullpath, new_fullpath, last_level);

	x_smbd_object_release(smbd_object);
}

static void notify_change(std::shared_ptr<x_smbd_topdir_t> &topdir,
		uint32_t notify_action,
		uint32_t notify_filter,
		const std::u16string &path,
		const std::u16string *new_path)
{
	bool watch_tree = topdir->watch_tree_cnt > 0;
	std::size_t curr_pos = 0, last_sep_pos = 0;
	for (;;) {
		auto found = path.find('\\', curr_pos);
		if (found == std::string::npos) {
			break;
		}
		
		if (watch_tree) {
			notify_one_level(topdir,
					path.substr(0, last_sep_pos),
					path, new_path,
					notify_action, notify_filter, false);
		}
		last_sep_pos = found;
		curr_pos = found + 1;
	}

	notify_one_level(topdir,
			path.substr(0, last_sep_pos),
			path, new_path,
			notify_action, notify_filter, true);
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

static void notify_change(std::shared_ptr<x_smbd_topdir_t> &topdir,
		const x_smb2_change_t &change)
{
	if (change.action == NOTIFY_ACTION_OLD_NAME) {
		X_ASSERT(!change.new_path.empty());
		if (is_same_parent(change.path, change.new_path)) {
			notify_change(topdir, change.action, change.filter,
					change.path, &change.new_path);
		} else {
			notify_change(topdir, NOTIFY_ACTION_REMOVED, change.filter,
					change.path, nullptr);
			notify_change(topdir, NOTIFY_ACTION_ADDED, change.filter,
					change.new_path, nullptr);
		}
	} else {
		notify_change(topdir, change.action, change.filter,
				change.path, nullptr);
	}
}

void x_smbd_notify_change(std::shared_ptr<x_smbd_topdir_t> &topdir,
		const std::vector<x_smb2_change_t> &changes)
{
	for (const auto &change: changes) {
		notify_change(topdir, change);
	}
}


