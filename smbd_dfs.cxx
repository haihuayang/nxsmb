
#include "smbd.hxx"
#include "smbd_share.hxx"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <attr/xattr.h>
#include "smbd_posixfs_utils.hxx"

static const std::string pesudo_tld_dir = ".tld";

struct dfs_root_open_t
{
	x_smbd_open_t base;
	x_dlink_t object_link;
};
X_DECLARE_MEMBER_TRAITS(dfs_root_open_object_traits, dfs_root_open_t, object_link)
X_DECLARE_MEMBER_TRAITS(dfs_root_open_from_base_t, dfs_root_open_t, base)

struct dfs_root_object_t
{
	dfs_root_object_t(uint64_t h, const std::shared_ptr<x_smbd_topdir_t> &topdir,
			const std::u16string &p);
	~dfs_root_object_t() {
		if (fd != -1) {
			close(fd);
		}
	}

	x_smbd_object_t base;

	bool exists() const { return fd != -1; }
	bool is_dir() const {
		return true;
	}
	x_dqlink_t hash_link;
	uint64_t hash;
	uint64_t unused_timestamp{0};
	std::atomic<uint32_t> use_count{1}; // protected by bucket mutex
	std::mutex mutex;
	// std::atomic<uint32_t> children_count{};
	int fd = -1;
	std::atomic<uint32_t> lease_cnt{0};
	// std::atomic<uint32_t> notify_cnt{0};

	enum {
		flag_initialized = 1,
		flag_not_exist = 2,
		flag_topdir = 4,
		flag_delete_on_close = 0x1000,
	};

	uint32_t flags = 0;
	bool statex_modified{false}; // TODO use flags
	posixfs_statex_t statex;
	const std::shared_ptr<x_smbd_topdir_t> topdir;
	/* protected by object mutex */
	x_tp_ddlist_t<dfs_root_open_object_traits> open_list;
	// x_tp_ddlist_t<requ_async_traits> defer_open_list;
};

static NTSTATUS dfs_root_object_op_close(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state)
{
	dfs_root_open_t *dfs_root_open = dfs_root_open_from_base_t::container(smbd_open);
	dfs_root_object_t *dfs_root_object = dfs_root_object_from_base_t::container(smbd_object);

	std::unique_lock<std::mutex> lock(dfs_root_object->mutex);

	if (dfs_root_open->smbd_lease) {
		x_smbd_lease_release(dfs_root_open->smbd_lease);
		dfs_root_open->smbd_lease = nullptr;
	}

	/* Windows server send NT_STATUS_NOTIFY_CLEANUP
	   when tree disconect.
	   while samba not send.
	   for simplicity we do not either for now
	 */
	x_smbd_requ_t *requ_notify;
	while ((requ_notify = dfs_root_open->notify_requ_list.get_front()) != nullptr) {
		posixfs_open->notify_requ_list.remove(requ_notify);
		lock.unlock();

		// TODO multi-thread safe
		std::unique_ptr<x_smb2_state_notify_t> notify_state{(x_smb2_state_notify_t *)requ_notify->requ_state};
		requ_notify->requ_state = nullptr;
		x_smbd_requ_remove(requ_notify);
		// TODO notify_state->done(smbd_conn, requ_notify, NT_STATUS_NOTIFY_CLEANUP);
		x_smbd_ref_dec(requ_notify);

		lock.lock();
	}

	posixfs_object_remove(posixfs_object, posixfs_open);

	share_mode_modified(posixfs_object);

	// TODO if last_write_time updated
	if (smbd_requ) {
		if (state->in_flags & SMB2_CLOSE_FLAGS_FULL_INFORMATION) {
			state->out_flags = SMB2_CLOSE_FLAGS_FULL_INFORMATION;
			fill_out_info(state->out_info, posixfs_object->statex);
		}
	}
	return NT_STATUS_OK;
}

static const x_smbd_object_ops_t dfs_root_object_ops = {
	dfs_root_object_op_close,
	nullptr,
	nullptr,
	dfs_root_object_op_getinfo,
	dfs_root_object_op_setinfo,
	dfs_root_object_op_ioctl,
	dfs_root_object_op_qdir,
	dfs_root_object_op_notify,
	dfs_root_object_op_lease_break,
	dfs_root_object_op_oplock_break,
	dfs_root_object_op_get_path,
	dfs_root_object_op_destroy,
};

dfs_root_object_t::dfs_root_object_t(const std::shared_ptr<x_smbd_topdir_t> &topdir)
	: base(&dfs_root_object_ops), topdir(topdir)
{
}

struct dfs_root_t : x_smbd_share_t
{
	dfs_root_t(const std::string &name, const std::string &path,
			const std::vector<std::string> &vgs)
		: x_smbd_share_t(name), vgs(vgs)
	{
		root_dir = x_smbd_topdir_create(path);
	}
	uint8_t get_type() const override {
		return SMB2_SHARE_TYPE_DISK;
	}
	bool is_dfs() const override { return true; }
	/* TODO not support ABE for now */
	bool abe_enabled() const override { return false; }
	NTSTATUS create(x_smbd_tcon_t *smbd_tcon, x_smbd_open_t **psmbd_open,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_create_t> &state) override
	{
		X_TODO;
		return NT_STATUS_OK;
	}
	NTSTATUS get_dfs_referral(x_dfs_referral_resp_t &dfs_referral,
			const char16_t *in_full_path_begin,
			const char16_t *in_full_path_end,
			const char16_t *in_server_begin,
			const char16_t *in_server_end,
			const char16_t *in_share_begin,
			const char16_t *in_share_end) const override;
	std::shared_ptr<x_smbd_topdir_t> root_dir;
	std::vector<std::string> vgs;
	uint32_t max_referral_ttl = 30;
};

static std::u16string resolve_tld(const dfs_root_t &dfs_root,
		const char16_t *in_tld_begin, const char16_t *in_tld_end)
{
	std::u16string ret;
	if (in_tld_end == in_tld_begin) {
		return ret;
	}

	auto topdir = dfs_root.root_dir;
	X_ASSERT(topdir);
	std::string tld = x_convert_utf16_to_lower_utf8(in_tld_begin, in_tld_end);
	/* pseudo dir for all tld */
	if (tld == pesudo_tld_dir) {
		return ret;
	}

	/* TODO reuse posixfs_open */
	int fd = openat(topdir->fd, tld.c_str(), O_NOFOLLOW);
	if (fd < 0) {
		return ret;
	}
	
	struct stat st;
	int err = fstat(fd, &st);
	X_ASSERT(!err);

	if (S_ISDIR(st.st_mode)) {
		char16_t tld_path[1024];
		ssize_t err = fgetxattr(fd, XATTR_TLD_PATH, tld_path, sizeof tld_path);
		if (err > 0) {
			X_ASSERT((err % 2) == 0);
			ret.assign(tld_path);
		}
	}

	close(fd);
	return ret;
}

NTSTATUS dfs_root_t::get_dfs_referral(x_dfs_referral_resp_t &dfs_referral_resp,
		const char16_t *in_full_path_begin,
		const char16_t *in_full_path_end,
		const char16_t *in_server_begin,
		const char16_t *in_server_end,
		const char16_t *in_share_begin,
		const char16_t *in_share_end) const
{
	/* distribute root */
	std::u16string alt_path;
	std::u16string node;
	std::u16string vg_path;
	const char16_t *in_tld_begin, *in_tld_end;
	if (in_share_end == in_full_path_end) {
		in_tld_begin = in_tld_end = in_full_path_end;
	} else {
		in_tld_begin = x_skip_sep(in_share_end + 1, in_full_path_end);
		in_tld_end = x_next_sep(in_tld_begin, in_full_path_end);
	}
	if ((vg_path = resolve_tld(*this, in_tld_begin, in_tld_end)).size()) {
		alt_path.assign(in_full_path_begin, in_tld_end);
		node = u'\\' + std::u16string(in_server_begin, in_server_end) + 
			u'\\' + vg_path;
		dfs_referral_resp.referrals.push_back(x_referral_t{0, 0,
				max_referral_ttl,
				alt_path, node});
		dfs_referral_resp.header_flags = DFS_HEADER_FLAG_STORAGE_SVR;
	} else {
		/* no tld, referral to itself */
		alt_path.assign(in_full_path_begin, in_share_end);
		node = u'\\' + std::u16string(in_server_begin, in_server_end)
			+ std::u16string(in_share_begin - 1, in_share_end);
		dfs_referral_resp.referrals.push_back(x_referral_t{DFS_SERVER_ROOT, 0,
				max_referral_ttl,
				alt_path, node});
		dfs_referral_resp.header_flags = DFS_HEADER_FLAG_REFERAL_SVR | DFS_HEADER_FLAG_STORAGE_SVR;
	}
	dfs_referral_resp.path_consumed = x_convert_assert<uint16_t>(alt_path.length() * 2);
	return NT_STATUS_OK;
}

NTSTATUS dfs_root_t::create(x_smbd_tcon_t *smbd_tcon, x_smbd_open_t **psmbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state) override
{
	if (!(smbd_requ->in_hdr_flags & SMB2_HDR_FLAG_DFS)) {
		return NT_STATUS_PATH_NOT_FOUND;
	}
	
	auto &in_path = state->in_name;
	std::u16string path;
	/* TODO we just simply skip the first 2 components for now */
	auto pos = in_path.find(u'\\');
	X_ASSERT(pos != std::u16string::npos);
	pos = in_path.find(u'\\', pos + 1);
	if (pos == std::u16string::npos) {
		path = u"";
	} else {
		path = in_path.substr(pos + 1);
	}

	return NT_STATUS_OK;
}

std::shared_ptr<x_smbd_share_t> x_smbd_dfs_root_create(const std::string &name,
		const std::string &path, const std::vector<std::string> &vgs)
{
	return std::make_shared<dfs_root_t>(name, path, vgs);
}


struct dfs_namespace_t : x_smbd_share_t
{
	dfs_namespace_t(const std::string &name, const std::string &dfs_root)
		: x_smbd_share_t(name), dfs_root(dfs_root)
	{
	}
	uint8_t get_type() const override
	{
		return SMB2_SHARE_TYPE_DISK;
	}
	bool is_dfs() const override { return true; }
	bool abe_enabled() const override { return false; }
	NTSTATUS create(x_smbd_tcon_t *smbd_tcon, x_smbd_open_t **psmbd_open,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_create_t> &state) override {
		return NT_STATUS_PATH_NOT_COVERED;
	}
	NTSTATUS get_dfs_referral(x_dfs_referral_resp_t &dfs_referral,
			const char16_t *in_full_path_begin,
			const char16_t *in_full_path_end,
			const char16_t *in_server_begin,
			const char16_t *in_server_end,
			const char16_t *in_share_begin,
			const char16_t *in_share_end) const override;
	const std::string dfs_root;
};

NTSTATUS dfs_namespace_t::get_dfs_referral(x_dfs_referral_resp_t &dfs_referral,
		const char16_t *in_full_path_begin,
		const char16_t *in_full_path_end,
		const char16_t *in_server_begin,
		const char16_t *in_server_end,
		const char16_t *in_share_begin,
		const char16_t *in_share_end) const override
{
	/* distribute namespace */
	std::u16string alt_path(in_full_path_begin, in_share_end);
	std::u16string node = u'\\' + std::u16string(in_server_begin, in_server_end)
		+ u'\\' + x_convert_utf8_to_utf16(dfs_root);
	dfs_referral_resp.referrals.push_back(x_referral_t{DFS_SERVER_ROOT, 0,
			max_referral_ttl,
			alt_path, node});
	dfs_referral_resp.header_flags = DFS_HEADER_FLAG_REFERAL_SVR | DFS_HEADER_FLAG_STORAGE_SVR;
	dfs_referral_resp.path_consumed = x_convert_assert<uint16_t>(alt_path.length() * 2);
}

std::shared_ptr<x_smbd_share_t> x_smbd_dfs_namespace_create(const std::string &name,
		const std::string &dfs_root)
{
	return std::make_shared<dfs_namespace_t>(name, dfs_root);
}
#if 0
NTSTATUS x_smbd_dfs_resolve_path(
		const std::shared_ptr<x_smbd_share_t> &smbd_share,
		const std::u16string &in_path,
		bool dfs,
		std::shared_ptr<x_smbd_topdir_t> &topdir,
		std::u16string &path)
{
	if (smbd_share->my_distribute_root.size() > 0) {
		return NT_STATUS_PATH_NOT_COVERED;
	}
	if (smbd_share->my_distribute_vgs.size() > 0) {
		if (!dfs) {
			X_TODO;
		}
	}

	if (dfs) {
		/* TODO we just skip the first 2 components for now */
		auto pos = in_path.find(u'\\');
		X_ASSERT(pos != std::u16string::npos);
		pos = in_path.find(u'\\', pos + 1);
		if (pos == std::u16string::npos) {
			path = u"";
		} else {
			path = in_path.substr(pos + 1);
		}
	} else {
		path = in_path;
	}
	topdir = smbd_share->root_dir;
	return NT_STATUS_OK;
}
#endif
