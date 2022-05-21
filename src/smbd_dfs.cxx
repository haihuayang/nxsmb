
#include "smbd.hxx"
#include "smbd_share.hxx"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <attr/xattr.h>
#include "smbd_posixfs_utils.hxx"

static const std::string pesudo_tld_dir = ".tld";
static constexpr uint32_t default_referral_ttl = 10;

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
	NTSTATUS create(x_smbd_open_t **psmbd_open,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_create_t> &state) override;
	NTSTATUS get_dfs_referral(x_dfs_referral_resp_t &dfs_referral,
			const char16_t *in_full_path_begin,
			const char16_t *in_full_path_end,
			const char16_t *in_server_begin,
			const char16_t *in_server_end,
			const char16_t *in_share_begin,
			const char16_t *in_share_end) const override;
	NTSTATUS resolve_path(const std::u16string &in_path,
		bool dfs,
		std::shared_ptr<x_smbd_topdir_t> &topdir,
		std::u16string &path) override
	{
		X_ASSERT(false);
		return NT_STATUS_INTERNAL_ERROR;
	}
	std::shared_ptr<x_smbd_topdir_t> root_dir;
	std::vector<std::string> vgs;
	uint32_t max_referral_ttl = default_referral_ttl;
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

NTSTATUS dfs_root_t::create(x_smbd_open_t **psmbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	X_TODO;
	return NT_STATUS_INTERNAL_ERROR;
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
	NTSTATUS create(x_smbd_open_t **psmbd_open,
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
	NTSTATUS resolve_path(const std::u16string &in_path,
		bool dfs,
		std::shared_ptr<x_smbd_topdir_t> &topdir,
		std::u16string &path) override
	{
		X_ASSERT(false);
		return NT_STATUS_INTERNAL_ERROR;
	}
	const std::string dfs_root;
	uint32_t max_referral_ttl = default_referral_ttl;
};

NTSTATUS dfs_namespace_t::get_dfs_referral(x_dfs_referral_resp_t &dfs_referral_resp,
		const char16_t *in_full_path_begin,
		const char16_t *in_full_path_end,
		const char16_t *in_server_begin,
		const char16_t *in_server_end,
		const char16_t *in_share_begin,
		const char16_t *in_share_end) const
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
	return NT_STATUS_OK;
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
