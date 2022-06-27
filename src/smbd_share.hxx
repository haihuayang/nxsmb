
#ifndef __smbd_share__hxx__
#define __smbd_share__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "smbd.hxx"

struct x_smbd_conf_t;

struct x_referral_t
{
	// uint32_t proximity;
	uint16_t server_type = 0;
	uint16_t flags = 0;
	uint32_t ttl;
	std::u16string path;
	std::u16string node;
};

#define DFS_HEADER_FLAG_REFERAL_SVR ( 0x00000001 )
#define DFS_HEADER_FLAG_STORAGE_SVR ( 0x00000002 )
#define DFS_HEADER_FLAG_TARGET_BCK ( 0x00000004 )

#define DFS_SERVER_ROOT 1

#define DFS_FLAG_REFERRAL_FIRST_TARGET_SET 0x0004

struct x_dfs_referral_resp_t
{
	uint16_t path_consumed;
	uint32_t header_flags;
	std::vector<x_referral_t> referrals;
};

struct x_smbd_share_t
{
	x_smbd_share_t(const std::string &name) : name(name) { }
	virtual ~x_smbd_share_t() { }
	virtual uint8_t get_type() const = 0;
	virtual bool is_dfs() const = 0;
	virtual bool abe_enabled() const = 0;
	virtual NTSTATUS create_open(x_smbd_open_t **psmbd_open,
			x_smbd_requ_t *smbd_requ,
			const std::string &volume,
			std::unique_ptr<x_smb2_state_create_t> &state) = 0;
	virtual NTSTATUS get_dfs_referral(x_dfs_referral_resp_t &dfs_referral,
			const char16_t *in_full_path_begin,
			const char16_t *in_full_path_end,
			const char16_t *in_server_begin,
			const char16_t *in_server_end,
			const char16_t *in_share_begin,
			const char16_t *in_share_end) const = 0;
#if 0
	/* TODO looks like resolve_path should not be here */
	virtual NTSTATUS resolve_path(const std::u16string &in_path,
		bool dfs,
		std::shared_ptr<x_smbd_topdir_t> &topdir,
		std::u16string &path) = 0;
#endif
	std::string name;
	bool read_only = false;
	bool dfs_test = false;
	uint32_t max_connections = 0;
	std::vector<std::string> vgs;
};

struct x_smbd_topdir_t;
struct x_smbd_topdir_t
{
	x_smbd_topdir_t();
	~x_smbd_topdir_t();
	// const std::shared_ptr<x_smbd_share_t> smbd_share;
	uint64_t const uuid;
	int fd = -1;
	std::atomic<uint32_t> watch_tree_cnt{0};
};

std::shared_ptr<x_smbd_topdir_t> x_smbd_topdir_create(const std::string &path);

std::shared_ptr<x_smbd_share_t> x_smbd_ipc_share_create();
std::shared_ptr<x_smbd_share_t> x_smbd_dfs_share_create(const x_smbd_conf_t &smbd_conf,
		const std::string &name,
		const std::vector<std::string> &vgs);
std::shared_ptr<x_smbd_share_t> x_smbd_dfs_link_create(const std::string &name, const std::string &dfs_root);
std::shared_ptr<x_smbd_share_t> x_smbd_dfs_root_create(const std::string &name, const std::string &path, const std::vector<std::string> &vgs);
std::shared_ptr<x_smbd_share_t> x_smbd_simplefs_share_create(const std::string &name, const std::string &path);
int x_smbd_simplefs_mktld(const std::shared_ptr<x_smbd_user_t> &smbd_user,
		std::shared_ptr<x_smbd_share_t> &smbd_share,
		const std::string &name,
		std::vector<uint8_t> &ntacl_blob);

int x_smbd_simplefs_rmtld(std::shared_ptr<x_smbd_share_t> &smbd_share,
		const std::string &name);

#endif /* __smbd_share__hxx__ */

