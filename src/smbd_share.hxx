
#ifndef __smbd_share__hxx__
#define __smbd_share__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "smbd.hxx"
#include "smbd_durable.hxx"

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

struct x_smbd_object_ops_t;
struct x_smbd_volume_t
{
	x_smbd_volume_t(const std::string &name, const std::string &path,
			const std::string &owner_node,
			const std::string &owner_share,
			const x_smb2_uuid_t &vol_uuid,
			uint16_t vol_id, int rootdir_fd,
			x_smbd_durable_db_t *durable_db);

	~x_smbd_volume_t();

	void set_ops(const x_smbd_object_ops_t *ops) {
		X_ASSERT(!this->ops);
		this->ops = ops;
	}

	const x_smbd_object_ops_t *ops = nullptr;
	const std::string name, path;
	const std::string owner_node;
	const std::string owner_share;
	const x_smb2_uuid_t volume_uuid;
	const uint16_t volume_id;
	const int rootdir_fd;
	std::atomic<uint32_t> watch_tree_cnt{0};

	x_smbd_durable_db_t *smbd_durable_db;
};

struct x_smbd_share_t
{
	enum {
		f_read_only = 1,
		f_durable_handle = 2,
		f_continuously_available = 4,
		f_abe = 8,
	};

	x_smbd_share_t(const std::string &name, uint32_t flags)
		: name(name), flags(flags)
	{
	}
	virtual ~x_smbd_share_t() { }
	virtual uint8_t get_type() const = 0;
	virtual bool is_dfs() const = 0;
	virtual NTSTATUS get_dfs_referral(x_dfs_referral_resp_t &dfs_referral,
			const char16_t *in_full_path_begin,
			const char16_t *in_full_path_end,
			const char16_t *in_server_begin,
			const char16_t *in_server_end,
			const char16_t *in_share_begin,
			const char16_t *in_share_end) const = 0;
	virtual NTSTATUS resolve_path(std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			std::u16string &out_path,
			long &path_priv_data,
			long &open_priv_data,
			bool dfs,
			const char16_t *in_path_begin,
			const char16_t *in_path_end,
			const std::string &volume) = 0;
	virtual NTSTATUS create_open(x_smbd_open_t **psmbd_open,
			x_smbd_requ_t *smbd_requ,
			const std::string &volume,
			std::unique_ptr<x_smb2_state_create_t> &state,
			std::vector<x_smb2_change_t>& changes) = 0;
	virtual NTSTATUS delete_object(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open, int fd,
			std::vector<x_smb2_change_t> &changes) = 0;

	bool is_read_only() const {
		return flags & f_read_only;
	}

	bool support_durable_handle() const {
		return flags & f_durable_handle;
	}

	bool is_continuously_available() const {
		return flags & f_continuously_available;
	}

	bool abe_enabled() const {
		return flags & f_abe;
	}

	std::string name;
	uint32_t flags;
	bool dfs_test = false;
	uint32_t max_connections = 0;
	uint32_t dfs_referral_ttl;
	std::vector<std::string> vgs;
};

std::shared_ptr<x_smbd_volume_t> x_smbd_volume_create(
		const std::string &name, const std::string &path,
		const std::string &owner_node, const std::string &owner_share);

NTSTATUS x_smbd_volume_get_fd_path(std::string &ret,
		const x_smbd_volume_t &smbd_volumen,
		int fd);
int x_smbd_volume_save_durable(x_smbd_volume_t &smbd_volume,
		uint64_t &id_persistent,
		const x_smbd_durable_t *durable);
int x_smbd_volume_set_durable_timeout(x_smbd_volume_t &smbd_volume,
		uint64_t id_persistent, uint32_t timeout_sec);
std::shared_ptr<x_smbd_share_t> x_smbd_ipc_share_create();
std::shared_ptr<x_smbd_share_t> x_smbd_dfs_share_create(
		const x_smbd_conf_t &smbd_conf,
		const std::string &name,
		uint32_t share_flags,
		const std::vector<std::shared_ptr<x_smbd_volume_t>> &smbd_volumes);
std::shared_ptr<x_smbd_share_t> x_smbd_simplefs_share_create(
		const std::string &name,
		uint32_t share_flags,
		const std::shared_ptr<x_smbd_volume_t> &smbd_volume);
int x_smbd_simplefs_mktld(const std::shared_ptr<x_smbd_user_t> &smbd_user,
		std::shared_ptr<x_smbd_share_t> &smbd_share,
		const std::string &name,
		std::vector<uint8_t> &ntacl_blob);

int x_smbd_simplefs_rmtld(std::shared_ptr<x_smbd_share_t> &smbd_share,
		const std::string &name);

#endif /* __smbd_share__hxx__ */

