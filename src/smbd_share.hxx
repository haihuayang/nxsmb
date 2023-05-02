
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
	x_smbd_volume_t(const x_smb2_uuid_t &uuid,
			const std::string &name,
			std::u16string &&name_u16,
			const std::string &path,
			const std::string &owner_node);

	~x_smbd_volume_t();

	void set_ops(const x_smbd_object_ops_t *ops) {
		X_ASSERT(!this->ops);
		this->ops = ops;
	}

	const x_smbd_object_ops_t *ops = nullptr;
	const x_smb2_uuid_t uuid;
	const std::string name;
	const std::u16string name_u16;
	const std::string path;
	const std::string owner_node;

	std::shared_ptr<x_smbd_share_t> owner_share;
	uint16_t volume_id;
	int rootdir_fd;
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

	x_smbd_share_t(const x_smb2_uuid_t &uuid, const std::string &name,
			std::u16string &&name_u16,
			uint32_t flags)
		: uuid(uuid), name(name), name_u16(name_u16), flags(flags)
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
			const std::shared_ptr<x_smbd_volume_t> &tcon_volume) = 0;
	virtual std::shared_ptr<x_smbd_volume_t> find_volume(const std::string &name) const = 0;

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

	const x_smb2_uuid_t uuid;
	std::string name;
	std::u16string name_u16;
	uint32_t flags;
	bool dfs_test = false;
	uint32_t max_connections = 0;
	uint32_t dfs_referral_ttl;
};

std::shared_ptr<x_smbd_volume_t> x_smbd_volume_create(
		const x_smb2_uuid_t &uuid,
		const std::string &name, std::u16string &&name_u16,
		const std::string &path, const std::string &owner_node);
int x_smbd_volume_init(x_smbd_volume_t &smbd_volume);

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
		const x_smb2_uuid_t &uuid,
		const std::string &name,
		std::u16string &&name_u16,
		uint32_t share_flags,
		std::vector<std::shared_ptr<x_smbd_volume_t>> &&smbd_volumes);
std::shared_ptr<x_smbd_share_t> x_smbd_simplefs_share_create(
		const x_smb2_uuid_t &uuid,
		const std::string &name,
		std::u16string &&name_u16,
		uint32_t share_flags,
		const std::shared_ptr<x_smbd_volume_t> &smbd_volume);
int x_smbd_simplefs_mktld(const std::shared_ptr<x_smbd_user_t> &smbd_user,
		std::shared_ptr<x_smbd_share_t> &smbd_share,
		const std::string &name,
		std::vector<uint8_t> &ntacl_blob);

int x_smbd_simplefs_rmtld(std::shared_ptr<x_smbd_share_t> &smbd_share,
		const std::string &name);
NTSTATUS x_smbd_open_restore(
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		x_smbd_durable_t &smbd_durable);

int x_smbd_restore_durable(const x_smbd_conf_t &smbd_conf);

int x_smbd_volume_restore_durable(std::shared_ptr<x_smbd_volume_t> &smbd_volume);

x_smbd_durable_t *x_smbd_share_lookup_durable(
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const std::shared_ptr<x_smbd_share_t> &smbd_share,
		uint64_t id_persistent);

#endif /* __smbd_share__hxx__ */

