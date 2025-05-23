
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
			uint16_t volume_id,
			const std::string &owner_node,
			const std::string &path,
			uint32_t allocation_roundup_size);

	~x_smbd_volume_t();

	const x_smbd_object_ops_t *ops = nullptr;
	const x_smb2_uuid_t uuid;
	const std::string owner_node;
	const std::string path;

	std::shared_ptr<x_smbd_share_t> owner_share;

	const uint32_t allocation_roundup_size;

	const uint16_t volume_id;
	std::atomic<uint32_t> watch_tree_cnt{0};
	int root_fd = -1;

	// x_smbd_object_t *root_object = nullptr;

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
			std::u16string &&name_16,
			std::u16string &&name_l16,
			uint32_t flags,
			x_smbd_feature_option_t smb_encrypt)
		: uuid(uuid), name(name)
		, name_16(name_16), name_l16(name_l16), flags(flags)
		, smb_encrypt(smb_encrypt)
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
	virtual std::shared_ptr<x_smbd_volume_t> find_volume(
			const char16_t *in_share_s, const char16_t *in_share_e)
			const = 0;

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
	std::u16string name_16, name_l16;

	uint32_t flags;
	x_smbd_feature_option_t smb_encrypt;
	bool dfs_test = false;
	uint32_t max_connections = 0;
	uint32_t dfs_referral_ttl;

	x_smbd_object_t *root_object = nullptr;
};

std::shared_ptr<x_smbd_volume_t> x_smbd_volume_create(
		const x_smb2_uuid_t &uuid,
		uint16_t volume_id,
		const std::string &owner_node,
		const std::string &path,
		uint32_t allocation_roundup_size);

NTSTATUS x_smbd_volume_get_fd_path(std::string &ret,
		const x_smbd_volume_t &smbd_volumen,
		int fd);

/*  id_persistent is in 0xVVVVRRRRDDDDDDDD
 *  the upper 16 bit VVVV is volume_id
 *  followed by 16 bit RRRR is a random number
 *  the lower 32 bit DDDDDDDD is the durable slot id
 *  durable slot id 0xffffffff is reserved for non-durable, assume number of
 *	slots is less than 2^32 -1
 *  id_persistent 0xffffffff is reserved for non-initialized,
 *	assume volume_id never be 0
 */
static inline uint64_t x_smbd_volume_non_durable_id(const x_smbd_volume_t &smbd_volume)
{
	return (uint64_t)smbd_volume.volume_id << 48 | 0xfffffffful;
}
static inline bool x_smbd_is_non_durable_id(uint64_t id)
{
	return (id & 0xfffffffful) == 0xfffffffful;
}
int x_smbd_volume_allocate_persistent(x_smbd_volume_t &smbd_volume,
		uint64_t *p_id_persistent, uint64_t id_volatile);
int x_smbd_volume_save_durable(x_smbd_volume_t &smbd_volume,
		uint64_t id_persistent,
		uint64_t id_volatile,
		const x_smbd_open_state_t &open_state,
		const x_smbd_lease_data_t &lease_data,
		const x_smbd_file_handle_t &file_handle);
int x_smbd_volume_update_durable_flags(x_smbd_volume_t &smbd_volume,
		uint64_t id_persistent,
		const x_smbd_open_state_t &open_state);
int x_smbd_volume_update_durable_locks(x_smbd_volume_t &smbd_volume,
		bool sync,
		uint64_t id_persistent,
		const std::vector<x_smb2_lock_element_t> &locks);
int x_smbd_volume_remove_durable(x_smbd_volume_t &smbd_volume,
		bool sync,
		uint64_t id_persistent);
int x_smbd_volume_disconnect_durable(x_smbd_volume_t &smbd_volume,
		bool sync,
		uint64_t id_persistent);
std::shared_ptr<x_smbd_share_t> x_smbd_ipc_share_create();
std::shared_ptr<x_smbd_share_t> x_smbd_simplefs_share_create(
		const std::string &node_name,
		const x_smb2_uuid_t &uuid,
		const std::string &name,
		std::u16string &&name_16,
		std::u16string &&name_l16,
		uint32_t share_flags,
		x_smbd_feature_option_t smb_encrypt,
		std::vector<std::shared_ptr<x_smbd_volume_t>> &&smbd_volumes);
int x_smbd_simplefs_mktld(const std::shared_ptr<x_smbd_user_t> &smbd_user,
		std::shared_ptr<x_smbd_share_t> &smbd_share,
		const std::string &name,
		std::vector<uint8_t> &ntacl_blob);

int x_smbd_simplefs_rmtld(std::shared_ptr<x_smbd_share_t> &smbd_share,
		const std::string &name);
NTSTATUS x_smbd_open_restore(
		std::shared_ptr<x_smbd_share_t> &smbd_share,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		uint64_t id_persistent,
		x_smbd_durable_t &smbd_durable,
		uint64_t timeout_msec);

int x_smbd_volume_restore_durable(std::shared_ptr<x_smbd_share_t> smbd_share,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume);

/* return id_volatile
 * 0 if no such durable
 */
uint64_t x_smbd_share_lookup_durable(
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const std::shared_ptr<x_smbd_share_t> &smbd_share,
		uint64_t id_persistent);

#endif /* __smbd_share__hxx__ */

