
#ifndef __smbconf__hxx__
#define __smbconf__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "defines.hxx"
#include "include/utils.hxx"
#include "include/networking.hxx"
#include "include/librpc/misc.hxx"
#include "smbd_share.hxx"
#include "smbd_secrets.hxx"
#include "smbd_group_mapping.hxx"
#include <map>
#include <atomic>

static inline bool lpcfg_param_bool(void *service, const char *type, const char *option, bool default_v)
{
	return default_v;
}

static constexpr uint32_t X_INFINITE = -1;

struct x_smbd_share_spec_t
{
	static const uint32_t default_dfs_referral_ttl = 300;

	x_smbd_share_spec_t(const std::string &name) : name(name) { }

	x_smb2_uuid_t uuid;
	const std::string name;
	uint32_t share_flags = x_smbd_share_t::f_durable_handle;
	x_smbd_feature_option_t smb_encrypt = x_smbd_feature_option_t::enabled;
	bool dfs_test = false;
	uint32_t dfs_referral_ttl = default_dfs_referral_ttl;
	std::vector<std::pair<x_smb2_uuid_t, int>> volumes;
};

struct x_smbd_volume_spec_t
{
	x_smbd_volume_spec_t(const x_smb2_uuid_t &uuid,
			uint16_t volume_id,
			std::string &&node,
			std::string &&path)
		: uuid(uuid), volume_id(volume_id)
		, owner_node(node), path(path)
	{
	}

	const x_smb2_uuid_t uuid;
	const uint16_t volume_id;
	const std::string owner_node;
	const std::string path;

	x_smbd_share_spec_t *share_spec = nullptr;
};

struct x_smbd_node_t
{
	std::string name;
	struct in_addr ip_int;
	std::vector<struct sockaddr_storage> ss_ext;
};

struct x_smbd_conf_t
{
	x_smbd_conf_t();
	~x_smbd_conf_t();

	idl::svcctl_ServerType get_default_server_announce() const {
		// lp_default_server_announce
		idl::svcctl_ServerType ret = idl::svcctl_ServerType(idl::SV_TYPE_WORKSTATION
			| idl::SV_TYPE_SERVER
			| idl::SV_TYPE_SERVER_UNIX
			| idl::SV_TYPE_SERVER_NT
			| idl::SV_TYPE_NT
			| idl::SV_TYPE_DOMAIN_MEMBER);
		return ret;
	}

	x_smb2_uuid_t guid; // uint8_t guid[16];
	uint32_t port = 445;
	uint32_t node_port = 7526;
	uint32_t client_thread_count = 0;
	uint32_t async_thread_count = 0;
	uint32_t winbindd_connection_count = 10;

	uint32_t max_trans_size = 1024 * 1024;
	uint32_t max_read_size = 1024 * 1024;
	uint32_t max_write_size = 1024 * 1024;

	uint32_t capabilities;
	uint16_t security_mode = X_SMB2_NEGOTIATE_SIGNING_ENABLED;
	bool lanman_auth = false;
	bool allow_trusted_domains = true;
	bool gensec_require_pac = false; // if (gensec_setting_bool(gensec_security->settings, "gensec", "require_pac", false)) {

	bool ndr64 = false;
	uint32_t max_session_expiration = X_INFINITE; // in seconds

	uint32_t smb2_max_credits = 8192;
	bool host_msdfs = false;

	std::string log_level;
	uint32_t max_connections = 64 * 1024;
	uint32_t max_sessions = 64 * 1024;
	/* TODO table_tcon use x_idtable_32_traits_t, so max is 64 * 1024 - 9 */
	uint32_t max_tcons = 64 * 1024 - 9;
	uint32_t max_opens = 64 * 1024;
	uint32_t max_requs = 64 * 1024;

	uint32_t allocation_roundup_size = 4096; // TODO should be volume param

	uint32_t smb2_break_timeout_ms = 35000;
	uint32_t sess_setup_timeout_ms = 40000;

	uint32_t my_stats_interval_ms = 0;
	uint32_t my_dev_delay_read_ms = 0;
	uint32_t my_dev_delay_write_ms = 0;
	uint32_t my_dev_delay_qdir_ms = 0;

	uint32_t durable_log_max_record = 0x10000;

	std::tuple<uint8_t, uint8_t, uint16_t> my_nbt_version{10, 0, 17763};

	std::string log_name = "stderr";
	uint64_t log_file_size = 2048 * 1024;
	std::string netbios_name_l8, workgroup_8, dns_domain_l8, realm;
	std::shared_ptr<std::u16string> netbios_name_u16, workgroup_u16, dns_domain_l16;
	std::string private_dir, lib_dir;
	std::string samba_locks_dir;
	std::vector<std::string> interfaces;
	std::shared_ptr<const std::vector<x_iface_t>> local_ifaces;

	std::vector<uint16_t> dialects{0x311, 0x302, 0x300, 0x210, 0x202};
	std::string node;
	std::vector<x_smbd_node_t> nodes;
	std::vector<std::shared_ptr<x_smbd_volume_t>> smbd_volumes;
	std::vector<std::shared_ptr<x_smbd_share_t>> smbd_shares;

	std::vector<std::unique_ptr<x_smbd_share_spec_t>> share_specs;
	std::vector<std::unique_ptr<x_smbd_volume_spec_t>> volume_specs;

	x_smbd_secrets_t secrets;
	x_smbd_group_mapping_t *group_mapping;
};

int x_smbd_conf_init(const char *configfile, const std::vector<std::string> &cmdline_options);
int x_smbd_conf_reload();
std::shared_ptr<x_smbd_conf_t> x_smbd_conf_get();
std::pair<std::shared_ptr<x_smbd_share_t>, std::shared_ptr<x_smbd_volume_t>>
x_smbd_resolve_share(const char16_t *in_share_s, const char16_t *in_share_e);

std::shared_ptr<x_smbd_share_t>
x_smbd_find_share(const x_smbd_conf_t &smbd_conf, const x_smb2_uuid_t &uuid);
std::shared_ptr<x_smbd_share_t> x_smbd_find_share(const x_smbd_conf_t &smbd_conf,
		const char16_t *in_share_s, const char16_t *in_share_e);
static inline std::shared_ptr<x_smbd_share_t> x_smbd_find_share(
		const x_smbd_conf_t &smbd_conf,
		const std::u16string &share_name)
{
	return x_smbd_find_share(smbd_conf, share_name.data(), share_name.data() + share_name.size());
}

std::shared_ptr<x_smbd_volume_t> x_smbd_find_volume(const x_smbd_conf_t &smbd_conf,
		const x_smb2_uuid_t &volume_uuid);

extern thread_local std::shared_ptr<x_smbd_conf_t> x_smbd_conf_curr;
extern thread_local int x_smbd_conf_curr_count;

static inline const x_smbd_conf_t &x_smbd_conf_get_curr()
{
	X_ASSERT(x_smbd_conf_curr);
	return *x_smbd_conf_curr;
}

struct x_smbd_conf_pin_t
{
	x_smbd_conf_pin_t();
	~x_smbd_conf_pin_t() {
		X_ASSERT(x_smbd_conf_curr);
		X_ASSERT(x_smbd_conf_curr_count > 0);
		if (--x_smbd_conf_curr_count == 0) {
			x_smbd_conf_curr = nullptr;
		}
	}
};

int x_smbd_init_shares(x_smbd_conf_t &smbd_conf);

/* return nullptr if it is local, other pointer to node name */
const std::string *x_smbd_volume_is_remote(const x_smbd_conf_t &smbd_conf, uint64_t volume_id);


#endif /* __smbconf__hxx__ */

