
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
#include <map>
#include <atomic>

static inline bool lpcfg_param_bool(void *service, const char *type, const char *option, bool default_v)
{
	return default_v;
}

static constexpr uint32_t X_INFINITE = -1;

struct x_smbd_conf_t
{
	x_smbd_conf_t();

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
	int port = 445;
	uint32_t client_thread_count = 1;
	uint32_t async_thread_count = 1;

	uint32_t capacities = 0;
	uint32_t max_trans_size = 1024 * 1024;
	uint32_t max_read_size = 1024 * 1024;
	uint32_t max_write_size = 1024 * 1024;

	uint32_t capabilities;
	uint16_t security_mode = X_SMB2_NEGOTIATE_SIGNING_ENABLED;
	bool lanman_auth = false;
	bool allow_trusted_domains = true;
	bool gensec_require_pac = false; // if (gensec_setting_bool(gensec_security->settings, "gensec", "require_pac", false)) {
	uint32_t max_session_expiration = X_INFINITE; // in seconds

	uint32_t smb2_max_credits = 8192;
	bool host_msdfs = true;

	unsigned int log_level = X_LOG_LEVEL_DBG;
	uint32_t max_connections = 512;
	uint32_t max_opens = 1024;

	uint32_t my_dev_delay_read_ms = 0;
	uint32_t my_dev_delay_write_ms = 0;
	uint32_t my_dev_delay_qdir_ms = 0;

	std::tuple<uint8_t, uint8_t, uint16_t> my_nbt_version{10, 0, 17763};

	std::string log_name = "stderr";
	std::string netbios_name_l8, workgroup_8, dns_domain_l8, realm;
	std::shared_ptr<std::u16string> netbios_name_u16, workgroup_u16, dns_domain_l16;
	std::string private_dir;
	std::string samba_locks_dir;
	std::vector<std::string> cluster_nodes;
	std::vector<std::string> interfaces;
	std::vector<x_iface_t> local_ifaces;

	std::vector<uint16_t> dialects{0x311, 0x310, 0x302, 0x210, 0x202};
	std::u16string node_l16;
	std::vector<std::string> nodes;
	std::vector<std::shared_ptr<x_smbd_volume_t>> smbd_volumes;
	std::vector<std::shared_ptr<x_smbd_share_t>> smbd_shares;

	x_smbd_secrets_t secrets;
};

int x_smbd_conf_init(const char *configfile, const std::vector<std::string> &cmdline_options);
int x_smbd_conf_reload();
std::shared_ptr<x_smbd_conf_t> x_smbd_conf_get();
std::pair<std::shared_ptr<x_smbd_share_t>, std::shared_ptr<x_smbd_volume_t>>
x_smbd_resolve_share(const char16_t *in_share_s, const char16_t *in_share_e);

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

#endif /* __smbconf__hxx__ */

