
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
#include <map>
#include <atomic>

static inline bool lpcfg_param_bool(void *service, const char *type, const char *option, bool default_v)
{
	return default_v;
}

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
	uint16_t security_mode = SMB2_NEGOTIATE_SIGNING_ENABLED;
	bool lanman_auth = false;
	bool allow_trusted_domains = true;
	bool gensec_require_pac = false; // if (gensec_setting_bool(gensec_security->settings, "gensec", "require_pac", false)) {

	uint32_t max_referral_ttl = 300;
	uint32_t smb2_max_credits = 8192;
	bool host_msdfs = true;

	unsigned int log_level = X_LOG_LEVEL_DBG;
	std::string log_name = "stderr";
	std::string netbios_name, workgroup, dns_domain, realm;
	std::string private_dir;
	std::string samba_locks_dir;
	std::vector<std::string> cluster_nodes;
	std::vector<std::string> interfaces;
	std::vector<x_iface_t> local_ifaces;

	std::vector<uint16_t> dialects{0x311, 0x310, 0x302, 0x210, 0x202};
	std::map<std::string, std::shared_ptr<x_smbd_share_t>> shares;
	std::string node;
	std::vector<std::string> nodes;
	std::string volume_dir;
	std::map<std::string, std::pair<std::string, std::shared_ptr<x_smbd_share_t>>> volume_map;
};

int x_smbd_conf_parse(const char *configfile, const std::vector<std::string> &cmdline_options);
std::shared_ptr<x_smbd_conf_t> x_smbd_conf_get();
std::shared_ptr<x_smbd_share_t> x_smbd_find_share(const std::string &name, std::string &volume);

#endif /* __smbconf__hxx__ */

