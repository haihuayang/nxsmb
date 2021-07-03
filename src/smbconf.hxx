
#ifndef __smbconf__hxx__
#define __smbconf__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/librpc/misc.hxx"

static inline bool lpcfg_param_bool(void *service, const char *type, const char *option, bool default_v)
{
	return default_v;
}

#if 0
static inline size_t lp_smb2_max_credits()
{
	return 8192;
}

static inline size_t lp_smb2_max_trans()
{
	return 1024 * 1024;
}

static inline size_t lp_smb2_max_read()
{
	return 1024 * 1024;
}

static inline size_t lp_smb2_max_write()
{
	return 1024 * 1024;
}

static inline bool lpcfg_server_signing_required()
{
	return false;
}

static inline const char *lpcfg_netbios_name()
{
	return "HH360U";
}

static inline const char *lpcfg_workgroup()
{
	return "CHILD4";
}

static inline const char *lpcfg_realm()
{
	return "HHDOM2.HHLAB";
}

static inline const char *lpcfg_salt_princ()
{
	return "host/hh360u.hhdom2.hhlab@CHILD4";
}

static inline std::vector<std::string> lpcfg_cluster_nodes()
{
	return std::vector<std::string>{"ntnx-hh360u-1.hhdom2.hhlab"};
}

static inline const char *lpcfg_dns_domain()
{
	return "hhdom2.hhlab";
}

static inline bool lpcfg_gensec_require_pac(bool def)
{
	return true;
}

static inline bool lpcfg_allow_trusted_domains()
{
	return false;
}

static inline bool lpcfg_host_msdfs()
{
	return true;
}

static inline uint32_t lpcfg_max_referral_ttl()
{
	return 300;
}
#endif

enum x_smbshare_type_t {
	TYPE_IPC,
	TYPE_DEFAULT,
	TYPE_HOME,
};

struct x_smbshare_t
{
	x_smbshare_t(const std::string &name) : name(name) { }
	x_smbshare_type_t type = TYPE_DEFAULT;
	bool read_only = false;
	std::string name;
	uuid_t uuid;
	//std::string uuid;
	std::string path;
	std::string msdfs_proxy;
	bool abe = false;
	uint32_t max_referral_ttl = 300;

	bool is_msdfs_root() const {
		// TODO
		return false && type != TYPE_IPC;
	}
	bool abe_enabled() const {
		// TODO
		return false;
	}
};

struct x_smbconf_t
{
	x_smbconf_t() {
		strcpy((char *)guid, "nxsmbd");
	}

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

	uint8_t guid[16];
	int port = 445;
	int backend_port = 446;
	uint32_t thread_count = 1;

	size_t max_trans = 1024 * 1024;
	size_t max_read = 1024 * 1024;
	size_t max_write = 1024 * 1024;

	bool signing_required = false;
	bool lanman_auth = false;
	bool allow_trusted_domains = true;
	bool gensec_require_pac = false; // if (gensec_setting_bool(gensec_security->settings, "gensec", "require_pac", false)) {

	uint32_t max_referral_ttl = 300;
	uint32_t smb2_max_credits = 8192;
	bool host_msdfs = true;
	std::string netbios_name, workgroup, dns_domain, realm;
	std::vector<std::string> cluster_nodes;

	std::vector<uint16_t> dialects{0x311, 0x310, 0x302, 0x210, 0x202};
	std::map<std::string, std::shared_ptr<x_smbshare_t>> shares;
};


#endif /* __smbconf__hxx__ */

