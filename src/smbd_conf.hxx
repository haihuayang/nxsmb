
#ifndef __smbconf__hxx__
#define __smbconf__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "defines.hxx"
#include "include/utils.hxx"
#include "include/networking.hxx"
#include "include/librpc/misc.hxx"
#include <map>
#include <atomic>

static inline bool lpcfg_param_bool(void *service, const char *type, const char *option, bool default_v)
{
	return default_v;
}

enum x_smbd_share_type_t {
	TYPE_IPC,
	TYPE_DEFAULT,
	TYPE_HOME,
};

struct x_smbd_topdir_t;

struct x_smbd_share_t
{
	x_smbd_share_t(const std::string &name) : name(name) { }
	x_smbd_share_type_t type = TYPE_DEFAULT;
	bool read_only = false;
	std::string name;
	uuid_t uuid;
	//std::string uuid;
	std::string path;
	bool abe = false;
	bool nt_acl_support = true;
	uint32_t max_referral_ttl = 300;
	uint32_t max_connections = 0;

	std::shared_ptr<x_smbd_topdir_t> root_dir;
	std::string msdfs_proxy;
#if 0
	bool is_msdfs_root() const {
		// TODO
		return false && type != TYPE_IPC;
	}
#endif
	bool abe_enabled() const {
		// TODO
		return false;
	}
};

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

	uint8_t guid[16];
	int port = 445;
	int backend_port = 446;
	uint32_t thread_count = 1;

	uint32_t capacities = 0;
	size_t max_trans = 1024 * 1024;
	size_t max_read = 1024 * 1024;
	size_t max_write = 1024 * 1024;

	uint32_t capabilities;
	uint16_t security_mode;
	bool signing_required = false;
	bool lanman_auth = false;
	bool allow_trusted_domains = true;
	bool gensec_require_pac = false; // if (gensec_setting_bool(gensec_security->settings, "gensec", "require_pac", false)) {

	uint32_t max_referral_ttl = 300;
	uint32_t smb2_max_credits = 8192;
	bool host_msdfs = true;
	std::string netbios_name, workgroup, dns_domain, realm;
	std::string private_dir;
	std::vector<std::string> cluster_nodes;
	std::vector<std::string> interfaces;
	std::vector<x_iface_t> local_ifaces;

	std::vector<uint16_t> dialects{0x311, 0x310, 0x302, 0x210, 0x202};
	std::map<std::string, std::shared_ptr<x_smbd_share_t>> shares;
};

struct x_smbd_topdir_t
{
	x_smbd_topdir_t(std::shared_ptr<x_smbd_share_t> &s)
		: smbd_share(s) { }
	const std::shared_ptr<x_smbd_share_t> smbd_share;
	int fd = -1;
	std::atomic<uint32_t> watch_tree_cnt{0};
};

int x_smbd_conf_parse(int argc, char **argv);
std::shared_ptr<x_smbd_conf_t> x_smbd_conf_get();
std::shared_ptr<x_smbd_share_t> x_smbd_find_share(const std::string &name);

#endif /* __smbconf__hxx__ */

