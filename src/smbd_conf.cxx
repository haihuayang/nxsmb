
#include "smbd.hxx"
#include "smbd_conf.hxx"
#include <fstream>
#include <fcntl.h>
#include <unistd.h>

#define PARSE_FATAL(fmt, ...) do { \
	X_PANIC(fmt "\n", __VA_ARGS__); \
} while (0)

struct share_spec_t
{
	share_spec_t(const std::string &name) : name(name) { }
	std::string name;
	std::string my_distribute_root;
	std::vector<std::string> my_distribute_vgs;
	std::string path;
	bool read_only = false;
	bool abe = false;
	bool dfs_test = false;
	uint32_t max_referral_ttl = 300;
	std::vector<std::string> volumes;
};

static std::shared_ptr<x_smbd_conf_t> g_smbd_conf;
#if 0
static int hex(char c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	} else if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	} else if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	} else {
		return -1;
	}
}

static int parse_uuid(const std::string &str, uuid_t &uuid)
{
	if (str.size() != 36) {
		return -1;
	}
	const char *p = str.c_str();

	for (auto &uv: uuid) {
		if (*p == '-') {
			++p;
		}
		int val = hex(*p);
		if (val < 0) {
			return -1;
		}
		++p;
		int val2 = hex(*p);
		if (val2 < 0) {
			return -1;
		}
		uv = uint8_t((val << 4) | val2);
	}
	return 0;
}
#endif
static bool parse_bool(const std::string &str)
{
	return str == "yes";
}

static bool parse_uint32(const std::string &str, uint32_t &ret)
{
	char *end;
	unsigned long val = strtoul(str.c_str(), &end, 0);
	if (*end) {
	       return false;
	}
	uint32_t v = uint32_t(val);
	if (v != val) {
		return false;
	}
	ret = v;
	return true;
}

static std::vector<std::string> parse_stringlist(const std::string &str)
{
	std::vector<std::string> ret;
	std::istringstream is(str);
	std::string token;
	while (std::getline(is, token, ' ')) {
		ret.push_back(token);
	}
	return ret;
}

static bool parse_volume_map(std::map<std::string, std::pair<std::string, std::shared_ptr<x_smbd_share_t>>> &map, const std::string &str)
{
	std::istringstream is(str);
	std::string token;
	while (std::getline(is, token, ' ')) {
		auto sep = token.find(':');
		if (sep == std::string::npos) {
			return false;
		}
		std::string volume = token.substr(0, sep);
		std::string node = token.substr(sep + 1);
		map[volume] = std::make_pair<std::string, std::shared_ptr<x_smbd_share_t>>(std::move(node), nullptr);
	}
	return true;
}

static std::string::size_type skip(const std::string &s, std::string::size_type pos, std::string::size_type end)
{
	for ( ; pos < end && isspace(s[pos]); ++pos) {
	}
	return pos;
}

static std::string::size_type rskip(const std::string &s, std::string::size_type pos, std::string::size_type end)
{
	--pos;
	for ( ; pos > end && isspace(s[pos]); --pos) {
	}
	return pos + 1;
}

static void add_share(x_smbd_conf_t &smbd_conf,
		const std::shared_ptr<x_smbd_share_t> &smbd_share)
{
	X_LOG_DBG("add share section %s", smbd_share->name.c_str());
	smbd_conf.shares[smbd_share->name] = smbd_share;
#if 0
	if (share_spec->type == TYPE_IPC) {

	} else if (share_spec->my_distribute_root.size() > 0) {
		/* dfs namespace */
	} else {
		/* TODO if the share is hosted by this node */
		int fd = open(share_spec->path.c_str(), O_RDONLY);
		X_ASSERT(fd != -1);
		auto topdir = std::make_shared<x_smbd_topdir_t>(share_spec);
		topdir->fd = fd;
		share_spec->root_dir = topdir; /* TODO cycle reference  */
	}
#endif
}

static void add_share(x_smbd_conf_t &smbd_conf,
		const share_spec_t &share_spec)
{
	if (false) {
	} else if (share_spec.volumes.size() > 0) {
		auto share = x_smbd_dfs_share_create(smbd_conf, share_spec.name, share_spec.volumes);
		for (const auto &v: share_spec.volumes) {
			auto it = smbd_conf.volume_map.find(v);
			X_ASSERT(it != smbd_conf.volume_map.end());
			X_ASSERT(!it->second.second);
			it->second.second = share;
		}

		add_share(smbd_conf, share);
#if 0
	} else if (share_spec.my_distribute_vgs.size() > 0) {
		X_ASSERT(share_spec.path.size() > 0);
		add_share(smbd_conf, x_smbd_dfs_root_create(share_spec.name, share_spec.path, share_spec.my_distribute_vgs));
#endif
	} else {
		X_ASSERT(share_spec.path.size() > 0);
		add_share(smbd_conf, x_smbd_simplefs_share_create(share_spec.name, share_spec.path));
	}
}

static void load_ifaces(x_smbd_conf_t &smbd_conf)
{
	std::vector<x_iface_t> probed_ifaces;

	/* Probe the kernel for interfaces */
	int err = x_probe_ifaces(probed_ifaces);
	X_ASSERT(!err);
	X_ASSERT(probed_ifaces.size() > 0);

	/* if we don't have a interfaces line then use all broadcast capable
	   interfaces except loopback */
	if (smbd_conf.interfaces.size() == 0) {
#if 0
		for (i=0;i<total_probed;i++) {
			if (probed_ifaces[i].flags & IFF_BROADCAST) {
				add_interface(&probed_ifaces[i]);
			}
		}
#endif
		smbd_conf.local_ifaces = probed_ifaces;
		return;
	}

	std::vector<x_iface_t> ret_ifaces;
	for (auto const &iface_name: smbd_conf.interfaces) {
		x_interpret_iface(ret_ifaces, iface_name, probed_ifaces);
	}

	if (ret_ifaces.size() == 0) {
		X_LOG_ERR("WARNING: no network interfaces found");
	}
	smbd_conf.local_ifaces = ret_ifaces;
}

static bool parse_log_level(const std::string &value, unsigned int &loglevel)
{
	uint32_t ll;
	if (!parse_uint32(value, ll)) {
		return false;
	}
	if (ll > 10) {
		loglevel = X_LOG_LEVEL_VERB;
	} else if (ll > 5) {
		loglevel = X_LOG_LEVEL_DBG;
	} else if (ll > 3) {
		loglevel = X_LOG_LEVEL_OP;
	} else if (ll > 1) {
		loglevel = X_LOG_LEVEL_NOTICE;
	} else if (ll > 0) {
		loglevel = X_LOG_LEVEL_WARN;
	} else {
		loglevel = X_LOG_LEVEL_ERR;
	}
	return true;
}

static bool parse_global_param(x_smbd_conf_t &smbd_conf,
		const std::string &name, const std::string &value)
{
	// global parameters
	if (name == "log level") {
		return parse_log_level(value, smbd_conf.log_level);
	} else if (name == "log name") {
		smbd_conf.log_name = value;
	} else if (name == "client thread count") {
		return parse_uint32(value, smbd_conf.client_thread_count);
	} else if (name == "async thread count") {
		return parse_uint32(value, smbd_conf.async_thread_count);
	} else if (name == "netbios name") {
		smbd_conf.netbios_name = value;
	} else if (name == "dns domain") {
		smbd_conf.dns_domain = value;
	} else if (name == "realm") {
		smbd_conf.realm = value;
	} else if (name == "workgroup") {
		smbd_conf.workgroup = value;
	} else if (name == "lanman auth") {
		smbd_conf.lanman_auth = parse_bool(value);
	} else if (name == "smb2 max credits") {
		return parse_uint32(value, smbd_conf.smb2_max_credits);
	} else if (name == "private dir") {
		smbd_conf.private_dir = value;
	} else if (name == "node") {
		smbd_conf.node = value;
	} else if (name == "my:nodes") {
		smbd_conf.nodes = parse_stringlist(value);
	} else if (name == "my:volume map") {
		return parse_volume_map(smbd_conf.volume_map, value);
	} else if (name == "interfaces") {
		smbd_conf.interfaces = parse_stringlist(value);
	} else if (name == "server multi channel support") {
		bool server_multi_channel_support = parse_bool(value);
		if (server_multi_channel_support) {
			smbd_conf.capabilities |= SMB2_CAP_MULTI_CHANNEL;
		} else {
			smbd_conf.capabilities &= ~SMB2_CAP_MULTI_CHANNEL;
		}
	} else {
		X_LOG_WARN("unknown global param '%s' with value '%s'",
				name.c_str(), value.c_str());
		return false;
	}
	return true;
}

static bool parse_share_param(share_spec_t &share_spec,
		const std::string &name, const std::string &value,
		const char *path, unsigned int lineno)
{
	if (false) {
#if 0
	} else if (name == "type") {
		/* TODO not support distribute share for now */
		if (false && value == "HOME_SHARE") {
			smbd_share.type = TYPE_HOME;
		} else if (value == "DEFAULT_SHARE") {
			smbd_share.type = TYPE_DEFAULT;
		} else {
			X_PANIC("Unknown share type %s",
					value.c_str());
		}
	} else if (name == "uuid") {
		uuid_t uuid;
		int ret = parse_uuid(value, uuid);
		if (ret < 0) {
			X_PANIC("Invalid uuid %s", value.c_str());
		}
		smbd_share.uuid = uuid;
	} else if (name == "msdfs proxy") {
		smbd_share.msdfs_proxy = value;
#endif
	} else if (name == "path") {
		share_spec.path = value;
	} else if (name == "abe") {
		if (value == "yes") {
			share_spec.abe = true;
		} else if (value == "no") {
			share_spec.abe = false;
		} else {
			X_PANIC("Unexpected boolean %s at %s:%u",
					value.c_str(), path, lineno);
		}
	} else if (name == "my distribute root") {
		share_spec.my_distribute_root = value;
	} else if (name == "my distribute vgs") {
		share_spec.my_distribute_vgs = parse_stringlist(value);
	} else if (name == "read only") {
		share_spec.read_only = parse_bool(value);
	} else if (name == "my:volumes") {
		share_spec.volumes = parse_stringlist(value);
	} else if (name == "dfs test") {
		share_spec.dfs_test = parse_bool(value);
	} else {
		X_LOG_WARN("unknown share param '%s' with value '%s'",
				name.c_str(), value.c_str());
		return false;
	}
	return true;
}

static bool split_option(const std::string opt, size_t pos,
		std::string &name, std::string &value)
{
	auto sep = opt.find('=', pos);
	if (sep == std::string::npos) {
		return false;
	}
	name = opt.substr(pos, rskip(opt, sep, pos) - pos);

	pos = skip(opt, sep + 1, opt.length());
	value = opt.substr(pos, rskip(opt, opt.length(), pos) - pos);
	return true;
}

static int parse_smbconf(x_smbd_conf_t &smbd_conf, const char *path,
		const std::vector<std::string> &cmdline_options)
{
	X_LOG_DBG("Loading smbd_conf from %s", path);

	std::vector<std::unique_ptr<share_spec_t>> share_specs;
	std::unique_ptr<share_spec_t> share_spec;

	smbd_conf.capabilities = SMB2_CAP_DFS | SMB2_CAP_LARGE_MTU | SMB2_CAP_LEASING
		| SMB2_CAP_DIRECTORY_LEASING | SMB2_CAP_MULTI_CHANNEL;

	std::string line;
	std::ifstream in(path);
	unsigned int lineno = 0;
	while (std::getline(in, line)) {
		++lineno;
		size_t pos = skip(line, 0, line.length());;
		if (pos == line.length() || line.compare(pos, 1, "#") == 0) {
			continue;
		}
		if (line[pos] == '[') {
			auto end = line.find(']', pos + 1);
			if (end == std::string::npos) {
				X_PANIC("Parsing error at %s:%u",
						path, lineno);
			}
			std::string section = line.substr(pos + 1, end - pos - 1);
			if (share_spec) {
				share_specs.push_back(std::move(share_spec));
				share_spec = nullptr;
			}
			if (section != "global") {
				share_spec.reset(new share_spec_t(section));
			}
		} else {
			std::string name, value;
			if (!split_option(line, pos, name, value)) {
				X_PANIC("No '=' at %s:%u",
						path, lineno);
			}

			if (share_spec) {
				parse_share_param(*share_spec, name, value, path, lineno);
			} else {
				parse_global_param(smbd_conf, name, value);
			}
		}
	}
	if (share_spec) {
		share_specs.push_back(std::move(share_spec));
	}

	// override global params by argv
	for (auto &opt: cmdline_options) {
		size_t pos = skip(opt, 0, opt.length());;
		if (pos == opt.length() || opt.compare(pos, 1, "#") == 0) {
			continue;
		}
		std::string name, value;
		if (!split_option(opt, pos, name, value)) {
			X_PANIC("No '=' at argv %s",
					opt.c_str());
		}
		parse_global_param(smbd_conf, name, value);
	}

	smbd_conf.security_mode = SMB2_NEGOTIATE_SIGNING_ENABLED;
	if (false /* signing_required*/) {
		smbd_conf.security_mode |= SMB2_NEGOTIATE_SIGNING_REQUIRED;
	}

	if (smbd_conf.node.empty()) {
		char hostname[1024];
		int err = gethostname(hostname, sizeof hostname);
		X_ASSERT(err == 0);
		char *sep = strchr(hostname, '.');
		if (sep) {
			smbd_conf.node.assign(hostname, sep);
		} else {
			smbd_conf.node = hostname;
		}
	}

	if (smbd_conf.dns_domain.empty()) {
		smbd_conf.dns_domain = smbd_conf.realm;
	}

	/* TODO utf8 */
	for (auto &c: smbd_conf.realm) {
		c = x_convert_assert<char>(std::toupper(c));
	}

	load_ifaces(smbd_conf);

	for (auto &ss: share_specs) {
		add_share(smbd_conf, *ss);
	}
	add_share(smbd_conf, x_smbd_ipc_share_create());
	return 0;
}

std::shared_ptr<x_smbd_conf_t> x_smbd_conf_get()
{
	return g_smbd_conf;
}

std::shared_ptr<x_smbd_share_t> x_smbd_find_share(const std::string &name,
		std::string &volume)
{
	auto smbd_conf = x_smbd_conf_get();
	const char *in_share_s = name.c_str();
	if (*in_share_s == '-') {
		++in_share_s;
		if (*in_share_s == '-') {
			std::string vol_tmp = in_share_s + 1;
			auto it = smbd_conf->volume_map.find(vol_tmp);
			if (it == smbd_conf->volume_map.end()) {
				return nullptr;
			}
			volume = std::move(vol_tmp);
			return it->second.second;
		}
	}

	auto it = smbd_conf->shares.find(in_share_s);
	if (it == smbd_conf->shares.end()) {
		return nullptr;
	}

	if (in_share_s != name.c_str()) {
		volume = "-";
	}
	return it->second;

	/* TODO USER_SHARE */
}

int x_smbd_conf_parse(const char *configfile, const std::vector<std::string> &cmdline_options)
{
	auto ret = std::make_shared<x_smbd_conf_t>();
	int err = parse_smbconf(*ret, configfile, cmdline_options);
	if (err < 0) {
		return err;
	}

	g_smbd_conf = ret;
	return 0;
}

x_smbd_conf_t::x_smbd_conf_t()
{
	strcpy((char *)&guid, "nxsmbd");
	// private_dir = "/var/lib/samba/private";
	private_dir = "/usr/local/samba/private";
}


