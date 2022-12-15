
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
	static const uint32_t default_dfs_referral_ttl = 300;

	share_spec_t(const std::string &name) : name(name) { }
	std::string name;
	bool read_only = false;
	bool abe = false;
	bool dfs_test = false;
	uint32_t dfs_referral_ttl = default_dfs_referral_ttl;
	std::vector<std::string> volumes;
};

struct volume_spec_t
{
	volume_spec_t(std::string &&name, std::string &&path, std::string &&node)
		: name(name), path(path), owner_node(node)
	{
	}

	const std::string name, path;
	const std::string owner_node;
	std::string owner_share; // dfs share use the whole volume,
				// so they cannot share the volume
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

/* unlike str_list_make_v3, we suppose the config file is utf8 */
static std::vector<std::string> split_string(const std::string &str)
{
	std::vector<std::string> ret;
	const char *s = str.c_str();
	while (*s) {
		if (*s == ' ' || *s == '\t') {
			++s;
			continue;
		}
		const char *p = strpbrk(s, " \t");
		if (!p) {
			ret.emplace_back(s);
			break;
		}
		ret.emplace_back(s, p);
		s = p + 1;
	}
	return ret;
}

static std::vector<std::string> parse_stringlist(const std::string &str)
{
	return split_string(str);
}

static bool parse_volume_map(std::vector<volume_spec_t> &volumes, const std::string &str)
{
	for (auto &token: split_string(str)) {
		auto sep = token.find(':');
		if (sep == std::string::npos) {
			return false;
		}
		std::string volume = token.substr(0, sep);
		++sep;
		auto sep2 = token.find(':', sep);
		if (sep2 == std::string::npos) {
			return false;
		}
		std::string node = token.substr(sep, sep2 - sep);
		std::string path = token.substr(sep2 + 1);

		volumes.emplace_back(std::move(volume),
				token.substr(sep2 + 1),
				token.substr(sep, sep2 - sep));
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

static const std::shared_ptr<x_smbd_volume_t> smbd_volume_find(
		const x_smbd_conf_t &smbd_conf,
		const std::string volume_name)
{
	for (auto &volume: smbd_conf.volumes) {
		if (volume->name == volume_name) {
			return volume;
		}
	}
	return nullptr;
}

static void add_share(x_smbd_conf_t &smbd_conf,
		const std::shared_ptr<x_smbd_share_t> &smbd_share)
{
	X_LOG_DBG("add share section %s", smbd_share->name.c_str());
	smbd_conf.shares[smbd_share->name] = smbd_share;
}

static void add_share(x_smbd_conf_t &smbd_conf,
		const share_spec_t &share_spec)
{
	std::shared_ptr<x_smbd_share_t> share;
	if (false) {
	} else if (share_spec.volumes.size() > 1) {
		std::vector<std::shared_ptr<x_smbd_volume_t>> volumes;
		for (auto &vn: share_spec.volumes) {
			auto smbd_volume = smbd_volume_find(smbd_conf,
					vn);
			X_ASSERT(smbd_volume);
			volumes.push_back(std::move(smbd_volume));
		}
		share = x_smbd_dfs_share_create(smbd_conf, share_spec.name,
				share_spec.abe,
				volumes);
	} else {
		auto smbd_volume = smbd_volume_find(smbd_conf,
				share_spec.volumes[0]);
		X_ASSERT(smbd_volume);
		share = x_smbd_simplefs_share_create(share_spec.name,
				share_spec.abe,
				smbd_volume);
	}
	share->dfs_referral_ttl = share_spec.dfs_referral_ttl;
	add_share(smbd_conf, share);
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
		std::vector<volume_spec_t> &volume_specs,
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
	} else if (name == "server signing") {
		if (value == "mandatory") {
			smbd_conf.security_mode |= X_SMB2_NEGOTIATE_SIGNING_REQUIRED;
		}
	} else if (name == "smb2 max credits") {
		return parse_uint32(value, smbd_conf.smb2_max_credits);
	} else if (name == "private dir") {
		smbd_conf.private_dir = value;
	} else if (name == "node") {
		smbd_conf.node = value;
	} else if (name == "max session expiration") {
		return parse_uint32(value, smbd_conf.max_session_expiration);
	} else if (name == "my:samba locks dir") {
		smbd_conf.samba_locks_dir = value;
	} else if (name == "my:nodes") {
		smbd_conf.nodes = parse_stringlist(value);
	} else if (name == "my:volume map") {
		return parse_volume_map(volume_specs, value);
	} else if (name == "interfaces") {
		smbd_conf.interfaces = parse_stringlist(value);
	} else if (name == "server multi channel support") {
		bool server_multi_channel_support = parse_bool(value);
		if (server_multi_channel_support) {
			smbd_conf.capabilities |= X_SMB2_CAP_MULTI_CHANNEL;
		} else {
			smbd_conf.capabilities &= ~X_SMB2_CAP_MULTI_CHANNEL;
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
	} else if (name == "dfs referral ttl") {
		return parse_uint32(value, share_spec.dfs_referral_ttl);
	} else if (name == "hide unreadable") {
		if (value == "yes") {
			share_spec.abe = true;
		} else if (value == "no") {
			share_spec.abe = false;
		} else {
			X_PANIC("Unexpected boolean %s at %s:%u",
					value.c_str(), path, lineno);
		}
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

static void parse_line(x_smbd_conf_t &smbd_conf,
		std::vector<std::unique_ptr<share_spec_t>> &share_specs,
		std::unique_ptr<share_spec_t> &share_spec,
		std::vector<volume_spec_t> &volume_specs,
		std::string &line,
		const char *path, unsigned int lineno)
{
	size_t pos = skip(line, 0, line.length());
	if (pos == line.length() || line.compare(pos, 1, "#") == 0) {
		return;
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
			parse_global_param(smbd_conf, volume_specs, name, value);
		}
	}
}

static std::string get_samba_path(const std::string &config_path)
{
	auto sep = config_path.rfind('/');
	X_ASSERT(sep != std::string::npos);
	X_ASSERT(sep > 0);
	sep = config_path.rfind('/', sep - 1);
	X_ASSERT(sep != std::string::npos);
	return config_path.substr(0, sep);
}

static volume_spec_t *find_volume_spec(std::vector<volume_spec_t> &volume_specs,
		const std::string &volume_name)
{
	for (auto &vs: volume_specs) {
		if (vs.name == volume_name) {
			return &vs;
		}
	}
	return nullptr;
}

static int parse_smbconf(x_smbd_conf_t &smbd_conf, const char *path,
		const std::vector<std::string> &cmdline_options)
{
	X_LOG_DBG("Loading smbd_conf from %s", path);

	std::vector<std::unique_ptr<share_spec_t>> share_specs;
	std::vector<volume_spec_t> volume_specs;
	std::unique_ptr<share_spec_t> share_spec;

	smbd_conf.capabilities = X_SMB2_CAP_DFS | X_SMB2_CAP_LARGE_MTU | X_SMB2_CAP_LEASING
		| X_SMB2_CAP_DIRECTORY_LEASING | X_SMB2_CAP_MULTI_CHANNEL;

	std::string line, last_line;
	std::ifstream in(path);

	auto samba_path = get_samba_path(path);
	smbd_conf.private_dir = samba_path + "/private";
	smbd_conf.samba_locks_dir = samba_path + "/var/locks";

	unsigned int lineno = 0;
	while (std::getline(in, line)) {
		++lineno;
		auto length = line.length();
		bool end_with_slash = false;
		if (length > 0 && line[length - 1] == '\\') {
			end_with_slash = true;
			line[length - 1] = ' ';
		}
		if (last_line.length()) {
			last_line += line;
		} else {
			last_line = std::move(line);
		}

		if (end_with_slash) {
			continue;
		}
		parse_line(smbd_conf, share_specs, share_spec, volume_specs,
				last_line, path, lineno);
		last_line.clear();
	}

	if (last_line.length()) {
		parse_line(smbd_conf, share_specs, share_spec, volume_specs,
				last_line, path, lineno);
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
		parse_global_param(smbd_conf, volume_specs, name, value);
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

	smbd_conf.realm = x_str_toupper(smbd_conf.realm);

	load_ifaces(smbd_conf);

	for (auto &ss: share_specs) {
		X_ASSERT(!ss->volumes.empty());
		for (auto &volume_name: ss->volumes) {
			volume_spec_t *vs = find_volume_spec(volume_specs, volume_name);
			if (!vs) {
				X_LOG_ERR("cannot find volume %s for share %s",
						volume_name.c_str(),
						ss->name.c_str());
				return -1;
			}
			if (!vs->owner_share.empty()) {
				X_LOG_ERR("share %s cannot own volume %s, "
						"already used by %s",
						ss->name.c_str(),
						volume_name.c_str(),
						vs->owner_share.c_str());
				return -1;
			}
			vs->owner_share = ss->name;
		}
	}

	for (auto &vs: volume_specs) {
		smbd_conf.volumes.push_back(x_smbd_volume_create(vs.name,
					vs.path, vs.owner_node, vs.owner_share));
	}

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
			auto smbd_volume = smbd_volume_find(*smbd_conf, vol_tmp);
			if (!smbd_volume && smbd_volume->owner_share.empty()) {
				return nullptr;
			}
			auto it = smbd_conf->shares.find(smbd_volume->owner_share);
			if (it == smbd_conf->shares.end()) {
				return nullptr;
			}
			volume = std::move(vol_tmp);
			return it->second;
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
}


