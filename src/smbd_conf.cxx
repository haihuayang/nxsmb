
#include "smbd.hxx"
#include "smbd_conf.hxx"
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include <uuid/uuid.h>

#define PARSE_FATAL(fmt, ...) do { \
	X_PANIC(fmt "\n", __VA_ARGS__); \
} while (0)

struct share_spec_t
{
	static const uint32_t default_dfs_referral_ttl = 300;

	share_spec_t(const std::string &name) : name(name) { }

	x_smb2_uuid_t uuid;
	const std::string name;
	uint32_t share_flags = x_smbd_share_t::f_durable_handle;
	bool dfs_test = false;
	uint32_t dfs_referral_ttl = default_dfs_referral_ttl;
	std::vector<x_smb2_uuid_t> volumes;
};

struct volume_spec_t
{
	volume_spec_t(const x_smb2_uuid_t &uuid,
			std::string &&name_8,
			std::u16string &&name_l16,
			std::u16string &&node_l16,
			std::string &&path)
		: uuid(uuid), name_8(name_8), name_l16(name_l16)
		, owner_node_l16(node_l16), path(path)
	{
	}

	const x_smb2_uuid_t uuid;
	const std::string name_8;
	const std::u16string name_l16;
	const std::u16string owner_node_l16;
	const std::string path;
};

static const char *g_configfile;
static std::vector<std::pair<std::string, std::string>> g_cmdline_options;
static std::shared_ptr<x_smbd_conf_t> g_smbd_conf;

static bool parse_uuid(x_smb2_uuid_t &uuid, const std::string &str)
{
	uuid_t tmp;
	int err = uuid_parse(str.c_str(), tmp);
	if (err) {
		return false;
	}
	memcpy(&uuid, tmp, sizeof uuid);
	return true;
}

static bool parse_bool(const std::string &str)
{
	return str == "yes";
}

static bool parse_share_flags(uint32_t &share_flags, uint32_t flag,
		const std::string &value)
{
	if (value == "yes") {
		share_flags |= flag;
	} else if (value == "no") {
		share_flags &= ~flag;
	} else {
		return false;
	}
	return true;
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

static bool parse_uuidlist(std::vector<x_smb2_uuid_t> &uuid_list,
		const std::string &str)
{
	std::vector<x_smb2_uuid_t> ret;
	for (auto s: split_string(str)) {
		x_smb2_uuid_t uuid;
		if (!parse_uuid(uuid, s)) {
			return false;
		}
		ret.push_back(uuid);
	}
	uuid_list.swap(ret);
	return true;
}

static bool parse_volume_map(std::vector<volume_spec_t> &volumes, const std::string &str)
{
	for (auto &token: split_string(str)) {
		auto sep = token.find(':');
		if (sep == std::string::npos) {
			return false;
		}
		std::string uuid_str = token.substr(0, sep);
		x_smb2_uuid_t uuid;
		if (!parse_uuid(uuid, uuid_str)) {
			X_LOG_ERR("invalid uuid '%s'", uuid_str.c_str());
			return false;
		}

		auto begin = ++sep;
		sep = token.find(':', begin);
		if (sep == std::string::npos) {
			return false;
		}
		std::string name = token.substr(begin, sep - begin);
		std::u16string name_l16;
		if (!x_convert_utf8_to_utf16_new(name, name_l16, x_tolower)) {
			X_LOG_ERR("invalid volume name '%s'", name.c_str());
			return false;
		}

		begin = ++sep;
		sep = token.find(':', begin);
		if (sep == std::string::npos) {
			return false;
		}
		std::string node = token.substr(begin, sep - begin);
		std::u16string node_l16;
		if (!x_convert_utf8_to_utf16_new(node, node_l16, x_tolower)) {
			X_LOG_ERR("invalid node name '%s'", node.c_str());
			return false;
		}

		volumes.emplace_back(uuid, std::move(name),
				std::move(name_l16),
				std::move(node_l16),
				token.substr(sep + 1));
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
	std::u16string volume_name_l16;
	if (!x_convert_utf8_to_utf16_new(volume_name, volume_name_l16)) {
		return nullptr;
	}
	for (auto &volume: smbd_conf.smbd_volumes) {
		if (volume->name_l16 == volume_name_l16) {
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

static bool add_share(x_smbd_conf_t &smbd_conf,
		const share_spec_t &share_spec,
		std::vector<std::shared_ptr<x_smbd_volume_t>> &smbd_volumes)
{
	std::u16string name_16;
	if (!x_convert_utf8_to_utf16_new(share_spec.name, name_16)) {
		X_LOG_ERR("Invalid share name '%s'", share_spec.name.c_str());
	}
	std::shared_ptr<x_smbd_share_t> share;
	if (false) {
	} else if (smbd_volumes.size() > 1) {
		share = x_smbd_dfs_share_create(smbd_conf,
				share_spec.uuid,
				share_spec.name,
				std::move(name_16),
				share_spec.share_flags,
				std::move(smbd_volumes));
	} else {
		share = x_smbd_simplefs_share_create(
				share_spec.uuid,
				share_spec.name,
				std::move(name_16),
				share_spec.share_flags,
				smbd_volumes[0]);
	}
	if (!share) {
		X_LOG_ERR("Failed create share '%s'", share_spec.name.c_str());
		return false;
	}

	for (auto &smbd_volume: smbd_volumes) {
		if (smbd_volume->owner_share) {
			X_LOG_ERR("Share '%s' cannot use volume '%s', owned by share '%s'",
					share_spec.name.c_str(),
					smbd_volume->name_8.c_str(),
					smbd_volume->owner_share->name.c_str());
			return false;
		}
		smbd_volume->owner_share = share;
	}

	share->dfs_referral_ttl = share_spec.dfs_referral_ttl;
	add_share(smbd_conf, share);
	return true;
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
	} else if (name == "netbios name") {
		smbd_conf.netbios_name_l8 = value;
	} else if (name == "dns domain") {
		smbd_conf.dns_domain_l8 = value;
	} else if (name == "realm") {
		smbd_conf.realm = value;
	} else if (name == "workgroup") {
		smbd_conf.workgroup_8 = value;
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
		if (!x_convert_utf8_to_utf16_new(value, smbd_conf.node_l16, x_tolower)) {
			X_LOG_ERR("Invalid node '%s'", value.c_str());
		}
	} else if (name == "max session expiration") {
		return parse_uint32(value, smbd_conf.max_session_expiration);
	} else if (name == "interfaces") {
		smbd_conf.interfaces = parse_stringlist(value);
	} else if (name == "server multi channel support") {
		bool server_multi_channel_support = parse_bool(value);
		if (server_multi_channel_support) {
			smbd_conf.capabilities |= X_SMB2_CAP_MULTI_CHANNEL;
		} else {
			smbd_conf.capabilities &= ~X_SMB2_CAP_MULTI_CHANNEL;
		}

	} else if (name == "my:client thread count") {
		return parse_uint32(value, smbd_conf.client_thread_count);
	} else if (name == "my:async thread count") {
		return parse_uint32(value, smbd_conf.async_thread_count);
	} else if (name == "my:max connections") {
		return parse_uint32(value, smbd_conf.max_connections);
	} else if (name == "my:max opens") {
		return parse_uint32(value, smbd_conf.max_opens);
	} else if (name == "my:samba locks dir") {
		smbd_conf.samba_locks_dir = value;
	} else if (name == "my:nodes") {
		smbd_conf.nodes = parse_stringlist(value);
	} else if (name == "my:volume map") {
		return parse_volume_map(volume_specs, value);

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
	} else if (name == "msdfs proxy") {
		smbd_share.msdfs_proxy = value;
#endif
	} else if (name == "dfs referral ttl") {
		return parse_uint32(value, share_spec.dfs_referral_ttl);
	} else if (name == "hide unreadable") {
		if (!parse_share_flags(share_spec.share_flags,
					x_smbd_share_t::f_abe, value)) {
			X_PANIC("Unexpected boolean %s at %s:%u",
					value.c_str(), path, lineno);
		}
	} else if (name == "read only") {
		if (!parse_share_flags(share_spec.share_flags,
					x_smbd_share_t::f_read_only, value)) {
			X_PANIC("Unexpected boolean %s at %s:%u",
					value.c_str(), path, lineno);
		}
	} else if (name == "continuously available") {
		if (!parse_share_flags(share_spec.share_flags,
					x_smbd_share_t::f_continuously_available, value)) {
			X_PANIC("Unexpected boolean %s at %s:%u",
					value.c_str(), path, lineno);
		}
	} else if (name == "my:uuid") {
		if (!parse_uuid(share_spec.uuid, value)) {
			X_PANIC("Share '%s' invalid uuid '%s'",
					share_spec.name.c_str(), value.c_str());
		}
	} else if (name == "my:volumes") {
		if (!parse_uuidlist(share_spec.volumes, value)) {
			X_PANIC("Share '%s' invalid volumes",
					share_spec.name.c_str(), value.c_str());
		}
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

static std::shared_ptr<x_smbd_volume_t> find_volume_by_uuid(
		x_smbd_conf_t &smbd_conf,
		const x_smb2_uuid_t &uuid)
{
	for (auto &smbd_volume: smbd_conf.smbd_volumes) {
		if (smbd_volume->uuid == uuid) {
			return smbd_volume;
		}
	}
	return nullptr;
}

template <class UnaryOp = x_identity_t>
static std::shared_ptr<std::u16string> make_u16string_ptr(const std::string &str,
		UnaryOp &&op = {})
{
	std::u16string ustr;
	if (!x_convert_utf8_to_utf16_new(str, ustr, std::forward<UnaryOp>(op))) {
		return nullptr;
	}
	return std::make_shared<std::u16string>(std::move(ustr));
}

static int parse_smbconf(x_smbd_conf_t &smbd_conf, bool reload)
{
	const char *path = g_configfile;
	X_LOG_DBG("Loading smbd_conf from %s", path);

	std::vector<std::unique_ptr<share_spec_t>> share_specs;
	std::vector<volume_spec_t> volume_specs;
	std::unique_ptr<share_spec_t> share_spec;

	smbd_conf.capabilities = X_SMB2_CAP_DFS | X_SMB2_CAP_LARGE_MTU | X_SMB2_CAP_LEASING
		| X_SMB2_CAP_DIRECTORY_LEASING | X_SMB2_CAP_MULTI_CHANNEL
		| X_SMB2_CAP_ENCRYPTION;

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
	for (const auto &[name, value]: g_cmdline_options) {
		parse_global_param(smbd_conf, volume_specs, name, value);
	}

	if (smbd_conf.node_l16.empty()) {
		char hostname[1024];
		int err = gethostname(hostname, sizeof hostname);
		X_ASSERT(err == 0);
		char *end = hostname;
		while (*end && *end != '.') {
			++end;
		}
		if (!x_convert_utf8_to_utf16_new((char8_t *)hostname, (char8_t *)end, smbd_conf.node_l16,
					x_tolower)) {
			X_LOG_ERR("Invalid hostname '%s'\n", hostname);
		}
	}

	if (smbd_conf.dns_domain_l8.empty()) {
		smbd_conf.dns_domain_l8 = smbd_conf.realm;
	}

	smbd_conf.realm = x_str_toupper(smbd_conf.realm);
	smbd_conf.dns_domain_l8 = x_str_tolower(smbd_conf.dns_domain_l8);
	smbd_conf.dns_domain_l16 = make_u16string_ptr(smbd_conf.dns_domain_l8);
	if (!smbd_conf.dns_domain_l16) {
		X_LOG_ERR("Invalid dns_domain '%s'", smbd_conf.dns_domain_l8.c_str());
		return -1;
	}

	smbd_conf.netbios_name_u16 = make_u16string_ptr(smbd_conf.netbios_name_l8, x_toupper);
	if (!smbd_conf.netbios_name_u16) {
		X_LOG_ERR("Invalid netbios_name '%s'", smbd_conf.netbios_name_l8.c_str());
		return -1;
	}

	smbd_conf.workgroup_u16 = make_u16string_ptr(smbd_conf.workgroup_8, x_toupper);
	if (!smbd_conf.workgroup_u16) {
		X_LOG_ERR("Invalid workgroup '%s'", smbd_conf.workgroup_8.c_str());
		return -1;
	}

	load_ifaces(smbd_conf);

	for (auto &vs: volume_specs) {
		smbd_conf.smbd_volumes.push_back(x_smbd_volume_create(vs.uuid,
				       	vs.name_8, vs.name_l16,
					vs.owner_node_l16, vs.path));
	}

	for (auto &ss: share_specs) {
		X_ASSERT(!ss->volumes.empty());
		std::vector<std::shared_ptr<x_smbd_volume_t>> smbd_volumes;
		for (auto &volume_uuid: ss->volumes) {
			std::shared_ptr<x_smbd_volume_t> smbd_volume = 
				find_volume_by_uuid(smbd_conf, volume_uuid);
			if (!smbd_volume) {
				X_LOG_ERR("cannot find volume %s for share %s",
						smbd_volume->name_8.c_str(),
						ss->name.c_str());
				return -1;
			}
			smbd_volumes.push_back(smbd_volume);
		}
		if (!add_share(smbd_conf, *ss, smbd_volumes)) {
			return -1;
		}
	}

	for (auto &smbd_volume: smbd_conf.smbd_volumes) {
		int err = x_smbd_volume_init(*smbd_volume);
		if (err != 0) {
			return err;
		}
	}

	add_share(smbd_conf, x_smbd_ipc_share_create());
	return 0;
}

std::shared_ptr<x_smbd_conf_t> x_smbd_conf_get()
{
	return g_smbd_conf;
}

std::pair<std::shared_ptr<x_smbd_share_t>, std::shared_ptr<x_smbd_volume_t>>
x_smbd_find_share(const std::string &name)
{
	auto smbd_conf = x_smbd_conf_get();
	const char *in_share_s = name.c_str();
	if (*in_share_s == '-') {
		++in_share_s;
		if (*in_share_s == '-') {
			std::string vol_tmp = in_share_s + 1;
			auto smbd_volume = smbd_volume_find(*smbd_conf, vol_tmp);
			if (!smbd_volume) {
				return {nullptr, nullptr};
			}
			return {smbd_volume->owner_share, smbd_volume};
		}
	}

	auto it = smbd_conf->shares.find(in_share_s);
	if (it == smbd_conf->shares.end()) {
		return {nullptr, nullptr};
	}

	std::shared_ptr<x_smbd_share_t> smbd_share = it->second;
	std::shared_ptr<x_smbd_volume_t> smbd_volume = smbd_share->find_volume(name);
	return {smbd_share, smbd_volume};

	/* TODO USER_SHARE */
}

static int smbd_conf_load(bool reload)
{
	auto ret = std::make_shared<x_smbd_conf_t>();
	int err = parse_smbconf(*ret, false);
	if (err < 0) {
		return err;
	}

	g_smbd_conf = ret;
	return 0;
}

int x_smbd_conf_init(const char *configfile,
		const std::vector<std::string> &cmdline_options)
{
	std::vector<std::pair<std::string, std::string>> pairs;
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
		pairs.emplace_back(std::move(name), std::move(value));
	}
	g_cmdline_options = std::move(pairs);
	g_configfile = configfile;
	return smbd_conf_load(false);
}

int x_smbd_conf_reload()
{
	return smbd_conf_load(true);
}

x_smbd_conf_t::x_smbd_conf_t()
{
	strcpy((char *)&guid, "nxsmbd");
}

int x_smbd_restore_durable(const x_smbd_conf_t &smbd_conf)
{
	for (auto smbd_volume: smbd_conf.smbd_volumes) {
		/* TODO only for local volume */
		x_smbd_volume_restore_durable(smbd_volume);
	}
	return 0;
}

x_smbd_durable_t *x_smbd_share_lookup_durable(
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const std::shared_ptr<x_smbd_share_t> &smbd_share,
		uint64_t id_persistent)
{
	uint64_t vol_id = id_persistent >> 48;
	auto smbd_conf = x_smbd_conf_get();
	for (auto &vol: smbd_conf->smbd_volumes) {
		if (vol->volume_id == vol_id &&
				vol->owner_share == smbd_share) {
			void *ret = x_smbd_durable_db_lookup(
					vol->smbd_durable_db,
					id_persistent);
			if (ret) {
				smbd_volume = vol;
				return (x_smbd_durable_t *)ret;
			}
			break;
		}
	}

	return nullptr;
}

std::shared_ptr<x_smbd_volume_t> x_smbd_find_volume(const x_smbd_conf_t &smbd_conf,
		const x_smb2_uuid_t &volume_uuid)
{
	for (auto &vol: smbd_conf.smbd_volumes) {
		if (vol->uuid == volume_uuid) {
			return vol;
		}
	}
	return nullptr;
}

