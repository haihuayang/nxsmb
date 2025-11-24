
#include "smbd.hxx"
#include "smbd_conf.hxx"
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <sys/sysinfo.h>

#define PARSE_FATAL(fmt, ...) do { \
	X_PANIC(fmt "\n", __VA_ARGS__); \
} while (0)

static const char *g_configfile;
static std::vector<std::pair<std::string, std::string>> g_cmdline_options;
static std::shared_ptr<x_smbd_conf_t> g_smbd_conf;

static int comp_uuid(const x_smb2_uuid_t &uuid1, const x_smb2_uuid_t &uuid2)
{
	if (uuid1.data[0] < uuid2.data[0]) {
		return -1;
	} else if (uuid1.data[0] > uuid2.data[0]) {
		return 1;
	}
	if (uuid1.data[1] < uuid2.data[1]) {
		return -1;
	} else if (uuid1.data[1] > uuid2.data[1]) {
		return 1;
	}
	return 0;
}

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

static bool parse_feature_option(x_smbd_feature_option_t &option,
		const std::string &value)
{
	if (value == "required") {
		option = x_smbd_feature_option_t::required;
	} else if (value == "desired") {
		option = x_smbd_feature_option_t::desired;
	} else if (value == "enabled") {
		option = x_smbd_feature_option_t::enabled;
	} else if (value == "disabled") {
		option = x_smbd_feature_option_t::disabled;
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

static bool parse_size(const std::string &str, uint64_t &ret)
{
	char *end;
	unsigned long long val = strtoull(str.c_str(), &end, 0);
	if (*end) {
		if (strcasecmp(end, "G") == 0) {
			val *= 1024 * 1024 * 1024;
		} else if (strcasecmp(end, "M") == 0) {
			val *= 1024 * 1024;
		} else if (strcasecmp(end, "K") == 0) {
			val *= 1024;
		} else if (strcasecmp(end, "B") == 0) {
		} else {
			return false;
		}
	}
	uint64_t v = uint64_t(val);
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

static bool parse_uuidlist(std::vector<std::pair<x_smb2_uuid_t, int>> &uuid_list,
		const std::string &str)
{
	std::vector<std::pair<x_smb2_uuid_t, int>> ret;
	for (auto s: split_string(str)) {
		x_smb2_uuid_t uuid;
		if (!parse_uuid(uuid, s)) {
			return false;
		}
		ret.push_back(std::make_pair(uuid, -1));
	}
	uuid_list.swap(ret);
	return true;
}

static bool parse_version(std::tuple<uint8_t, uint8_t, uint16_t> &ver,
		const std::string &str)
{
	const char *p = str.c_str();
	char *sep;
	unsigned long v1 = strtoul(p, &sep, 0);
	unsigned long v2 = 0;
	unsigned long v3 = 0;
	if (*sep == '.') {
		v2 = strtoul(sep + 1, &sep, 0);
	}
	if (*sep == '.') {
		v3 = strtoul(sep + 1, &sep, 0);
	}
	if (*sep) {
		return false;
	}
	if (v1 >= UINT8_MAX || v2 >= UINT8_MAX || v3 >= UINT16_MAX) {
		return false;
	}
	ver = { uint8_t(v1), uint8_t(v2), uint16_t(v3) };
	return true;
}

static bool parse_ip(int af, void *buf, const std::string &str)
{
	return inet_pton(af, str.c_str(), buf) == 1;
}

static bool parse_ip(struct sockaddr_storage &ss, const std::string &str)
{
	struct in_addr tmp4;
	struct in6_addr tmp6;
	if (parse_ip(AF_INET, &tmp4, str)) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
		memset(sin, 0, sizeof *sin);
		sin->sin_family = AF_INET;
		sin->sin_addr = tmp4;
	} else if (parse_ip(AF_INET6, &tmp6, str)) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
		memset(sin6, 0, sizeof *sin6);
		sin6->sin6_family = AF_INET;
		sin6->sin6_addr = tmp6;
	} else {
		return false;
	}
	return true;
}

static bool parse_nodes(std::vector<x_smbd_node_t> &nodes,
		const std::string &str)
{
	const char delim = ',';
	for (auto &token: split_string(str)) {
		auto sep = token.find(delim);
		if (sep == std::string::npos) {
			return false;
		}
		std::string node_name = token.substr(0, sep);

		auto begin = sep + 1;
		sep = token.find(delim, begin);
		if (sep == std::string::npos) {
			return false;
		}
		struct in_addr ip_int;
		if (!parse_ip(AF_INET, &ip_int, token.substr(begin, sep - begin))) {
			return false;
		}
		
		std::vector<struct sockaddr_storage> ss_ext;
		for (;;) {
			begin = sep + 1;
			sep = token.find(delim, begin);
			if (sep == std::string::npos) {
				break;
			}
			struct sockaddr_storage ss;
			if (!parse_ip(ss, token.substr(begin, sep - begin))) {
				return false;
			}
			ss_ext.push_back(ss);
		}
		struct sockaddr_storage ss;
		if (!parse_ip(ss, token.substr(begin))) {
			return false;
		}
		ss_ext.push_back(ss);

		nodes.push_back({node_name, ip_int, std::move(ss_ext)});
	}
	return true;
}

static bool parse_volume_map(
		std::vector<std::unique_ptr<x_smbd_volume_spec_t>> &volumes,
		const std::string &str)
{
	const char delim = ':';
	for (auto &token: split_string(str)) {
		auto sep = token.find(delim);
		if (sep == std::string::npos) {
			return false;
		}
		std::string uuid_str = token.substr(0, sep);
		x_smb2_uuid_t uuid;
		if (!parse_uuid(uuid, uuid_str)) {
			X_LOG(CONF, ERR, "invalid uuid '%s'", uuid_str.c_str());
			return false;
		}

		auto begin = ++sep;
		char *end;
		unsigned long volume_id = strtoul(token.c_str() + begin, &end, 0);
		if (*end != delim) {
			return false;
		}
		if (volume_id > 0xffff) {
			X_LOG(CONF, ERR, "invalid volume id %lu", volume_id);
			return false;
		}

		begin = end - token.c_str() + 1;
		sep = token.find(delim, begin);
		if (sep == std::string::npos) {
			return false;
		}
		std::string node = token.substr(begin, sep - begin);

		volumes.push_back(std::make_unique<x_smbd_volume_spec_t>(uuid, uint16_t(volume_id),
				std::move(node),
				token.substr(sep + 1)));
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
#if 0
static const std::shared_ptr<x_smbd_volume_t> smbd_volume_find(
		const x_smbd_conf_t &smbd_conf,
		const char16_t *vol_s, const char16_t *vol_e)
{
	std::u16string volume_name_l16;
	volume_name_l16.reserve(vol_e - vol_s);
	if (!x_str_convert(volume_name_l16, vol_s, vol_e, x_tolower_t())) {
		return nullptr;
	}
	for (auto &volume: smbd_conf.smbd_volumes) {
		if (volume->name_l16 == volume_name_l16) {
			return volume;
		}
	}
	return nullptr;
}
#endif
static void add_share(x_smbd_conf_t &smbd_conf,
		const std::shared_ptr<x_smbd_share_t> &smbd_share)
{
	X_LOG(CONF, DBG, "add share section %s", smbd_share->name.c_str());
	smbd_conf.smbd_shares.push_back(smbd_share);
}

static bool smbd_conf_add_share(x_smbd_conf_t &smbd_conf,
		const x_smbd_share_spec_t &share_spec)
{
	std::vector<std::shared_ptr<x_smbd_volume_t>> smbd_volumes;
	for (auto [uuid, volume_idx]: share_spec.volumes) {
		smbd_volumes.push_back(smbd_conf.smbd_volumes[volume_idx]);
	}
	X_ASSERT(smbd_volumes.size() != 0);

	std::u16string name_16;
	std::u16string name_l16;
	if (!x_str_convert(name_16, share_spec.name)) {
		X_LOG(CONF, ERR, "Invalid share name '%s'", share_spec.name.c_str());
	}
	X_ASSERT(x_str_tolower(name_l16, name_16));

	std::shared_ptr<x_smbd_share_t> share = x_smbd_simplefs_share_create(
			smbd_conf.node,
			share_spec.uuid,
			share_spec.name,
			std::move(name_16),
			std::move(name_l16),
			share_spec.share_flags,
			share_spec.smb_encrypt,
			std::move(smbd_volumes));

	if (!share) {
		X_LOG(CONF, ERR, "Failed create share '%s'", share_spec.name.c_str());
		return false;
	}

	for (auto &smbd_volume: smbd_volumes) {
		if (smbd_volume->owner_share) {
			X_LOG(CONF, ERR, "Share '%s' cannot use volume %u, owned by share '%s'",
					share_spec.name.c_str(),
					smbd_volume->volume_id,
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

	std::vector<x_iface_t> ret_ifaces;
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
		ret_ifaces = std::move(probed_ifaces);
	} else {
		for (auto const &iface_name: smbd_conf.interfaces) {
			x_interpret_iface(ret_ifaces, iface_name, probed_ifaces);
		}
	}

	if (ret_ifaces.size() == 0) {
		X_LOG(CONF, ERR, "WARNING: no network interfaces found");
	}

	smbd_conf.local_ifaces = std::make_shared<std::vector<x_iface_t>>(std::move(ret_ifaces));
}

static bool parse_global_param(x_smbd_conf_t &smbd_conf,
		std::vector<std::unique_ptr<x_smbd_volume_spec_t>> &volume_specs,
		const std::string &name, const std::string &value)
{
	// global parameters
	if (name == "log level") {
		smbd_conf.log_level = value;
	} else if (name == "log name") {
		smbd_conf.log_name = value;
	} else if (name == "log file size") {
		return parse_size(value, smbd_conf.log_file_size);
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
	} else if (name == "ndr64") {
		smbd_conf.ndr64 = parse_bool(value);
	} else if (name == "server signing") {
		if (value == "mandatory") {
			smbd_conf.security_mode |= X_SMB2_NEGOTIATE_SIGNING_REQUIRED;
		}
	} else if (name == "smb2 max credits") {
		return parse_uint32(value, smbd_conf.smb2_max_credits);
	} else if (name == "smb2 break timeout ms") {
		return parse_uint32(value, smbd_conf.smb2_break_timeout_ms);
	} else if (name == "sess setup timeout ms") {
		return parse_uint32(value, smbd_conf.sess_setup_timeout_ms);
	} else if (name == "node") {
		smbd_conf.node = value;
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
	} else if (name == "allocation roundup size") {
		uint32_t size;
		if (!parse_uint32(value, size)) {
			return false;
		}
		if (size < 512 || (size & ~size) != 0) {
			return false;
		}
		smbd_conf.allocation_roundup_size = size;
		return true;

	} else if (name == "my:nbt version") {
		return parse_version(smbd_conf.my_nbt_version, value);
	} else if (name == "my:client thread count") {
		return parse_uint32(value, smbd_conf.client_thread_count);
	} else if (name == "my:async thread count") {
		return parse_uint32(value, smbd_conf.async_thread_count);
	} else if (name == "my:winbindd connection count") {
		return parse_uint32(value, smbd_conf.winbindd_connection_count);
	} else if (name == "my:max connections") {
		return parse_uint32(value, smbd_conf.max_connections);
	} else if (name == "my:max sessions") {
		return parse_uint32(value, smbd_conf.max_sessions);
	} else if (name == "my:max tcons") {
		return parse_uint32(value, smbd_conf.max_tcons);
	} else if (name == "my:max opens") {
		return parse_uint32(value, smbd_conf.max_opens);
	} else if (name == "my:max requs") {
		return parse_uint32(value, smbd_conf.max_requs);
	} else if (name == "my:samba lib dir") {
		smbd_conf.samba_lib_dir = value;
	} else if (name == "my:nodes") {
		return parse_nodes(smbd_conf.nodes, value);
	} else if (name == "my:volume map") {
		return parse_volume_map(volume_specs, value);
	} else if (name == "my:stats interval ms") {
		return parse_uint32(value, smbd_conf.my_stats_interval_ms);
	} else if (name == "my:dev delay read ms") {
		return parse_uint32(value, smbd_conf.my_dev_delay_read_ms);
	} else if (name == "my:dev delay write ms") {
		return parse_uint32(value, smbd_conf.my_dev_delay_write_ms);
	} else if (name == "my:dev delay qdir ms") {
		return parse_uint32(value, smbd_conf.my_dev_delay_qdir_ms);
	} else if (name == "durable log max record") {
		return parse_uint32(value, smbd_conf.durable_log_max_record);
	} else if (name == "node port") {
		return parse_uint32(value, smbd_conf.node_port);

	} else {
		X_LOG(CONF, WARN, "unknown global param '%s' with value '%s'",
				name.c_str(), value.c_str());
		return false;
	}
	return true;
}

static bool parse_share_param(x_smbd_share_spec_t &share_spec,
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
	} else if (name == "smb encrypt") {
		if (!parse_feature_option(share_spec.smb_encrypt, value)) {
			X_PANIC("Unexpected feature option %s at %s:%u",
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
		X_LOG(CONF, WARN, "unknown share param '%s' with value '%s'",
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
		std::vector<std::unique_ptr<x_smbd_share_spec_t>> &share_specs,
		std::unique_ptr<x_smbd_share_spec_t> &share_spec,
		std::vector<std::unique_ptr<x_smbd_volume_spec_t>> &volume_specs,
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
			share_spec.reset(new x_smbd_share_spec_t(section));
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

static int find_volume_by_uuid(
		const std::vector<std::unique_ptr<x_smbd_volume_spec_t>> &volume_specs,
		const x_smb2_uuid_t &uuid)
{
	int idx = 0;
	for (auto &volume: volume_specs) {
		if (volume->uuid == uuid) {
			return idx;
		}
		++idx;
	}
	return -1;
}

template <class UnaryOp = x_identity_t>
static std::shared_ptr<std::u16string> make_u16string_ptr(const std::string &str,
		UnaryOp &&op = {})
{
	std::u16string ustr;
	if (!x_str_convert(ustr, str, std::forward<UnaryOp>(op))) {
		return nullptr;
	}
	return std::make_shared<std::u16string>(std::move(ustr));
}

static int parse_smbconf(x_smbd_conf_t &smbd_conf)
{
	const char *path = g_configfile;
	X_LOG(CONF, DBG, "Loading smbd_conf from %s", path);

	smbd_conf.capabilities = X_SMB2_CAP_DFS |
		X_SMB2_CAP_LEASING |
		X_SMB2_CAP_LARGE_MTU |
		X_SMB2_CAP_MULTI_CHANNEL |
		X_SMB2_CAP_PERSISTENT_HANDLES |
		X_SMB2_CAP_DIRECTORY_LEASING |
		X_SMB2_CAP_ENCRYPTION;

	std::string line, last_line;
	std::ifstream in(path);

	auto samba_path = get_samba_path(path);
	smbd_conf.samba_lib_dir = "/var/lib/samba";
	std::unique_ptr<x_smbd_share_spec_t> share_spec;

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
		parse_line(smbd_conf, smbd_conf.share_specs, share_spec, smbd_conf.volume_specs,
				last_line, path, lineno);
		last_line.clear();
	}

	if (last_line.length()) {
		parse_line(smbd_conf, smbd_conf.share_specs, share_spec, smbd_conf.volume_specs,
				last_line, path, lineno);
	}

	if (share_spec) {
		smbd_conf.share_specs.push_back(std::move(share_spec));
	}

	// override global params by argv
	for (const auto &[name, value]: g_cmdline_options) {
		parse_global_param(smbd_conf, smbd_conf.volume_specs, name, value);
	}

	if (smbd_conf.client_thread_count == 0 || smbd_conf.async_thread_count == 0) {
		int ncpu = get_nprocs();
		if (ncpu <= 0) {
			X_LOG(CONF, ERR, "get_nprocs return %d, errno=%d",
					ncpu, errno);
			ncpu = 1;
		}
		if (smbd_conf.client_thread_count == 0) {
			X_LOG(CONF, NOTICE, "set client_thread_count to 4 * %d",
					ncpu);
			smbd_conf.client_thread_count = 4 * ncpu;
		}

		if (smbd_conf.async_thread_count == 0) {
			X_LOG(CONF, NOTICE, "set async_thread_count to 10 * %d",
					ncpu);
			smbd_conf.async_thread_count = 10 * ncpu;
		}
	}

	if (smbd_conf.node.empty()) {
		char hostname[1024];
		int err = gethostname(hostname, sizeof hostname);
		X_ASSERT(err == 0);
		X_LOG(CONF, NOTICE, "derive node from hostname '%s'", hostname);
		char *end = hostname;
		while (*end && *end != '.') {
			++end;
		}
		smbd_conf.node.assign(hostname, end);
	}

	if (smbd_conf.dns_domain_l8.empty()) {
		smbd_conf.dns_domain_l8 = smbd_conf.realm;
	}

	if (!x_str_toupper(smbd_conf.realm)) {
		X_LOG(CONF, ERR, "Invalid realm '%s'\n", smbd_conf.realm.c_str());
	}

	if (!x_str_tolower(smbd_conf.dns_domain_l8)) {
		X_LOG(CONF, ERR, "Invalid realm '%s'\n", smbd_conf.dns_domain_l8.c_str());
	}

	smbd_conf.dns_domain_l16 = make_u16string_ptr(smbd_conf.dns_domain_l8);
	if (!smbd_conf.dns_domain_l16) {
		X_LOG(CONF, ERR, "Invalid dns_domain '%s'", smbd_conf.dns_domain_l8.c_str());
		return -1;
	}

	std::string netbios_name_u8;
	bool ret = x_str_convert(netbios_name_u8, smbd_conf.netbios_name_l8,
			x_toupper_t());
	if (!ret) {
		X_LOG(CONF, ERR, "Invalid netbios_name '%s'", smbd_conf.netbios_name_l8.c_str());
		return -1;
	}
	smbd_conf.netbios_name_l8.clear();
	x_str_convert(smbd_conf.netbios_name_l8, netbios_name_u8,
			x_tolower_t());

	smbd_conf.netbios_name_u16 = make_u16string_ptr(smbd_conf.netbios_name_l8, x_toupper_t());
	if (!smbd_conf.netbios_name_u16) {
		X_LOG(CONF, ERR, "Invalid netbios_name '%s'", smbd_conf.netbios_name_l8.c_str());
		return -1;
	}

	smbd_conf.workgroup_u16 = make_u16string_ptr(smbd_conf.workgroup_8, x_toupper_t());
	if (!smbd_conf.workgroup_u16) {
		X_LOG(CONF, ERR, "Invalid workgroup '%s'", smbd_conf.workgroup_8.c_str());
		return -1;
	}

	int err = x_smbd_secrets_load(smbd_conf.secrets,
			smbd_conf.samba_lib_dir + "/private",
			smbd_conf.workgroup_8,
			netbios_name_u8);
	if (err != 0) {
		X_LOG(CONF, ERR, "Fail loading secrets");
		return err;
	}

	err = x_smbd_group_mapping_load(smbd_conf.group_mapping,
			smbd_conf.samba_lib_dir);
	if (err != 0) {
		X_LOG(CONF, ERR, "Fail loading group_mapping");
		return err;
	}

	std::sort(smbd_conf.volume_specs.begin(), smbd_conf.volume_specs.end(),
			[](const auto &vs1, const auto &vs2) {
				return comp_uuid(vs1->uuid, vs2->uuid) < 0;
			});

	std::sort(smbd_conf.share_specs.begin(), smbd_conf.share_specs.end(),
			[](const auto &ss1, const auto &ss2) {
				return comp_uuid(ss1->uuid, ss2->uuid) < 0;
			});

	for (auto &ss: smbd_conf.share_specs) {
		X_ASSERT(!ss->volumes.empty());
		for (auto &volume: ss->volumes) {
			int volume_idx = find_volume_by_uuid(
					smbd_conf.volume_specs, volume.first);
			if (volume_idx == -1) {
				X_LOG(CONF, ERR, "cannot find volume %s for share %s",
						x_tostr(volume.first).c_str(),
						ss->name.c_str());
				return -1;
			}

			auto &volume_spec = smbd_conf.volume_specs[volume_idx];
			if (volume_spec->share_spec) {
				return -1;
			}
			volume.second = volume_idx;
			volume_spec->share_spec = ss.get();
		}
	}

	return 0;
}

std::shared_ptr<x_smbd_conf_t> x_smbd_conf_get()
{
	return g_smbd_conf;
}

std::shared_ptr<x_smbd_share_t>
x_smbd_find_share(const x_smbd_conf_t &smbd_conf,
		const char16_t *in_share_s, const char16_t *in_share_e)
{
	std::u16string share_name_l16;
	if (!x_str_convert(share_name_l16, in_share_s, in_share_e, x_tolower_t())) {
		return nullptr;
	}

	for (auto &smbd_share: smbd_conf.smbd_shares) {
		if (smbd_share->name_l16 == share_name_l16) {
			return smbd_share;
		}
	}
	return nullptr;
	/* TODO USER_SHARE */
}

std::shared_ptr<x_smbd_share_t>
x_smbd_find_share(const x_smbd_conf_t &smbd_conf, const x_smb2_uuid_t &uuid)
{
	for (auto &smbd_share: smbd_conf.smbd_shares) {
		if (smbd_share->uuid == uuid) {
			return smbd_share;
		}
	}
	return nullptr;
	/* TODO USER_SHARE */
}

std::pair<std::shared_ptr<x_smbd_share_t>, std::shared_ptr<x_smbd_volume_t>>
x_smbd_resolve_share(const char16_t *in_share_s, const char16_t *in_share_e)
{
	const x_smbd_conf_t &smbd_conf = x_smbd_conf_get_curr();

	if (in_share_s == in_share_e) {
		return {nullptr, nullptr};
	}
#if 0
	if (*in_share_s == u'-') {
		++in_share_s;
		if (in_share_s == in_share_e) {
			return {nullptr, nullptr};
		}

		if (*in_share_s == '-') {
			auto smbd_volume = smbd_volume_find(smbd_conf, in_share_s, in_share_e);
			if (!smbd_volume) {
				return {nullptr, nullptr};
			}
			return {smbd_volume->owner_share, smbd_volume};
		}
	}
#endif
	std::shared_ptr<x_smbd_share_t> smbd_share = x_smbd_find_share(smbd_conf,
			in_share_s, in_share_e);
	if (!smbd_share) {
		return {nullptr, nullptr};
	}

	return { smbd_share, nullptr };
#if 0
	std::shared_ptr<x_smbd_volume_t> smbd_volume = smbd_share->find_volume(in_share_s, in_share_e);
	return {smbd_share, smbd_volume};

	/* TODO USER_SHARE */
#endif
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

	auto smbd_conf = std::make_shared<x_smbd_conf_t>();

	int err = parse_smbconf(*smbd_conf);
	if (err) {
		return err;
	}

	load_ifaces(*smbd_conf);

	g_smbd_conf = smbd_conf;

	return 0;
}

static int reload_volumes(x_smbd_conf_t &smbd_conf,
		const std::vector<std::unique_ptr<x_smbd_volume_spec_t>> &volume_specs)
{
	auto curr_it = g_smbd_conf->smbd_volumes.begin();
	auto curr_end = g_smbd_conf->smbd_volumes.end();
	for (auto &spec: volume_specs) {
		int cmp = 1;
		for ( ; curr_it != curr_end; ++curr_it) {
			cmp = comp_uuid((*curr_it)->uuid, spec->uuid);
			if (cmp >= 0) {
				break;
			}
			X_LOG(CONF, NOTICE, "volume %s removed",
					x_tostr((*curr_it)->uuid).c_str());
		}
		if (cmp == 0) {
			/* TODO we suppose path not changed */
			smbd_conf.smbd_volumes.push_back(*curr_it);
			++curr_it;
		} else {
			/* new volume */
			smbd_conf.smbd_volumes.push_back(x_smbd_volume_create(spec->uuid,
						spec->volume_id,
						spec->owner_node, spec->path,
						smbd_conf.allocation_roundup_size));
		}
	}
	for ( ; curr_it != curr_end; ++curr_it) {
		X_LOG(CONF, NOTICE, "volume %s removed",
				x_tostr((*curr_it)->uuid).c_str());
	}
	return 0;
}

static int reload_shares(x_smbd_conf_t &smbd_conf,
		const std::vector<std::unique_ptr<x_smbd_share_spec_t>> &share_specs)
{
	auto curr_it = g_smbd_conf->smbd_shares.begin();
	auto curr_end = g_smbd_conf->smbd_shares.end();

	/* ipc$ is the first one */
	X_ASSERT(curr_it != curr_end);
	smbd_conf.smbd_shares.push_back(*curr_it);
	++curr_it;

	for (auto &spec: share_specs) {
		int cmp = 1;
		for ( ; curr_it != curr_end; ++curr_it) {
			cmp = comp_uuid((*curr_it)->uuid, spec->uuid);
			if (cmp >= 0) {
				break;
			}
			X_LOG(CONF, NOTICE, "share %s removed",
					x_tostr((*curr_it)->uuid).c_str());
		}
		if (cmp == 0) {
			std::u16string name_16;
			std::u16string name_l16;
			if (!x_str_convert(name_16, spec->name)) {
				X_LOG(CONF, ERR, "Invalid share name '%s'", spec->name.c_str());
				return -1;
			}
			X_ASSERT(x_str_tolower(name_l16, name_16));

			/* TODO not atomic, and we do not update volumes,
			 * and convert simple share to/from dfs share
			 */
			auto smbd_share = *curr_it;
			smbd_share->name = std::move(spec->name);
			smbd_share->name_16 = std::move(name_16);
			smbd_share->name_l16 = std::move(name_l16);
			smbd_share->flags = spec->share_flags;
			smbd_conf.smbd_shares.push_back(smbd_share);
			++curr_it;
		} else {
			if (!smbd_conf_add_share(smbd_conf, *spec)) {
				return -1;
			}
		}
	}
	for ( ; curr_it != curr_end; ++curr_it) {
		X_LOG(CONF, NOTICE, "share %s removed",
				x_tostr((*curr_it)->uuid).c_str());
	}
	return 0;
}

int x_smbd_conf_reload()
{
	auto smbd_conf = std::make_shared<x_smbd_conf_t>();

	int err = parse_smbconf(*smbd_conf);
	if (err) {
		return err;
	}

	if (smbd_conf->log_name != g_smbd_conf->log_name) {
		x_log_init(smbd_conf->log_name.c_str(),
				smbd_conf->log_level.c_str(),
				smbd_conf->log_file_size);
	} else if (smbd_conf->log_level != g_smbd_conf->log_level ||
			smbd_conf->log_file_size != g_smbd_conf->log_file_size) {
		x_log_init(nullptr, smbd_conf->log_level.c_str(),
				smbd_conf->log_file_size);
	}

	if (smbd_conf->interfaces != g_smbd_conf->interfaces) {
		load_ifaces(*smbd_conf);
	} else {
		smbd_conf->local_ifaces = g_smbd_conf->local_ifaces;
	}

	reload_volumes(*smbd_conf, smbd_conf->volume_specs);
	reload_shares(*smbd_conf, smbd_conf->share_specs);

	g_smbd_conf = smbd_conf;
	return 0;
}

x_smbd_conf_t::x_smbd_conf_t()
{
	strcpy((char *)&guid, "nxsmbd");
	group_mapping = x_smbd_group_mapping_create();
}

x_smbd_conf_t::~x_smbd_conf_t()
{
	x_smbd_group_mapping_delete(group_mapping);
}

int x_smbd_init_shares(x_smbd_conf_t &smbd_conf)
{
	for (auto &vs: smbd_conf.volume_specs) {
		smbd_conf.smbd_volumes.push_back(x_smbd_volume_create(vs->uuid,
					vs->volume_id,
					vs->owner_node, vs->path,
					smbd_conf.allocation_roundup_size));
	}

	add_share(smbd_conf, x_smbd_ipc_share_create());

	for (auto &ss: smbd_conf.share_specs) {
		if (!smbd_conf_add_share(smbd_conf, *ss)) {
			return -1;
		}
	}

	return 0;
}

uint64_t x_smbd_share_lookup_durable(
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const std::shared_ptr<x_smbd_share_t> &smbd_share,
		uint64_t id_persistent)
{
	uint64_t vol_id = id_persistent >> 48;
	const x_smbd_conf_t &smbd_conf = x_smbd_conf_get_curr();

	for (auto &vol: smbd_conf.smbd_volumes) {
		if (vol->volume_id == vol_id &&
				vol->owner_share == smbd_share) {
			uint64_t id_volatile = x_smbd_durable_lookup(
					vol->smbd_durable_db,
					id_persistent);
			if (id_volatile != 0) {
				smbd_volume = vol;
				return id_volatile;
			}
			break;
		}
	}

	return 0;
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

const std::string *x_smbd_volume_is_remote(const x_smbd_conf_t &smbd_conf, uint64_t volume_id)
{
	for (auto &smbd_volume : smbd_conf.smbd_volumes) {
		if (smbd_volume->volume_id == volume_id) {
			if (smbd_volume->owner_node == smbd_conf.node) {
				return nullptr;
			} else {
				return &smbd_volume->owner_node;
			}
		}
	}
	X_LOG(CONF, ERR, "volume %lu not found", volume_id);
	return nullptr;
}

thread_local std::shared_ptr<x_smbd_conf_t> x_smbd_conf_curr;
thread_local int x_smbd_conf_curr_count = 0;

x_smbd_conf_pin_t::x_smbd_conf_pin_t()
{
	if (x_smbd_conf_curr_count++ == 0) {
		X_ASSERT(!x_smbd_conf_curr);
		x_smbd_conf_curr = g_smbd_conf;
	}
}


