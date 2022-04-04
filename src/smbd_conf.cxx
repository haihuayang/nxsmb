
#include "smb2.hxx"
#include "smbd_conf.hxx"
#include <fstream>
#include <getopt.h>
#include <fcntl.h>
//#include "smbd_lfs.hxx"

#define PARSE_FATAL(fmt, ...) do { \
	X_PANIC(fmt "\n", __VA_ARGS__); \
} while (0)

static std::shared_ptr<x_smbd_conf_t> g_smbd_conf;

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
		uv = (val << 4) | val2;
	}
	return 0;
}

static bool parse_bool(const std::string &str)
{
	return str == "yes";
}

static int parse_integer(const std::string &str)
{
	return strtol(str.c_str(), nullptr, 0);
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

static void add_share(x_smbd_conf_t &smbd_conf, std::shared_ptr<x_smbd_share_t> &share_spec)
{
	X_LOG_DBG("add share section %s", share_spec->name.c_str());
	smbd_conf.shares[share_spec->name] = share_spec;
	if (share_spec->type == TYPE_DEFAULT) {
		/* TODO if the share is hosted by this node */
		int fd = open(share_spec->path.c_str(), O_RDONLY);
		X_ASSERT(fd != -1);
		auto topdir = std::make_shared<x_smbd_topdir_t>(share_spec);
		topdir->fd = fd;
		share_spec->root_dir = topdir; /* TODO cycle reference  */
	} else if (share_spec->type == TYPE_HOME) {
		X_ASSERT(0);
		/* if the files_at_root vg is host by this node,
		   create a top_dir point the files_at_root vg.

		   create a root_dir point the dir has all the vg mounted
		 */
	} else {
		X_ASSERT(share_spec->type == TYPE_IPC);
	}
}


static int parse_smbconf(x_smbd_conf_t &smbd_conf, const char *path)
{
	X_LOG_DBG("Loading smbd_conf from %s", path);

	std::shared_ptr<x_smbd_share_t> share_spec = std::make_shared<x_smbd_share_t>("ipc$");
	share_spec->type = TYPE_IPC;
	share_spec->read_only = true;
	add_share(smbd_conf, share_spec);
	share_spec = nullptr;

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
				add_share(smbd_conf, share_spec);
				share_spec = nullptr;
			}
			if (section != "global") {
				share_spec = std::make_shared<x_smbd_share_t>(section);
			}
		} else {
			auto sep = line.find('=', pos);
			if (sep == std::string::npos) {
				X_PANIC("No '=' at %s:%u",
						path, lineno);
			}
			auto name = line.substr(pos, rskip(line, sep, pos) - pos);

			pos = skip(line, sep + 1, line.length());
			auto value = line.substr(pos, rskip(line, line.length(), pos) - pos);

			if (share_spec) {
				if (name == "type") {
					/* TODO not support distribute share for now */
					if (false && value == "HOME_SHARE") {
						share_spec->type = TYPE_HOME;
					} else if (value == "DEFAULT_SHARE") {
						share_spec->type = TYPE_DEFAULT;
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
					share_spec->uuid = uuid;
				} else if (name == "path") {
					share_spec->path = value;
				} else if (name == "abe") {
					if (value == "yes") {
						share_spec->abe = true;
					} else if (value == "no") {
						share_spec->abe = false;
					} else {
						X_PANIC("Unexpected boolean %s at %s:%u",
								value.c_str(), path, lineno);
					}
				}
			} else {
				// global parameters
				if (name == "netbios name") {
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
					smbd_conf.smb2_max_credits = parse_integer(value);
				}
			}
		}
	}
	if (share_spec) {
		add_share(smbd_conf, share_spec);
	}
	smbd_conf.capabilities = SMB2_CAP_DFS | SMB2_CAP_LARGE_MTU | SMB2_CAP_LEASING
		| SMB2_CAP_DIRECTORY_LEASING; // | SMB2_CAP_MULTI_CHANNEL
	smbd_conf.security_mode = SMB2_NEGOTIATE_SIGNING_ENABLED;
	if (false /* signing_required*/) {
		smbd_conf.security_mode |= SMB2_NEGOTIATE_SIGNING_REQUIRED;
	}

	return 0;
}

std::shared_ptr<x_smbd_conf_t> x_smbd_conf_get()
{
	return g_smbd_conf;
}

std::shared_ptr<x_smbd_share_t> x_smbd_find_share(const std::string &name)
{
	auto it = g_smbd_conf->shares.find(name);
	if (it != g_smbd_conf->shares.end()) {
		return it->second;
	}
	return nullptr;
	/* TODO USER_SHARE */
}

int x_smbd_conf_parse(int argc, char **argv)
{
	int32_t thread_count = -1;
	const char *configfile = nullptr;

	const struct option long_options[] = {
		{ "configfile", required_argument, 0, 'c'},
		{ "thread-count", required_argument, 0, 't'},
	};

	int optind = 0;
	for (;;) {
		int c = getopt_long(argc, argv, "c:t:",
				long_options, &optind);
		if (c == -1) {
			break;
		}
		switch (c) {
			case 'c':
				configfile = optarg;
				break;
			case 't':
				thread_count = atoi(optarg);
				break;
			default:
				abort();
		}
	}

	if (!configfile) {
		configfile = "/etc/samba/smb.conf";
	}
	auto ret = std::make_shared<x_smbd_conf_t>();
	int err = parse_smbconf(*ret, configfile);
	if (err < 0) {
		return err;
	}

	if (thread_count != -1) {
		ret->thread_count = thread_count;
	}
	g_smbd_conf = ret;
	return 0;
}


