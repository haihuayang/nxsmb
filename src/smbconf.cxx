
#include "smbd.hxx"
#include <fstream>
#include <getopt.h>

#define PARSE_FATAL(fmt, ...) do { \
	X_PANIC(fmt "\n", __VA_ARGS__); \
} while (0)

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

static void add_share(x_smbconf_t &smbconf, std::shared_ptr<x_smbshare_t> &share_spec)
{
	X_DBG("add share section %s",
			share_spec->name.c_str());
	smbconf.shares[share_spec->name] = share_spec;
}

static int parse_smbconf(x_smbconf_t &smbconf, const char *path)
{
	X_DBG("Loading smbconf from %s", path);

	std::shared_ptr<x_smbshare_t> share_spec = std::make_shared<x_smbshare_t>("ipc$");
	share_spec->type = TYPE_IPC;
	share_spec->read_only = true;
	add_share(smbconf, share_spec);
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
				add_share(smbconf, share_spec);
				share_spec = nullptr;
			}
			if (section != "global") {
				share_spec = std::make_shared<x_smbshare_t>(section);
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
					if (value == "HOME_SHARE") {
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
					smbconf.netbios_name = value;
				} else if (name == "dns domain") {
					smbconf.dns_domain = value;
				} else if (name == "realm") {
					smbconf.realm = value;
				} else if (name == "workgroup") {
					smbconf.workgroup = value;
				} else if (name == "lanman auth") {
					smbconf.lanman_auth = parse_bool(value);
				}
			}
		}
	}
	if (share_spec) {
		add_share(smbconf, share_spec);
	}
	return 0;
}

int x_smbd_parse_cmdline(std::shared_ptr<x_smbconf_t> &smbconf, int argc, char **argv)
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
	auto ret = std::make_shared<x_smbconf_t>();
	int err = parse_smbconf(*ret, configfile);
	if (err < 0) {
		return err;
	}

	if (thread_count != -1) {
		ret->thread_count = thread_count;
	}
	smbconf = ret;
	return 0;
}


