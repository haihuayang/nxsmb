
#include "smbd.hxx"

std::shared_ptr<x_smbd_share_t> x_smbd_find_share(x_smbd_t *smbd, const std::string &name)
{
	std::shared_ptr<x_smbd_conf_t> smbconf = smbd->smbd_conf;
	auto it = smbconf->shares.find(name);
	if (it != smbconf->shares.end()) {
		return it->second;
	}
	return nullptr;
	/* TODO USER_SHARE */
}
#if 0
#include <map>

static std::mutex g_smbdshare_mutex;
static std::map<std::string, std::shared_ptr<x_smbd_share_t>> g_smbdshare_map;
int x_smbd_load_shares()
{
	/* TODO read from conf */
	auto share = std::make_shared<x_smbd_share_t>(x_smbd_share_t{"ipc$", TYPE_IPC, true});
	g_smbdshare_map["ipc$"] = share;

	g_smbdshare_map["gen1"] = std::make_shared<x_smbd_share_t>(x_smbd_share_t{"gen1",
			TYPE_DEFAULT, false,
			{ 0xa9, 0xa0, 0x58, 0xe1, 0x62, 0x10, 0x4e, 0x21, 0x9a, 0xef, 0xa8, 0xcb, 0x3d, 0x15, 0x32, 0x7a, },
			"/zroot/shares/84989cf1-4927-4d82-96ed-1a941d9a991a/:041d4c70-8af3-4ffd-80bd-5a37b0987b4f/a9a058e1-6210-4e21-9aef-a8cb3d15327a",
			"NTNX-hh360u-1"});
	g_smbdshare_map["gsmb1"] = std::make_shared<x_smbd_share_t>(x_smbd_share_t{"gsmb1",
			TYPE_DEFAULT, false,
			{ 0x54, 0x40, 0x37, 0xfd, 0x1a, 0x20, 0x40, 0x7c, 0x82, 0x11, 0x9e, 0xe5, 0x3d, 0x7d, 0x2e, 0xb9, },
			"/zroot/shares/84989cf1-4927-4d82-96ed-1a941d9a991a/:041d4c70-8af3-4ffd-80bd-5a37b0987b4f/544037fd-1a20-407c-8211-9ee53d7d2eb9",
			"NTNX-hh360u-1"});
	// g_smbdshare_map["home1"] = std::make_shared<x_smbd_share_t>(x_smbd_share_t{"home1", x_smbd_share_t::TYPE_HOME, false});
	return 0;
}

void x_smbd_shares_foreach(std::function<bool(std::shared_ptr<x_smbd_share_t> &share)> visitor)
{
	std::lock_guard<std::mutex> lock(g_smbdshare_mutex);
	for (auto it = g_smbdshare_map.begin(); it != g_smbdshare_map.end(); ++it) {
		if (!visitor(it->second)) {
			break;
		}
	}
}
#endif
