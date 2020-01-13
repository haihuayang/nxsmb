
#include "smbd.hxx"
#include <map>

static std::mutex g_smbdshare_mutex;
static std::map<std::string, std::shared_ptr<x_smbd_share_t>> g_smbdshare_map;

std::shared_ptr<x_smbd_share_t> x_smbd_share_find(const std::string &name)
{
	std::lock_guard<std::mutex> lock(g_smbdshare_mutex);
	auto it = g_smbdshare_map.find(name);
	if (it != g_smbdshare_map.end()) {
		return it->second;
	}
	return nullptr;
	/* TODO USER_SHARE */
}

int x_smbd_load_shares()
{
	/* TODO read from conf */
	auto share = std::make_shared<x_smbd_share_t>(x_smbd_share_t{"ipc$", x_smbd_share_t::TYPE_IPC, true});
	g_smbdshare_map["ipc$"] = share;

	g_smbdshare_map["gen1"] = std::make_shared<x_smbd_share_t>(x_smbd_share_t{"gen1", x_smbd_share_t::TYPE_DEFAULT, false, "NTNX-hh360u-1"});
	g_smbdshare_map["home1"] = std::make_shared<x_smbd_share_t>(x_smbd_share_t{"home1", x_smbd_share_t::TYPE_HOME, false});
	return 0;
}

