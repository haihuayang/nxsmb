
#include "nxfsd.hxx"
#include "nxfsd_stats.hxx"
#include "smbd_ctrl.hxx"

static std::mutex nxfsd_stats_mutex;
static x_stats_store_t nxfsd_stats_store;

void x_nxfsd_stats_init(uint32_t num_thread)
{
	x_stats_init(num_thread);
	nxfsd_stats_store.init();
}

int x_nxfsd_stats_register(uint32_t thread_id)
{
	return x_stats_register_thread(thread_id);
}

static const uint32_t band_start = 3, band_group = 8, band_step = 3;
struct x_nxfsd_stats_report_t : x_ctrl_handler_t
{
	x_nxfsd_stats_report_t() {
		x_stats_store_t stats;
		stats.init();
		{
			auto lock = std::lock_guard(nxfsd_stats_mutex);
			x_stats_load(stats);
			stats.merge(nxfsd_stats_store);
		}
		stats_data = x_stats_output(stats,
				band_start, band_group, band_step);
	}

	bool output(std::string &data) override;

	std::string stats_data;
};

bool x_nxfsd_stats_report_t::output(std::string &data)
{
	if (!stats_data.empty()) {
		data = std::move(stats_data);
	}
	return false;
}

x_ctrl_handler_t *x_nxfsd_stats_report_create()
{
	return new x_nxfsd_stats_report_t;
}

void x_nxfsd_stats_report()
{
	x_stats_store_t stats;
	stats.init();
	{
		auto lock = std::lock_guard(nxfsd_stats_mutex);
		x_stats_collect(stats);
		nxfsd_stats_store.merge(stats);
	}

	auto data = x_stats_output(stats,
			band_start, band_group, band_step);

	if (!data.empty()) {
		X_LOG(SMB, NOTICE, "stats:\n%s", data.c_str());
	}
}
