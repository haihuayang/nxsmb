
#include "nxfsd_stats.hxx"
#include "smbd_ctrl.hxx"

#undef X_NXFSD_COUNTER_DECL
#define X_NXFSD_COUNTER_DECL(x) # x,
static const char *smbd_counter_names[] = {
	X_NXFSD_COUNTER_ENUM
};

#undef X_NXFSD_PAIR_COUNTER_DECL
#define X_NXFSD_PAIR_COUNTER_DECL(x) # x,
static const char *smbd_pair_counter_names[] = {
	X_NXFSD_PAIR_COUNTER_ENUM
};

#undef X_NXFSD_HISTOGRAM_DECL
#define X_NXFSD_HISTOGRAM_DECL(x) # x,
static const char *smbd_histogram_names[] = {
	X_NXFSD_HISTOGRAM_ENUM
};

static std::mutex nxfsd_stats_mutex;
static x_stats_store_t nxfsd_stats_store;

void x_nxfsd_stats_init()
{
	x_stats_init(X_SMBD_MAX_THREAD,
			X_NXFSD_COUNTER_ID_MAX,
			X_NXFSD_PAIR_COUNTER_ID_MAX,
			X_NXFSD_HISTOGRAM_ID_MAX);
	nxfsd_stats_store.init();
}

int x_nxfsd_stats_register(uint32_t thread_id)
{
	return x_stats_register(thread_id);
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
		stats_data = x_stats_output(stats, smbd_counter_names,
				smbd_pair_counter_names,
				smbd_histogram_names,
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

	auto data = x_stats_output(stats, smbd_counter_names,
			smbd_pair_counter_names,
			smbd_histogram_names,
			band_start, band_group, band_step);

	if (!data.empty()) {
		X_LOG(SMB, NOTICE, "stats:\n%s", data.c_str());
	}
}
