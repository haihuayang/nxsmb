
#include "smbd_stats.hxx"
#include "smbd_ctrl.hxx"

thread_local x_smbd_stats_t *g_smbd_stats;

static x_smbd_stats_t g_smbd_stats_table[X_SMBD_MAX_THREAD];
static std::atomic<uint32_t> g_max_thread = 0;

#undef X_SMBD_COUNTER_DECL
#define X_SMBD_COUNTER_DECL(x) # x,
static const char *smbd_counter_names[] = {
	X_SMBD_COUNTER_ENUM
};

#define MO std::memory_order_relaxed

int x_smbd_stats_init(uint32_t thread_id)
{
	g_smbd_stats = &g_smbd_stats_table[thread_id];
	uint32_t oval = g_max_thread.load(MO);
	for (;;) {
		if (oval > thread_id) {
			break;
		}
		if (g_max_thread.compare_exchange_strong(oval, thread_id + 1,
					MO, MO)) {
			break;
		}
	}
	return 0;
}

struct x_smbd_stats_report_t : x_smbd_ctrl_handler_t
{
	x_smbd_stats_report_t() {
		uint32_t max_thread = g_max_thread.load(MO);
		for (uint32_t ti = 0; ti < max_thread; ++ti) {
			const auto &thread_stats = g_smbd_stats_table[ti];
			for (uint32_t ci = 0; ci < X_SMBD_COUNTER_ID_MAX; ++ci) {
				stats.counters[ci].fetch_add(
						thread_stats.counters[ci].load(MO),
						MO);
			}
		}
	}

	bool output(std::string &data) override;
	x_smbd_stats_t stats;
	uint32_t counter_index = 0;
};

bool x_smbd_stats_report_t::output(std::string &data)
{
	std::ostringstream os;

	if (counter_index >= X_SMBD_COUNTER_ID_MAX) {
		return false;
	}

	os << smbd_counter_names[counter_index] << ": " <<
		stats.counters[counter_index].load(MO) << std::endl;
	++counter_index;
	data = os.str();
	return true;
}

x_smbd_ctrl_handler_t *x_smbd_stats_report_create()
{
	return new x_smbd_stats_report_t;
}

