
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

#undef X_SMBD_PAIR_COUNTER_DECL
#define X_SMBD_PAIR_COUNTER_DECL(x) # x,
static const char *smbd_pair_counter_names[] = {
	X_SMBD_PAIR_COUNTER_ENUM
};

#undef X_SMBD_HISTOGRAM_DECL
#define X_SMBD_HISTOGRAM_DECL(x) # x,
static const char *smbd_histogram_names[] = {
	X_SMBD_HISTOGRAM_ENUM
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

			for (uint32_t pi = 0; pi < X_SMBD_PAIR_COUNTER_ID_MAX; ++pi) {
				stats.pair_counters[pi][0].fetch_add(
						thread_stats.pair_counters[pi][0].load(MO),
						MO);
				stats.pair_counters[pi][1].fetch_add(
						thread_stats.pair_counters[pi][1].load(MO),
						MO);
			}

			for (uint32_t hi = 0; hi < X_SMBD_HISTOGRAM_ID_MAX; ++hi) {
				auto &dst = stats.histograms[hi];
				auto &src = thread_stats.histograms[hi];
				dst.sum.fetch_add(src.sum.load(MO), MO);
				auto max = src.max.load(MO);
				if (dst.max.load(MO) < max) {
					dst.max.store(max, MO);
				}
				auto min = src.min.load(MO);
				if (dst.min.load(MO) > min) {
					dst.min.store(min, MO);
				}
				for (uint32_t bi = 0; bi < x_smbd_histogram_t::BAND_NUMBER; ++bi) {
					auto tmp = src.bands[bi].load(MO);
					dst.bands[bi].fetch_add(tmp, MO);
					histogram_totals[hi] += tmp;
				}
			}
		}
	}

	bool output(std::string &data) override;

	const uint32_t band_start = 8, band_end = x_smbd_histogram_t::BAND_NUMBER, band_step = 3;
	x_smbd_stats_t stats;
	std::array<uint64_t, X_SMBD_HISTOGRAM_ID_MAX> histogram_totals{};
	uint32_t output_lineno = 0;
};

static void output_counter_header(std::ostream &os)
{
	char buf[1024];
	snprintf(buf, sizeof buf, "    %-20s %10s",
			"Counter", "total");
	os << buf << std::endl;
}

static void output_counter(std::ostream &os, uint64_t total, const char *name)
{
	char buf[1024];
	snprintf(buf, sizeof buf, "    %-20s %10ld",
			name, total);
	os << buf << std::endl;
}

static void output_pair_header(std::ostream &os)
{
	char buf[1024];
	snprintf(buf, sizeof buf, "    %-20s %10s %10s",
			"PairCounter", "create", "delete");
	os << buf << std::endl;
}

static void output_pair(std::ostream &os, uint64_t total_create, uint64_t total_delete, const char *name)
{
	char buf[1024];
	snprintf(buf, sizeof buf, "    %-20s %10ld %10ld",
			name, total_create, total_delete);
	os << buf << std::endl;
}

static void output_histogram_header(std::ostream &os,
		uint32_t band_start, uint32_t band_end, uint32_t band_step)
{
	char buf[1024];
	snprintf(buf, sizeof buf, "    %-20s %10s %15s %15s %9s %12s",
			"Histogram", "total", "sum", "average", "min", "max");
	os << buf;
	uint32_t band;
	uint32_t last_band = 0;
	for (band = band_start; band < band_end; ++band) {
		char bbuf[24];
		if (band == band_end - 1) {
			snprintf(bbuf, sizeof bbuf, ">=2^%u", last_band);
			snprintf(buf, sizeof buf, " %10s", bbuf);
			os << buf;
		} else if (((band - band_start) % band_step) == 0) {
			snprintf(bbuf, sizeof bbuf, "<2^%u", band);
			snprintf(buf, sizeof buf, " %10s", bbuf);
			os << buf;
			last_band = band;
		}
	}
	os << std::endl;
}

#define HISTOGRAM_FMT	"%-20s %10lu %15lu %15.3f %9lu %12lu"
static void output_histogram(std::ostream &os,
		uint32_t band_start, uint32_t band_end, uint32_t band_step,
		const x_smbd_histogram_t &hist, uint64_t total,
		const char *name)
{
	char buf[1024];
	snprintf(buf, sizeof buf, "    " HISTOGRAM_FMT, name,
			total, hist.sum.load(MO), (double)(hist.sum.load(MO)) / (double)total,
			hist.min.load(MO), hist.max.load(MO));
	os << buf;
	uint32_t band;
	uint64_t band_sum = 0;
	for (band = 0; band < band_start; ++band) {
		band_sum += hist.bands[band];
	}

	for (band = band_start; band < band_end; ++band) {
		band_sum += hist.bands[band];
		if (band == band_end - 1 || ((band - band_start) % band_step) == 0) {
			snprintf(buf , sizeof buf, " %10lu", band_sum);
			os << buf;
			band_sum = 0;
		}
	}
	os << std::endl;
}

bool x_smbd_stats_report_t::output(std::string &data)
{
	std::ostringstream os;
	for (;;) {
		if (output_lineno == 0) {
			output_counter_header(os);
		} else if (output_lineno < 1 + X_SMBD_COUNTER_ID_MAX) {
			uint32_t ci = output_lineno - 1;
			auto total = stats.counters[ci].load(MO);
			if (total) {
				output_counter(os, total, smbd_counter_names[ci]);
			}
		} else if (output_lineno == 1 + X_SMBD_COUNTER_ID_MAX) {
			output_pair_header(os);
		} else if (output_lineno < 2 + X_SMBD_COUNTER_ID_MAX + X_SMBD_PAIR_COUNTER_ID_MAX) {
			uint32_t pi = output_lineno - 2 - X_SMBD_COUNTER_ID_MAX;
			auto total_create = stats.pair_counters[pi][0].load(MO);
			auto total_delete = stats.pair_counters[pi][1].load(MO);
			if (total_create != 0 || total_delete != 0) {
				output_pair(os, total_create, total_delete, smbd_pair_counter_names[pi]);
			}
		} else if (output_lineno == 2 + X_SMBD_COUNTER_ID_MAX + X_SMBD_PAIR_COUNTER_ID_MAX) {
			output_histogram_header(os, band_start, band_end, band_step);
		} else if (output_lineno < 3 + X_SMBD_COUNTER_ID_MAX + X_SMBD_PAIR_COUNTER_ID_MAX + X_SMBD_HISTOGRAM_ID_MAX) {
			uint32_t hi = output_lineno - 3 - X_SMBD_COUNTER_ID_MAX - X_SMBD_PAIR_COUNTER_ID_MAX;
			if (histogram_totals[hi] > 0) {
				output_histogram(os, band_start, band_end, band_step,
						stats.histograms[hi], histogram_totals[hi],
						smbd_histogram_names[hi]);
			}
		} else {
			return false;
		}

		data = os.str();
		++output_lineno;

		if (data.size() > 0) {
			break;
		}
	}
	return true;
}

x_smbd_ctrl_handler_t *x_smbd_stats_report_create()
{
	return new x_smbd_stats_report_t;
}

