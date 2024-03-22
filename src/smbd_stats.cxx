
#include "smbd_stats.hxx"
#include "smbd_ctrl.hxx"

thread_local x_smbd_stats_t<atomic_relaxed_t> *g_smbd_stats;

static x_smbd_stats_t<atomic_relaxed_t> g_smbd_stats_table[X_SMBD_MAX_THREAD];
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

template <class T>
struct single_threaded_t
{
	T val;
	operator T() const {
		return val;
	}
	T operator+=(T v) {
		return val += v;
	}
	void operator=(T v) {
		val = v;
	}
};

static x_smbd_stats_t<single_threaded_t> g_stats;

struct x_smbd_stats_report_t : x_smbd_ctrl_handler_t
{
	x_smbd_stats_report_t() {
		uint32_t max_thread = g_max_thread.load(MO);
		for (uint32_t ti = 0; ti < max_thread; ++ti) {
			const auto &thread_stats = g_smbd_stats_table[ti];
			for (uint32_t ci = 0; ci < X_SMBD_COUNTER_ID_MAX; ++ci) {
				stats.counters[ci] += thread_stats.counters[ci];
			}

			for (uint32_t pi = 0; pi < X_SMBD_PAIR_COUNTER_ID_MAX; ++pi) {
				stats.pair_counters[pi][0] += thread_stats.pair_counters[pi][0];
				stats.pair_counters[pi][1] += thread_stats.pair_counters[pi][1];
			}

			for (uint32_t hi = 0; hi < X_SMBD_HISTOGRAM_ID_MAX; ++hi) {
				auto &dst = stats.histograms[hi];
				auto &src = thread_stats.histograms[hi];
				dst.sum += src.sum;
				if (dst.max < src.max) {
					dst.max = src.max;
				}
				if (dst.min > src.min) {
					dst.min = src.min;
				}
				for (uint32_t bi = 0; bi < X_SMBD_HISTOGRAM_BAND_NUMBER; ++bi) {
					dst.bands[bi] += src.bands[bi];
					histogram_totals[hi] += src.bands[bi];
				}
			}
		}
	}

	bool output(std::string &data) override;

	const uint32_t band_start = 3, band_group = 8, band_step = 3;
	x_smbd_stats_t<single_threaded_t> stats;
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
		uint32_t band_start, uint32_t band_group, uint32_t band_step)
{
	char buf[512];
	char bbuf[24];
	snprintf(buf, sizeof buf, "    %-20s %10s %15s %9s %12s",
			"Histogram", "total", "average", "min", "max");
	os << buf;
	uint32_t band = band_start;
	for (uint32_t i = 0; i < band_group; ++i, band += band_step) {
		snprintf(bbuf, sizeof bbuf, "<2^%u", band);
		snprintf(buf, sizeof buf, " %10s", bbuf);
		os << buf;
	}
	snprintf(bbuf, sizeof bbuf, ">=2^%u", band);
	snprintf(buf, sizeof buf, " %10s", bbuf);
	os << buf << std::endl;
}

#define HISTOGRAM_FMT	"%-20s %10lu %15.3f %9lu %12lu"
static void output_histogram(std::ostream &os,
		uint32_t band_start, uint32_t band_group, uint32_t band_step,
		const x_smbd_histogram_t<single_threaded_t> &hist, uint64_t total,
		const char *name)
{
	char buf[512];
	snprintf(buf, sizeof buf, "    " HISTOGRAM_FMT, name,
			total, double(hist.sum) / double(total),
			uint64_t(hist.min), uint64_t(hist.max));
	os << buf;
	uint32_t band;
	uint64_t band_sum = 0;
	for (band = 0; band < band_start; ++band) {
		band_sum += hist.bands[band];
	}

	for (uint32_t i = 0; i < band_group; ++i) {
		band_sum += hist.bands[band];
		snprintf(buf , sizeof buf, " %10lu", band_sum);
		os << buf;
		band_sum = 0;

		++band;
		for (uint32_t j = 1; j < band_step; ++j, ++band) {
			band_sum += hist.bands[band];
		}
	}

	for (; band < X_SMBD_HISTOGRAM_BAND_NUMBER; ++band) {
		band_sum += hist.bands[band];
	}
	snprintf(buf , sizeof buf, " %10lu", band_sum);
	os << buf << std::endl;
}

bool x_smbd_stats_report_t::output(std::string &data)
{
	std::ostringstream os;
	for (;;) {
		if (output_lineno == 0) {
			output_counter_header(os);
		} else if (output_lineno < 1 + X_SMBD_COUNTER_ID_MAX) {
			uint32_t ci = output_lineno - 1;
			auto total = stats.counters[ci];
			if (total) {
				output_counter(os, total, smbd_counter_names[ci]);
			}
		} else if (output_lineno == 1 + X_SMBD_COUNTER_ID_MAX) {
			output_pair_header(os);
		} else if (output_lineno < 2 + X_SMBD_COUNTER_ID_MAX + X_SMBD_PAIR_COUNTER_ID_MAX) {
			uint32_t pi = output_lineno - 2 - X_SMBD_COUNTER_ID_MAX;
			auto total_create = stats.pair_counters[pi][0];
			auto total_delete = stats.pair_counters[pi][1];
			if (total_create != 0 || total_delete != 0) {
				output_pair(os, total_create, total_delete, smbd_pair_counter_names[pi]);
			}
		} else if (output_lineno == 2 + X_SMBD_COUNTER_ID_MAX + X_SMBD_PAIR_COUNTER_ID_MAX) {
			output_histogram_header(os, band_start, band_group, band_step);
		} else if (output_lineno < 3 + X_SMBD_COUNTER_ID_MAX + X_SMBD_PAIR_COUNTER_ID_MAX + X_SMBD_HISTOGRAM_ID_MAX) {
			uint32_t hi = output_lineno - 3 - X_SMBD_COUNTER_ID_MAX - X_SMBD_PAIR_COUNTER_ID_MAX;
			if (histogram_totals[hi] > 0) {
				output_histogram(os, band_start, band_group, band_step,
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

void x_smbd_stats_report()
{
	x_smbd_stats_t<single_threaded_t> stats;
	std::array<uint64_t, X_SMBD_HISTOGRAM_ID_MAX> histogram_totals{};
	uint32_t max_thread = g_max_thread.load(MO);
	for (uint32_t ti = 0; ti < max_thread; ++ti) {
		auto &thread_stats = g_smbd_stats_table[ti];
		for (uint32_t ci = 0; ci < X_SMBD_COUNTER_ID_MAX; ++ci) {
			stats.counters[ci] += thread_stats.counters[ci].reset(0);
		}

		for (uint32_t pi = 0; pi < X_SMBD_PAIR_COUNTER_ID_MAX; ++pi) {
			stats.pair_counters[pi][0] += thread_stats.pair_counters[pi][0].reset(0);
			stats.pair_counters[pi][1] += thread_stats.pair_counters[pi][1].reset(0);
		}

		for (uint32_t hi = 0; hi < X_SMBD_HISTOGRAM_ID_MAX; ++hi) {
			auto &dst = stats.histograms[hi];
			auto &src = thread_stats.histograms[hi];
			dst.sum += src.sum.reset(0);
			auto max = src.max.reset(0);
			auto min = src.min.reset(-1);
			if (dst.max < max) {
				dst.max = max;
			}
			if (dst.min > min) {
				dst.min = min;
			}
			for (uint32_t bi = 0; bi < X_SMBD_HISTOGRAM_BAND_NUMBER; ++bi) {
				auto val = src.bands[bi].reset(0);
				dst.bands[bi] += val;
				histogram_totals[hi] += val;
			}
		}
	}

	std::ostringstream os;
	bool first = true;
	/* keep in g_stats */
	for (uint32_t ci = 0; ci < X_SMBD_COUNTER_ID_MAX; ++ci) {
		auto total = stats.counters[ci];
		if (total) {
			if (first) {
				output_counter_header(os);
				first = false;
			}
			output_counter(os, total, smbd_counter_names[ci]);
		}
		g_stats.counters[ci] += total;
	}

	first = true;
	for (uint32_t pi = 0; pi < X_SMBD_PAIR_COUNTER_ID_MAX; ++pi) {
		auto total_create = stats.pair_counters[pi][0];
		auto total_delete = stats.pair_counters[pi][1];
		if (total_create != 0 || total_delete != 0) {
			if (first) {
				output_pair_header(os);
				first = false;
			}
			output_pair(os, total_create, total_delete, smbd_pair_counter_names[pi]);
		}
		g_stats.pair_counters[pi][0] += total_create;
		g_stats.pair_counters[pi][1] += total_delete;
	}

	const uint32_t band_start = 3, band_group = 8, band_step = 3;
	first = true;
	for (uint32_t hi = 0; hi < X_SMBD_HISTOGRAM_ID_MAX; ++hi) {
		if (histogram_totals[hi] > 0) {
			if (first) {
				output_histogram_header(os, band_start, band_group, band_step);
				first = false;
			}
			output_histogram(os, band_start, band_group, band_step,
					stats.histograms[hi], histogram_totals[hi],
					smbd_histogram_names[hi]);
		}
		auto &dst = g_stats.histograms[hi];
		auto &src = stats.histograms[hi];
		dst.sum += src.sum;
		auto max = src.max;
		auto min = src.min;
		if (dst.max < max) {
			dst.max = max;
		}
		if (dst.min > min) {
			dst.min = min;
		}
		for (uint32_t bi = 0; bi < X_SMBD_HISTOGRAM_BAND_NUMBER; ++bi) {
			auto val = src.bands[bi];
			dst.bands[bi] += val;
		}
	}

	auto data = os.str();
	if (!data.empty()) {
		X_LOG(SMB, NOTICE, "stats:\n%s", data.c_str());
	}
}

