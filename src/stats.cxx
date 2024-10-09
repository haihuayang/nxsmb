
#include "include/utils.hxx"
#include "stats.hxx"
#include <vector>

static struct {
	uint32_t num_counter;
	uint32_t num_pair_counter;
	uint32_t num_histogram;
	uint32_t num_thread;
	x_stats_t **stats_table{};
} g_stats;

thread_local x_stats_t local_stats;

void x_stats_init(uint32_t num_thread, uint32_t num_counter,
		uint32_t num_pair_counter, uint32_t num_histogram)
{
	X_ASSERT(!g_stats.stats_table);
	g_stats.num_counter = num_counter;
	g_stats.num_pair_counter = num_pair_counter;
	g_stats.num_histogram = num_histogram;
	g_stats.num_thread = num_thread;
	g_stats.stats_table = new x_stats_t*[num_thread]{};
}

int x_stats_register(uint32_t thread_id)
{
	X_ASSERT(thread_id < g_stats.num_thread);
	if (g_stats.stats_table[thread_id]) {
		return 0;
	}
	
	size_t alloc_size = sizeof(*local_stats.counters) * g_stats.num_counter
		+ sizeof(*local_stats.pair_counters) * 2 * g_stats.num_pair_counter
		+ sizeof(*local_stats.histograms) * g_stats.num_histogram;

	uint8_t *ptr = (uint8_t *)malloc(alloc_size);

	local_stats.counters = (uint64_t *)ptr;
	memset(ptr, 0, sizeof(*local_stats.counters) * g_stats.num_counter);
	ptr += sizeof(*local_stats.counters) * g_stats.num_counter;

	local_stats.pair_counters = (uint64_t *)ptr;
	memset(ptr, 0, sizeof(*local_stats.counters) * 2 * g_stats.num_pair_counter);
	ptr += sizeof(*local_stats.pair_counters) * 2 * g_stats.num_pair_counter;

	local_stats.histograms = new(ptr) x_histogram_t[g_stats.num_histogram];

	g_stats.stats_table[thread_id] = &local_stats;
	return 0;
}

void x_stats_unregister(uint32_t thread_id)
{
	/* we do not free the thread local stats, later new thread allocated
	 * with the same thread_id can keep using the local stats.
	 */
}

template <class LR>
void x_stats_cumulate(x_stats_store_t &store, const LR &load_reset)
{
	for (uint32_t ti = 0; ti < g_stats.num_thread; ++ti) {
		auto thread_stats = g_stats.stats_table[ti];
		if (!thread_stats) {
			continue;
		}
		for (uint32_t ci = 0; ci < g_stats.num_counter; ++ci) {
			store.counters[ci] += load_reset(thread_stats->counters[ci], 0);
		}

		for (uint32_t pi = 0; pi < g_stats.num_pair_counter * 2; ++pi) {
			store.pair_counters[pi] += load_reset(thread_stats->pair_counters[pi], 0);
		}

		for (uint32_t hi = 0; hi < g_stats.num_histogram; ++hi) {
			auto &dst = store.histograms[hi];
			auto &src = thread_stats->histograms[hi];
			dst.sum += load_reset(src.sum, 0);
			auto max = load_reset(src.max, 0);
			auto min = load_reset(src.min, -1);
			if (dst.max < max) {
				dst.max = max;
			}
			if (dst.min > min) {
				dst.min = min;
			}
			for (uint32_t bi = 0; bi < X_HISTOGRAM_BAND_NUMBER; ++bi) {
				auto val = load_reset(src.bands[bi], 0);
				dst.bands[bi] += val;
				store.histogram_totals[hi] += val;
			}
		}
	}
}

void x_stats_load(x_stats_store_t &store)
{
	x_stats_cumulate(store, [](uint64_t &dst, uint64_t val) {
			return __atomic_load_n(&dst, __ATOMIC_RELAXED);
		});
}

void x_stats_collect(x_stats_store_t &store)
{
	x_stats_cumulate(store, [](uint64_t &dst, uint64_t val) {
			return __atomic_exchange_n(&dst, val, __ATOMIC_RELAXED);
		});
}

void x_stats_store_t::init()
{
	X_ASSERT(g_stats.stats_table);
	counters.resize(g_stats.num_counter);
	pair_counters.resize(g_stats.num_pair_counter * 2);
	histogram_totals.resize(g_stats.num_histogram);
	histograms.resize(g_stats.num_histogram);
}

void x_stats_store_t::merge(const x_stats_store_t &other)
{
	for (uint32_t ci = 0; ci < g_stats.num_counter; ++ci) {
		counters[ci] += other.counters[ci];
	}

	for (uint32_t pi = 0; pi < g_stats.num_pair_counter * 2; ++pi) {
		pair_counters[pi] += other.pair_counters[pi];
	}

	for (uint32_t hi = 0; hi < g_stats.num_histogram; ++hi) {
		histogram_totals[hi] += other.histogram_totals[hi];
		auto &dst = histograms[hi];
		auto &src = other.histograms[hi];
		dst.sum += src.sum;
		if (dst.max < src.max) {
			dst.max = src.max;
		}
		if (dst.min > src.min) {
			dst.min = src.min;
		}
		for (uint32_t bi = 0; bi < X_HISTOGRAM_BAND_NUMBER; ++bi) {
			dst.bands[bi] += src.bands[bi];
		}
	}
}

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
		const x_histogram_t &hist, uint64_t total,
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

	for (; band < X_HISTOGRAM_BAND_NUMBER; ++band) {
		band_sum += hist.bands[band];
	}
	snprintf(buf , sizeof buf, " %10lu", band_sum);
	os << buf << std::endl;
}

std::string x_stats_output(const x_stats_store_t &stats,
		const char *const counter_names[],
		const char *const pair_counter_names[],
		const char *const histogram_names[],
		uint32_t band_start, uint32_t band_group, uint32_t band_step)
{
	std::ostringstream os;
	bool first = true;
	for (uint32_t ci = 0; ci < g_stats.num_counter; ++ci) {
		auto total = stats.counters[ci];
		if (total) {
			if (first) {
				output_counter_header(os);
				first = false;
			}
			output_counter(os, total, counter_names[ci]);
		}
	}

	first = true;
	for (uint32_t pi = 0; pi < g_stats.num_pair_counter; ++pi) {
		auto total_create = stats.pair_counters[pi * 2];
		auto total_delete = stats.pair_counters[pi * 2 + 1];
		if (total_create != 0 || total_delete != 0) {
			if (first) {
				output_pair_header(os);
				first = false;
			}
			output_pair(os, total_create, total_delete, pair_counter_names[pi]);
		}
	}

	first = true;
	for (uint32_t hi = 0; hi < g_stats.num_histogram; ++hi) {
		if (stats.histogram_totals[hi] > 0) {
			if (first) {
				output_histogram_header(os, band_start, band_group, band_step);
				first = false;
			}
			output_histogram(os, band_start, band_group, band_step,
					stats.histograms[hi],
					stats.histogram_totals[hi],
					histogram_names[hi]);
		}
	}

	return os.str();
}
