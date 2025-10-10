
#include "include/iuflog.hxx"
#include <random>
#include <vector>
#include <map>
#include <memory>
#include <atomic>
#include <fcntl.h>
#include <getopt.h>

enum {
	NUM_SLOT = 100,
	MAX_LOG_LENGTH = 0x10000,
};

static std::atomic<uint64_t> g_next_id{1};
static std::atomic<int> g_finished{0};

static thread_local std::mt19937 randgen(std::random_device{}());
static thread_local uint8_t randbuf[MAX_LOG_LENGTH];
static x_iuflog_t *g_iuflog;

struct test_worker_t
{
	test_worker_t(uint32_t counter);
	x_job_t job;
	uint32_t counter;
	std::vector<std::pair<uint64_t, size_t>> logs;
	uint64_t num_initiated = 0, num_updated = 0, num_finalized = 0;
};

struct test_log_save_t
{
	x_iuflog_state_t base;
	const void *const data;
	size_t const length;
};

static ssize_t test_log_save_op_encode(const x_iuflog_state_t *state, void *data, size_t size)
{
	const test_log_save_t *st = X_CONTAINER_OF(state, test_log_save_t, base);
	if (size < st->length) {
		return -EINVAL;
	}
	memcpy(data, st->data, st->length);
	return st->length;
}


struct x_iuflog_state_ops_t test_log_save_ops = {
	nullptr,
	test_log_save_op_encode,
	nullptr,
};


static x_job_t::retval_t test_worker_run(x_job_t *job, void *sche)
{
	test_worker_t *tt = X_CONTAINER_OF(job, test_worker_t, job);

	if (tt->counter == 0) {
		g_finished.fetch_add(1);
		g_finished.notify_all();
		return x_job_t::JOB_DONE;
	}

	--tt->counter;
	int rand = std::uniform_int_distribution<int>(0, 2 * (NUM_SLOT - 1))(randgen);
	int idx = rand / 2;
	bool update = rand % 2;
	auto &p = tt->logs[idx];

	if (p.second == 0) {
		uint64_t myid = g_next_id++;

		uint32_t length = std::uniform_int_distribution<uint32_t>(1, MAX_LOG_LENGTH)(randgen);
		test_log_save_t save{{&test_log_save_ops}, randbuf, length};
		x_iuflog_initiate(g_iuflog, true, myid, &save.base);

		p.first = myid;
		p.second = length;
		++tt->num_initiated;
	} else if (update) {
		uint32_t length = std::uniform_int_distribution<uint32_t>(1, MAX_LOG_LENGTH)(randgen);
		test_log_save_t save{{&test_log_save_ops}, randbuf, length};
		x_iuflog_update(g_iuflog, true, p.first, &save.base);
		p.second = length;
		++tt->num_updated;
	} else {
		x_iuflog_finalize(g_iuflog, true, p.first);
		p.second = 0;
		++tt->num_finalized;
	}

	return x_job_t::JOB_CONTINUE;
}

test_worker_t::test_worker_t(uint32_t counter)
	: job(test_worker_run), counter(counter), logs(NUM_SLOT, {0, 0})
{
}

struct test_log_load_t
{
	x_iuflog_state_t base;
	std::vector<uint8_t> data;
};

static void test_log_load_op_release(x_iuflog_state_t *state)
{
	test_log_load_t *st = X_CONTAINER_OF(state, test_log_load_t, base);
	delete st;
}

static ssize_t test_log_load_op_encode(const x_iuflog_state_t *state, void *data, size_t size)
{
	const test_log_load_t *st = X_CONTAINER_OF(state, test_log_load_t, base);
	if (size < st->data.size()) {
		return -EINVAL;
	}
	memcpy(data, st->data.data(), st->data.size());
	return st->data.size();
}

static int test_log_load_op_update(x_iuflog_state_t *state, const void *data, size_t size)
{
	test_log_load_t *st = X_CONTAINER_OF(state, test_log_load_t, base);
	st->data.assign((const uint8_t *)data, (const uint8_t *)data + size);
	return 0;
}

struct x_iuflog_state_ops_t test_log_load_ops = {
	test_log_load_op_release,
	test_log_load_op_encode,
	test_log_load_op_update,
};

static x_iuflog_state_t *parse_state(uint64_t id, const void *data, size_t size)
{
	auto *ret = new test_log_load_t{{&test_log_load_ops},
		std::vector<uint8_t>((const uint8_t *)data, (const uint8_t *)data + size)};
	return &ret->base;
}

static void open_iuflog(x_threadpool_t *tpool, int fd)
{
	g_iuflog = x_iuflog_open(tpool, fd, parse_state, MAX_LOG_LENGTH,
			1000, 4);
	if (!g_iuflog) {
		fprintf(stderr, "Cannot create iuflog\n");
		exit(1);
	}
	x_iuflog_restore(g_iuflog, [](uint64_t id, x_iuflog_state_t *state) {
		// Just print the log id and length
		return -1;
	});
}

static void usage(const char *progname)
{
	fprintf(stderr, "Usage: %s -c <configfile> [-D] [-o option] [-v]\n",
			progname);
	exit(1);
}

int main(int argc, char **argv)
{
	const char *progname = argv[0];
	// int optind = 0;
	int num_thread = 1, num_worker = 1;
	int count = 100;
	const char *dir = "./tmp-iuflog";
	for (;;) {
		int c = getopt(argc, argv, "c:t:w:d:");
		if (c == -1) {
			break;
		}
		switch (c) {
			case 'c':
				count = atoi(optarg);
				break;
			case 'w':
				num_worker = atoi(optarg);
				break;
			case 't':
				num_thread = atoi(optarg);
				break;
			case 'd':
				dir = optarg;
				break;
			default:
				usage(progname);
		}
	}

	if (optind != argc) {
		usage(progname);
	}

	int dirfd = open(dir, O_RDONLY);
	X_ASSERT(dirfd >= 0);

	x_threadpool_t *tpool = x_threadpool_create("test", num_thread, nullptr);
	open_iuflog(tpool, dirfd);

	std::vector<std::unique_ptr<test_worker_t>> workers;
	workers.reserve(num_worker);

	for (int i = 0; i < num_worker; i++) {
		workers.emplace_back(std::make_unique<test_worker_t>(uint32_t(count)));
	}

	for (auto &w : workers) {
		x_threadpool_schedule(tpool, &w->job);
	}

	int finished = g_finished.load();
	while (finished < num_worker) {
		g_finished.wait(finished);
		finished = g_finished.load();
	}

	x_iuflog_release(g_iuflog);

	std::map<uint64_t, size_t> worker_remaining;
	uint64_t worker_initiated = 0, worker_updated = 0, worker_finalized = 0;
	for (auto &w : workers) {
		for (auto &p : w->logs) {
			if (p.second != 0) {
				auto [it, inserted] = worker_remaining.insert(p);
				X_ASSERT(inserted);
			}
		}
		worker_initiated += w->num_initiated;
		worker_updated += w->num_updated;
		worker_finalized += w->num_finalized;
	}

	std::map<uint64_t, size_t> log_remaining;
	uint64_t log_initiated = 0, log_updated = 0, log_finalized = 0;
	x_iuflog_read(dirfd, MAX_LOG_LENGTH,
		[&](uint64_t id, x_iuflog_record_type_t type,
			const void *data, size_t size) {
			if (type == x_iuflog_record_type_t::initiate) {
				auto [it, inserted] = log_remaining.insert({id, size});
				X_ASSERT(inserted);
				log_initiated++;
			} else if (type == x_iuflog_record_type_t::update) {
				auto it = log_remaining.find(id);
				X_ASSERT(it != log_remaining.end());
				it->second = size;
				log_updated++;
			} else if (type == x_iuflog_record_type_t::finalize) {
				log_remaining.erase(id);
				log_finalized++;
			} else {
				X_ASSERT(false);
			}
			return 0;
		});

	printf("Worker initiated: %lu, updated: %lu, finalized: %lu, remaining: %lu\n",
		worker_initiated, worker_updated, worker_finalized, worker_remaining.size());
	printf("Log initiated: %lu, updated: %lu, finalized: %lu, remaining: %lu\n",
		log_initiated, log_updated, log_finalized, log_remaining.size());
	X_ASSERT(worker_remaining == log_remaining);
	return 0;
}

