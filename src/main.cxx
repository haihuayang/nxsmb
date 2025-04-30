
#include "smbd.hxx"
#include "noded.hxx"
#include "nxfsd_stats.hxx"
#include "smbd_conf.hxx"
#include "nxfsd.hxx"
#include "include/version.hxx"
#include <sys/uio.h>
#include <getopt.h>
#include <openssl/crypto.h>
#include <sys/resource.h>
#include <pthread.h>

static struct {
	volatile bool stopped = false;
	bool do_async = false;
	x_threadpool_t *tpool_evtmgmt{}, *tpool_async{};
	x_tick_t tick_start_mono, tick_start_real;
	pthread_t signal_handler_thread;
} g_nxfsd;

static __thread int thread_id = -1;
static x_bitmap_t g_thread_id_bitmap{X_NXFSD_MAX_THREAD};
static std::mutex g_thread_id_mutex;

static void x_nxfsd_thread_init(uint32_t no)
{
	{
		auto lock = std::lock_guard(g_thread_id_mutex);
		thread_id = g_thread_id_bitmap.alloc();
	}
	X_LOG(UTILS, NOTICE, "allocate thread_id %u", thread_id);
	x_nxfsd_stats_register(thread_id);
}

static void *signal_handler_func(void *arg)
{
	x_thread_init("SIGHAND");
	x_nxfsd_thread_init(0);

	x_tick_t last = x_tick_now();
	auto smbd_conf = x_smbd_conf_get();

	for (;;) {
		sigset_t sigmask;
		sigemptyset(&sigmask);
		sigaddset(&sigmask, SIGTERM);
		sigaddset(&sigmask, SIGHUP);

		siginfo_t siginfo;
		uint64_t timeout = X_SEC_TO_NSEC(60);
		if (smbd_conf->my_stats_interval_ms > 0) {
			x_tick_t now = x_tick_now();
			x_tick_t next = last +
				X_MSEC_TO_NSEC(smbd_conf->my_stats_interval_ms);
			if (now >= next) {
				x_nxfsd_stats_report();
				last = now;
				timeout = X_MSEC_TO_NSEC(smbd_conf->my_stats_interval_ms);
			} else {
				timeout = next - last;
			}
		}
		struct timespec ts;
		if (timeout > X_SEC_TO_NSEC(60)) {
			ts = { 60, 0, };
		} else if (timeout < 1000) {
			ts = { 0, 1000, };
		} else {
			ts = { long(timeout / X_NSEC_PER_SEC),
				long(timeout % X_NSEC_PER_SEC), };
		}

		int ret = sigtimedwait(&sigmask, &siginfo, &ts);
		if (ret == -1) {
			if (errno == EAGAIN) {
				x_log_check_size();
			}
		} else if (ret == SIGHUP) {
			x_smbd_conf_reload();
			smbd_conf = x_smbd_conf_get();
		} else {
			X_LOG(UTILS, ERR, "sigtimedwait ret %d, errno=%d", ret, errno);
			break;
		}
	}
	g_nxfsd.stopped = true;
	return nullptr;
}

static void main_loop()
{
	while (!g_nxfsd.stopped) {
		x_evtmgmt_dispatch(g_evtmgmt);
	}
	/* TODO clean up */
}

static void nxfsd_init(const char *progname)
{
	auto smbd_conf = x_smbd_conf_get();

	x_log_init(smbd_conf->log_name.c_str(), smbd_conf->log_level.c_str(),
			smbd_conf->log_file_size);

	X_LOG(UTILS, NOTICE, "%s build %s %s %s %s %s starting",
			progname,
			g_build.version, g_build.git_hash,
			g_build.build_type,
			g_build.date,
			g_build.branch);

	x_sched_stats_init();
	x_smbd_stats_init();
	x_noded_stats_init();
	x_nxfsd_stats_init();

	x_nxfsd_thread_init(0);

	struct timespec ts_now;
	x_tick_t tick_now1 = x_tick_now();
	clock_gettime(CLOCK_REALTIME, &ts_now);
	x_tick_t tick_now2 = x_tick_now();

	g_nxfsd.tick_start_mono = tick_now1 + (tick_now2 - tick_now1) / 2;
	g_nxfsd.tick_start_real = x_tick_from_timespec(ts_now);

	/* durable db use rand() to pick slot */
	srand((unsigned int)tick_now2.val);

	uint32_t max_opens = std::max(smbd_conf->max_opens, 1024u);
	/* reserver 80 fd for other purpose for now */
	uint32_t max_fd = max_opens + smbd_conf->max_connections + 80;
	struct rlimit rl_nofile;
	X_ASSERT(getrlimit(RLIMIT_NOFILE, &rl_nofile) == 0);
	X_LOG(UTILS, DBG, "RLIMIT_NOFILE max=%lu cur=%lu",
			rl_nofile.rlim_max, rl_nofile.rlim_cur);
	if (rl_nofile.rlim_cur < max_fd) {
		rl_nofile.rlim_max = rl_nofile.rlim_cur = max_fd;
		X_ASSERT(setrlimit(RLIMIT_NOFILE, &rl_nofile) == 0);
	}

	signal(SIGPIPE, SIG_IGN);
	sigset_t sigmask, osigmask;
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGTERM);
	sigaddset(&sigmask, SIGHUP);
	/* block signals for threads */
	X_ASSERT(pthread_sigmask(SIG_BLOCK, &sigmask, &osigmask) == 0);

	int err = pthread_create(&g_nxfsd.signal_handler_thread, nullptr,
			signal_handler_func, nullptr);
	X_ASSERT(err == 0);

	g_nxfsd.tpool_async = x_threadpool_create("ASYNC", smbd_conf->async_thread_count, x_nxfsd_thread_init);
	x_threadpool_t *tpool = x_threadpool_create("CLIENT", smbd_conf->client_thread_count, x_nxfsd_thread_init);
	g_nxfsd.tpool_evtmgmt = tpool;

	g_evtmgmt = x_evtmgmt_create(tpool, max_fd, 1000, 100);

	x_nxfsd_context_init();

	x_nxfsd_requ_pool_init(smbd_conf->max_requs);

	x_smbd_init();
	x_noded_init();
	x_smbd_ctrl_init();
}

static void usage(const char *progname)
{
	fprintf(stderr, "Usage: %s -c <configfile> [-D] [-o option] [-v]\n",
			progname);
	exit(1);
}

int main(int argc, char **argv)
{
	x_thread_init("MAIN");

	const char *configfile = nullptr;

	const struct option long_options[] = {
		{ "configfile", required_argument, 0, 'c'},
		{ "daemon", required_argument, 0, 'D'},
		{ "option", required_argument, 0, 'o'},
		{ "version", required_argument, 0, 'v'},
	};

	const char *progname = argv[0];
	std::vector<std::string> cmdline_options;
	bool daemon = false;
	int optind = 0;
	for (;;) {
		int c = getopt_long(argc, argv, "c:Dvo:",
				long_options, &optind);
		if (c == -1) {
			break;
		}
		switch (c) {
			case 'c':
				configfile = optarg;
				break;
			case 'D':
				daemon = true;
				break;
			case 'o':
				cmdline_options.push_back(optarg);
				break;
			case 'v':
				printf("%s build %s %s %s %s %s\n",
						progname,
						g_build.version, g_build.git_hash,
						g_build.build_type,
						g_build.date,
						g_build.branch);
				exit(0);
			default:
				usage(progname);
		}
	}

	if (!configfile) {
		configfile = "/my/samba/etc/smb.conf";
	}
	int err = x_smbd_conf_init(configfile, cmdline_options);
	if (err < 0) {
		fprintf(stderr, "x_smbd_conf_init failed %d\n", err);
		exit(1);
	}

	// TODO daemonize
	(void)daemon;

	OPENSSL_init();
	FIPS_mode_set(0);

	nxfsd_init(progname);

	main_loop();

	x_threadpool_destroy(g_nxfsd.tpool_evtmgmt);
	x_threadpool_destroy(g_nxfsd.tpool_async);
	pthread_join(g_nxfsd.signal_handler_thread, nullptr);
	return 0;
}

void x_smbd_schedule_async(x_job_t *job)
{
	bool ret = x_threadpool_schedule(g_nxfsd.tpool_async, job);
	X_ASSERT(ret);
}

std::array<x_tick_t, 2> x_smbd_get_time()
{
	return { g_nxfsd.tick_start_real,
		g_nxfsd.tick_start_real + (tick_now - g_nxfsd.tick_start_mono)};
}
