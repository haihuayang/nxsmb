
#include "smbd.hxx"
#include <atomic>
#include <memory>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <openssl/crypto.h>
#include <sys/resource.h>
#include <pthread.h>

#include "smbd_conf.hxx"
#include "network.hxx"
#include "smbd_lease.hxx"
#include "smbd_replay.hxx"
#include "smbd_secrets.hxx"
#include "smbd_stats.hxx"
#include "smbd_registry.hxx"
#include "smbd_requ.hxx"
#include "auth.hxx"

#include "smb2.hxx"

static struct {
	volatile bool stopped = false;
	bool do_async = false;
	x_threadpool_t *tpool_evtmgmt{}, *tpool_async{};
	x_wbpool_t *wbpool;
	x_auth_context_t *auth_context;
	std::vector<uint8_t> negprot_spnego;
	x_tick_t tick_start_mono, tick_start_real;
	x_tick_diff_t timers[static_cast<int>(x_smbd_timer_id_t::LAST)];
	pthread_t signal_handler_thread;
} g_smbd;


x_evtmgmt_t *g_evtmgmt = nullptr;

static void main_loop()
{
	while (!g_smbd.stopped) {
		x_evtmgmt_dispatch(g_evtmgmt);
	}
	/* TODO clean up */
}

x_auth_t *x_smbd_create_auth(const void *sec_buf, size_t sec_len)
{
	if (sec_len >= 8 && memcmp(sec_buf, "NTLMSSP", 8) == 0) {
		return x_auth_create_ntlmssp(g_smbd.auth_context);
	}
	return x_auth_create_by_oid(g_smbd.auth_context, GSS_SPNEGO_MECHANISM);
}

static __thread int thread_id = -1;
static std::array<uint64_t, X_SMBD_MAX_THREAD / sizeof(uint64_t) / 8> g_thread_id_bitmap{};
static std::mutex g_thread_id_mutex;

static uint32_t thread_id_allocate()
{
	auto lock = std::lock_guard(g_thread_id_mutex);
	uint32_t ret = 0;
	for (auto &bitmap : g_thread_id_bitmap) {
		int index = __builtin_ffsl(~bitmap);
		if (index != 0) {
			int bit = index - 1;
			bitmap |= (1ul << bit);
			return ret + bit;
		}
		ret += 64;
	}
	X_ASSERT(false);
	return -1;
}

static void x_smbd_thread_init(uint32_t no)
{
	thread_id = thread_id_allocate();
	X_LOG(UTILS, NOTICE, "allocate thread_id %u", thread_id);
	x_smbd_stats_init(thread_id);
}

enum {
	X_SMBD_MAX_SESSION = 1024,
	X_SMBD_MAX_TCON = 1024,
	X_SMBD_MAX_REQUEST = 64 * 1024,
};

static void *signal_handler_func(void *arg)
{
	x_thread_init("SIGHAND");
	x_smbd_thread_init(0);

	for (;;) {
		sigset_t sigmask;
		sigemptyset(&sigmask);
		sigaddset(&sigmask, SIGTERM);
		sigaddset(&sigmask, SIGHUP);

		siginfo_t siginfo;
		struct timespec timeout = { 60, 0 };
		int ret = sigtimedwait(&sigmask, &siginfo, &timeout);
		if (ret == -1) {
			if (errno == EAGAIN) {
				x_log_check_size();
			}
		} else if (ret == SIGHUP) {
			x_smbd_conf_reload();
		} else {
			X_LOG(UTILS, ERR, "sigtimedwait ret %d, errno=%d", ret, errno);
			break;
		}
	}
	g_smbd.stopped = true;
	return nullptr;
}

static void init_smbd()
{
	auto smbd_conf = x_smbd_conf_get();

	x_log_init(smbd_conf->log_name.c_str(), smbd_conf->log_level.c_str(),
			smbd_conf->log_file_size);

	struct timespec ts_now;
	x_tick_t tick_now1 = x_tick_now();
	clock_gettime(CLOCK_REALTIME, &ts_now);
	x_tick_t tick_now2 = x_tick_now();

	g_smbd.tick_start_mono = tick_now1 + (tick_now2 - tick_now1) / 2;
	g_smbd.tick_start_real = x_tick_from_timespec(ts_now);

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

	int err = pthread_create(&g_smbd.signal_handler_thread, nullptr,
			signal_handler_func, nullptr);
	X_ASSERT(err == 0);

	g_smbd.tpool_async = x_threadpool_create("ASYNC", smbd_conf->async_thread_count, x_smbd_thread_init);
	x_threadpool_t *tpool = x_threadpool_create("CLIENT", smbd_conf->client_thread_count, x_smbd_thread_init);
	g_smbd.tpool_evtmgmt = tpool;

	g_evtmgmt = x_evtmgmt_create(tpool, max_fd, 1000, 100);

	g_smbd.wbpool = x_wbpool_create(g_evtmgmt, 2,
			smbd_conf->samba_locks_dir + "/winbindd_privileged/pipe");

	x_smbd_registry_init();

	x_smbd_object_pool_init(max_opens);
	x_smbd_open_table_init(max_opens);
	x_smbd_tcon_table_init(X_SMBD_MAX_TCON);
	x_smbd_sess_table_init(X_SMBD_MAX_SESSION);
	x_smbd_requ_pool_init(max_opens); // TODO use max_opens for now
	x_smbd_lease_pool_init(max_opens, max_opens / 16); // TODO use max_opens for now
	x_smbd_replay_cache_init(max_opens, max_opens / 16); // TODO use max_opens for now

	x_smbd_ipc_init();
	x_smbd_posixfs_init(max_opens);
	x_smbd_ctrl_init(g_evtmgmt);

	g_smbd.auth_context = x_auth_create_context();
	x_auth_krb5_init(g_smbd.auth_context);
	x_auth_ntlmssp_init(g_smbd.auth_context);
	x_auth_spnego_init(g_smbd.auth_context);

	x_auth_t *spnego(x_smbd_create_auth(nullptr, 0));

	if (spnego) {
		std::vector<uint8_t> negprot_spnego;
		std::shared_ptr<x_auth_info_t> auth_info;
		NTSTATUS status = spnego->update(NULL, 0, false, 0,
				negprot_spnego, NULL, auth_info);
		X_ASSERT(NT_STATUS_IS_OK(status));
		g_smbd.negprot_spnego.swap(negprot_spnego);
		x_auth_destroy(spnego);
	}

#define TIMER_INIT(id, ms) g_smbd.timers[static_cast<int>(id)] = X_MSEC_TO_NSEC(ms)
	TIMER_INIT(x_smbd_timer_id_t::SESSSETUP, smbd_conf->sess_setup_timeout_ms);
	TIMER_INIT(x_smbd_timer_id_t::BREAK, smbd_conf->smb2_break_timeout_ms);

	x_smbd_init_shares(*smbd_conf);

	x_smbd_conn_srv_init(smbd_conf->port);
}

const std::vector<uint8_t> &x_smbd_get_negprot_spnego()
{
	return g_smbd.negprot_spnego;
}

void x_smbd_add_timer(x_timer_job_t *entry, x_smbd_timer_id_t timer_id)
{
	x_evtmgmt_add_timer(g_evtmgmt, entry,
			g_smbd.timers[static_cast<int>(timer_id)]);
}

void x_smbd_add_timer(x_timer_job_t *entry, x_tick_diff_t expires)
{
	x_evtmgmt_add_timer(g_evtmgmt, entry, expires);
}

bool x_smbd_del_timer(x_timer_job_t *entry)
{
	return x_evtmgmt_del_timer(g_evtmgmt, entry);
}

int main(int argc, char **argv)
{
	x_thread_init("MAIN");
	x_smbd_thread_init(0);

	const char *configfile = nullptr;

	const struct option long_options[] = {
		{ "configfile", required_argument, 0, 'c'},
		{ "daemon", required_argument, 0, 'D'},
		{ "option", required_argument, 0, 'o'},
	};

	std::vector<std::string> cmdline_options;
	bool daemon = false;
	int optind = 0;
	for (;;) {
		int c = getopt_long(argc, argv, "c:D:o:",
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
			default:
				abort();
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

	init_smbd();

	main_loop();

	x_threadpool_destroy(g_smbd.tpool_evtmgmt);
	x_threadpool_destroy(g_smbd.tpool_async);
	pthread_join(g_smbd.signal_handler_thread, nullptr);
	return 0;
}

void x_smbd_wbpool_request(x_wbcli_t *wbcli)
{
	x_wbpool_request(g_smbd.wbpool, wbcli);
}

void x_smbd_schedule_async(x_job_t *job)
{
	bool ret = x_threadpool_schedule(g_smbd.tpool_async, job);
	X_ASSERT(ret);
}

std::array<x_tick_t, 2> x_smbd_get_time()
{
	return { g_smbd.tick_start_real,
		g_smbd.tick_start_real + (tick_now - g_smbd.tick_start_mono)};
}

