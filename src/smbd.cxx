
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

#include "smbd_conf.hxx"
#include "network.hxx"
#include "smbd_lease.hxx"
#include "smbd_secrets.hxx"
#include "smbd_stats.hxx"
#include "auth.hxx"

#include "smb2.hxx"

static struct {
	bool do_async = false;
	x_threadpool_t *tpool_evtmgmt{}, *tpool_async;
	x_wbpool_t *wbpool;
	x_auth_context_t *auth_context;
	std::vector<uint8_t> negprot_spnego;
	x_timerq_t timerq[static_cast<int>(x_smbd_timer_t::LAST)];
} g_smbd;

static inline x_timerq_t &get_timerq(x_smbd_timer_t timer_id)
{
	return g_smbd.timerq[static_cast<int>(timer_id)];
}

x_evtmgmt_t *g_evtmgmt = nullptr;

static void main_loop()
{
	snprintf(task_name, sizeof task_name, "MAIN");
	for (;;) {
		x_evtmgmt_dispatch(g_evtmgmt);
	}
}

x_auth_t *x_smbd_create_auth()
{
	return x_auth_create_by_oid(g_smbd.auth_context, GSS_SPNEGO_MECHANISM);
}

enum {
	X_SMBD_MAX_SESSION = 1024,
	X_SMBD_MAX_TCON = 1024,
	X_SMBD_MAX_OPEN = 1024,
	X_SMBD_MAX_REQUEST = 1024,
};

static void init_smbd()
{
	auto smbd_conf = x_smbd_conf_get();

	x_log_init(smbd_conf->log_level.c_str(), smbd_conf->log_name.c_str());

	x_smbd_stats_init();

	g_smbd.tpool_async = x_threadpool_create(smbd_conf->async_thread_count);
	x_threadpool_t *tpool = x_threadpool_create(smbd_conf->client_thread_count);
	g_smbd.tpool_evtmgmt = tpool;

	g_evtmgmt = x_evtmgmt_create(tpool, 0);
	g_smbd.wbpool = x_wbpool_create(g_evtmgmt, 2);

	x_smbd_open_table_init(X_SMBD_MAX_OPEN);
	x_smbd_tcon_table_init(X_SMBD_MAX_TCON);
	x_smbd_sess_table_init(X_SMBD_MAX_SESSION);
	x_smbd_requ_pool_init(X_SMBD_MAX_OPEN); // TODO use X_SMBD_MAX_OPEN for now
	x_smbd_lease_pool_init(X_SMBD_MAX_OPEN, X_SMBD_MAX_OPEN / 16); // TODO use X_SMBD_MAX_OPEN for now

	x_smbd_ipc_init();
	x_smbd_posixfs_init(X_SMBD_MAX_OPEN);
	x_smbd_ctrl_init(g_evtmgmt);

	int err = x_smbd_secrets_init();
	X_ASSERT(err == 0);

	g_smbd.auth_context = x_auth_create_context();
	x_auth_krb5_init(g_smbd.auth_context);
	x_auth_ntlmssp_init(g_smbd.auth_context);
	x_auth_spnego_init(g_smbd.auth_context);

	x_auth_t *spnego(x_smbd_create_auth());

	if (spnego) {
		std::vector<uint8_t> negprot_spnego;
		std::shared_ptr<x_auth_info_t> auth_info;
		NTSTATUS status = spnego->update(NULL, 0, negprot_spnego, NULL, auth_info);
		X_ASSERT(NT_STATUS_IS_OK(status));
		g_smbd.negprot_spnego.swap(negprot_spnego);
		x_auth_destroy(spnego);
	}

#define TIMERQ_INIT(id, sec) \
	x_timerq_init(get_timerq(id), g_evtmgmt, X_SEC_TO_NSEC(sec))

	TIMERQ_INIT(x_smbd_timer_t::SESSSETUP, 40);
	TIMERQ_INIT(x_smbd_timer_t::BREAK, 35);

	x_smbd_conn_srv_init(smbd_conf->port);

}

const std::vector<uint8_t> &x_smbd_get_negprot_spnego()
{
	return g_smbd.negprot_spnego;
}

void x_smbd_add_timer(x_smbd_timer_t timer_id, x_timerq_entry_t *entry)
{
	x_timerq_add(get_timerq(timer_id), entry);
}

bool x_smbd_cancel_timer(x_smbd_timer_t timer_id, x_timerq_entry_t *entry)
{
	return x_timerq_cancel(get_timerq(timer_id), entry);
}

int main(int argc, char **argv)
{
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
		int c = getopt_long(argc, argv, "c:t:",
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
		configfile = "/etc/samba/smb.conf";
	}
	int err = x_smbd_conf_parse(configfile, cmdline_options);
	if (err < 0) {
		fprintf(stderr, "x_smbd_conf_parse failed %d\n", err);
		exit(1);
	}

	// TODO daemonize
	(void)daemon;

	signal(SIGPIPE, SIG_IGN);

	init_smbd();

	main_loop();

	x_threadpool_destroy(g_smbd.tpool_evtmgmt);
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

