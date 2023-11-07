
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

#include "smbd_conf.hxx"
#include "smbd_lease.hxx"
#include "smbd_replay.hxx"
#include "smbd_secrets.hxx"
#include "smbd_stats.hxx"
#include "smbd_registry.hxx"
#include "smbd_requ.hxx"
#include "auth.hxx"

#include "smb2.hxx"

static struct {
	x_wbpool_t *wbpool;
	x_auth_context_t *auth_context;
	std::vector<uint8_t> negprot_spnego;
	x_tick_diff_t timers[static_cast<int>(x_smbd_timer_id_t::LAST)];
} g_smbd;

x_auth_t *x_smbd_create_auth(const void *sec_buf, size_t sec_len)
{
	if (sec_len >= 8 && memcmp(sec_buf, "NTLMSSP", 8) == 0) {
		return x_auth_create_ntlmssp(g_smbd.auth_context);
	}
	return x_auth_create_by_oid(g_smbd.auth_context, GSS_SPNEGO_MECHANISM);
}

enum {
	X_SMBD_MAX_SESSION = 1024,
	X_SMBD_MAX_TCON = 1024,
	X_SMBD_MAX_REQUEST = 64 * 1024,
};

void x_smbd_init()
{
	auto smbd_conf = x_smbd_conf_get();

	g_smbd.wbpool = x_wbpool_create(g_evtmgmt, 2,
			smbd_conf->samba_locks_dir + "/winbindd_privileged/pipe");

	x_smbd_registry_init();

	uint32_t max_opens = std::max(smbd_conf->max_opens, 1024u);
	x_smbd_object_pool_init(max_opens);
	x_smbd_open_table_init(max_opens);
	x_smbd_tcon_table_init(X_SMBD_MAX_TCON);
	x_smbd_sess_table_init(X_SMBD_MAX_SESSION);
	x_smbd_requ_pool_init(max_opens); // TODO use max_opens for now
	x_smbd_lease_pool_init(max_opens, max_opens / 16); // TODO use max_opens for now
	x_smbd_replay_cache_init(max_opens, max_opens / 16); // TODO use max_opens for now

	x_smbd_ipc_init();
	x_smbd_posixfs_init(max_opens);

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

void x_smbd_wbpool_request(x_wbcli_t *wbcli)
{
	x_wbpool_request(g_smbd.wbpool, wbcli);
}
