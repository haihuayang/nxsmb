
#include "include/wbpool.hxx"
#include <unistd.h>
#include <string.h>
#include <iostream>

struct domain_info_cli_t
{
	domain_info_cli_t(const char *dom_name);
	x_wbcli_t wbcli;
	x_wbrequ_t requ;
	x_wbresp_t resp;
};

static void domain_info_cb_reply(x_wbcli_t *wbcli, int err)
{
	domain_info_cli_t *dicli = X_CONTAINER_OF(wbcli, domain_info_cli_t, wbcli);

	X_ASSERT(err == 0);
	X_ASSERT(dicli->resp.header.result == WINBINDD_OK);

	const auto &domain_info = dicli->resp.header.data.domain_info;
	printf("name='%s', alt_name='%s', sid=%s, native_mode=%d, active_directory=%d, primary=%d\n",
			domain_info.name, domain_info.alt_name,
			domain_info.sid,
			domain_info.native_mode,
			domain_info.active_directory,
			domain_info.primary);


	delete dicli;
}

static const x_wb_cbs_t domain_info_cbs = {
	domain_info_cb_reply,
};

domain_info_cli_t::domain_info_cli_t(const char *dom_name)
{
	requ.header.length = sizeof(struct winbindd_request);
	requ.header.cmd = WINBINDD_DOMAIN_INFO;
	requ.header.pid = getpid();
	strncpy(requ.header.domain_name, dom_name, sizeof(requ.header.domain_name) - 1);

	wbcli.requ = &requ;
	wbcli.resp = &resp;
	wbcli.cbs = &domain_info_cbs;
}

static void get_domain_info(x_wbpool_t *wbpool, const char *dom_name)
{
	domain_info_cli_t *domain_info = new domain_info_cli_t(dom_name);
	x_wbpool_request(wbpool, &domain_info->wbcli);
}

static x_wbpool_t *wbpool;
static const char *workgroup;

static long get_domain_info_timer_func(x_timer_t *timer)
{
	get_domain_info(wbpool, workgroup);
	return 3000;
}

static void get_domain_info_timer_done(x_timer_t *timer)
{
	X_DBG("");
}

static const x_timer_upcall_cbs_t get_domain_info_timer_cbs = {
	get_domain_info_timer_func,
	get_domain_info_timer_done,
};

int main(int argc, char **argv)
{
	workgroup = argv[1];
	const char *wbpipe = argv[2];
	x_threadpool_t *tpool = x_threadpool_create("wbpool", 2);
	x_evtmgmt_t *evtmgmt = x_evtmgmt_create(tpool, 2000000000, 1024);
	wbpool = x_wbpool_create(evtmgmt, 2, wbpipe);

	x_timer_t timer;
	timer.cbs = &get_domain_info_timer_cbs;

	x_evtmgmt_add_timer(evtmgmt, &timer, 0);

	for (;;) {
		x_evtmgmt_dispatch(evtmgmt);
	}

	return 0;
}


