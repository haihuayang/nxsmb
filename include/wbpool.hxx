
#ifndef __wbpool__hxx__
#define __wbpool__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "evtmgmt.hxx"

#include <vector>
#include <memory>
#include <functional>
#include <string>
#include "winbind_wrap.hxx"


struct x_wbrequ_t
{
	struct winbindd_request header;
	std::vector<uint8_t> extra;
};

struct x_wbresp_t
{
	struct winbindd_response header;
	std::vector<uint8_t> extra;
};

struct x_wbpool_t;
struct x_wbcli_t;

struct x_wb_cbs_t
{
	void (*cb_reply)(x_wbcli_t *, int);
};

struct x_wbcli_t
{
	void on_reply(int status) {
		cbs->cb_reply(this, status);
	}
	x_dlink_t dlink;
	x_tick_t timeout;
	const x_wb_cbs_t *cbs;
	x_wbrequ_t *requ;
	x_wbresp_t *resp;
};

x_wbpool_t *x_wbpool_create(x_evtmgmt_t *ep, unsigned int count,
		const std::string &wbpipe);

int x_wbpool_request(x_wbpool_t *wbpool, x_wbcli_t *wbcli);


#endif /* __wbpool__hxx__ */

