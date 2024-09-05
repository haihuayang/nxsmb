
#ifndef __ctrld__hxx__
#define __ctrld__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include <string>
#include "network.hxx"

struct x_ctrl_handler_t
{
	virtual ~x_ctrl_handler_t() { }
	virtual bool output(std::string &data) = 0;
};

typedef x_ctrl_handler_t *x_ctrl_create_handler_t(const char *command);

struct x_ctrld_t
{
	x_ctrld_t(x_ctrl_create_handler_t *handler)
		: create_handler(handler) { }
	x_strm_srv_t base;
	x_ctrl_create_handler_t *const create_handler;
};


int x_ctrld_init(x_ctrld_t &ctrld, const char *name);


#endif /* __ctrld__hxx__ */

