
#ifndef __smbd_ctrl__hxx__
#define __smbd_ctrl__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "smbd.hxx"

struct x_smbd_ctrl_handler_t
{
	virtual ~x_smbd_ctrl_handler_t() { }
	virtual bool output(std::string &data) = 0;
};

x_smbd_ctrl_handler_t *x_smbd_sess_list_create();
x_smbd_ctrl_handler_t *x_smbd_tcon_list_create();
x_smbd_ctrl_handler_t *x_smbd_open_list_create();
x_smbd_ctrl_handler_t *x_smbd_stats_report_create();


#endif /* __smbd_ctrl__hxx__ */

