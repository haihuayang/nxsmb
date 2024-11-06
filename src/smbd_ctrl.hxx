
#ifndef __smbd_ctrl__hxx__
#define __smbd_ctrl__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "smbd.hxx"
#include "ctrld.hxx"

x_ctrl_handler_t *x_smbd_sess_list_create();
x_ctrl_handler_t *x_smbd_tcon_list_create();
x_ctrl_handler_t *x_smbd_open_list_create();
x_ctrl_handler_t *x_smbd_lease_list_create();
x_ctrl_handler_t *x_nxfsd_requ_list_create();
x_ctrl_handler_t *x_smbd_stats_report_create();


#endif /* __smbd_ctrl__hxx__ */

