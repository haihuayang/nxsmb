
#include "smbd_ctrl.hxx"
#include <sys/un.h>

/* to access ctrl,
   socat ABSTRACT-CONNECT:nxsmbctrl -
 */

static x_ctrl_handler_t *smbd_create_handler(const char *command)
{
	if (strcmp(command, "stats") == 0) {
		return x_smbd_stats_report_create();
	} else if (strcmp(command, "list-requ") == 0) {
		return x_nxfsd_requ_list_create();
	} else if (strcmp(command, "list-sess") == 0) {
		return x_smbd_sess_list_create();
	} else if (strcmp(command, "list-tcon") == 0) {
		return x_smbd_tcon_list_create();
	} else if (strcmp(command, "list-open") == 0) {
		return x_smbd_open_list_create();
	} else if (strcmp(command, "list-lease") == 0) {
		return x_smbd_lease_list_create();
	} else {
		return nullptr;
	}
}

static x_ctrld_t g_smbd_ctrl(smbd_create_handler);

void x_smbd_ctrl_init()
{
	int err = x_ctrld_init(g_smbd_ctrl, "nxsmbctrl");
	X_ASSERT(err == 0);
}
