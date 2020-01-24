
#include "samba/include/config.h"
#include "misc.hxx"

void x_smbd_report_nt_status(NTSTATUS status, unsigned int line, const char *file)
{
	X_LOG_WARN("error status 0x%x at %s:%d", status.v, file, line);
}


