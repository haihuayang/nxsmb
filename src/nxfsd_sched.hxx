
#ifndef __nxfsd_sched__hxx__
#define __nxfsd_sched__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "event.hxx"

struct x_nxfsd_scheduler_t
{
	x_nxfsd_scheduler_t();
	~x_nxfsd_scheduler_t();
};

void x_nxfsd_schedule(x_fdevt_user_t *evt);

#endif /* __nxfsd_sched__hxx__ */

