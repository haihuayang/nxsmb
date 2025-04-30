
#ifndef __nxfsd_stats__hxx__
#define __nxfsd_stats__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
#include "include/stats.hxx"

void x_nxfsd_stats_init();
int x_nxfsd_stats_register(uint32_t thread_id);
void x_nxfsd_stats_report();


#endif /* __nxfsd_stats__hxx__ */

