
#ifndef __ndr_misc__hxx__
#define __ndr_misc__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "librpc/idl/misc.h"

namespace idl {

void x_ndr_ostr(const GUID &v, x_ndr_ostr_t &os, uint32_t flags, x_ndr_switch_t level);

}

#endif /* __ndr_misc__hxx__ */

