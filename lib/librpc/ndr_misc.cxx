
#include "include/librpc/ndr_misc.hxx"

namespace idl {

x_ndr_off_t GUID::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(time_low, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(time_mid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(time_hi_and_version, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(clock_seq, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(node, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


x_ndr_off_t GUID::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(time_low, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(time_mid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(time_hi_and_version, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(clock_seq, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(node, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

void x_ndr_ostr(const GUID &v, x_ndr_ostr_t &os, uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	char buf[80];
	snprintf(buf, sizeof(buf),
		 "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		 v.time_low, v.time_mid,
		 v.time_hi_and_version,
		 v.clock_seq[0],
		 v.clock_seq[1],
		 v.node[0], v.node[1],
		 v.node[2], v.node[3],
		 v.node[4], v.node[5]);
	os << buf;
}

}

