
#include "include/librpc/ndr_misc.hxx"

namespace idl {

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

