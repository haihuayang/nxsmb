
#include "include/librpc/misc.hxx"

namespace idl {

void ndr_traits_t<GUID>::ostr(const GUID &__val, x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	char buf[80];
	snprintf(buf, sizeof(buf),
		 "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		 __val.time_low, __val.time_mid,
		 __val.time_hi_and_version,
		 __val.clock_seq[0],
		 __val.clock_seq[1],
		 __val.node[0], __val.node[1],
		 __val.node[2], __val.node[3],
		 __val.node[4], __val.node[5]);
	__ndr << buf;
}

void ndr_traits_t<ndr_syntax_id>::ostr(const ndr_syntax_id &__val, x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	x_ndr_ostr_simple(__val.uuid, __ndr, __flags, X_NDR_SWITCH_NONE);
	__ndr << '/' << __val.if_version;
}

}

