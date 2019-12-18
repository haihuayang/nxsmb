
#include "include/librpc/ndr_nxsmb.hxx"

namespace idl {

void x_ndr_ostr(const NTTIME &t, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	ndr.os << t.val;
}

}
