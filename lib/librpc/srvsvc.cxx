#include "include/librpc/srvsvc.hxx"

namespace idl {

x_ndr_off_t ndr_traits_t<srvsvc_NetDiskInfo0>::scalars(
		const srvsvc_NetDiskInfo0 &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	uint32_t size = x_convert<uint32_t>(val.disk.size());
	X_NDR_HEADER_ALIGN(4, ndr, bpos, epos, flags);
	X_NDR_SCALARS_DEFAULT(uint32_t(0), ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS_DEFAULT(size + 1, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	bpos = X_NDR_CHECK(x_ndr_scalars_string(val.disk, ndr,
				bpos, epos, flags, true));
	X_NDR_TRAILER_ALIGN(4, ndr, bpos, epos, flags);
	return bpos;
}

x_ndr_off_t ndr_traits_t<srvsvc_NetDiskInfo0>::scalars(
		srvsvc_NetDiskInfo0 &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	uint32_t offset, length;
	X_NDR_HEADER_ALIGN(4, ndr, bpos, epos, flags);
	X_NDR_SCALARS_DEFAULT(offset, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS_DEFAULT(length, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	epos = X_NDR_CHECK_POS(bpos + length * 2, bpos, epos);
	bpos = X_NDR_CHECK(x_ndr_scalars_string(val.disk, ndr,
				bpos, epos, flags, true));
	X_NDR_TRAILER_ALIGN(4, ndr, bpos, epos, flags);
	return bpos;
}


}

