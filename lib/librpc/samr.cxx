
#include "include/librpc/samr.hxx"

namespace idl {

x_ndr_off_t ndr_traits_t<samr_LogonHours>::scalars(
		const samr_LogonHours &__val, x_ndr_push_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_TODO;
	return __bpos;
}


x_ndr_off_t ndr_traits_t<samr_LogonHours>::scalars(
		samr_LogonHours &__val, x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_TODO;
	return __bpos;
}

}
