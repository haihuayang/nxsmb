/* ndr parser auto-generated by pidl */
	
#include "include/librpc/mytest_length_is.hxx"


namespace idl {

// namespace mytest1 {

x_ndr_off_t MY_lsa_DATA_BUF::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	X_NDR_SCALARS(length, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(data, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	uint3264 __tmp_size = get_size(data);
	X_NDR_SCALARS(__tmp_size, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t MY_lsa_DATA_BUF::ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_BUFFERS(data, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}


x_ndr_off_t MY_lsa_DATA_BUF::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	X_NDR_SCALARS(length, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_ARRAY(data, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE, __tmp_size);
	uint3264 __tmp_size;
	X_NDR_SCALARS(__tmp_size, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}
x_ndr_off_t MY_lsa_DATA_BUF::ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_BUFFERS(data, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

void MY_lsa_DATA_BUF::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	__ndr << enter;
	X_NDR_OSTR_NEXT(data, __ndr, __flags, X_NDR_SWITCH_NONE);
	__ndr << leave;
}



// }
}
