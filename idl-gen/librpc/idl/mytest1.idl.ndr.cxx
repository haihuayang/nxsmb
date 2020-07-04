/* ndr parser auto-generated by pidl */
	
#include "include/librpc/mytest1.hxx"


namespace idl {

// namespace mytest1 {

x_ndr_off_t MY_lsa_PrivArray::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	uint32 __tmp_count = get_size(privs);
	X_NDR_SCALARS(__tmp_count, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(privs, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t MY_lsa_PrivArray::ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_BUFFERS(privs, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}


x_ndr_off_t MY_lsa_PrivArray::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	uint32 __tmp_count;
	X_NDR_SCALARS(__tmp_count, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_ARRAY(privs, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE, __tmp_count);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}
x_ndr_off_t MY_lsa_PrivArray::ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_BUFFERS(privs, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

void MY_lsa_PrivArray::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	__ndr << enter;
	X_NDR_OSTR_NEXT(privs, __ndr, __flags, X_NDR_SWITCH_NONE);
	__ndr << leave;
}



x_ndr_off_t MY_ACCOUNT_NAME::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __tmp_size = __bpos;
	X_NDR_SKIP(uint16, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __tmp_pos_account_name == __bpos;
	X_NDR_SCALARS(account_name, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(uint16(__bpos - __tmp_pos_account_name), __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(pid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


x_ndr_off_t MY_ACCOUNT_NAME::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	uint16 __tmp_size;
	X_NDR_SCALARS(__tmp_size, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(account_name, __ndr, __bpos, X_NDR_CHECK_POS(__bpos + __tmp_size, __bpos, __epos), __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(pid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

void MY_ACCOUNT_NAME::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	__ndr << enter;
	X_NDR_OSTR_NEXT(account_name, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(pid, __ndr, __flags, X_NDR_SWITCH_NONE);
	__ndr << leave;
}



// }
}
