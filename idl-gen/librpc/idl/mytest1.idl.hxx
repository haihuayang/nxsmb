/* header auto-generated by gen-rpc */
#ifndef __GEN_RPC__HEADER_mytest1
#define __GEN_RPC__HEADER_mytest1
#include "include/librpc/ndr_nxsmb.hxx"

namespace idl {
#ifndef _HEADER_mytest1
#define _HEADER_mytest1

struct MY_lsa_PrivArray {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	x_ndr_off_t ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_array_ptr_with_size_is<privs, uint32> privs;/* [size_is(count)] */
} ;

template <> struct x_ndr_traits_t<MY_lsa_PrivArray> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};

struct MY_ACCOUNT_NAME {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_vector_t<account_name> account_name;/* [charset(UTF16)] */
	pid pid;
} ;

template <> struct x_ndr_traits_t<MY_ACCOUNT_NAME> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_struct;
};

#endif /* _HEADER_mytest1 */

} /* namespace idl */

#endif /* __GEN_RPC__HEADER_mytest1 */

