/* header auto-generated by gen-rpc */
#ifndef __GEN_RPC__HEADER_mytest1
#define __GEN_RPC__HEADER_mytest1
#include "include/librpc/ndr_nxsmb.hxx"

namespace idl {
#ifndef _HEADER_mytest1
#define _HEADER_mytest1

struct MY_ACCOUNT_NAME {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_vector_t<uint16> account_name;/* [charset(UTF16)] */
	uint32 pid;
} ;

template <> struct x_ndr_traits_t<MY_ACCOUNT_NAME> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_struct;
};

#endif /* _HEADER_mytest1 */

} /* namespace idl */

#endif /* __GEN_RPC__HEADER_mytest1 */

