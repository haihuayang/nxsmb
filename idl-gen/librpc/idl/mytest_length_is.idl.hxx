/* header auto-generated by gen-rpc */
#ifndef __GEN_RPC__HEADER_mytest1
#define __GEN_RPC__HEADER_mytest1
#include "include/librpc/ndr_nxsmb.hxx"

namespace idl {
#ifndef _HEADER_mytest1
#define _HEADER_mytest1

struct MY_lsa_DATA_BUF {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	x_ndr_off_t ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_unique_ptr_with_size_length_t<uint8, uint3264> data;/* [length_is(length), size_is(size)] */
} /* [public, flag(LIBNDR_PRINT_ARRAY_HEX)] */;

template <> struct x_ndr_traits_t<MY_lsa_DATA_BUF> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};

#endif /* _HEADER_mytest1 */

} /* namespace idl */

#endif /* __GEN_RPC__HEADER_mytest1 */

