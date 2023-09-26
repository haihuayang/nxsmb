
#ifndef __ndr_types__hxx__
#define __ndr_types__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/utils.hxx"
#include <string>
#include <memory>
#include <arpa/inet.h>
#include "include/charset.hxx"

namespace idl {

#define X_NDR_SCALARS_DEFAULT(val, ndr, bpos, epos, flags, switch_is) \
	X_NDR_VERIFY((bpos), x_ndr_scalars_default((val), (ndr), (bpos), (epos), (flags), (switch_is)))


#define X_NDR_XSIZE_PRE_PUSH(type, order, ndr, bpos, epos, flags) \
	x_ndr_off_t __base_##order = (bpos);

#define X_NDR_XSIZE_PRE_PULL(type, order, ndr, bpos, epos, flags) \
	x_ndr_off_t __base_##order = (bpos);

#define X_NDR_XSIZE_PUSH(type, order, ndr, bpos, epos, flags) \
	x_ndr_off_t __pos_##order = (bpos); \
	X_NDR_SKIP(type, ndr, bpos, epos, flags);

#define X_NDR_XSIZE_PULL(type, order, ndr, bpos, epos, flags) \
	type __tmp_##order; \
	X_NDR_SCALARS_DEFAULT(__tmp_##order, (ndr), (bpos), (epos), (flags), X_NDR_SWITCH_NONE); \
	(epos) = X_NDR_CHECK_POS(__base_##order + __tmp_##order, __base_##order, (epos));

#define X_NDR_XSIZE_POST_PUSH(type, order, ndr, bpos, epos, flags) \
	X_NDR_SCALARS_DEFAULT(type((bpos) - __base_##order), (ndr), __pos_##order, (epos), (flags), X_NDR_SWITCH_NONE);

#define X_NDR_XSIZE_POST_PULL(type, order, ndr, bpos, epos, flags) \
	(bpos) = (epos);


#define X_NDR_VECTOR_LEN_PUSH(type, order, vector_name, ndr, bpos, epos, flags) \
	X_NDR_VERIFY((bpos), x_ndr_scalars_default(type(__val.vector_name.size()), (ndr), (bpos), (epos), (flags), X_NDR_SWITCH_NONE)); \

#define X_NDR_VECTOR_LEN_PULL(type, order, vector_name, ndr, bpos, epos, flags) \
	type __tmp_len_##order; \
	X_NDR_VERIFY((bpos), x_ndr_scalars_default(__tmp_len_##order, (ndr), (bpos), (epos), (flags), X_NDR_SWITCH_NONE)); \
	__val.vector_name.resize(__tmp_len_##order);

template <typename T>
inline x_ndr_off_t x_ndr_scalars_unique_ptr(
		const std::shared_ptr<T> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	uint3264 ptr;
	if (t) {
		ptr.val = ndr.next_ptr();
	} else {
		ptr.val = 0;
	}
	X_NDR_SCALARS_DEFAULT(ptr, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_scalars_unique_ptr(
		std::shared_ptr<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	uint3264 ptr;
	X_NDR_SCALARS_DEFAULT(ptr, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (ptr.val) {
		x_ndr_allocate_ptr<T>(t, level);
		ndr.next_ptr();
	}
	return bpos;
}

#define X_NDR_SCALARS_UNIQUE_PTR(val, ndr, bpos, epos, flags, switch_is) \
	X_NDR_VERIFY((bpos), x_ndr_scalars_unique_ptr((val), (ndr), (bpos), (epos), (flags), (switch_is)))


#define X_NDR_BUFFERS_RELATIVE_PTR_START_PUSH(ptr_type, val, ndr, bpos, epos, flags, switch_is) do { \
	x_ndr_off_t __tmp_pos = (ndr).load_pos(); \
	if (val) { \
		X_NDR_DO_ALIGN((ndr), (bpos), (epos), (flags)); \
		X_NDR_SCALARS_DEFAULT((ptr_type)((bpos) - (ndr).base), (ndr), __tmp_pos, (epos), (flags), X_NDR_SWITCH_NONE);

#define X_NDR_BUFFERS_RELATIVE_PTR_END_PUSH(val, ndr, bpos, epos, flags, switch_is) \
} } while (0)

#define X_NDR_BUFFERS_RELATIVE_PTR_START_PULL(ptr_type, val, ndr, bpos, epos, flags, switch_is) do { \
	x_ndr_off_t __tmp_pos = (ndr).load_pos(); \
	ptr_type __tmp_rel_pos; \
	X_NDR_SCALARS_DEFAULT(__tmp_rel_pos, (ndr), __tmp_pos, (epos), (flags), X_NDR_SWITCH_NONE); \
	if (__tmp_rel_pos) { \
		X_NDR_CHECK_ALIGN((ndr), (flags), __tmp_rel_pos); \
		x_ndr_allocate_ptr((val), (switch_is)); \
		x_ndr_off_t __tmp_bpos = (bpos); \
		(bpos) = X_NDR_CHECK_POS((ndr).base + __tmp_rel_pos, 0, (epos));

#define X_NDR_BUFFERS_RELATIVE_PTR_END_PULL(val, ndr, bpos, epos, flags, switch_is) \
		(bpos) = std::max((bpos), __tmp_bpos); \
	} \
} while (0)


#define X_NDR_SUBCTX_LEVEL0_INT_SIZE_START_PUSH(subctx_size, ndr, bpos, epos, flags) do { \
	x_ndr_off_t __tmp_save_epos = (epos); \
	(epos) = X_NDR_CHECK_POS((bpos) + (subctx_size), (bpos), (epos));

#define X_NDR_SUBCTX_LEVEL0_INT_SIZE_END_PUSH(subctx_size, ndr, bpos, epos, flags) \
	(bpos) = (epos); \
	(epos) = __tmp_save_epos; \
} while (0)

#define X_NDR_SUBCTX_LEVEL0_INT_SIZE_START_PULL(subctx_size, ndr, bpos, epos, flags) do { \
	x_ndr_off_t __tmp_save_epos = (epos); \
	(epos) = X_NDR_CHECK_POS((bpos) + (subctx_size), (bpos), (epos));

#define X_NDR_SUBCTX_LEVEL0_INT_SIZE_END_PULL(subctx_size, ndr, bpos, epos, flags) \
	(bpos) = (epos); \
	(epos) = __tmp_save_epos; \
} while (0)


#define X_NDR_SUBCTX_LEVEL0_SIZE_START_PUSH(subctx_size_type, subctx_size_pos, ndr, bpos, epos, flags) do { \
	x_ndr_off_t __tmp_subctx_pos = (bpos);

#define X_NDR_SUBCTX_LEVEL0_SIZE_END_PUSH(subctx_size_type, subctx_size_pos, ndr, bpos, epos, flags) \
	X_NDR_SCALARS_DEFAULT((subctx_size_type)((bpos) - (__tmp_subctx_pos)), (ndr), (subctx_size_pos), (epos), (flags), X_NDR_SWITCH_NONE); \
} while (0)

#define X_NDR_SUBCTX_LEVEL0_SIZE_START_PULL(subctx_size_type, subctx_size_pos, ndr, bpos, epos, flags) do { \
	subctx_size_type __tmp_subctx_size; \
	X_NDR_SCALARS_DEFAULT(__tmp_subctx_size, (ndr), (subctx_size_pos), (epos), (flags), X_NDR_SWITCH_NONE); \
	x_ndr_off_t __tmp_save_epos = (epos); \
	(epos) = X_NDR_CHECK_POS((bpos) + __tmp_subctx_size, (bpos), (epos));

#define X_NDR_SUBCTX_LEVEL0_SIZE_END_PULL(subctx_size_type, subctx_size_pos, ndr, bpos, epos, flags) \
	(bpos) = (epos); \
	(epos) = __tmp_save_epos; \
} while (0)


#define X_NDR_SUBCTX_LEVEL_NOSIZE_START_PUSH(size_type, ndr, bpos, epos, flags) do { \
	x_ndr_off_t __tmp_size_pos = (bpos); \
	X_NDR_SKIP(size_type, (ndr), (bpos), (epos), (flags)); \
	x_ndr_off_t __tmp_subctx_pos = (bpos);

#define X_NDR_SUBCTX_LEVEL_NOSIZE_END_PUSH(size_type, ndr, bpos, epos, flags) \
	X_NDR_SCALARS_DEFAULT((size_type)((bpos) - (__tmp_subctx_pos)), (ndr), __tmp_size_pos, (epos), (flags), X_NDR_SWITCH_NONE); \
} while (0)

#define X_NDR_SUBCTX_LEVEL_NOSIZE_START_PULL(size_type, ndr, bpos, epos, flags) do { \
	size_type __tmp_size; \
	X_NDR_SCALARS_DEFAULT(__tmp_size, (ndr), (bpos), (epos), (flags), X_NDR_SWITCH_NONE); \
	x_ndr_off_t __tmp_save_epos = (epos); \
	(epos) = X_NDR_CHECK_POS((bpos) + __tmp_size, (bpos), (epos));

#define X_NDR_SUBCTX_LEVEL_NOSIZE_END_PULL(size_type, ndr, bpos, epos, flags) \
	(bpos) = (epos); \
	(epos) = __tmp_save_epos; \
} while (0)


#define X_NDR_SUBCTX_LEVEL_SIZE_START_PUSH(subctx_size_type, subctx_size_pos, size_type, ndr, bpos, epos, flags) do { \
	x_ndr_off_t __tmp_size_pos = (bpos); \
	X_NDR_SKIP(size_type, (ndr), (bpos), (epos), (flags)); \
	x_ndr_off_t __tmp_subctx_pos = (bpos);

#define X_NDR_SUBCTX_LEVEL_SIZE_END_PUSH(subctx_size_type, subctx_size_pos, size_type, ndr, bpos, epos, flags) \
	X_NDR_SCALARS_DEFAULT((size_type)((bpos) - (__tmp_subctx_pos)), (ndr), __tmp_size_pos, (epos), (flags), X_NDR_SWITCH_NONE); \
	X_NDR_SCALARS_DEFAULT((subctx_size_type)((bpos) - (__tmp_subctx_pos)), (ndr), (subctx_size_pos), (epos), (flags), X_NDR_SWITCH_NONE); \
} while (0)

#define X_NDR_SUBCTX_LEVEL_SIZE_START_PULL(subctx_size_type, subctx_size_pos, size_type, ndr, bpos, epos, flags) do { \
	subctx_size_type __tmp_subctx_size; \
	X_NDR_SCALARS_DEFAULT(__tmp_subctx_size, (ndr), (subctx_size_pos), (epos), (flags), X_NDR_SWITCH_NONE); \
	size_type __tmp_size; \
	X_NDR_SCALARS_DEFAULT(__tmp_size, (ndr), (bpos), (epos), (flags), X_NDR_SWITCH_NONE); \
	if (__tmp_size != __tmp_subctx_size) { \
		return -NDR_ERR_LENGTH; \
	} \
	x_ndr_off_t __tmp_save_epos = (epos); \
	(epos) = X_NDR_CHECK_POS((bpos) + __tmp_size, (bpos), (epos));

#define X_NDR_SUBCTX_LEVEL_SIZE_END_PULL(subctx_size_type, subctx_size_pos, size_type, ndr, bpos, epos, flags) \
	(bpos) = (epos); \
	(epos) = __tmp_save_epos; \
} while (0)


#define X_NDR_SUBCTXLEVEL_START_PUSH(subndr, ndr, bpos, epos) do { \
	x_ndr_push_t subndr{(ndr).buff, (bpos)};

#define X_NDR_SUBCTXLEVEL_END_PUSH(subndr, ndr, bpos, epos) \
} while (0)

#define X_NDR_SUBCTXLEVEL_START_PULL(subndr, ndr, bpos, epos) do { \
	x_ndr_pull_t subndr{(ndr).buff, (bpos)};

#define X_NDR_SUBCTXLEVEL_END_PULL(subndr, ndr, bpos, epos) \
} while (0)


#define X_NDR_SUBCTXFFFFFC01_START_PUSH(subndr, ndr, bpos, epos, flags) do { \
	x_ndr_subctx_t __subctx; \
	x_ndr_off_t __pos_subctx = (bpos); \
	X_NDR_SCALARS_DEFAULT(__subctx, (ndr), (bpos), (epos), (flags), X_NDR_SWITCH_NONE); \
	x_ndr_off_t __tmp_bpos = (bpos); \
	x_ndr_push_t subndr{(ndr).buff, (bpos)};

// TODO force subctx round 8, is it correct?
#define X_NDR_SUBCTXFFFFFC01_END_PUSH(subndr, ndr, bpos, epos, _flags) \
	__subctx.content_size = x_convert_assert<uint32_t>(X_NDR_ROUND((bpos) - __tmp_bpos, 8)); \
	(bpos) = X_NDR_CHECK_POS(__tmp_bpos + __subctx.content_size, __tmp_bpos, (epos)); \
	__subctx.flags = (_flags); \
	X_NDR_SCALARS_DEFAULT(__subctx, (ndr), __pos_subctx, (epos), (_flags), X_NDR_SWITCH_NONE); \
} while (0)

#define X_NDR_SUBCTXFFFFFC01_START_PULL(subndr, ndr, bpos, epos, flags) do { \
	x_ndr_subctx_t __subctx; \
	X_NDR_SCALARS_DEFAULT(__subctx, (ndr), (bpos), (epos), (flags), X_NDR_SWITCH_NONE); \
	x_ndr_pull_t subndr{(ndr).buff, (bpos)}; \
	x_ndr_off_t __tmp_save_epos = (epos); \
	(epos) = X_NDR_CHECK_POS((bpos) + __subctx.content_size, (bpos), (epos));

#define X_NDR_SUBCTXFFFFFC01_END_PULL(subndr, ndr, bpos, epos, flags) \
	(bpos) = (epos); \
	(epos) = __tmp_save_epos; \
} while (0)


#define X_NDR_BUFFERS_SIZE_IS_PUSH(name, ndr) \
	x_ndr_off_t __pos_##name = (ndr).load_pos(); \

#define X_NDR_BUFFERS_SIZE_IS_PULL(name, ndr) \
	x_ndr_off_t __pos_##name = (ndr).load_pos(); \


#define X_NDR_SCALARS_SIZE_IS_VECTOR_STEP0_PUSH(val, ndr, bpos, epos, flags) \
	X_NDR_SCALARS_DEFAULT(uint3264((val).size()), (ndr), (bpos), (epos), (flags), X_NDR_SWITCH_NONE)

#define X_NDR_SCALARS_SIZE_IS_VECTOR_STEP0_PULL(val, ndr, bpos, epos, flags) \
	uint3264 __tmp_size_is_2; \
	X_NDR_SCALARS_DEFAULT(__tmp_size_is_2, (ndr), (bpos), (epos), (flags), X_NDR_SWITCH_NONE); \
	(val).resize(int_val(__tmp_size_is_2));

#define X_NDR_SCALARS_SIZE_IS_VECTOR_PUSH(tmp_size_is, __val, ndr, bpos, epos, flags) \
	(tmp_size_is).val = (__val).size(); \
	X_NDR_SCALARS_DEFAULT((tmp_size_is), (ndr), (bpos), (epos), (flags), X_NDR_SWITCH_NONE); \

#define X_NDR_SCALARS_SIZE_IS_VECTOR_PULL(tmp_size_is, val, ndr, bpos, epos, flags) \
	X_NDR_SCALARS_DEFAULT((tmp_size_is), (ndr), (bpos), (epos), (flags), X_NDR_SWITCH_NONE); \
	(val).resize(int_val(tmp_size_is));

#define X_NDR_SIZE_IS_POST_PUSH(tmp_size_is, pos_size_is, type, ndr, bpos, epos, flags) do { \
	type __tmp_val; \
	x_convert_assert(__tmp_val, int_val(tmp_size_is)); \
	X_NDR_SCALARS_DEFAULT(__tmp_val, (ndr), (pos_size_is), (epos), (flags), X_NDR_SWITCH_NONE); \
} while (0)

#define X_NDR_SIZE_IS_POST_PULL(tmp_size_is, pos_size_is, type, ndr, bpos, epos, flags) do { \
	type __tmp_val; \
	X_NDR_SCALARS_DEFAULT(__tmp_val, (ndr), (pos_size_is), (epos), (flags), X_NDR_SWITCH_NONE); \
	if (int_val(__tmp_val) != int_val(tmp_size_is)) { \
		return -NDR_ERR_LENGTH; \
	} \
} while (0)

#define X_NDR_SCALARS_SIZE_IS_VECTOR_PRE_PUSH(order) \
	uint3264 __tmp_size_is_##order

#define X_NDR_SCALARS_SIZE_IS_VECTOR_PRE_PULL(order) \
	uint3264 __tmp_size_is_##order

#define X_NDR_SCALARS_LENGTH_IS_VECTOR_2_PRE_PUSH(order) \
	uint3264 __tmp_size_is_##order, __tmp_length_is_##order

#define X_NDR_SCALARS_LENGTH_IS_VECTOR_2_PRE_PULL(order) \
	uint3264 __tmp_size_is_##order, __tmp_length_is_##order

#define X_NDR_SCALARS_LENGTH_IS_VECTOR_2_PUSH(order, val, ndr, bpos, epos, flags) do { \
	x_convert_assert(__tmp_size_is_##order, (val).size()); \
	x_convert_assert(__tmp_length_is_##order, (val).size()); \
	X_NDR_SCALARS_DEFAULT(__tmp_size_is_##order, (ndr), (bpos), (epos), (flags), X_NDR_SWITCH_NONE); \
	X_NDR_SCALARS_DEFAULT(uint3264(0), (ndr), (bpos), (epos), (flags), X_NDR_SWITCH_NONE); \
	X_NDR_SCALARS_DEFAULT(__tmp_length_is_##order, (ndr), (bpos), (epos), (flags), X_NDR_SWITCH_NONE); \
} while (0)

#define X_NDR_SCALARS_LENGTH_IS_VECTOR_2_PULL(order, val, ndr, bpos, epos, flags) do {\
	uint3264 __tmp_offset_##order; \
	X_NDR_SCALARS_DEFAULT(__tmp_size_is_##order, (ndr), (bpos), (epos), (flags), X_NDR_SWITCH_NONE); \
	X_NDR_SCALARS_DEFAULT(__tmp_offset_##order, (ndr), (bpos), (epos), (flags), X_NDR_SWITCH_NONE); \
	X_NDR_SCALARS_DEFAULT(__tmp_length_is_##order, (ndr), (bpos), (epos), (flags), X_NDR_SWITCH_NONE); \
	if (int_val(__tmp_offset_##order) != 0 || int_val(__tmp_length_is_##order) > int_val(__tmp_size_is_##order)) { \
		return -NDR_ERR_LENGTH; \
	} \
	(val).resize(int_val(__tmp_length_is_##order)); \
} while (0)

#define X_NDR_SCALARS_LENGTH_IS_VECTOR_1_PUSH(size_is, order, val, ndr, bpos, epos, flags) do { \
	x_convert_assert(__tmp_size_is_##order, (size_is)); \
	x_convert_assert(__tmp_length_is_##order, (val).size()); \
	X_NDR_SCALARS_DEFAULT(__tmp_size_is_##order, (ndr), (bpos), (epos), (flags), X_NDR_SWITCH_NONE); \
	X_NDR_SCALARS_DEFAULT(uint3264(0), (ndr), (bpos), (epos), (flags), X_NDR_SWITCH_NONE); \
	X_NDR_SCALARS_DEFAULT(__tmp_length_is_##order, (ndr), (bpos), (epos), (flags), X_NDR_SWITCH_NONE); \
} while (0)

#define X_NDR_SCALARS_LENGTH_IS_VECTOR_1_PULL(size_is, order, val, ndr, bpos, epos, flags) do {\
	uint3264 __tmp_offset_##order; \
	X_NDR_SCALARS_DEFAULT(__tmp_size_is_##order, (ndr), (bpos), (epos), (flags), X_NDR_SWITCH_NONE); \
	X_NDR_SCALARS_DEFAULT(__tmp_offset_##order, (ndr), (bpos), (epos), (flags), X_NDR_SWITCH_NONE); \
	X_NDR_SCALARS_DEFAULT(__tmp_length_is_##order, (ndr), (bpos), (epos), (flags), X_NDR_SWITCH_NONE); \
	if (int_val(__tmp_offset_##order) != 0 || int_val(__tmp_length_is_##order) > int_val(__tmp_size_is_##order) || int_val(__tmp_size_is_##order) != (size_is)) { \
		return -NDR_ERR_LENGTH; \
	} \
	(val).resize(int_val(__tmp_length_is_2)); \
} while (0)

template <typename T>
static inline size_t vector_ptr_get_size(const std::shared_ptr<std::vector<T>> &val)
{
	if (val) {
		return val->size();
	} else {
		return 0;
	}
}

template <> struct ndr_traits_t<uint1632>
{
	using has_buffers = std::false_type;
	using ndr_data_type = x_ndr_type_primary;
	using ndr_base_type = uint1632;

	x_ndr_off_t scalars(uint1632 val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		if ((flags & LIBNDR_FLAG_NDR64) != 0) {
			return x_ndr_push_uint32(val.val, ndr, bpos, epos, flags);
		} else {
			return x_ndr_push_uint16(x_convert_assert<uint16_t>(val.val),
					ndr, bpos, epos, flags);
		}
	}
	x_ndr_off_t scalars(uint1632 &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		if ((flags & LIBNDR_FLAG_NDR64) != 0) {
			return x_ndr_pull_uint32(val.val, ndr, bpos, epos, flags);
		} else {
			uint16_t tmp;
			x_ndr_off_t ret = x_ndr_pull_uint16(tmp, ndr, bpos, epos, flags);
			if (ret >= 0) {
				val.val = tmp;
			}
			return ret;
		}
	}
	void ostr(uint1632 val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		ndr.os << val.val;
	}
};

template <> struct ndr_traits_t<uint3264>
{
	using has_buffers = std::false_type;
	using ndr_data_type = x_ndr_type_primary;
	using ndr_base_type = uint3264;

	x_ndr_off_t scalars(uint3264 val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		if ((flags & LIBNDR_FLAG_NDR64) != 0) {
			return x_ndr_push_uint64_align(val.val, ndr, bpos, epos, flags, 8);
		} else {
			return x_ndr_push_uint32(x_convert_assert<uint32_t>(val.val),
					ndr, bpos, epos, flags);
		}
	}
	x_ndr_off_t scalars(uint3264 &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		if ((flags & LIBNDR_FLAG_NDR64) != 0) {
			return x_ndr_pull_uint64_align(val.val, ndr, bpos, epos, flags, 8);
		} else {
			uint32_t tmp;
			x_ndr_off_t ret = x_ndr_pull_uint32(tmp, ndr, bpos, epos, flags);
			if (ret >= 0) {
				val.val = tmp;
			}
			return ret;
		}
	}
	void ostr(uint3264 val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		ndr.os << val.val;
	}
};

template <> struct ndr_traits_t<uint64_t>
{
	using has_buffers = std::false_type;
	using ndr_data_type = x_ndr_type_primary;
	using ndr_base_type = uint64_t;

	x_ndr_off_t scalars(uint64_t val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_push_uint64(val, ndr, bpos, epos, flags);
	}
	x_ndr_off_t scalars(uint64_t &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_pull_uint64(val, ndr, bpos, epos, flags);
	}
	void ostr(uint64_t val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		ndr.os << val;
	}
};

template <> struct ndr_traits_t<int64_t>
{
	using has_buffers = std::false_type;
	using ndr_data_type = x_ndr_type_primary;
	using ndr_base_type = int64_t;

	x_ndr_off_t scalars(int64_t val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_push_int64(val, ndr, bpos, epos, flags);
	}
	x_ndr_off_t scalars(int64_t &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_pull_int64(val, ndr, bpos, epos, flags);
	}
	void ostr(int64_t val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		ndr.os << val;
	}
};

template <> struct ndr_traits_t<uint32_t>
{
	using has_buffers = std::false_type;
	using ndr_data_type = x_ndr_type_primary;
	using ndr_base_type = uint32_t;

	x_ndr_off_t scalars(uint32_t val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_push_uint32(val, ndr, bpos, epos, flags);
	}
	x_ndr_off_t scalars(uint32_t &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_pull_uint32(val, ndr, bpos, epos, flags);
	}
	void ostr(uint32_t val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		ndr.os << val;
	}
};

template <> struct ndr_traits_t<int32_t>
{
	using has_buffers = std::false_type;
	using ndr_data_type = x_ndr_type_primary;
	using ndr_base_type = int32_t;

	x_ndr_off_t scalars(int32_t val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_push_int32(val, ndr, bpos, epos, flags);
	}
	x_ndr_off_t scalars(int32_t &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_pull_int32(val, ndr, bpos, epos, flags);
	}
	void ostr(int32_t val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		ndr.os << val;
	}
};

template <> struct ndr_traits_t<uint16_t>
{
	using has_buffers = std::false_type;
	using ndr_data_type = x_ndr_type_primary;
	using ndr_base_type = uint16_t;

	x_ndr_off_t scalars(uint16_t val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_push_uint16(val, ndr, bpos, epos, flags);
	}
	x_ndr_off_t scalars(uint16_t &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_pull_uint16(val, ndr, bpos, epos, flags);
	}
	void ostr(uint16_t val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		ndr.os << val;
	}
};

template <> struct ndr_traits_t<uint8_t>
{
	using has_buffers = std::false_type;
	using ndr_data_type = x_ndr_type_primary;
	using ndr_base_type = uint8_t;

	x_ndr_off_t scalars(uint8_t val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_push_uint8(val, ndr, bpos, epos, flags);
	}
	x_ndr_off_t scalars(uint8_t &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_pull_uint8(val, ndr, bpos, epos, flags);
	}
	void ostr(uint8_t val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		ndr.os << val;
	}
};

typedef struct in_addr ipv4address;
typedef struct in6_addr ipv6address;
template <> struct ndr_traits_t<struct in_addr>
{
	using has_buffers = std::false_type;
	using ndr_data_type = x_ndr_type_primary;
	using ndr_base_type = struct in_addr;

	x_ndr_off_t scalars(struct in_addr val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_push_uint32(htonl(val.s_addr), ndr, bpos, epos, flags);
	}
	x_ndr_off_t scalars(struct in_addr &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		uint32_t addr;
		bpos = x_ndr_pull_uint32(addr, ndr, bpos, epos, flags);
		if (bpos < 0) {
			return bpos;
		}
		val.s_addr = ntohl(addr);
		return bpos;
	}
	void ostr(struct in_addr val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		char buf[32];
		snprintf(buf, sizeof buf, "%d.%d.%d.%d", X_IPQUAD_BE(val));
		ndr.os << buf;
	}
};

template <> struct ndr_traits_t<struct in6_addr>
{
	using has_buffers = std::false_type;
	using ndr_data_type = x_ndr_type_primary;
	using ndr_base_type = struct in6_addr;

	x_ndr_off_t scalars(struct in6_addr val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_push_bytes(&val, ndr, bpos, epos, 16);
	}
	x_ndr_off_t scalars(struct in6_addr &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_pull_bytes(&val, ndr, bpos, epos, 16);
	}
	void ostr(struct in6_addr val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		char buf[INET6_ADDRSTRLEN];
		ndr.os << inet_ntop(AF_INET6, &val, buf, sizeof buf);
	}
};


using u8string = std::string;
using u16string = std::u16string;

#define X_NDR_BUFFERS_DEFAULT(val, ndr, bpos, epos, ...) \
	X_NDR_VERIFY((bpos), x_ndr_buffers_default((val), (ndr), (bpos), (epos), __VA_ARGS__))



#define X_NDR_SCALARS_SIMPLE(nt, val, ndr, bpos, epos, flags, level) \
	X_NDR_VERIFY((bpos), (nt{}).scalars((val), (ndr), (bpos), (epos), (flags), (level)))

#define X_NDR_BUFFERS_SIMPLE(nt, val, ndr, bpos, epos, flags, level) \
	X_NDR_VERIFY((bpos), (nt{}).buffers((val), (ndr), (bpos), (epos), (flags), (level)))

#define X_NDR_OSTR_SIMPLE(nt, val, ndr, ...) \
	(nt{}).ostr((val), (ndr), __VA_ARGS__)


template <typename T, size_t C, typename NDR, typename NT = ndr_traits_t<T>>
static inline x_ndr_off_t x_ndr_scalars_array(NT &&nt, const std::array<T, C> &val, NDR &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	for (auto &&i: val) {
		bpos = nt.scalars(i, ndr, bpos, epos, flags, level);
		if (bpos < 0) {
			return bpos;
		}
	}
	return bpos;
}

template <typename T, size_t C, typename NDR, typename NT = ndr_traits_t<T>>
static inline x_ndr_off_t x_ndr_scalars_array(NT &&nt, std::array<T, C> &val, NDR &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	for (auto &&i: val) {
		bpos = nt.scalars(i, ndr, bpos, epos, flags, level);
		if (bpos < 0) {
			return bpos;
		}
	}
	return bpos;
}

template <typename T, size_t C, typename NDR, typename NT>
static inline x_ndr_off_t x_ndr_buffers_array(NT &&nt, std::array<T, C> &&val, NDR &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	for (auto &&i: val) {
		bpos = x_ndr_buffers_simple(nt, i, ndr, bpos, epos, flags, level);
		if (bpos < 0) {
			return bpos;
		}
	}
	return bpos;
}

template <typename T, size_t C, typename NT>
static inline void x_ndr_ostr_array(NT &&nt, const std::array<T, C> &val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	ndr << "length=" << C << enter;
	for (size_t i = 0; i < C; ++i) {
		ndr << '#' << i << ": ";
		nt.ostr(val[i], ndr, flags, level);
		ndr << next;
	}
	ndr << leave;
}

#define X_NDR_SCALARS_ARRAY(nt, val, ndr, bpos, epos, ...) \
	X_NDR_VERIFY((bpos), x_ndr_scalars_array((nt){}, (val), (ndr), (bpos), (epos), __VA_ARGS__))

#define X_NDR_BUFFERS_ARRAY(nt, val, ndr, bpos, epos, ...) \
	X_NDR_VERIFY((bpos), x_ndr_buffers_array((nt){}, (val), (ndr), (bpos), (epos), __VA_ARGS__))

#define X_NDR_OSTR_ARRAY(nt, val, ndr, flags, level) \
	x_ndr_ostr_array((nt){}, (val), (ndr), (flags), (level))

template <typename T, typename NT>
static inline x_ndr_off_t x_ndr_scalars_vector(NT &&nt, const std::vector<T> &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	for (auto &i: val) {
		bpos = nt.scalars(i, ndr, bpos, epos, flags, level);
		if (bpos < 0) {
			return bpos;
		}
	}
	return bpos;
}

template <typename T, typename NT>
static inline x_ndr_off_t x_ndr_scalars_vector(NT &&nt, std::vector<T> &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	for (auto &i: val) {
		bpos = nt.scalars(i, ndr, bpos, epos, flags, level);
		if (bpos < 0) {
			return bpos;
		}
	}
	return bpos;
}

template <typename T, typename NT>
static inline x_ndr_off_t x_ndr_buffers_vector(NT &&nt, const std::vector<T> &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	for (auto &i: val) {
		bpos = nt.buffers(i, ndr, bpos, epos, flags, level);
		if (bpos < 0) {
			return bpos;
		}
	}
	return bpos;
}

template <typename T, typename NT>
static inline x_ndr_off_t x_ndr_buffers_vector(NT &&nt, std::vector<T> &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	for (auto &i: val) {
		bpos = nt.buffers(i, ndr, bpos, epos, flags, level);
		if (bpos < 0) {
			return bpos;
		}
	}
	return bpos;
}

template <typename T, typename NT>
static inline void x_ndr_ostr_vector(NT &&nt, const std::vector<T> &val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	ndr << "length=" << val.size() << enter;
	for (size_t i = 0; i < val.size(); ++i) {
		ndr << '#' << i << ": ";
		nt.ostr(val[i], ndr, flags, level);
		ndr << next;
	}
	ndr << leave;
}

#define X_NDR_SCALARS_VECTOR(nt, val, ndr, bpos, epos, flags, level) \
	X_NDR_VERIFY((bpos), x_ndr_scalars_vector((nt){}, (val), (ndr), (bpos), (epos), flags, level))

#define X_NDR_BUFFERS_VECTOR(nt, val, ndr, bpos, epos, flags, level) \
	X_NDR_VERIFY((bpos), x_ndr_buffers_vector((nt){}, (val), (ndr), (bpos), (epos), flags, level))

#define X_NDR_OSTR_VECTOR(nt, val, ndr, flags, level) \
	x_ndr_ostr_vector((nt){}, (val), (ndr), (flags), (level))


template <typename T, typename NT = ndr_traits_t<T>>
static inline x_ndr_off_t x_ndr_scalars_value(NT &&nt, T &&val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	return nt.scalars(val, ndr, bpos, epos, flags, level);
}

template <typename T, typename NT = ndr_traits_t<T>>
static inline x_ndr_off_t x_ndr_scalars_value(NT &&nt, T &&val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	T tmp;
	bpos = nt.scalars(tmp, ndr, bpos, epos, flags, level);
	if (bpos >= 0 && tmp != val) {
		return -NDR_ERR_VALIDATE;
	}
	return bpos;
}

#define X_NDR_SCALARS_VALUE(nt, val, ndr, bpos, epos, flags, level) \
	X_NDR_VERIFY((bpos), x_ndr_scalars_value((nt{}), (val), (ndr), (bpos), (epos), (flags), (level)))

template <typename T, size_t C, typename NT = ndr_traits_t<T>>
static inline x_ndr_off_t x_ndr_scalars_array_value(NT &&nt,
		const std::array<T, C> &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	return x_ndr_scalars_array(nt, val, ndr, bpos, epos, flags, level);
}

template <typename T, size_t C, typename NT = ndr_traits_t<T>>
static inline x_ndr_off_t x_ndr_scalars_array_value(NT &&nt,
		std::array<T, C> &&val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	return x_ndr_scalars_array(nt, val, ndr, bpos, epos, flags, level);
}

template <typename T, size_t C, typename NT = ndr_traits_t<T>>
static inline x_ndr_off_t x_ndr_scalars_array_value(NT &&nt,
		const std::array<T, C> &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	std::array<T, C> tmp;
	bpos = x_ndr_scalars_array(nt, tmp, ndr, bpos, epos, flags, level);
	if (bpos >= 0 && tmp != val) {
		return -NDR_ERR_VALIDATE;
	}
	return bpos;
}

#define X_NDR_SCALARS_ARRAY_VALUE(nt, val, ndr, bpos, epos, flags, level) \
	X_NDR_VERIFY((bpos), x_ndr_scalars_array_value((nt{}), (val), (ndr), (bpos), (epos), (flags), (level)))



x_ndr_off_t x_ndr_scalars_string_intl(const std::string &str, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, bool add_nul_empty);
x_ndr_off_t x_ndr_scalars_string_intl(std::string &str, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, bool add_nul_empty);

x_ndr_off_t x_ndr_scalars_string_intl(const std::u16string &str, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, bool add_nul_empty);
x_ndr_off_t x_ndr_scalars_string_intl(std::u16string &str, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, bool add_nul_empty);

x_ndr_off_t x_ndr_scalars_string(const std::string &str, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, bool add_nul_empty);
x_ndr_off_t x_ndr_scalars_string(std::string &str, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, bool add_nul_empty);
void x_ndr_ostr_string(const std::string &str, x_ndr_ostr_t &ndr, uint32_t flags);

x_ndr_off_t x_ndr_scalars_string(const std::u16string &str, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, bool add_nul_empty);
x_ndr_off_t x_ndr_scalars_string(std::u16string &str, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, bool add_nul_empty);
void x_ndr_ostr_string(const std::u16string &str, x_ndr_ostr_t &ndr, uint32_t flags);


template <> struct ndr_traits_t<std::string>
{
	using has_buffers = std::false_type;
	using ndr_base_type = std::string;
	using ndr_data_type = x_ndr_type_primary;

	x_ndr_off_t scalars(const std::string &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_scalars_string(val, ndr, bpos, epos, flags, true);
	}

	x_ndr_off_t scalars(std::string &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_scalars_string(val, ndr, bpos, epos, flags, true);
	}

	void ostr(const std::string &val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		x_ndr_ostr_string(val, ndr, flags);
	}
};

template <> struct ndr_traits_t<std::u16string>
{
	using has_buffers = std::false_type;
	using ndr_base_type = std::string;
	using ndr_data_type = x_ndr_type_primary;

	x_ndr_off_t scalars(const std::u16string &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_scalars_string(val, ndr, bpos, epos, flags, true);
	}

	x_ndr_off_t scalars(std::u16string &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_scalars_string(val, ndr, bpos, epos, flags, true);
	}

	void ostr(const std::u16string &val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		x_ndr_ostr_string(val, ndr, flags);
	}
};

struct DATA_BLOB
{
	std::vector<uint8_t> val;
};

template <>
struct ndr_traits_t<DATA_BLOB>
{
	using has_buffers = std::false_type;
	using ndr_data_type = x_ndr_type_primary;
	using ndr_base_type = DATA_BLOB;

	x_ndr_off_t scalars(const DATA_BLOB &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const;

	x_ndr_off_t scalars(DATA_BLOB &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const;

	void ostr(const DATA_BLOB &val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const;
};

template <typename T, typename NDR>
inline x_ndr_off_t x_ndr_scalars_charset(T &&val, NDR &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	if ((flags & LIBNDR_FLAG_STR_NULLTERM) == 0) {
		flags |= LIBNDR_FLAG_STR_NOTERM;
	}
	return x_ndr_scalars_string_intl(std::forward<T>(val), ndr, bpos, epos, flags, false);
}

#define X_NDR_SCALARS_CHARSET(__val, __ndr, __bpos, __epos, __flags, __level) do { \
	X_ASSERT((__level) == X_NDR_SWITCH_NONE); \
	X_NDR_VERIFY((__bpos), x_ndr_scalars_charset((__val), (__ndr), (__bpos), (__epos), (__flags))); \
} while (0)

#define X_NDR_OSTR_CHARSET(__val, __ndr, __flags, __level) do { \
	X_ASSERT((__level) == X_NDR_SWITCH_NONE); \
	x_ndr_ostr_string((__val), (__ndr), (__flags)); \
} while (0)


enum {
	str_size_noterm = 1,
	str_length_noterm = 2,
};

x_ndr_off_t x_ndr_scalars_size_length_string(const std::u16string &val, x_ndr_push_t &ndr, x_ndr_off_t bpos,  x_ndr_off_t epos, uint32_t flags, uint32_t size_length_flags);
x_ndr_off_t x_ndr_scalars_size_length_string(std::u16string &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos,  x_ndr_off_t epos, uint32_t flags, uint32_t size_length_flags);

#define X_NDR_SCALARS_STRING_CHARSET_unused(__val, __ndr, __bpos, __epos, __flags, __level) do { \
	X_ASSERT((__level) == X_NDR_SWITCH_NONE); \
	X_NDR_VERIFY((__bpos), x_ndr_scalars_size_length_string((__val), (__ndr), (__bpos), (__epos), (__flags), str_size_noterm|str_length_noterm)); \
} while (0)

#define X_NDR_SCALARS_STRING_CHARSET(__val, __ndr, __bpos, __epos, __flags, __level) do { \
	X_ASSERT((__level) == X_NDR_SWITCH_NONE); \
	X_NDR_VERIFY((__bpos), x_ndr_scalars_size_length_string((__val), (__ndr), (__bpos), (__epos), (__flags), 0)); \
} while (0)

#define X_NDR_OSTR_STRING_CHARSET(__val, __ndr, __flags, __level) do { \
	X_ASSERT((__level) == X_NDR_SWITCH_NONE); \
	x_ndr_ostr_string((__val), (__ndr), (__flags)); \
} while (0)

}

#endif /* __ndr_types__hxx__ */

