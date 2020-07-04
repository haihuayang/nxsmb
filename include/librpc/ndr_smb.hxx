
#ifndef __ndr_nxsmb__hxx__
#define __ndr_nxsmb__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "ndr.hxx"
#include "ndr_wrap.hxx"

namespace idl {

struct NTTIME
{
	enum {
		TIME_FIXUP_CONSTANT = 11644473600L,
	};
	uint64_t val;
};

std::ostream &operator<<(std::ostream &os, NTTIME v);

template <>
struct x_ndr_traits_t<NTTIME> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_struct;
};

template <>
inline x_ndr_off_t x_ndr_scalars(const NTTIME &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint64_align(t.val, ndr, bpos, epos, flags, 4);
}

template <>
inline x_ndr_off_t x_ndr_scalars(NTTIME &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	return x_ndr_pull_uint64_align(t.val, ndr, bpos, epos, flags, 4);
}

static inline void x_ndr_ostr(const NTTIME &t, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	ndr.os << t;
}

struct NTTIME_hyper
{
	uint64_t val;
};

std::ostream &operator<<(std::ostream &os, NTTIME_hyper v);

template <>
struct x_ndr_traits_t<NTTIME_hyper> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_struct;
};

template <>
inline x_ndr_off_t x_ndr_scalars(const NTTIME_hyper &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint64_align(t.val, ndr, bpos, epos, flags, 4);
}

template <>
inline x_ndr_off_t x_ndr_scalars(NTTIME_hyper &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	return x_ndr_pull_uint64_align(t.val, ndr, bpos, epos, flags, 4);
}

static inline void x_ndr_ostr(const NTTIME_hyper &t, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	ndr.os << NTTIME{t.val};
}



template <>
inline x_ndr_off_t x_ndr_scalars(const std::u16string &t,
		x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	return x_ndr_push_u16string(t, ndr, bpos, epos, flags);
}

template <>
inline x_ndr_off_t x_ndr_scalars(std::u16string &t,
		x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	return x_ndr_pull_u16string(t, ndr, bpos, epos, flags); 
}

#if 0
template <typename T, typename CT>
struct x_ndr_unique_array_t
{
	std::shared_ptr<std::vector<T>> val;
};

template <typename T, typename CT>
struct x_ndr_unique_with_size_length_TODO
{
	std::shared_ptr<std::vector<T>> val;
};

template <typename T, typename LT>
struct x_ndr_unique_ptr_with_size_length_t {
	mutable x_ndr_off_t __length_pos;
	mutable x_ndr_off_t __size_pos;
	void set_size_pos(x_ndr_off_t size_pos) { __size_pos = size_pos; }
	void set_length_pos(x_ndr_off_t length_pos) { __length_pos = length_pos; }
	std::shared_ptr<T> val;
};

template <typename T, typename LT>
struct x_ndr_traits_t<x_ndr_unique_ptr_with_size_length_t<T, LT>> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};

template <typename T, typename LT>
inline x_ndr_off_t x_ndr_scalars(const x_ndr_unique_ptr_with_size_length_t<T, LT> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	uint3264 ptr;
	if (t.val) {
		ptr.val = ndr.next_ptr();
		t.__pos_ptr = bpos;
	} else {
		ptr.val = 0;
	}
	X_NDR_SCALARS(LT(0), ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(ptr, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	return bpos;
}

template <typename T, typename LT>
inline x_ndr_off_t x_ndr_buffers(const x_ndr_unique_ptr_with_size_length_t<T, LT> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	if (t.val) {
		x_ndr_off_t orig_bpos = bpos;
		bpos = x_ndr_pusher_t<T, typename x_ndr_traits_t<T>::has_buffers>()(*t.val, ndr,
				bpos, epos, flags, level);
		if (bpos < 0) {
			return bpos;
		}
		X_NDR_SCALARS(LT(bpos - orig_bpos), ndr, t.__pos_ptr, epos, flags, X_NDR_SWITCH_NONE);
	}
	return bpos;
}

template <typename T, typename LT>
inline x_ndr_off_t x_ndr_scalars(x_ndr_unique_ptr_with_size_length_t<T, LT> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	uint3264 ptr;
	t.__pos_ptr = bpos;
	X_NDR_SKIP(LT, ndr, bpos, epos, flags);
	X_NDR_SCALARS(ptr, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (ptr.val) {
		t.val = x_ndr_allocate_ptr<T>(level);
	}
	return bpos;
}

template <typename T, typename LT>
inline x_ndr_off_t x_ndr_buffers(x_ndr_unique_ptr_with_size_length_t<T, LT> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	if (t.val) {
		LT length;
		X_NDR_SCALARS(length, ndr, t.__pos_ptr, epos, flags, X_NDR_SWITCH_NONE);
		epos = X_NDR_CHECK_POS(bpos + length, bpos, epos);
		bpos = x_ndr_puller_t<T, typename x_ndr_traits_t<T>::has_buffers>()(*t.val, ndr,
				bpos, epos, flags, level);
	}
	return bpos;
}
#endif
}

#endif /* __ndr_nxsmb__hxx__ */

