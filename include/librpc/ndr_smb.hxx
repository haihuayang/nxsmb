
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
	uint64_t val{0};
};

std::ostream &operator<<(std::ostream &os, NTTIME v);

template <>
struct x_ndr_traits_t<NTTIME> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_struct;
};

template <>
struct ndr_traits_t<NTTIME>
{
	x_ndr_off_t ndr_scalars(NTTIME t, x_ndr_push_t &ndr,
			x_ndr_off_t bpos, x_ndr_off_t epos,
			uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_push_uint64_align(t.val, ndr, bpos, epos, flags, 4);
	}

	x_ndr_off_t ndr_scalars(NTTIME &t, x_ndr_pull_t &ndr,
			x_ndr_off_t bpos, x_ndr_off_t epos,
			uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_pull_uint64_align(t.val, ndr, bpos, epos, flags, 4);
	}

	void ostr(NTTIME t, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		ndr.os << t;
	}
};
typedef NTTIME NTTIME_hyper; // TODO different push/pull
#if 0
template <>
inline x_ndr_off_t x_ndr_scalars(
		const ndr_traits_t<NTTIME> &ndr_traits,
		NTTIME t, x_ndr_push_t &ndr,
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
#endif


}

#endif /* __ndr_nxsmb__hxx__ */

