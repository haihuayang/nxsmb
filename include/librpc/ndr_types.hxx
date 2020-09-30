
#ifndef __ndr_types__hxx__
#define __ndr_types__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

namespace idl {

template <typename T, size_t C>
struct ndr_traits_t<std::array<T, C>>
{
	x_ndr_off_t ndr_scalars(const std::array<T, C> &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		for (auto &&i: val) {
			X_NDR_SCALARS_SIMPLE(i, ndr, bpos, epos, flags, level);
		}
		return bpos;
	}
	x_ndr_off_t ndr_scalars(std::array<T, C> &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		for (auto &&i: val) {
			X_NDR_SCALARS_SIMPLE(i, ndr, bpos, epos, flags, level);
		}
		return bpos;
	}
	void ostr(const std::array<T, C> &val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		ndr << "length=" << C << enter;
		for (size_t i = 0; i < C; ++i) {
			ndr << '#' << i << ": ";
			x_ndr_ostr_simple(val[i], ndr, flags, level);
			ndr << next;
		}
		ndr << leave;
	}
};

template <typename T>
struct ndr_traits_t<std::vector<T>>
{
	x_ndr_off_t ndr_scalars(const std::vector<T> &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		for (auto &&i: val) {
			X_NDR_SCALARS_SIMPLE(i, ndr, bpos, epos, flags, level);
		}
		return bpos;
	}
	x_ndr_off_t ndr_scalars(std::vector<T> &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		for (auto &&i: val) {
			X_NDR_SCALARS_SIMPLE(i, ndr, bpos, epos, flags, level);
		}
		return bpos;
	}
	void ostr(const std::vector<T> &val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		ndr << "length=" << val.size() << enter;
		for (size_t i = 0; i < val.size(); ++i) {
			ndr << '#' << i << ": ";
			x_ndr_ostr_simple(val[i], ndr, flags, level);
			ndr << next;
		}
		ndr << leave;
	}
};


#if 0
static inline x_ndr_off_t x_ndr_scalars(uint3264 t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	if (unlikely(flags & LIBNDR_FLAG_NDR64)) {
		return x_ndr_push_uint64_align(t.val, ndr, bpos, epos, flags, 8);
	}
	return x_ndr_push_uint32(t.val, ndr, bpos, epos, flags);
}

static inline x_ndr_off_t x_ndr_scalars(uint3264 &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	if (unlikely(flags & LIBNDR_FLAG_NDR64)) {
		uint64_t val;
		x_ndr_off_t ret = x_ndr_pull_uint64_align(val, ndr, bpos, epos, flags, 8);
		if (ret == 0) {
			t.val = val;
		}
		return ret;
	}
	return x_ndr_pull_uint32(t.val, ndr, bpos, epos, flags);
}
#endif

template <> struct ndr_traits_t<uint3264>
{
	x_ndr_off_t ndr_scalars(uint3264 val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		if (unlikely(flags & LIBNDR_FLAG_NDR64)) {
			return x_ndr_push_uint64_align(val.val, ndr, bpos, epos, flags, 8);
		}
		return x_ndr_push_uint32(val.val, ndr, bpos, epos, flags);
	}
	x_ndr_off_t ndr_scalars(uint3264 &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		if (unlikely(flags & LIBNDR_FLAG_NDR64)) {
			uint64_t tmp;
			x_ndr_off_t ret = x_ndr_pull_uint64_align(tmp, ndr, bpos, epos, flags, 8);
			if (ret == 0) {
				val.val = tmp;
			}
			return ret;
		}
		return x_ndr_pull_uint32(val.val, ndr, bpos, epos, flags);
	}
	void ostr(uint3264 val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		ndr.os << val.val;
	}
};

template <> struct ndr_traits_t<uint64_t>
{
	using has_buffers = std::false_type;
	x_ndr_off_t ndr_scalars(uint64_t val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_push_uint64(val, ndr, bpos, epos, flags);
	}
	x_ndr_off_t ndr_scalars(uint64_t &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_pull_uint64(val, ndr, bpos, epos, flags);
	}
	void ostr(uint64_t val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		ndr.os << val;
	}
};

template <> struct ndr_traits_t<uint32_t>
{
	using has_buffers = std::false_type;
	x_ndr_off_t ndr_scalars(uint32_t val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_push_uint32(val, ndr, bpos, epos, flags);
	}
	x_ndr_off_t ndr_scalars(uint32_t &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_pull_uint32(val, ndr, bpos, epos, flags);
	}
	void ostr(uint32_t val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		ndr.os << val;
	}
};

template <> struct ndr_traits_t<uint16_t>
{
	using has_buffers = std::false_type;
	x_ndr_off_t ndr_scalars(uint16_t val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_push_uint16(val, ndr, bpos, epos, flags);
	}
	x_ndr_off_t ndr_scalars(uint16_t &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
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
	x_ndr_off_t ndr_scalars(uint8_t val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_push_uint8(val, ndr, bpos, epos, flags);
	}
	x_ndr_off_t ndr_scalars(uint8_t &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_pull_uint8(val, ndr, bpos, epos, flags);
	}
	void ostr(uint8_t val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		ndr.os << val;
	}
};

template <> struct ndr_traits_t<std::u16string>
{
	using has_buffers = std::false_type;
#if 0
	x_ndr_off_t ndr_scalars(uint8_t val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_push_uint8(val, ndr, bpos, epos, flags);
	}
	x_ndr_off_t ndr_scalars(uint8_t &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		return x_ndr_pull_uint8(val, ndr, bpos, epos, flags);
	}
#endif
	void ostr(const std::u16string &val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const;
};

#if 0
static inline x_ndr_off_t x_ndr_scalars(int64_t t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	return x_ndr_push_int64(t, ndr, bpos, epos, flags);
}

static inline x_ndr_off_t x_ndr_scalars(int64_t &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	return x_ndr_pull_int64(t, ndr, bpos, epos, flags);
}

static inline x_ndr_off_t x_ndr_scalars(uint32_t t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	return x_ndr_push_uint32(t, ndr, bpos, epos, flags);
}

static inline x_ndr_off_t x_ndr_scalars(uint32_t &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	return x_ndr_pull_uint32(t, ndr, bpos, epos, flags);
}

template <>
inline x_ndr_off_t x_ndr_skip<uint32_t>(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	uint32_t tmp{0};
	return x_ndr_scalars(tmp, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
}

template <>
inline x_ndr_off_t x_ndr_skip<uint32_t>(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	uint32_t tmp{0};
	return x_ndr_scalars(tmp, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
}

static inline x_ndr_off_t x_ndr_scalars(int32_t t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	return x_ndr_push_uint32((uint32_t)t, ndr, bpos, epos, flags);
}

static inline x_ndr_off_t x_ndr_scalars(int32_t &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	uint32_t tmp;
	x_ndr_off_t ret = x_ndr_pull_uint32(tmp, ndr, bpos, epos, flags);
	t = (int32_t)tmp;
	return ret;
}

static inline x_ndr_off_t x_ndr_scalars(uint16_t t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	return x_ndr_push_uint16(t, ndr, bpos, epos, flags);
}

static inline x_ndr_off_t x_ndr_scalars(uint16_t &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	return x_ndr_pull_uint16(t, ndr, bpos, epos, flags);
}

template <>
inline x_ndr_off_t x_ndr_skip<uint16_t>(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	uint16_t tmp{0};
	return x_ndr_scalars(tmp, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
}

template <>
inline x_ndr_off_t x_ndr_skip<uint16_t>(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	uint16_t tmp{0};
	return x_ndr_scalars(tmp, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
}

static inline x_ndr_off_t x_ndr_scalars(uint8_t t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	return x_ndr_push_uint8(t, ndr, bpos, epos, flags);
}

static inline x_ndr_off_t x_ndr_scalars(uint8_t &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	return x_ndr_pull_uint8(t, ndr, bpos, epos, flags);
}

static inline x_ndr_off_t x_ndr_scalars(char t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	return x_ndr_push_uint8(t, ndr, bpos, epos, flags);
}

static inline x_ndr_off_t x_ndr_scalars(char &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	uint8_t tmp;
	x_ndr_off_t ret = x_ndr_pull_uint8(tmp, ndr, bpos, epos, flags);
	if (ret > 0) {
		t = (char)tmp;
	}
	return ret;
}
#endif
}

#endif /* __ndr_types__hxx__ */

