
#ifndef __ndr_types__hxx__
#define __ndr_types__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include <string>
#include <memory>
#include <arpa/inet.h>
#include "include/charset.hxx"

namespace idl {

template <typename T>
static inline size_t vector_ptr_get_size(const std::shared_ptr<std::vector<T>> &val)
{
	if (val) {
		return val->size();
	} else {
		return 0;
	}
}

template <typename NT>
struct ndr_traits_at_t
{
	NT nt;
	x_ndr_off_t pos;
	uint32_t flags;
	void operator()(x_ndr_push_t &ndr, typename NT::ndr_base_type val, x_ndr_off_t epos) const {
		X_ASSERT(x_ndr_scalars_default(val, ndr, pos, epos, flags, X_NDR_SWITCH_NONE) > 0);
	}
	typename NT::ndr_base_type operator()(x_ndr_pull_t &ndr, x_ndr_off_t epos) const {
		typename NT::ndr_base_type val;
		X_ASSERT(x_ndr_scalars_default(val, ndr, pos, epos, flags, X_NDR_SWITCH_NONE) > 0);
		return val;
	}
};

template <> struct ndr_traits_t<uint3264>
{
	using has_buffers = std::false_type;
	using ndr_data_type = x_ndr_type_primary;
	using ndr_base_type = uint3264;

	x_ndr_off_t scalars(uint3264 val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		if (unlikely(flags & LIBNDR_FLAG_NDR64)) {
			return x_ndr_push_uint64_align(val.val, ndr, bpos, epos, flags, 8);
		}
		return x_ndr_push_uint32(val.val, ndr, bpos, epos, flags);
	}
	x_ndr_off_t scalars(uint3264 &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
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

struct ndr_traits_astring
{
	using has_buffers = std::false_type;
	using ndr_data_type = x_ndr_type_primary;
	using ndr_base_type = std::string;

	x_ndr_off_t scalars(const std::string &val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t scalars(std::string &val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(const std::string &val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const;
};

struct ndr_traits_nstring
{
	using has_buffers = std::false_type;
	using ndr_data_type = x_ndr_type_primary;
	using ndr_base_type = std::u16string;

	x_ndr_off_t scalars(const std::u16string &val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t scalars(std::u16string &val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(const std::u16string &val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const;
};


template <> struct ndr_traits_t<std::vector<uint16_t>>
{
	using has_buffers = std::false_type;
	using ndr_data_type = x_ndr_type_primary;
	using ndr_base_type = std::vector<uint16_t>;

	x_ndr_off_t scalars(const std::vector<uint16_t> &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		X_ASSERT(!x_ndr_be(flags)); // TODO
		return x_ndr_push_bytes(val.data(), ndr, bpos, epos, val.size() * 2);
	}
	x_ndr_off_t scalars(std::vector<uint16_t> &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		X_ASSERT(!x_ndr_be(flags)); // TODO
		size_t length = epos - bpos;
		if (length % 2 != 0) {
			return -NDR_ERR_LENGTH;
		}
		val.assign((const uint16_t *)(ndr.get_data() + bpos), (const uint16_t *)(ndr.get_data() + epos));
		return epos;
	}
	void ostr(const std::vector<uint16_t> &val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		X_TODO;
		// ndr.os << val;
	}
};


#define X_NDR_SCALARS_DEFAULT(val, ndr, bpos, epos, ...) \
	X_NDR_VERIFY((bpos), x_ndr_scalars_default((val), (ndr), (bpos), (epos), __VA_ARGS__))

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
		std::array<T, C> &&val, x_ndr_pull_t &ndr,
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


template <> struct ndr_traits_t<std::string>
{
	using has_buffers = std::false_type;
	x_ndr_off_t scalars(const std::string &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		X_TODO;
		return bpos;
	}
	x_ndr_off_t scalars(std::string &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		X_TODO;
		return bpos;
	}
	void ostr(const std::string &val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		ndr << enter;
		X_TODO;
		ndr << leave;
	}
};


template <> struct ndr_traits_t<std::u16string>
{
	using has_buffers = std::false_type;

	x_ndr_off_t scalars(const std::u16string &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		X_ASSERT(!X_NDR_BE(flags)); // TODO support bigendian
		return x_ndr_push_bytes(val.data(), ndr, bpos, epos, val.size() * 2);
	}

	x_ndr_off_t scalars(std::u16string &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		X_ASSERT(!X_NDR_BE(flags)); // TODO support bigendian
		size_t length = epos - bpos;
		if (length & 1) {
			return -NDR_ERR_LENGTH;
		}
		val.assign((const char16_t *)(ndr.get_data() + bpos), (const char16_t *)(ndr.get_data() + epos)); 
		return epos;
	}

	void ostr(const std::u16string &val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		ndr << enter;
		ndr << "u'" << x_convert_utf16_to_utf8(val) << "'";
		ndr << leave;
	}
};

#define X_NDR_SCALARS_STRING(nt, val, ndr, bpos, epos, flags, level) \
	X_NDR_VERIFY((bpos), (nt){}.scalars((val), (ndr), (bpos), (epos), flags, level))
#if 0
#define X_NDR_BUFFERS_STRING(nt, val, ndr, bpos, epos, flags, level) \
	X_NDR_VERIFY((bpos), x_ndr_buffers_string((nt){}, (val), (ndr), (bpos), (epos), flags, level))
#endif
#define X_NDR_OSTR_STRING(nt, val, ndr, flags, level) \
	(nt){}.ostr((val), (ndr), (flags), (level))


template <typename T, typename NT>
inline x_ndr_off_t x_ndr_scalars_unique_ptr(NT &&nt,
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

template <typename T, typename NT>
inline x_ndr_off_t x_ndr_scalars_unique_ptr(NT &&nt,
		std::shared_ptr<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	uint3264 ptr;
	X_NDR_SCALARS_DEFAULT(ptr, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (ptr.val) {
		t = x_ndr_allocate_ptr<T, NT>(level);
		ndr.next_ptr();
	}
	return bpos;
}

template <typename T, typename NT>
inline x_ndr_off_t x_ndr_buffers_unique_ptr(NT &&nt, const std::shared_ptr<T> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	if (t) {
		bpos = x_ndr_both(nt, *t, ndr,
				bpos, epos, flags, level);
	}
	return bpos;
}

template <typename T, typename NT>
inline x_ndr_off_t x_ndr_buffers_unique_ptr(NT &&nt, std::shared_ptr<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	if (t) {
		bpos = x_ndr_both(nt, *t, ndr,
				bpos, epos, flags, level);
	}
	return bpos;
}

#define X_NDR_OSTR_PTR(nt, val, ndr, ...) do { \
	if (val) { \
		(nt{}).ostr(*(val), (ndr), __VA_ARGS__); \
	} else { \
		ndr << "NULL"; \
	} \
} while (0)

#define X_NDR_SCALARS_UNIQUE_PTR(nt, val, ndr, bpos, epos, flags, level) \
	X_NDR_VERIFY((bpos), x_ndr_scalars_unique_ptr((nt){}, (val), (ndr), (bpos), (epos), flags, level))

#define X_NDR_BUFFERS_UNIQUE_PTR(nt, val, ndr, bpos, epos, flags, level) \
	X_NDR_VERIFY((bpos), x_ndr_buffers_unique_ptr((nt){}, (val), (ndr), (bpos), (epos), flags, level))

#define X_NDR_OSTR_UNIQUE_PTR X_NDR_OSTR_PTR


template <typename T>
inline x_ndr_off_t x_ndr_scalars_unique_string(const std::shared_ptr<T> &t, x_ndr_push_t &ndr,
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
inline x_ndr_off_t x_ndr_scalars_unique_string(std::shared_ptr<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	uint3264 ptr;
	X_NDR_SCALARS_DEFAULT(ptr, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (ptr.val) {
		t = std::make_shared<T>();
		ndr.next_ptr();
	}
	return bpos;
}

template <typename T, typename NT>
inline x_ndr_off_t x_ndr_buffers_unique_string(NT &&nt, const std::shared_ptr<T> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	if (t) {
		bpos = x_ndr_both(nt, *t, ndr,
				bpos, epos, flags, level);
	}
	return bpos;
}

template <typename T, typename NT>
inline x_ndr_off_t x_ndr_buffers_unique_string(NT &&nt, std::shared_ptr<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	if (t) {
		bpos = x_ndr_both(nt, *t, ndr,
				bpos, epos, flags, level);
	}
	return bpos;
}

#define X_NDR_OSTR_STRING_PTR(nt, val, ndr, ...) do { \
	if (val) { \
		(nt{}).ostr(*(val), (ndr), __VA_ARGS__); \
	} else { \
		ndr << "NULL"; \
	} \
} while (0)

#define X_NDR_SCALARS_UNIQUE_STRING(nt, val, ndr, bpos, epos, flags, level) \
	X_NDR_VERIFY((bpos), x_ndr_scalars_unique_string((val), (ndr), (bpos), (epos), flags, level))

#define X_NDR_BUFFERS_UNIQUE_STRING(nt, val, ndr, bpos, epos, flags, level) \
	X_NDR_VERIFY((bpos), x_ndr_buffers_unique_string((nt){}, (val), (ndr), (bpos), (epos), flags, level))

#define X_NDR_OSTR_UNIQUE_STRING X_NDR_OSTR_STRING_PTR

template <typename T>
inline x_ndr_off_t x_ndr_scalars_unique_vector(const std::shared_ptr<T> &t, x_ndr_push_t &ndr,
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
inline x_ndr_off_t x_ndr_scalars_unique_vector(std::shared_ptr<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	uint3264 ptr;
	X_NDR_SCALARS_DEFAULT(ptr, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (ptr.val) {
		t = std::make_shared<T>();
		ndr.next_ptr();
	}
	return bpos;
}

template <typename T, typename NT, typename AT>
x_ndr_off_t x_ndr_vector_size_is(
		NT &&nt, const std::vector<T> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		AT &&size_is)
{
	size_is(ndr, t.size(), epos);
	bpos = x_ndr_scalars_default(uint3264(t.size()), ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (bpos < 0) {
		return bpos;
	}
	for (auto &v: t) {
		bpos = x_ndr_both(nt, v, ndr, bpos, epos, flags, level);
		if (bpos < 0) {
			return bpos;
		}
	}
	return bpos;
}

template <typename T, typename NT, typename AT>
x_ndr_off_t x_ndr_vector_size_is(
		NT &&nt, std::vector<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		AT &&size_is)
{
	// we ignore it for now since size is duplicated, auto s = size_is(ndr, epos);
	uint3264 size;
	bpos = x_ndr_scalars_default(size, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (bpos < 0) {
		return bpos;
	}

	t.resize(size.val); // TODO check size valid, not exhaust memory
	for (auto &v: t) {
		bpos = x_ndr_both(nt, v, ndr, bpos, epos, flags, level);
		if (bpos < 0) {
			return bpos;
		}
	}
	return bpos;
}

template <typename T, typename NT, typename AT>
inline x_ndr_off_t x_ndr_buffers_unique_size_is(
		NT &&nt, const std::shared_ptr<T> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		AT &&size_is)
{
	if (t) {
		bpos = x_ndr_vector_size_is(nt, *t, ndr, bpos, epos, flags, level, size_is);
	}
	return bpos;
}

template <typename T, typename NT, typename AT>
inline x_ndr_off_t x_ndr_buffers_unique_size_is(
		NT &&nt, std::shared_ptr<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		AT &&size_is)
{
	if (t) {
		bpos = x_ndr_vector_size_is(nt, *t, ndr, bpos, epos, flags, level, size_is);
	}
	return bpos;
}

template <typename T, typename NT, typename SizeIs, typename LengthIs>
inline x_ndr_off_t x_ndr_buffers_unique_length_is(
		NT &&nt, const std::shared_ptr<T> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		SizeIs &&size_is, LengthIs &&length_is)
{
	X_TODO;
	return bpos;
}

template <typename T, typename NT, typename SizeIs, typename LengthIs>
inline x_ndr_off_t x_ndr_buffers_unique_length_is(
		NT &&nt, std::shared_ptr<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		SizeIs &&size_is, LengthIs &&length_is)
{
	X_TODO;
	return bpos;
}

template <typename T, typename NT>
static inline void x_ndr_ostr_ptr_vector(NT &&nt, const std::shared_ptr<std::vector<T>> &val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	if (val) {
		x_ndr_ostr_vector(nt, *val, ndr, flags, level);
	} else {
		ndr << "NULL";
	}
}

#define X_NDR_SCALARS_UNIQUE_VECTOR(nt, val, ndr, bpos, epos, flags, level) \
	X_NDR_VERIFY((bpos), x_ndr_scalars_unique_vector((val), (ndr), (bpos), (epos), flags, level))

#define X_NDR_BUFFERS_UNIQUE_VECTOR(nt, val, ndr, bpos, epos, flags, level) \
	X_NDR_VERIFY((bpos), x_ndr_buffers_unique_vector((nt){}, (val), (ndr), (bpos), (epos), flags, level))

#define X_NDR_BUFFERS_UNIQUE_SIZE_IS(nt, val, ndr, bpos, epos, flags, level, at_size_is) \
	X_NDR_VERIFY((bpos), x_ndr_buffers_unique_size_is((nt){}, (val), (ndr), (bpos), (epos), (flags), (level), (at_size_is)))

#define X_NDR_BUFFERS_UNIQUE_LENGTH_IS(nt, val, ndr, bpos, epos, flags, level, at_size_is, at_length_is) \
	X_NDR_VERIFY((bpos), x_ndr_buffers_unique_length_is((nt){}, (val), (ndr), (bpos), (epos), (flags), (level), (at_size_is), (at_length_is)))

#define X_NDR_OSTR_PTR_VECTOR(nt, val, ndr, flags, level) \
	x_ndr_ostr_ptr_vector((nt){}, (val), (ndr), (flags), (level))

template <typename T, typename NT, typename AT>
x_ndr_off_t x_ndr_buffers_relative_ptr(NT &&nt,
		const std::shared_ptr<T> &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		AT &&pos_at)
{
	if (val) {
		X_NDR_DO_ALIGN(ndr, bpos, epos, flags);
		pos_at(ndr, bpos - ndr.base, epos);
		bpos = x_ndr_both(nt, *val, ndr, bpos, epos, flags, level);
	} 
	return bpos;
}

template <typename T, typename NT, typename AT>
x_ndr_off_t x_ndr_buffers_relative_ptr(NT &&nt,
		std::shared_ptr<T> &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		AT &&pos_at)
{
	auto offset = pos_at(ndr, epos);
	if (offset) {
		X_NDR_CHECK_ALIGN(ndr, flags, offset);
		val = x_ndr_allocate_ptr<T, NT>(level);

		x_ndr_off_t tmp_bpos = X_NDR_CHECK_POS(ndr.base + offset, 0, epos);
		tmp_bpos = x_ndr_both(nt, *val, ndr, tmp_bpos, epos, flags, level);
		if (tmp_bpos < 0) {
			return tmp_bpos;
		}

		bpos = std::max(bpos, tmp_bpos);
	}
	return bpos;
}


template <typename T, typename NT, typename AT, typename SIZE_AT>
x_ndr_off_t x_ndr_buffers_relative_ptr(NT &&nt,
		const std::shared_ptr<T> &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		AT &&pos_at, SIZE_AT &&size_at)
{
	x_ndr_off_t orig_bpos = bpos;
	if (val) {
		X_NDR_DO_ALIGN(ndr, bpos, epos, flags);
		pos_at(ndr, bpos - ndr.base, epos);
		bpos = x_ndr_both(nt, *val, ndr, bpos, epos, flags, level);
		if (bpos < 0) {
			return bpos;
		}
	}
	size_at(ndr, bpos - orig_bpos, epos);
	return bpos;
}

template <typename T, typename NT, typename AT, typename SIZE_AT>
x_ndr_off_t x_ndr_buffers_relative_ptr(NT &&nt,
		std::shared_ptr<T> &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		AT &&pos_at, SIZE_AT &&size_at)
{
	auto offset = pos_at(ndr, epos);
	if (offset) {
		X_NDR_CHECK_ALIGN(ndr, flags, offset);
		val = std::make_shared<T>();
		val->__init(level);

		auto size = size_at(ndr, epos);
		x_ndr_off_t tmp_bpos = X_NDR_CHECK_POS(ndr.base + offset, 0, epos);
		tmp_bpos = x_ndr_both(nt, *val, ndr, tmp_bpos, epos, flags, level);
		epos = X_NDR_CHECK_POS(tmp_bpos + size, tmp_bpos, epos);
		if (tmp_bpos < 0) {
			return bpos;
		}

		bpos = std::max(bpos, tmp_bpos);
	} 
	return bpos;
}


#define X_NDR_BUFFERS_RELATIVE_PTR__0(nt, val, ndr, bpos, epos, flags, level, at_ptr) \
	X_NDR_VERIFY((bpos), x_ndr_buffers_relative_ptr((nt){}, (val), (ndr), (bpos), (epos), (flags), (level), (at_ptr)))

#define X_NDR_BUFFERS_RELATIVE_PTR__1(nt, val, ndr, bpos, epos, flags, level, pos_nt, pos_ptr, size_nt, size_ptr) \
	X_NDR_VERIFY((bpos), x_ndr_buffers_relative_ptr((nt){}, (val), (ndr), (bpos), (epos), (flags), (level), (ndr_traits_at_t<const pos_nt>{pos_nt{}, (pos_ptr)}), (ndr_traits_at_t<const size_nt>{size_nt{}, (size_ptr)})))

template <typename T, typename NT, typename AT_POS, typename AT_SIZE_IS>
x_ndr_off_t x_ndr_buffers_relative_size_is(NT &&nt,
		const std::shared_ptr<T> &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		AT_POS &&at_pos, AT_SIZE_IS && at_size_is)
{
	if (val) {
		X_NDR_DO_ALIGN(ndr, bpos, epos, flags);
		at_pos(ndr, bpos - ndr.base, epos);
		bpos = x_ndr_vector_size_is(nt, *val, ndr, bpos, epos, flags, level, at_size_is);
	} 
	return bpos;
}

template <typename T, typename NT, typename AT_POS, typename AT_SIZE_IS>
x_ndr_off_t x_ndr_buffers_relative_size_is(NT &&nt,
		std::shared_ptr<T> &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		AT_POS &&at_pos, AT_SIZE_IS && at_size_is)
{
	auto offset = at_pos(ndr, epos);
	if (offset) {
		X_NDR_CHECK_ALIGN(ndr, flags, offset);
		val = x_ndr_allocate_ptr<T, NT>(level);

		x_ndr_off_t tmp_bpos = X_NDR_CHECK_POS(ndr.base + offset, 0, epos);
		tmp_bpos = x_ndr_vector_size_is(nt, *val, ndr, tmp_bpos, epos, flags, level, at_size_is);
		if (tmp_bpos < 0) {
			return tmp_bpos;
		}

		bpos = std::max(bpos, tmp_bpos);
	}
	return bpos;
}

#define X_NDR_BUFFERS_RELATIVE_SIZE_IS(nt, val, ndr, bpos, epos, flags, level, at_ptr, at_size_is) \
	X_NDR_VERIFY((bpos), x_ndr_buffers_relative_size_is((nt){}, (val), (ndr), (bpos), (epos), (flags), (level), (at_ptr), (at_size_is)))

#if 0
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
#endif

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
template <typename T, size_t C>
struct ndr_traits_t<std::array<T, C>>
{
	x_ndr_off_t scalars(const std::array<T, C> &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		for (auto &&i: val) {
			X_NDR_SCALARS_DEFAULT(i, ndr, bpos, epos, flags, level);
		}
		return bpos;
	}
	x_ndr_off_t scalars(std::array<T, C> &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		for (auto &&i: val) {
			X_NDR_SCALARS_DEFAULT(i, ndr, bpos, epos, flags, level);
		}
		return bpos;
	}
	void ostr(const std::array<T, C> &val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		ndr << "length=" << C << enter;
		for (size_t i = 0; i < C; ++i) {
			ndr << '#' << i << ": ";
			x_ndr_ostr_default(val[i], ndr, flags, level);
			ndr << next;
		}
		ndr << leave;
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

}

#endif /* __ndr_types__hxx__ */

