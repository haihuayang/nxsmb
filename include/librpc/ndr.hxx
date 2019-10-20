
#ifndef __ndr__hxx__
#define __ndr__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
#include <vector>
#include <utility>
#include <sstream>
#include <netinet/in.h>
#include <assert.h>
#include "samba/libcli/util/ntstatus.h"
#include "samba/lib/util/time.h"
#include "samba/lib/util/byteorder.h"
#include <array>
#include <memory>
#include <algorithm>
#include <functional>
#include <iomanip>
#include <limits.h>

namespace idl {

enum x_ndr_err_code_t : int {
	NDR_ERR_SUCCESS = 0,
	NDR_ERR_ARRAY_SIZE,
	NDR_ERR_BAD_SWITCH,
	NDR_ERR_OFFSET,
	NDR_ERR_RELATIVE,
	NDR_ERR_CHARCNV,
	NDR_ERR_LENGTH,
	NDR_ERR_SUBCONTEXT,
	NDR_ERR_COMPRESSION,
	NDR_ERR_STRING,
	NDR_ERR_VALIDATE,
	NDR_ERR_BUFSIZE,
	NDR_ERR_ALLOC,
	NDR_ERR_RANGE,
	NDR_ERR_TOKEN,
	NDR_ERR_IPV4ADDRESS,
	NDR_ERR_IPV6ADDRESS,
	NDR_ERR_INVALID_POINTER,
	NDR_ERR_UNREAD_BYTES,
	NDR_ERR_NDR64,
	NDR_ERR_FLAGS,
	NDR_ERR_INCOMPLETE_BUFFER
};


#define LIBNDR_FLAG_BIGENDIAN  (1<<0)
#define LIBNDR_FLAG_NOALIGN    (1<<1)

#define LIBNDR_FLAG_STR_ASCII		(1<<2)
#define LIBNDR_FLAG_STR_LEN4		(1<<3)
#define LIBNDR_FLAG_STR_SIZE4		(1<<4)
#define LIBNDR_FLAG_STR_NOTERM		(1<<5)
#define LIBNDR_FLAG_STR_NULLTERM	(1<<6)
#define LIBNDR_FLAG_STR_SIZE2		(1<<7)
#define LIBNDR_FLAG_STR_BYTESIZE	(1<<8)
#define LIBNDR_FLAG_STR_CONFORMANT	(1<<10)
#define LIBNDR_FLAG_STR_CHARLEN		(1<<11)
#define LIBNDR_FLAG_STR_UTF8		(1<<12)
#define LIBNDR_FLAG_STR_RAW8		(1<<13)
#define LIBNDR_STRING_FLAGS		(0x7FFC)

/*
 * don't debug NDR_ERR_BUFSIZE failures,
 * as the available buffer might be incomplete.
 *
 * return NDR_ERR_INCOMPLETE_BUFFER instead.
 */
#define LIBNDR_FLAG_INCOMPLETE_BUFFER (1<<16)

/*
 * This lets ndr_pull_subcontext_end() return
 * NDR_ERR_UNREAD_BYTES.
 */
#define LIBNDR_FLAG_SUBCONTEXT_NO_UNREAD_BYTES (1<<17)

/* set if relative pointers should *not* be marshalled in reverse order */
#define LIBNDR_FLAG_NO_RELATIVE_REVERSE	(1<<18)

/* set if relative pointers are marshalled in reverse order */
#define LIBNDR_FLAG_RELATIVE_REVERSE	(1<<19)

#define LIBNDR_FLAG_REF_ALLOC    (1<<20)
#define LIBNDR_FLAG_REMAINING    (1<<21)
#define LIBNDR_FLAG_ALIGN2       (1<<22)
#define LIBNDR_FLAG_ALIGN4       (1<<23)
#define LIBNDR_FLAG_ALIGN8       (1<<24)

#define LIBNDR_ALIGN_FLAGS ( 0        | \
		LIBNDR_FLAG_NOALIGN   | \
		LIBNDR_FLAG_REMAINING | \
		LIBNDR_FLAG_ALIGN2    | \
		LIBNDR_FLAG_ALIGN4    | \
		LIBNDR_FLAG_ALIGN8    | \
		0)

#define LIBNDR_PRINT_ARRAY_HEX   (1<<25)
#define LIBNDR_PRINT_SET_VALUES  (1<<26)

/* used to force a section of IDL to be little-endian */
#define LIBNDR_FLAG_LITTLE_ENDIAN (1<<27)

/* used to check if alignment padding is zero */
#define LIBNDR_FLAG_PAD_CHECK     (1<<28)

#define LIBNDR_FLAG_NDR64         (1<<29)

/* set if an object uuid will be present */
#define LIBNDR_FLAG_OBJECT_PRESENT    (1<<30)

/* set to avoid recursion in ndr_size_*() calculation */
#define LIBNDR_FLAG_NO_NDR_SIZE		(1<<31)

static inline uint32_t x_ndr_set_flags(uint32_t flags, uint32_t extra_flags)
{
	return flags | extra_flags;
}

template <typename T, typename... Args>
void construct(T &t, Args&&... args)
{
	new (&t) T{std::forward<Args>(args)...};
}

template <typename T>
void destruct(T &t) noexcept
{
	t.~T();
}

/* no std::size in c++14 */
template <typename T>
inline ssize_t get_size(const std::vector<T> &t)
{
	return t.size();
}

template <typename T, size_t N>
inline ssize_t get_size(const std::array<T, N> &t)
{
	return N;
}


typedef ssize_t x_ndr_off_t;
enum { X_NDR_MAX_SIZE = SSIZE_MAX };

typedef uint32_t x_ndr_switch_t;
enum : uint32_t {
	X_NDR_SWITCH_NONE = 0xffffffffu,
};

typedef unsigned int uint;
typedef uint32_t uint32;
typedef uint16_t uint16;
typedef int8_t int8;
typedef uint8_t uint8;
typedef uint64_t hyper;
typedef uint64_t uint64;
typedef uint32_t boolean32;
using string = std::string;

typedef std::vector<std::pair<const void *, uint32_t>> x_ndr_token_list_t;

#define NDR_BASE_MARSHALL_SIZE 1024
/* structure passed to functions that generate NDR formatted data */
struct x_ndr_push_t {
        x_ndr_push_t() {
                data.reserve(NDR_BASE_MARSHALL_SIZE);
        }

	std::vector<uint8_t> finish() {
		return std::move(data);
	}
	std::vector<uint8_t> data;
#if 0
	size_t get_offset() const {
		return data.size();
	}

        uint32_t flags = 0; /* LIBNDR_FLAG_* */
        bool fixed_buf_size;

        uint32_t relative_base_offset;
        uint32_t relative_end_offset;
        x_ndr_token_list_t relative_base_list;

        x_ndr_token_list_t switch_list;
        x_ndr_token_list_t relative_list;
        x_ndr_token_list_t relative_begin_list;
        x_ndr_token_list_t nbt_string_list;
        x_ndr_token_list_t dns_string_list;
        x_ndr_token_list_t full_ptr_list;

        // struct ndr_compression_state *cstate;

        /* this is used to ensure we generate unique reference IDs */
        uint32_t ptr_count = 0;
#endif
};

struct x_ndr_pull_t {
	x_ndr_pull_t(const uint8_t *d, size_t l) : data(d), data_size(l) { }
	uint32_t flags = 0; /* LIBNDR_FLAG_* */
	const uint8_t *data;
	uint32_t data_size;
#if 0
	uint32_t offset = 0;

        uint32_t relative_highest_offset;
        uint32_t relative_base_offset;
        uint32_t relative_rap_convert;
        x_ndr_token_list_t relative_base_list;

        x_ndr_token_list_t relative_list;
        x_ndr_token_list_t array_size_list;
        x_ndr_token_list_t array_length_list;
        x_ndr_token_list_t switch_list;

        // struct ndr_compression_state *cstate;

        /* this is used to ensure we generate unique reference IDs
           between request and reply */
        uint32_t ptr_count;
#endif
};

struct x_ndr_ostr_t {
	x_ndr_ostr_t(std::ostream &os, uint32_t indent, uint32_t ts = 4)
		: os(os), indent(indent), tabstop(ts) {}
#if 0
        void output_string(const char *name, const char *tname) {
                os << std::setw(4 * depth) << "" << name << ":" << tname << std::endl;
        }
        // void newline(uint32_t flags) { os << std::endl; }
	void next() { newline = true; }

	void leave() {
		X_ASSERT(depth > 0);
	       	--depth;
		newline = true;
	}

	void enter() {
		++depth;
		newline = true;
	}
#endif
	x_ndr_ostr_t &operator<<(x_ndr_ostr_t &(*pf)(x_ndr_ostr_t &)) {
		return pf(*this);
	}

        std::ostream &os;
	bool newline = false;
	uint32_t indent;
	uint32_t tabstop;
        int depth = 0;
};


template <typename T>
struct x_hex_t
{
	x_hex_t(T v) : v(v) {}
	const T v;
};

template <typename T>
x_ndr_ostr_t &operator<<(x_ndr_ostr_t &ndr, const T &v)
{
	if (ndr.newline) {
		ndr.newline = false;
		ndr.os << std::endl << std::setw(ndr.indent + ndr.tabstop * ndr.depth) << "";
	}
	ndr.os << v;
	return ndr;
}

x_ndr_ostr_t &next(x_ndr_ostr_t &ndr);

x_ndr_ostr_t &leave(x_ndr_ostr_t &ndr);

x_ndr_ostr_t &enter(x_ndr_ostr_t &ndr);

template <typename T>
std::ostream &operator<<(std::ostream &os, x_hex_t<T> v);

struct x_ndr_ostr_type_default { };
struct x_ndr_ostr_type_custom { };
struct x_ndr_ostr_type_enum { };
struct x_ndr_ostr_type_bitmap { };
struct x_ndr_ostr_type_struct { };
struct x_ndr_ostr_type_union { };

template <typename T> struct x_ndr_traits_t {
	using ndr_ostr_type = x_ndr_ostr_type_default;
};

template <typename T, typename Traits>
struct x_ndr_ostreamer_t {
	void operator()(const T& t, x_ndr_ostr_t &os, uint32_t flags, x_ndr_switch_t level) const {
		t.ostr(os, flags, level);
	}
};

template <typename T>
struct x_ndr_ostreamer_t<T, x_ndr_ostr_type_enum> {
	void operator()(const T& t, x_ndr_ostr_t &os, uint32_t flags, x_ndr_switch_t level) const {
		typedef x_ndr_traits_t<T> traits_t;
		const char *enum_name = "<UNKNOWN>";
		for (const auto &pair: traits_t::value_name_map) {
			if (pair.first == t) {
				enum_name = pair.second;
				break;
			}
		}
		os << enum_name << ',' << t;
	}
};

#if 0
template <typename T>
void x_ndr_ostr_bitmap(uint32_t v, x_ndr_ostr_t &os, uint32_t flags, )
{
		os << t << x_ndr_ostr_t::newline;
		os.enter();
		uint32_t nt = t;
		for (const auto &pair: traits_t::value_name_map) {
			if (pair.first & nt) {
				ndr_output_name(ndr, flags, pair.second);
				ndr.os << (uint32_t)pair.first << std::endl;
				nt &= ~pair.first;
				if (nt == 0) {
					break;
				}
			}
		}
		if (nt) {
			ndr_output_name(ndr, flags, "<UNKNOWN>");
			ndr.os << (uint32_t)nt << std::endl;
		}
		ndr.leave();
}
#endif
template <typename T>
struct x_ndr_ostreamer_t<T, x_ndr_ostr_type_bitmap> {
	void operator()(const T& t, x_ndr_ostr_t &os, uint32_t flags, x_ndr_switch_t level) const {
		if (t == 0) {
			os << 0;
			return;
		}
		using traits_t = x_ndr_traits_t<T>;
		using base_type = typename traits_t::ndr_base_type;
		base_type nt = t;
		os << x_hex_t<base_type>(nt) << enter;
		for (const auto &pair: traits_t::value_name_map) {
			if (pair.first & nt) {
				os << pair.second << ',' << x_hex_t<base_type>(pair.first) << next;
				nt &= ~pair.first;
				if (nt == 0) {
					break;
				}
			}
		}
		if (nt) {
			os << "<UNKNOWN>" << ',' << x_hex_t<base_type>(nt) << next;
		}
		os << leave;
	}
};

#define X_NDR_ERR_CODE_IS_SUCCESS(x) (x >= 0)

/* these are used to make the error checking on each element in libndr
   less tedious, hopefully making the code more readable */
#define X_NDR_CHECK(call) ({ \
        x_ndr_off_t _ret = call; \
        if (unlikely(!X_NDR_ERR_CODE_IS_SUCCESS(_ret))) { \
                return _ret; \
        } \
        _ret; \
})

#define X_NDR_VERIFY(ret, call) do { \
	x_ndr_off_t _ret = (call); \
	if (unlikely(!X_NDR_ERR_CODE_IS_SUCCESS(_ret))) { \
		X_DEVEL_ASSERT(0); \
		return _ret; \
	} \
	(ret) = _ret; \
} while (0)

static inline x_ndr_off_t x_ndr_check_range(ssize_t size, ssize_t min_num, ssize_t max_num)
{
	if (size < min_num || size > max_num) {
		return -NDR_ERR_RANGE;
	}
	return 0;
}

#define X_NDR_CHECK_RANGE(size, min_num, max_num) \
	X_NDR_CHECK(x_ndr_check_range((size), (min_num), (max_num)))

template <typename T>
inline x_ndr_off_t x_ndr_data(
	       	const T &t,
		x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
        return t.push(ndr, bpos, epos, flags, level);
}

template <typename T>
inline x_ndr_off_t x_ndr_data(
	       	T &t,
		x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t extra_flags, x_ndr_switch_t level)
{
        return t.pull(ndr, bpos, epos, extra_flags, level);
}

#define X_NDR_DATA(t, ndr, bpos, epos, ...) \
	X_NDR_VERIFY((bpos), x_ndr_data((t), (ndr), (bpos), (epos), __VA_ARGS__))

#define X_NDR_NORET(t, ndr, bpos, epos, extra_flags, level) \
	X_NDR_CHECK(x_ndr_data((t), (ndr), (bpos), (epos), (extra_flags), (level)))

#define X_NDR_PUSH_PTR(ptr, base, elem, ndr, bpos, epos, flags, level) do { \
	if (elem) { \
		X_NDR_DATA(*(elem), (ndr), (bpos), (epos), (flags), (level)); \
	} else { \
		/* this set offset to 0 */ \
		(ptr) = (base); \
	} \
} while (0)

#define X_NDR_PULL_RELATIVE(off, base, elem, ndr, bpos, epos, flags, level) do { \
	x_ndr_off_t __tmp_off = (base) + (off); \
	X_NDR_DATA((elem), (ndr), __tmp_off, (epos), (flags), (level)); \
	(bpos) = std::max((bpos), __tmp_off); \
} while (0)

#define X_NDR_PULL_RELATIVE_LENGTH(len, off, base, elem, ndr, bpos, epos, flags, level) do { \
	x_ndr_off_t __tmp_off = (base) + (off); \
	x_ndr_off_t __tmp_epos = X_NDR_ELEM_EPOS((len), (base), __tmp_off, (epos)); \
	X_NDR_DATA((elem), (ndr), __tmp_off, __tmp_epos, (flags), (level)); \
	(bpos) = std::max((bpos), __tmp_off); \
} while (0)

#define X_NDR_PULL_PTR(off, base, elem, ...) do { \
	if ((off)) { \
		X_NDR_PULL_RELATIVE((off), (base), (elem), __VA_ARGS__); \
	} \
} while (0)

#define X_NDR_PULL_PTR_LENGTH(len, off, base, elem, ndr, bpos, epos, flags, level) do { \
	if ((off)) { \
		x_ndr_off_t __tmp_off = (base) + (off); \
		x_ndr_off_t __tmp_epos = X_NDR_ELEM_EPOS((len), (base), __tmp_off, (epos)); \
		X_NDR_PULL_RELATIVE((off), (base), (elem), (ndr), (bpos), __tmp_epos, (flags), (level)); \
	} \
} while (0)


template <typename T, size_t C>
inline x_ndr_off_t x_ndr_data(const std::array<T,C> &t, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level)
{
	for (auto &i: t) {
		X_NDR_DATA(i, ndr, bpos, epos, flags, level);
	}
	return bpos;
}

template <typename T, size_t C>
inline x_ndr_off_t x_ndr_data(std::array<T,C> &t, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level)
{
	for (auto &i: t) {
		X_NDR_DATA(i, ndr, bpos, epos, flags, level);
	}
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_data(const std::vector<T> &t, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level)
{
	for (auto &i: t) {
		X_NDR_DATA(i, ndr, bpos, epos, flags, level);
	}
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_data(std::vector<T> &t, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level)
{
	while (bpos < epos) {
		T v;
		X_NDR_DATA(v, ndr, bpos, epos, flags, level);
		t.push_back(v);
	}
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_data(std::vector<T> &t, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level, uint32_t count)
{
	for (uint32_t i = 0; i < count; ++i) {
		T v;
		X_NDR_DATA(v, ndr, bpos, epos, flags, level);
		t.push_back(v);
	}
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_data(const std::shared_ptr<T> &t, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level)
{
	return x_ndr_data(*t, ndr, bpos, epos, flags, level);
}

template <typename T>
inline x_ndr_off_t x_ndr_data(std::shared_ptr<T> &t, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level)
{
	t = std::make_shared<T>();
	return x_ndr_data(*t, ndr, bpos, epos, flags, level);
}

x_ndr_off_t x_ndr_align(size_t alignment, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags);
x_ndr_off_t x_ndr_align(size_t alignment, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags);
#define X_NDR_ALIGN(size, ndr, bpos, epos, flags) X_NDR_VERIFY(bpos, x_ndr_align((size), (ndr), (bpos), (epos), (flags)))

#define X_NDR_HEADER_ALIGN(alignment, ndr, bpos, epos, extra_flags) X_NDR_VERIFY(bpos, x_ndr_align(alignment, ndr, bpos, epos, extra_flags))
#define X_NDR_TRAILER_ALIGN(alignment, ndr, bpos, epos, flags) 

static inline x_ndr_off_t x_ndr_union_align(size_t alignment, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	/* MS-RPCE section 2.2.5.3.4.4 */
	if (flags & LIBNDR_FLAG_NDR64) {
		return x_ndr_align(alignment, ndr, bpos, epos, flags);
	}
	return bpos;
}

static inline x_ndr_off_t x_ndr_union_align(size_t alignment, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	/* MS-RPCE section 2.2.5.3.4.4 */
	if (flags & LIBNDR_FLAG_NDR64) {
		return x_ndr_align(alignment, ndr, bpos, epos, flags);
	}
	return bpos;
}

#define X_NDR_UNION_ALIGN(alignment, ndr, bpos, epos, flags) X_NDR_VERIFY((bpos), x_ndr_union_align((alignment), (ndr), (bpos), (epos), (flags)))

static inline x_ndr_off_t x_ndr_reserve(size_t size, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos)
{
	x_ndr_off_t pos = bpos + size;
	if (pos > epos) {
		return -NDR_ERR_LENGTH;
	}
	if (long(ndr.data.size()) < pos) {
		ndr.data.resize(pos);
	}
	return pos;
}

static inline x_ndr_off_t x_ndr_reserve(size_t size, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos)
{
	x_ndr_off_t pos = bpos + size;
	if (pos > epos) {
		return -NDR_ERR_LENGTH;
	}
	return pos;
}

#define X_NDR_RESERVE(size, ndr, bpos, epos, flags) X_NDR_VERIFY((bpos), x_ndr_reserve((size), (ndr), (bpos), (epos)))

#define X_NDR_HOLE(size, ndr, bpos, epos, extra_flags) \
	X_NDR_VERIFY((bpos), x_ndr_hole(size, ndr, bpos, epos, extra_flags))


static inline x_ndr_off_t x_ndr_set_marshall_size(size_t marshall_size,
		x_ndr_off_t base,
		x_ndr_off_t bpos, x_ndr_off_t epos)
{
	x_ndr_off_t pos = base + marshall_size;
	if (pos < bpos || pos > epos) {
	       return -NDR_ERR_LENGTH;
	}
	return pos;
}

#define X_NDR_SET_EPOS(marshall_size, base, bpos, epos) \
	X_NDR_VERIFY(epos, x_ndr_set_marshall_size(marshall_size, base, bpos, epos))

#define X_NDR_SWITCH(sw_type, sw_name, ndr, bpos, epos, flags, switch_is) do { \
	sw_type __sw_tmp; \
	X_NDR_DATA(__sw_tmp, (ndr), (bpos), (epos), (flags), (switch_is)); \
	set_##sw_name(__sw_tmp); \
} while (0)

#define X_NDR_ELEM_EPOS(len, base, bpos, epos) ({ \
	x_ndr_off_t new_epos = (bpos) + (len); \
	if (new_epos > (epos) || new_epos < (bpos)) { \
		return -NDR_ERR_LENGTH; \
	} \
	new_epos; \
})


static inline bool x_ndr_be(uint32_t flags)
{
	return (flags & (LIBNDR_FLAG_BIGENDIAN|LIBNDR_FLAG_LITTLE_ENDIAN)) == LIBNDR_FLAG_BIGENDIAN;
}

#define X_NDR_BE(flags) (unlikely(((flags) & (LIBNDR_FLAG_BIGENDIAN|LIBNDR_FLAG_LITTLE_ENDIAN)) == LIBNDR_FLAG_BIGENDIAN))

#define X_NDR_SVAL(ndr, flags, ofs) (X_NDR_BE(flags)?RSVAL(ndr.data,ofs):SVAL(ndr.data,ofs))
#define X_NDR_IVAL(ndr, flags, ofs) (X_NDR_BE(flags)?RIVAL(ndr.data,ofs):IVAL(ndr.data,ofs))
#define X_NDR_IVALS(ndr, flags, ofs) (X_NDR_BE(flags)?RIVALS(ndr.data,ofs):IVALS(ndr.data,ofs))
#define X_NDR_SSVAL(ndr, flags, ofs, v) do { if (X_NDR_BE(flags))  { RSSVAL(ndr.data.data(),ofs,v); } else SSVAL(ndr.data.data(),ofs,v); } while (0)
#define X_NDR_SIVAL(ndr, flags, ofs, v) do { if (X_NDR_BE(flags))  { RSIVAL(ndr.data.data(),ofs,v); } else SIVAL(ndr.data.data(),ofs,v); } while (0)
#define X_NDR_SIVALS(ndr, flags, ofs, v) do { if (X_NDR_BE(flags))  { RSIVALS(ndr.data.data(),ofs,v); } else SIVALS(ndr.data.data(),ofs,v); } while (0)


x_ndr_off_t x_ndr_push_uint32(uint32 v, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags);
x_ndr_off_t x_ndr_pull_uint32(uint32 &v, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags);
x_ndr_off_t x_ndr_push_uint16(uint16 v, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags);
x_ndr_off_t x_ndr_pull_uint16(uint16 &v, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags);
x_ndr_off_t x_ndr_push_uint8(uint8 v, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags);
x_ndr_off_t x_ndr_pull_uint8(uint8 &v, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags);
x_ndr_off_t x_ndr_push_uint64(hyper v, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags);
x_ndr_off_t x_ndr_pull_uint64(hyper &v, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags);


x_ndr_off_t x_ndr_push_string(const std::string &v,
		x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t extra_flags);
x_ndr_off_t x_ndr_pull_string(std::string &v,
		x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t extra_flags);

inline x_ndr_off_t x_ndr_push_uint8(x_ndr_push_t &ndr, uint32_t extra_flags, uint8_t v)
{
	ndr.data.push_back(v);
	return 1;
}

x_ndr_off_t x_ndr_push_uint1632(uint16_t v, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags);
x_ndr_off_t x_ndr_pull_uint1632(uint16_t &v, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags);
x_ndr_off_t x_ndr_push_hyper(x_ndr_push_t &ndr, uint32_t extra_flags, uint64_t v);
x_ndr_off_t x_ndr_push_array_uint8(x_ndr_push_t &ndr, uint32_t extra_flags, const uint8_t *addr, size_t count);
x_ndr_off_t x_ndr_push_NTSTATUS(x_ndr_push_t &ndr, uint32_t extra_flags, NTSTATUS v);

x_ndr_off_t x_ndr_pull_uint16(x_ndr_pull_t &ndr, uint32_t extra_flags, uint16_t &v);
x_ndr_off_t x_ndr_pull_uint8(x_ndr_pull_t &ndr, uint32_t extra_flags, uint8_t &v);
x_ndr_off_t x_ndr_pull_hyper(x_ndr_pull_t &ndr, uint32_t extra_flags, uint64_t &v);
x_ndr_off_t x_ndr_pull_array_uint8(x_ndr_pull_t &ndr, uint32_t extra_flags, uint8_t *addr, size_t count);
x_ndr_off_t x_ndr_pull_NTSTATUS(x_ndr_pull_t &ndr, uint32_t extra_flags, NTSTATUS &v);

void x_ndr_output_uint64(x_ndr_ostr_t &ndr, uint32_t flags, uint64_t val, const char *name);
void x_ndr_output_uint32(x_ndr_ostr_t &ndr, uint32_t flags, uint32_t val, const char *name);
void x_ndr_output_uint16(x_ndr_ostr_t &ndr, uint32_t flags, uint16_t val, const char *name);
void x_ndr_output_uint8(x_ndr_ostr_t &ndr, uint32_t flags, uint8_t val, const char *name);
void x_ndr_output_enum(x_ndr_ostr_t &ndr, uint32_t flags, const char *name, const char *val_name, uint32_t val);

#if 0
static inline x_ndr_off_t x_ndr_fill_uint32(x_ndr_push_t &ndr, size_t off, uint32_t val)
{
	X_ASSERT(ndr.data.size() >= off + val);
	NDR_SIVAL(ndr, off, val);
	return 0;
}
#define X_NDR_FILL_UINT32(ndr, off, val) X_NDR_CHECK(x_ndr_fill_uint32((ndr), (off), (val)))

static inline x_ndr_off_t x_ndr_relate_uint32_ptr(x_ndr_pull_t &ndr, uint32_t extra_flags, size_t &offset)
{
	uint32_t tmp;
	x_ndr_off_t ret = x_ndr_pull_uint32(ndr, extra_flags, tmp);
	if (ret >= 0) {
		offset = tmp;
	}
	return ret;
}
static inline x_ndr_off_t x_ndr_relate_uint32_ptr(x_ndr_push_t &ndr, uint32_t extra_flags, size_t &offset)
{
	x_ndr_off_t ret = X_NDR_HEADER_ALIGN(ndr, extra_flags, 4);
	ret += X_NDR_CHECK(x_ndr_expand(ndr, offset, 4));
	return ret;
}
#define X_NDR_RELATE_UINT32_PTR(ndr, extra_flags, offset) X_NDR_CHECK(x_ndr_relate_uint32_ptr((ndr), (extra_flags), (offset)))
#endif

static inline x_ndr_off_t x_ndr_fill(uint32_t v, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	if (bpos + long(sizeof(v)) > epos) {
		return -NDR_ERR_LENGTH;
	}
	X_NDR_SIVAL(ndr, flags, bpos, v);
	return bpos + sizeof(v);
}

static inline x_ndr_off_t x_ndr_fill(uint16_t v, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	if (bpos + long(sizeof(v)) > epos) {
		return -NDR_ERR_LENGTH;
	}
	X_NDR_SSVAL(ndr, flags, bpos, v);
	return bpos + sizeof(v);
}

#define X_NDR_FILL(v, ndr, bpos, epos, flags) X_NDR_CHECK(x_ndr_fill((v), (ndr), (bpos), (epos), (flags)))

static inline x_ndr_off_t x_ndr_data(uint64_t t,
		x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t extra_flags, x_ndr_switch_t level)
{
	return x_ndr_push_uint64(t, ndr, bpos, epos, extra_flags);
}

static inline x_ndr_off_t x_ndr_data(uint64_t &t,
		x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t extra_flags, x_ndr_switch_t level)
{
	return x_ndr_pull_uint64(t, ndr, bpos, epos, extra_flags);
}

static inline x_ndr_off_t x_ndr_data(uint32_t t,
		x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t extra_flags, x_ndr_switch_t level)
{
	return x_ndr_push_uint32(t, ndr, bpos, epos, extra_flags);
}

static inline x_ndr_off_t x_ndr_data(uint32_t &t,
		x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t extra_flags, x_ndr_switch_t level)
{
	return x_ndr_pull_uint32(t, ndr, bpos, epos, extra_flags);
}

static inline x_ndr_off_t x_ndr_data(uint16_t t,
		x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t extra_flags, x_ndr_switch_t level)
{
	return x_ndr_push_uint16(t, ndr, bpos, epos, extra_flags);
}

static inline x_ndr_off_t x_ndr_data(uint16_t &t,
		x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t extra_flags, x_ndr_switch_t level)
{
	return x_ndr_pull_uint16(t, ndr, bpos, epos, extra_flags);
}

static inline x_ndr_off_t x_ndr_data(uint8_t t,
		x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t extra_flags, x_ndr_switch_t level)
{
	return x_ndr_push_uint8(t, ndr, bpos, epos, extra_flags);
}

static inline x_ndr_off_t x_ndr_data(uint8_t &t,
		x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t extra_flags, x_ndr_switch_t level)
{
	return x_ndr_pull_uint8(t, ndr, bpos, epos, extra_flags);
}

static inline x_ndr_off_t x_ndr_data(const std::string &t,
		x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t extra_flags, x_ndr_switch_t level)
{
	return x_ndr_push_string(t, ndr, bpos, epos, extra_flags);
}

static inline x_ndr_off_t x_ndr_data(std::string &t,
		x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t extra_flags, x_ndr_switch_t level)
{
	return x_ndr_pull_string(t, ndr, bpos, epos, extra_flags);
}

typedef uint32_t ipv4address;

/* simple ascill string */
struct sstring
{
	x_ndr_off_t push(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const;
	x_ndr_off_t pull(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level);
	void ostr(x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const;
	std::string val;
};

struct u16string
{
	x_ndr_off_t push(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const;
	x_ndr_off_t pull(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level);
	void ostr(x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const;
	std::u16string val;
};

/* can be either u16string or sstring */
struct gstring
{
	x_ndr_off_t push(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const;
	x_ndr_off_t pull(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level);
	void ostr(x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const;
	std::u16string val;
};

struct astring
{
	x_ndr_off_t push(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const;
	x_ndr_off_t pull(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level);
	std::string val;
};

struct nstring
{
	x_ndr_off_t push(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const;
	x_ndr_off_t pull(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level);
	void ostr(x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const;
	std::string val;
};

struct nstring_array
{
	x_ndr_off_t push(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const;
	x_ndr_off_t pull(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level);
	void ostr(x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const;
        std::vector<std::string> val;
};

struct blob_t
{
	x_ndr_off_t push(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const;
	x_ndr_off_t pull(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level);
	void ostr(x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const;
	std::vector<uint8_t> val;
};

struct DATA_BLOB
{
	x_ndr_off_t push(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const;
	x_ndr_off_t pull(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level);
	void ostr(x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const;
	std::vector<uint8_t> val;
};

#if 0
struct dom_sid
{
	x_ndr_off_t push(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const;
	x_ndr_off_t pull(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level);
	uint8_t sid_rev_num;
	int8_t num_auths;/* [range(0,15)] */
	uint8_t id_auth[6];
	uint32_t sub_auths[15];
};

template <>
inline x_ndr_off_t x_ndr_data<uint16_t>(x_ndr_push_t &ndr, const uint16_t &t, uint32_t extra_flags, x_ndr_switch_t level)
{
	return x_ndr_push_uint16(ndr, extra_flags, t);
}

template <>
inline x_ndr_off_t x_ndr_data<uint16_t>(x_ndr_pull_t &ndr, uint16_t &t, uint32_t extra_flags, x_ndr_switch_t level)
{
	return x_ndr_pull_uint16(ndr, extra_flags, t);
}

template <>
inline x_ndr_off_t x_ndr_data<uint8_t>(x_ndr_push_t &ndr, const uint8_t &t, uint32_t extra_flags, x_ndr_switch_t level)
{
	return x_ndr_push_uint8(ndr, extra_flags, t);
}

template <>
inline x_ndr_off_t x_ndr_data<uint8_t>(x_ndr_pull_t &ndr, uint8_t &t, uint32_t extra_flags, x_ndr_switch_t level)
{
	return x_ndr_pull_uint8(ndr, extra_flags, t);
}

template <>
inline x_ndr_off_t x_ndr_data<uint64_t>(x_ndr_push_t &ndr, const uint64_t &t, uint32_t extra_flags, x_ndr_switch_t level)
{
	return x_ndr_push_hyper(ndr, extra_flags, t);
}

template <>
inline x_ndr_off_t x_ndr_data<uint64_t>(x_ndr_pull_t &ndr, uint64_t &t, uint32_t extra_flags, x_ndr_switch_t level)
{
	return x_ndr_pull_hyper(ndr, extra_flags, t);
}

struct string
{
	string(const char *v) : val(v) { }
	string(const std::string &v) : val(v) { }
	string() = default;
	size_t length() const { return val.length(); }
	std::string val;
};


struct ipv4address {
	struct in_addr val;
};

x_ndr_off_t x_ndr_at(x_ndr_pull_t &ndr, string &str, uint32_t extra_flags, x_ndr_switch_t level, uint32_t off, uint32_t len);
#endif
#define X_NDR_AT(ndr, v, extra_flags, level, bpos, epos) X_NDR_CHECK(x_ndr_at((ndr), (v), (extra_flags), (level), (off), (len)))

#if 0
static inline uint32_t ndr_ntlmssp_negotiated_string_flags(uint32_t negotiate_flags)
{
	uint32_t flags = LIBNDR_FLAG_STR_NOTERM |
			 LIBNDR_FLAG_STR_CHARLEN |
			 LIBNDR_FLAG_REMAINING;

	if (!(negotiate_flags & NTLMSSP_NEGOTIATE_UNICODE)) {
		flags |= LIBNDR_FLAG_STR_ASCII;
	}

	return flags;
}
#endif

template <typename T>
inline x_ndr_off_t x_ndr_pull(T &t, const uint8_t *data, size_t size)
{
	x_ndr_pull_t ndr_pull{data, size};
	return x_ndr_data(t, ndr_pull, 0, size, 0, X_NDR_SWITCH_NONE);
}

template <typename T>
inline x_ndr_off_t x_ndr_push(const T &t, std::vector<uint8_t> &data)
{
	x_ndr_push_t ndr_push;
	x_ndr_off_t ret = x_ndr_data(t, ndr_push, 0, X_NDR_MAX_SIZE, 0, X_NDR_SWITCH_NONE);
	if (ret >= 0) {
		data = ndr_push.finish();
	}
	return ret;
}

static inline void x_ndr_ostr(uint32_t v, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	ndr.os << v;
}

static inline void x_ndr_ostr(uint16_t v, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	ndr.os << v;
}

static inline void x_ndr_ostr(uint8_t v, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	ndr.os << v;
}

static inline void x_ndr_ostr(uint64_t v, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	ndr.os << v;
}

template <typename T>
static inline void x_ndr_ostr(const std::shared_ptr<T> &v, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	if (v) {
		x_ndr_ostr(*v, ndr, flags, level);
	} else {
		ndr.os << "<NULL>";
	}
}

template <typename T>
void x_ndr_ostr_array(const T *v, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level, size_t count)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	ndr << "length=" << count << enter;
	for (size_t i = 0; i < count; ++i) {
		ndr << '#' << i << ": ";
		x_ndr_ostr(v[i], ndr, flags, level);
		ndr << next;
	}
	ndr << leave;
}

template <typename T, size_t C>
inline void x_ndr_ostr(const std::array<T, C> &v, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	x_ndr_ostr_array(v.data(), ndr, flags, level, C);
}

template <typename T>
inline void x_ndr_ostr(const std::vector<T> &v, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	x_ndr_ostr_array(v.data(), ndr, flags, level, v.size());
}

template <typename T>
inline void x_ndr_ostr(const T &t, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	x_ndr_ostreamer_t<T, typename x_ndr_traits_t<T>::ndr_ostr_type>()(t, ndr, flags, level);
	// t.ostr(ndr, flags, level);
}

template <typename T>
inline void x_ndr_ostr(const T &t, std::ostream &os, uint32_t indent, uint32_t tabstop)
{
	x_ndr_ostr_t ndr(os, indent, tabstop);
	x_ndr_ostr(t, ndr, 0, X_NDR_SWITCH_NONE);
}

#define X_NDR_OSTR(val, ndr, flags, level) do { \
	(ndr) << #val << ": "; \
	x_ndr_ostr(val, ndr, flags, level); \
} while (0)

#define X_NDR_OSTR_NEXT(val, ndr, flags, level) do { \
	(ndr) << #val << ": "; \
	x_ndr_ostr(val, ndr, flags, level); \
	(ndr) << next; \
} while (0)

}

extern "C" {
// #include "samba/librpc/ndr/libndr.h"
}


#endif /* __ndr__hxx__ */

