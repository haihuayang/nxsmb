
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
#include <array>
#include <memory>
#include <algorithm>
#include <functional>
#include <iomanip>
#include <limits.h>

extern "C" {
#include "samba/libcli/util/ntstatus.h"
#include "samba/lib/util/time.h"
#include "samba/libcli/util/werror.h"
#include "samba/lib/util/byteorder.h"
}

#define X_NDR_ERR_CODE_IS_SUCCESS(x) (x >= 0)

/* these are used to make the error checking on each element in libndr
   less tedious, hopefully making the code more readable */
#define X_NDR_CHECK(call) ({ \
	idl::x_ndr_off_t _ret = call; \
	if (unlikely(!X_NDR_ERR_CODE_IS_SUCCESS(_ret))) { \
		return _ret; \
	} \
	_ret; \
})

#define X_NDR_VERIFY(ret, call) do { \
	auto _ret = (call); \
	if (unlikely(!X_NDR_ERR_CODE_IS_SUCCESS(_ret))) { \
		X_DEVEL_ASSERT(0); \
		return _ret; \
	} \
	(ret) = _ret; \
} while (0)

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

#define LIBNDR_ALIGN_FLAGS ( 0	| \
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

#define LIBNDR_FLAG_NDR64	 (1<<29)

/* set if an object uuid will be present */
#define LIBNDR_FLAG_OBJECT_PRESENT    (1<<30)

/* set to avoid recursion in ndr_size_*() calculation */
#define LIBNDR_FLAG_NO_NDR_SIZE		(1<<31)

static inline uint32_t x_ndr_set_flags(uint32_t flags, uint32_t extra_flags)
{
	// TODO some flags should exclude others
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
inline uint32_t get_size(const std::vector<T> &t)
{
	return t.size();
}

template <typename T, size_t N>
inline uint32_t get_size(const std::array<T, N> &t)
{
	return N;
}


typedef ssize_t x_ndr_off_t;
enum { X_NDR_MAX_SIZE = SSIZE_MAX };

typedef uint32_t x_ndr_switch_t;
enum : uint32_t {
	X_NDR_SWITCH_NONE = 0xffffffffu,
};

NTSTATUS x_ndr_map_error2ntstatus(x_ndr_off_t ndr_off);

typedef unsigned int uint;
typedef int32_t int32;
typedef uint32_t uint32;
typedef uint16_t uint16;
typedef int8_t int8;
typedef uint8_t uint8;
typedef uint64_t hyper;
typedef uint64_t uint64;
typedef uint32_t boolean32;
struct uint3264 {
	uint3264(uint32_t v = 0) : val(v) { }
	bool operator==(uint3264 o) const {
		return val == o.val;
	}
	bool operator==(unsigned long o) const {
		return val == o;
	}
	uint32_t val;
};
typedef int64_t dlong;
typedef uint64_t udlong;
using string = const char *;

struct x_ndr_push_buff_t {
	enum { NDR_BASE_MARSHALL_SIZE = 1024, };
	x_ndr_push_buff_t() {
		data.reserve(NDR_BASE_MARSHALL_SIZE);
	}
	std::vector<uint8_t> finish() {
		return std::move(data);
	}

	uint32_t next_ptr() {
		uint32_t ret = 0x20000 + 4 * ptr_count;
		++ptr_count;
		return ret;
	}
	std::vector<uint8_t> data;

	/* this is used to ensure we generate unique reference IDs */
	uint32_t ptr_count = 0;
};

/* structure passed to functions that generate NDR formatted data */
struct x_ndr_push_t {
	x_ndr_push_t(x_ndr_push_buff_t &buff, x_ndr_off_t base): buff(buff), base(base) {
	}
	void reserve(size_t size) {
		if (buff.data.size() < size) {
			buff.data.resize(size);
		}
	}
	uint8_t *get_data() {
		return buff.data.data();
	}
	uint32_t next_ptr() {
		return buff.next_ptr();
	}

	x_ndr_push_buff_t &buff;
	x_ndr_off_t base;

	void save_pos(x_ndr_off_t pos) {
		X_ASSERT(pos_index == pos_array.size());
		pos_array.push_back(pos);
		++pos_index;
	}

	x_ndr_off_t load_pos() {
		X_ASSERT(pos_index < pos_array.size());
		x_ndr_off_t pos = pos_array[pos_index];
		++pos_index;
		return pos;
	}

	uint32_t pos_index = 0;
	std::vector<x_ndr_off_t> pos_array;
};

struct x_ndr_pull_buff_t {
	x_ndr_pull_buff_t(const uint8_t *d, size_t l) : data(d), data_size(l) { }
	const uint8_t *data;
	uint32_t data_size;
};

struct x_ndr_pull_t {
	x_ndr_pull_t(x_ndr_pull_buff_t &buff, x_ndr_off_t base): buff(buff), base(base) {
	}
	const uint8_t *get_data() const {
		return buff.data;
	}

	x_ndr_pull_buff_t &buff;
	x_ndr_off_t base;

	void save_pos(x_ndr_off_t pos) {
		X_ASSERT(pos_index == pos_array.size());
		pos_array.push_back(pos);
		++pos_index;
	}

	x_ndr_off_t load_pos() {
		X_ASSERT(pos_index < pos_array.size());
		x_ndr_off_t pos = pos_array[pos_index];
		++pos_index;
		return pos;
	}

	uint32_t pos_index = 0;
	std::vector<x_ndr_off_t> pos_array;
};

struct x_ndr_ostr_t {
	x_ndr_ostr_t(std::ostream &os, uint32_t indent, uint32_t ts = 4)
		: os(os), indent(indent), tabstop(ts) {}

	x_ndr_ostr_t &operator<<(x_ndr_ostr_t &(*pf)(x_ndr_ostr_t &)) {
		return pf(*this);
	}

	std::ostream &os;
	bool newline = false;
	uint32_t indent;
	uint32_t tabstop;
	int depth = 0;
};

struct x_ndr_type_default { };
struct x_ndr_type_custom { };
struct x_ndr_type_enum { };
struct x_ndr_type_bitmap { };
struct x_ndr_type_struct { };
struct x_ndr_type_union { };

template <typename T> struct x_ndr_traits_t {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_default;
};

template <typename T> struct x_ndr_traits_t<std::vector<T>> {
	using has_buffers = typename x_ndr_traits_t<T>::has_buffers;
	using ndr_type = x_ndr_type_default;
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

template <typename T, typename Traits>
struct x_ndr_ostreamer_t {
	void operator()(const T& t, x_ndr_ostr_t &os, uint32_t flags, x_ndr_switch_t level) const {
		t.ostr(os, flags, level);
	}
};

template <typename T>
struct x_ndr_ostreamer_t<T, x_ndr_type_enum> {
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
struct x_ndr_ostreamer_t<T, x_ndr_type_bitmap> {
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

template <typename T, typename Traits>
struct x_ndr_ptr_allocator_t
{
	std::shared_ptr<T> operator()(x_ndr_switch_t level) const {
		return std::make_shared<T>();
	}
};

template <typename T>
inline std::shared_ptr<T> x_ndr_allocate_ptr(x_ndr_switch_t level)
{
	return x_ndr_ptr_allocator_t<T, typename x_ndr_traits_t<T>::ndr_type>()(level);
}

template <typename T>
struct x_ndr_ptr_allocator_t<T, x_ndr_type_union>
{
	std::shared_ptr<T> operator()(x_ndr_switch_t level) const {
		return std::make_shared<T>(level);
	}
};

static inline x_ndr_off_t x_ndr_check_pos(x_ndr_off_t pos,
		x_ndr_off_t bpos, x_ndr_off_t epos)
{
	if (pos < bpos || pos > epos) {
	       return -NDR_ERR_LENGTH;
	}
	return pos;
}

#define X_NDR_CHECK_POS(pos, bpos, epos) \
	X_NDR_CHECK(x_ndr_check_pos(pos, bpos, epos))

static inline x_ndr_off_t x_ndr_check_range(ssize_t size, ssize_t min_num, ssize_t max_num)
{
	if (size < min_num || size > max_num) {
		return -NDR_ERR_RANGE;
	}
	return 0;
}

#define X_NDR_CHECK_RANGE(size, min_num, max_num) \
	X_NDR_CHECK(x_ndr_check_range((size), (min_num), (max_num)))

#define X_NDR_SCALARS(t, ndr, bpos, epos, ...) \
	X_NDR_VERIFY((bpos), x_ndr_scalars((t), (ndr), (bpos), (epos), __VA_ARGS__))

#define X_NDR_BUFFERS(t, ndr, bpos, epos, ...) \
	X_NDR_VERIFY((bpos), x_ndr_buffers((t), (ndr), (bpos), (epos), __VA_ARGS__))

#define X_NDR_VALUE(t, ndr, bpos, epos, ...) \
	X_NDR_VERIFY((bpos), x_ndr_value((t), (ndr), (bpos), (epos), __VA_ARGS__))

template <typename T>
x_ndr_off_t x_ndr_skip(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags);

template <typename T>
x_ndr_off_t x_ndr_skip(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags);

#define X_NDR_SKIP(type, ndr, bpos, epos, flags) \
	X_NDR_VERIFY(bpos, x_ndr_skip<type>(ndr, bpos, epos, flags))

template <typename T>
inline x_ndr_off_t x_ndr_save_pos(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	ndr.save_pos(bpos);
	T v{};
	return x_ndr_scalars(v, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
}

template <typename T>
inline x_ndr_off_t x_ndr_save_pos(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	ndr.save_pos(bpos);
	T v;
	return x_ndr_scalars(v, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
}

#define X_NDR_SAVE_POS(type, ndr, bpos, epos, flags) \
	X_NDR_VERIFY(bpos, x_ndr_save_pos<type>(ndr, bpos, epos, flags))

template <typename T>
inline x_ndr_off_t x_ndr_scalars(const T &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	return t.ndr_scalars(ndr, bpos, epos, flags, level);
}

template <typename T>
inline x_ndr_off_t x_ndr_buffers(const T &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	return t.ndr_buffers(ndr, bpos, epos, flags, level);
}

template <typename T>
inline x_ndr_off_t x_ndr_scalars(T &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	return t.ndr_scalars(ndr, bpos, epos, flags, level);
}

template <typename T>
inline x_ndr_off_t x_ndr_buffers(T &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	return t.ndr_buffers(ndr, bpos, epos, flags, level);
}

template <typename T>
inline x_ndr_off_t x_ndr_scalars(const std::vector<T> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	for (const auto &e: t) {
		X_NDR_SCALARS(e, ndr, bpos, epos, flags, level); 
	}
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_buffers(const std::vector<T> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	for (auto &e: t) {
		X_NDR_BUFFERS(e, ndr, bpos, epos, flags, level); 
	}
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_scalars(std::vector<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	for (auto &e: t) {
		X_NDR_SCALARS(e, ndr, bpos, epos, flags, level); 
	}
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_buffers(std::vector<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	for (auto &e: t) {
		X_NDR_BUFFERS(e, ndr, bpos, epos, flags, level); 
	}
	return bpos;
}

#if 0
template <typename T, typename HasBuffers>
struct x_ndr_puller_t {
	x_ndr_off_t operator()(T& t, x_ndr_pull_t &ndr,
			x_ndr_off_t bpos, x_ndr_off_t epos,
			uint32_t flags, x_ndr_switch_t level) const {
		X_NDR_SCALARS(t, ndr, bpos, epos, flags, level); 
		return bpos;
	}
};

template <typename T>
struct x_ndr_puller_t<T, std::true_type> {
	x_ndr_off_t operator()(T& t, x_ndr_pull_t &ndr,
			x_ndr_off_t bpos, x_ndr_off_t epos,
			uint32_t flags, x_ndr_switch_t level) const {
		ndr.pos_index = 0;
		X_NDR_SCALARS(t, ndr, bpos, epos, flags, level); 
		ndr.pos_index = 0;
		X_NDR_BUFFERS(t, ndr, bpos, epos, flags, level); 
		return bpos;
	}
};

template <typename T, typename HasBuffers>
struct x_ndr_pusher_t
{
	x_ndr_off_t operator()(const T& t, x_ndr_push_t &ndr,
			x_ndr_off_t bpos, x_ndr_off_t epos,
			uint32_t flags, x_ndr_switch_t level) const {
		X_NDR_SCALARS(t, ndr, bpos, epos, flags, level); 
		return bpos;
	}
};
#endif

template <typename T, typename HasBuffers>
struct x_ndr_handler_t
{
	x_ndr_off_t operator()(const T& t, x_ndr_push_t &ndr,
			x_ndr_off_t bpos, x_ndr_off_t epos,
			uint32_t flags, x_ndr_switch_t level) const {
		X_NDR_SCALARS(t, ndr, bpos, epos, flags, level); 
		return bpos;
	}

	x_ndr_off_t operator()(T& t, x_ndr_pull_t &ndr,
			x_ndr_off_t bpos, x_ndr_off_t epos,
			uint32_t flags, x_ndr_switch_t level) const {
		X_NDR_SCALARS(t, ndr, bpos, epos, flags, level); 
		return bpos;
	}
};

template <typename T>
struct x_ndr_handler_t<T, std::true_type>
{
	x_ndr_off_t operator()(const T& t, x_ndr_push_t &ndr,
			x_ndr_off_t bpos, x_ndr_off_t epos,
			uint32_t flags, x_ndr_switch_t level) const {
		ndr.pos_index = 0;
		X_NDR_SCALARS(t, ndr, bpos, epos, flags, level); 
		ndr.pos_index = 0;
		X_NDR_BUFFERS(t, ndr, bpos, epos, flags, level); 
		return bpos;
	}

	x_ndr_off_t operator()(T& t, x_ndr_pull_t &ndr,
			x_ndr_off_t bpos, x_ndr_off_t epos,
			uint32_t flags, x_ndr_switch_t level) const {
		ndr.pos_index = 0;
		X_NDR_SCALARS(t, ndr, bpos, epos, flags, level); 
		ndr.pos_index = 0;
		X_NDR_BUFFERS(t, ndr, bpos, epos, flags, level); 
		return bpos;
	}
};

template <typename T>
struct x_ndr_handler_t<std::vector<T>, std::false_type>
{
	x_ndr_off_t operator()(const std::vector<T>& t, x_ndr_push_t &ndr,
			x_ndr_off_t bpos, x_ndr_off_t epos,
			uint32_t flags, x_ndr_switch_t level) const {
		for (auto &e: t) {
			X_NDR_SCALARS(e, ndr, bpos, epos, flags, level); 
		}
		return bpos;
	}

	x_ndr_off_t operator()(std::vector<T>& t, x_ndr_pull_t &ndr,
			x_ndr_off_t bpos, x_ndr_off_t epos,
			uint32_t flags, x_ndr_switch_t level) const {
		for (auto &e: t) {
			X_NDR_SCALARS(e, ndr, bpos, epos, flags, level); 
		}
		return bpos;
	}
};

template <typename T>
struct x_ndr_handler_t<std::vector<T>, std::true_type>
{
	x_ndr_off_t operator()(const std::vector<T>& t, x_ndr_push_t &ndr,
			x_ndr_off_t bpos, x_ndr_off_t epos,
			uint32_t flags, x_ndr_switch_t level) const {
		ndr.pos_index = 0;
		X_NDR_SCALARS(t, ndr, bpos, epos, flags, level); 
		ndr.pos_index = 0;
		X_NDR_BUFFERS(t, ndr, bpos, epos, flags, level); 
		return bpos;
	}

	x_ndr_off_t operator()(std::vector<T>& t, x_ndr_pull_t &ndr,
			x_ndr_off_t bpos, x_ndr_off_t epos,
			uint32_t flags, x_ndr_switch_t level) const {
		ndr.pos_index = 0;
		X_NDR_SCALARS(t, ndr, bpos, epos, flags, level); 
		ndr.pos_index = 0;
		X_NDR_BUFFERS(t, ndr, bpos, epos, flags, level); 
		return bpos;
	}
};

template <typename T>
inline x_ndr_off_t x_ndr_push(const T &t, std::vector<uint8_t> &data, uint32_t flags)
{
	x_ndr_push_buff_t ndr_data{};
	x_ndr_push_t ndr{ndr_data, 0};
	x_ndr_off_t ret = x_ndr_handler_t<T, typename x_ndr_traits_t<T>::has_buffers>()(t, ndr, 0, X_NDR_MAX_SIZE, flags, X_NDR_SWITCH_NONE);
	if (ret >= 0) {
		std::swap(data, ndr_data.data);
	}
	return ret;
}

template <typename T>
inline x_ndr_off_t x_ndr_pull(T &t, const uint8_t *data, size_t size, uint32_t flags)
{
	x_ndr_pull_buff_t ndr_data{data, size};
	x_ndr_pull_t ndr{ndr_data, 0};
	return x_ndr_handler_t<T, typename x_ndr_traits_t<T>::has_buffers>()(t, ndr, 0, size, flags, X_NDR_SWITCH_NONE);
}

static inline x_ndr_off_t x_ndr_do_align(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	size_t offset = bpos - ndr.base;
	size_t alignment = 0;
	if (flags & LIBNDR_FLAG_ALIGN2) {
		alignment = 2;
	} else if (flags & LIBNDR_FLAG_ALIGN4) {
		alignment = 4;
	} else if (flags & LIBNDR_FLAG_ALIGN8) {
		alignment = 8;
	}
	if (alignment) {
		offset = (offset + alignment - 1) & ~(alignment - 1);
		bpos = X_NDR_CHECK_POS(ndr.base + offset, bpos, epos);
	}
	return bpos;
}

#define X_NDR_DO_ALIGN(ndr, bpos, epos, flags) \
	X_NDR_VERIFY((bpos), x_ndr_do_align((ndr), (bpos), (epos), (flags)))


#define X_NDR_CHECK_ALIGN(ndr, flags, offset)

template <typename T>
inline x_ndr_off_t x_ndr_value(const T &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	T tmp;
	x_ndr_off_t ret = x_ndr_scalars(tmp, ndr, bpos, epos, flags, level);
	if (ret < 0) {
		return ret;
	}
	if (tmp != t) {
		return -NDR_ERR_VALIDATE;
	}
	return ret;
}

template <typename T>
inline x_ndr_off_t x_ndr_value(const T &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	return x_ndr_scalars(t, ndr, bpos, epos, flags, level);
}

template <class T>
using shared_vector = std::shared_ptr<std::vector<T>>;

#if 0
#define X_NDR_PTR(t, ndr, bpos, epos, ...) \
	X_NDR_VERIFY((bpos), x_ndr_ptr((t), (ndr), (bpos), (epos), __VA_ARGS__))

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

#endif

x_ndr_off_t x_ndr_align(size_t alignment, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags);
x_ndr_off_t x_ndr_align(size_t alignment, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags);
#define X_NDR_ALIGN(size, ndr, bpos, epos, flags) \
	X_NDR_VERIFY(bpos, x_ndr_align((size), (ndr), (bpos), (epos), (flags)))

#define X_NDR_ALIGN_TYPE(type, ndr, bpos, epos, flags)

#define X_NDR_HEADER_ALIGN(alignment, ndr, bpos, epos, flags) X_NDR_VERIFY(bpos, x_ndr_align(alignment, ndr, bpos, epos, flags))
#define X_NDR_TRAILER_ALIGN(alignment, ndr, bpos, epos, flags) 

static inline x_ndr_off_t x_ndr_union_align(size_t alignment, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	/* MS-RPCE section 2.2.5.3.4.4 */
	if (flags & LIBNDR_FLAG_NDR64) {
		return x_ndr_align(alignment, ndr, bpos, epos, flags);
	}
	return bpos;
}

static inline x_ndr_off_t x_ndr_union_align(size_t alignment, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	/* MS-RPCE section 2.2.5.3.4.4 */
	if (flags & LIBNDR_FLAG_NDR64) {
		return x_ndr_align(alignment, ndr, bpos, epos, flags);
	}
	return bpos;
}

#define X_NDR_UNION_ALIGN(alignment, ndr, bpos, epos, flags) X_NDR_VERIFY((bpos), x_ndr_union_align((alignment), (ndr), (bpos), (epos), (flags)))

#if 0
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
#endif
#define X_NDR_HOLE(size, ndr, bpos, epos, extra_flags) \
	X_NDR_VERIFY((bpos), x_ndr_hole(size, ndr, bpos, epos, extra_flags))

#define X_NDR_ROUND(size, align) (((size)+((align)-1)) & ~((align)-1))

#if 0
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

#define X_NDR_SET_BPOS(pos, bpos, epos) \
	X_NDR_CHECK(x_ndr_check_pos(pos, bpos, epos))

#define X_NDR_SET_EPOS(pos, bpos, epos) \
	X_NDR_CHECK(x_ndr_check_pos(pos, bpos, epos))
#define X_NDR_ELEM_EPOS(len, base, bpos, epos) ({ \
	x_ndr_off_t new_epos = (bpos) + (len); \
	if (new_epos > (epos) || new_epos < (bpos)) { \
		return -NDR_ERR_LENGTH; \
	} \
	new_epos; \
})
#endif
#define X_NDR_SWITCH(sw_type, sw_name, ndr, bpos, epos, flags, switch_is) do { \
	sw_type __sw_tmp; \
	X_NDR_SCALARS(__sw_tmp, (ndr), (bpos), (epos), (flags), (switch_is)); \
	set_##sw_name(__sw_tmp); \
} while (0)


static inline bool x_ndr_be(uint32_t flags)
{
	return (flags & (LIBNDR_FLAG_BIGENDIAN|LIBNDR_FLAG_LITTLE_ENDIAN)) == LIBNDR_FLAG_BIGENDIAN;
}

#define X_NDR_BE(flags) (unlikely(((flags) & (LIBNDR_FLAG_BIGENDIAN|LIBNDR_FLAG_LITTLE_ENDIAN)) == LIBNDR_FLAG_BIGENDIAN))
#define X_NDR_SVAL(ndr, flags, ofs) (X_NDR_BE(flags)?RSVAL(ndr.get_data(),ofs):SVAL(ndr.get_data(),ofs))
#define X_NDR_IVAL(ndr, flags, ofs) (X_NDR_BE(flags)?RIVAL(ndr.get_data(),ofs):IVAL(ndr.get_data(),ofs))
#define X_NDR_IVALS(ndr, flags, ofs) (X_NDR_BE(flags)?RIVALS(ndr.get_data(),ofs):IVALS(ndr.get_data(),ofs))
#define X_NDR_SSVAL(ndr, flags, ofs, v) do { if (X_NDR_BE(flags))  { RSSVAL(ndr.get_data(),ofs,v); } else SSVAL(ndr.get_data(),ofs,v); } while (0)
#define X_NDR_SIVAL(ndr, flags, ofs, v) do { if (X_NDR_BE(flags))  { RSIVAL(ndr.get_data(),ofs,v); } else SIVAL(ndr.get_data(),ofs,v); } while (0)
#define X_NDR_SIVALS(ndr, flags, ofs, v) do { if (X_NDR_BE(flags))  { RSIVALS(ndr.get_data(),ofs,v); } else SIVALS(ndr.get_data(),ofs,v); } while (0)

x_ndr_off_t x_ndr_push_uint32(uint32 v, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags);
x_ndr_off_t x_ndr_pull_uint32(uint32 &v, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags);
x_ndr_off_t x_ndr_push_uint16(uint16 v, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags);
x_ndr_off_t x_ndr_pull_uint16(uint16 &v, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags);
x_ndr_off_t x_ndr_push_uint8(uint8 v, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags);
x_ndr_off_t x_ndr_pull_uint8(uint8 &v, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags);
x_ndr_off_t x_ndr_push_uint64_align(uint64_t v, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, uint32_t alignment);
x_ndr_off_t x_ndr_pull_uint64_align(uint64_t &v, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, uint32_t alignment);

static inline x_ndr_off_t x_ndr_push_uint64(uint64_t v, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	return x_ndr_push_uint64_align(v, ndr, bpos, epos, flags, 8);
}

static inline x_ndr_off_t x_ndr_pull_uint64(uint64_t &v, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	return x_ndr_pull_uint64_align(v, ndr, bpos, epos, flags, 8);
}

static inline x_ndr_off_t x_ndr_push_int64(int64_t v, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	return x_ndr_push_uint64_align(v, ndr, bpos, epos, flags, 8);
}

static inline x_ndr_off_t x_ndr_pull_int64(int64_t &v, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	uint64_t tmp;
	x_ndr_off_t ret = x_ndr_pull_uint64_align(tmp, ndr, bpos, epos, flags, 8);
	v = tmp;
	return ret;
}

x_ndr_off_t x_ndr_push_uint1632(uint16_t v, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags);
x_ndr_off_t x_ndr_pull_uint1632(uint16_t &v, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags);
x_ndr_off_t x_ndr_push_bytes(const void *data, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, size_t size);
x_ndr_off_t x_ndr_pull_bytes(void *addr, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, size_t length);
x_ndr_off_t x_ndr_pull_bytes(void *addr, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos);
void x_ndr_ostr_bytes(const void *addr, x_ndr_ostr_t &ndr, size_t size);


x_ndr_off_t x_ndr_push_string(const std::string &v, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags);
x_ndr_off_t x_ndr_pull_string(std::string &v, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags);
#if 0
inline x_ndr_off_t x_ndr_push_uint8(x_ndr_push_t &ndr, uint32_t extra_flags, uint8_t v)
{
	ndr.data.push_back(v);
	return 1;
}

x_ndr_off_t x_ndr_push_hyper(x_ndr_push_t &ndr, uint32_t extra_flags, uint64_t v);
x_ndr_off_t x_ndr_push_array_uint8(x_ndr_push_t &ndr, uint32_t extra_flags, const uint8_t *addr, size_t count);
x_ndr_off_t x_ndr_push_NTSTATUS(x_ndr_push_t &ndr, uint32_t extra_flags, NTSTATUS v);

x_ndr_off_t x_ndr_pull_uint16(x_ndr_pull_t &ndr, uint32_t extra_flags, uint16_t &v);
x_ndr_off_t x_ndr_pull_uint8(x_ndr_pull_t &ndr, uint32_t extra_flags, uint8_t &v);
x_ndr_off_t x_ndr_pull_hyper(x_ndr_pull_t &ndr, uint32_t extra_flags, uint64_t &v);
x_ndr_off_t x_ndr_pull_array_uint8(x_ndr_pull_t &ndr, uint32_t extra_flags, uint8_t *addr, size_t count);
x_ndr_off_t x_ndr_pull_NTSTATUS(x_ndr_pull_t &ndr, uint32_t extra_flags, NTSTATUS &v);
#endif
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
#endif

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

template <>
inline x_ndr_off_t x_ndr_skip<uint3264>(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	uint3264 tmp{0};
	return x_ndr_scalars(tmp, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
}

template <>
inline x_ndr_off_t x_ndr_skip<uint3264>(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	uint3264 tmp{0};
	return x_ndr_scalars(tmp, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
}

static inline x_ndr_off_t x_ndr_scalars(uint64_t t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	return x_ndr_push_uint64(t, ndr, bpos, epos, flags);
}

static inline x_ndr_off_t x_ndr_scalars(uint64_t &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	return x_ndr_pull_uint64(t, ndr, bpos, epos, flags);
}

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

static inline x_ndr_off_t x_ndr_scalars(const std::vector<uint8_t> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_TODO;
	return -1;
}

static inline x_ndr_off_t x_ndr_scalars(std::vector<uint8_t> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_TODO;
	return -1;
}

static inline x_ndr_off_t x_ndr_scalars(const std::string &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	return x_ndr_push_string(t, ndr, bpos, epos, flags);
}

static inline x_ndr_off_t x_ndr_scalars(std::string &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	return x_ndr_pull_string(t, ndr, bpos, epos, flags);
}

static inline void x_ndr_ostr(const std::string &t, x_ndr_ostr_t &ndr,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	ndr.os << '"' << t << '"';
}


#if 0
static inline x_ndr_off_t x_ndr_scalars(const std::string &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	return x_ndr_push_string(t, ndr, bpos, epos, flags);
}

static inline x_ndr_off_t x_ndr_scalars(std::string &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	return x_ndr_pull_string(t, ndr, bpos, epos, flags);
}

typedef uint32_t ipv4address;
#endif
x_ndr_off_t x_ndr_push_u16string(const std::u16string &str, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags);
x_ndr_off_t x_ndr_pull_u16string(std::u16string &str, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags);

#if 0
struct x_ndr_u16string_t
{
	std::u16string val;
};
#endif
/* simple ascill string */
struct sstring
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level);
	void ostr(x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const;
	std::string val;
};
#if 0
struct u16string
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level);
	void ostr(x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const;
	bool operator!=(const u16string &other) const { return val != other.val; }
	std::u16string val;
};
#endif
/* can be either u16string or sstring */
struct gstring
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level);
	void ostr(x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const;
	std::string val;
};
#if 0
struct astring
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level);
	std::string val;
};
#endif
struct nstring
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level);
	void ostr(x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const;
	std::string val;
};

struct nstring_array
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level);
	void ostr(x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const;
	std::vector<std::string> val;
};

struct DATA_BLOB
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level);
	void ostr(x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const;
	std::vector<uint8_t> val;
};

#if 0
struct blob_t
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level);
	void ostr(x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const;
	std::vector<uint8_t> val;
};

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
#define X_NDR_AT(ndr, v, extra_flags, level, bpos, epos) X_NDR_CHECK(x_ndr_at((ndr), (v), (extra_flags), (level), (off), (len)))

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

static inline void x_ndr_ostr(uint32_t v, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	ndr.os << v;
}

static inline void x_ndr_ostr(int32_t v, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
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

static inline void x_ndr_ostr(int64_t v, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	ndr.os << v;
}

void x_ndr_ostr_u16string(const std::u16string &str, x_ndr_ostr_t &ndr, uint32_t flags);

static inline void x_ndr_ostr(const std::u16string &v, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	x_ndr_ostr_u16string(v, ndr, flags);
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

void x_ndr_ostr_uint8_array(const uint8_t *v, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level, size_t count);

template <size_t C>
inline void x_ndr_ostr(const std::array<uint8_t, C> &v, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	x_ndr_ostr_uint8_array(v.data(), ndr, flags, level, C);
}

inline void x_ndr_ostr(const std::vector<uint8_t> &v, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	x_ndr_ostr_uint8_array(v.data(), ndr, flags, level, v.size());
}

template <typename T>
inline void x_ndr_ostr(const T &t, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	x_ndr_ostreamer_t<T, typename x_ndr_traits_t<T>::ndr_type>()(t, ndr, flags, level);
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

template <typename T, size_t C>
inline x_ndr_off_t x_ndr_scalars(const std::array<T,C> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	for (auto &i: t) {
		X_NDR_SCALARS(i, ndr, bpos, epos, flags, level);
	}
	return bpos;
}

template <typename T, size_t C>
inline x_ndr_off_t x_ndr_scalars(std::array<T,C> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	for (auto &i: t) {
		X_NDR_SCALARS(i, ndr, bpos, epos, flags, level);
	}
	return bpos;
}

struct x_ndr_subctx_t
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	uint32_t content_size;
	uint32_t flags = 0;
};

x_ndr_off_t x_ndr_scalars(const x_ndr_subctx_t &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level);

x_ndr_off_t x_ndr_scalars(x_ndr_subctx_t &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level);

template <typename T>
inline x_ndr_off_t x_ndr_subctx(const T &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	x_ndr_subctx_t subctx;

	x_ndr_off_t pos_subctx = bpos;
	X_NDR_SCALARS(subctx, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	x_ndr_off_t tmp_bpos = bpos;
	x_ndr_push_t subndr{ndr.buff, bpos};
	bpos = x_ndr_handler_t<T, typename x_ndr_traits_t<T>::has_buffers>()(
			t, subndr, bpos, epos, x_ndr_set_flags(flags, subctx.flags), level);
	subctx.content_size = X_NDR_ROUND(bpos - tmp_bpos, 8);
	subctx.flags = flags;
	X_NDR_SCALARS(subctx, ndr, pos_subctx, epos, flags, X_NDR_SWITCH_NONE);
	return tmp_bpos + subctx.content_size;
}

template <typename T>
inline x_ndr_off_t x_ndr_subctx(T &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	x_ndr_subctx_t subctx;
	X_NDR_SCALARS(subctx, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	x_ndr_pull_t subndr{ndr.buff, bpos};
	epos = X_NDR_CHECK_POS(bpos + subctx.content_size, bpos, epos);
	
	bpos = x_ndr_handler_t<T, typename x_ndr_traits_t<T>::has_buffers>()(
			t, subndr, bpos, epos, x_ndr_set_flags(flags, subctx.flags), level);
	if (bpos < 0) {
		return bpos;
	} else {
		return epos;
	}
}

#define X_NDR_SUBCTX(t, ndr, bpos, epos, flags, level) \
	X_NDR_VERIFY((bpos), x_ndr_subctx((t), (ndr), (bpos), (epos), (flags), (level)))

#if 0
template <typename T>
struct x_ndr_vector_t {
	std::vector<T> val;
};

template <typename T>
inline uint32_t get_size(const x_ndr_vector_t<T> &t)
{
	return t.val.size();
}

template <typename T>
inline x_ndr_off_t x_ndr_scalars(const x_ndr_vector_t<T> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	for (auto &i: t.val) {
		X_NDR_SCALARS(i, ndr, bpos, epos, flags, level);
	}
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_scalars(x_ndr_vector_t<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	while (bpos < epos) {
		T v;
		X_NDR_SCALARS(v, ndr, bpos, epos, flags, level);
		t.val.push_back(v);
	}
	return bpos;
}

template <typename T>
inline void x_ndr_ostr(const x_ndr_vector_t<T> &t, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	x_ndr_ostr_array(t.val.data(), ndr, flags, level, t.val.size());
}

template <typename T>
struct x_ndr_vector_with_count_t {
	void resize(size_t count) {
		val.resize(count);
	}
	std::vector<T> val;
};

template <typename T>
inline uint32_t get_size(const x_ndr_vector_with_count_t<T> &t)
{
	return t.val.size();
}

template <typename T>
inline x_ndr_off_t x_ndr_scalars(const x_ndr_vector_with_count_t<T> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	for (auto &i: t.val) {
		X_NDR_SCALARS(i, ndr, bpos, epos, flags, level);
	}
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_scalars(x_ndr_vector_with_count_t<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	for (auto &i: t.val) {
		X_NDR_SCALARS(i, ndr, bpos, epos, flags, level);
	}
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_buffers(const x_ndr_vector_with_count_t<T> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	for (auto &i: t.val) {
		X_NDR_BUFFERS(i, ndr, bpos, epos, flags, level);
	}
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_buffers(x_ndr_vector_with_count_t<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	for (auto &i: t.val) {
		X_NDR_BUFFERS(i, ndr, bpos, epos, flags, level);
	}
	return bpos;
}

template <typename T, typename HasBuffers>
struct x_ndr_vector_pusher_t {
	x_ndr_off_t operator()(const x_ndr_vector_with_count_t<T>& vec, x_ndr_push_t &ndr,
			x_ndr_off_t bpos, x_ndr_off_t epos,
			uint32_t flags, x_ndr_switch_t level) const {
		for (auto &t: vec.val) {
			X_NDR_SCALARS(t, ndr, bpos, epos, flags, level); 
		}
		return bpos;
	}
};

template <typename T>
struct x_ndr_vector_pusher_t<T, std::true_type> {
	x_ndr_off_t operator()(const x_ndr_vector_with_count_t<T>& vec, x_ndr_push_t &ndr,
			x_ndr_off_t bpos, x_ndr_off_t epos,
			uint32_t flags, x_ndr_switch_t level) const {
		for (auto &t: vec.val) {
			X_NDR_SCALARS(t, ndr, bpos, epos, flags, level); 
		}
		for (auto &t: vec.val) {
			X_NDR_BUFFERS(t, ndr, bpos, epos, flags, level); 
		}
		return bpos;
	}
};

template <typename T, typename HasBuffers>
struct x_ndr_vector_puller_t {
	x_ndr_off_t operator()(x_ndr_vector_with_count_t<T>& vec, x_ndr_pull_t &ndr,
			x_ndr_off_t bpos, x_ndr_off_t epos,
			uint32_t flags, x_ndr_switch_t level) const {
		for (auto &t: vec.val) {
			X_NDR_SCALARS(t, ndr, bpos, epos, flags, level); 
		}
		return bpos;
	}
};

template <typename T>
struct x_ndr_vector_puller_t<T, std::true_type> {
	x_ndr_off_t operator()(x_ndr_vector_with_count_t<T>& vec, x_ndr_pull_t &ndr,
			x_ndr_off_t bpos, x_ndr_off_t epos,
			uint32_t flags, x_ndr_switch_t level) const {
		for (auto &t: vec.val) {
			X_NDR_SCALARS(t, ndr, bpos, epos, flags, level); 
		}
		for (auto &t: vec.val) {
			X_NDR_BUFFERS(t, ndr, bpos, epos, flags, level); 
		}
		return bpos;
	}
};

template <typename T>
inline void x_ndr_ostr(const x_ndr_vector_with_count_t<T> &t, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	x_ndr_ostr_array(t.val.data(), ndr, flags, level, t.val.size());
}

template <typename T>
inline x_ndr_off_t x_ndr_scalars(std::vector<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level, size_t count)
{
	for (uint32_t i = 0; i < count; ++i) {
		T v;
		X_NDR_SCALAR(v, ndr, bpos, epos, flags, level);
		t.push_back(v);
	}
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_scalars(std::vector<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level, size_t count)
{
	for (uint32_t i = 0; i < count; ++i) {
		T v;
		X_NDR_SCALAR(v, ndr, bpos, epos, flags, level);
		t.push_back(v);
	}
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_scalars(const std::shared_ptr<T> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	return x_ndr_scalars(*t, ndr, bpos, epos, flags, level);
}

template <typename T>
inline x_ndr_off_t x_ndr_scalars(std::shared_ptr<T> &t, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level)
{
	t = std::make_shared<T>();
	return x_ndr_data(*t, ndr, bpos, epos, flags, level);
}

template <typename T, typename... LT>
struct x_ndr_relative_ptr_t {
	mutable x_ndr_off_t __pos_ptr;
	std::shared_ptr<T> val;
};

template <typename T, typename... LT>
struct x_ndr_traits_t<x_ndr_relative_ptr_t<T, LT...>> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};

template <typename T>
inline x_ndr_off_t x_ndr_scalars(const x_ndr_relative_ptr_t<T> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	t.__pos_ptr = bpos;
	X_NDR_SCALARS(uint32_t(0), ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_buffers(const x_ndr_relative_ptr_t<T> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	if (t.val) {
		X_NDR_SCALARS(uint32_t(bpos - ndr.base), ndr, t.__pos_ptr, epos, flags, level);
		bpos = x_ndr_pusher_t<T, typename x_ndr_traits_t<T>::has_buffers>()(*t.val, ndr,
				bpos, epos, flags, level);
	}
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_scalars(x_ndr_relative_ptr_t<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	t.__pos_ptr = bpos;
	X_NDR_SKIP(uint32_t, ndr, bpos, epos, flags);
	return bpos;
}

template <typename T>
x_ndr_off_t x_ndr_pull_at(T &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		uint32_t offset)
{
	x_ndr_off_t tmp_bpos = X_NDR_CHECK_POS(ndr.base + offset, 0, epos);
	tmp_bpos = x_ndr_puller_t<T, typename x_ndr_traits_t<T>::has_buffers>()(t, ndr,
			tmp_bpos, epos, flags, level);
	if (tmp_bpos < 0) {
		return tmp_bpos;
	}
	return std::max(bpos, tmp_bpos);
}

template <typename T>
x_ndr_off_t x_ndr_pull_at(T &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		uint32_t offset, uint32_t length)
{
	x_ndr_off_t tmp_bpos = X_NDR_CHECK_POS(ndr.base + offset, 0, epos);
	epos = X_NDR_CHECK_POS(tmp_bpos + length, tmp_bpos, epos);
	tmp_bpos = x_ndr_puller_t<T, typename x_ndr_traits_t<T>::has_buffers>()(t, ndr,
			tmp_bpos, epos, flags, level);
	if (tmp_bpos < 0) {
		return tmp_bpos;
	}
	return std::max(bpos, tmp_bpos);
}

template <typename T>
inline x_ndr_off_t x_ndr_buffers(x_ndr_relative_ptr_t<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	uint32_t offset;
	X_NDR_SCALARS(offset, ndr, t.__pos_ptr, epos, flags, X_NDR_SWITCH_NONE);
	if (offset != 0) {
		t.val = x_ndr_allocate_ptr<T>(level);
		bpos = x_ndr_pull_at(*t.val, ndr,
				bpos, epos, flags, level, offset);
	}
	return bpos;
}

template <typename T>
inline void x_ndr_ostr(const x_ndr_relative_ptr_t<T> &t, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	if (t.val) {
		x_ndr_ostr(*t.val, ndr, flags, level);
	} else {
		ndr.os << "NULL";
	}
}

template <typename T>
struct x_ndr_l2s2o4_ptr_t {
	mutable x_ndr_off_t __pos_ptr;
	std::shared_ptr<T> val;
};

template <typename T>
struct x_ndr_traits_t<x_ndr_l2s2o4_ptr_t<T>> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};

template <typename T>
inline x_ndr_off_t x_ndr_scalars(const x_ndr_l2s2o4_ptr_t<T> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	t.__pos_ptr = bpos;
	X_NDR_SKIP(uint16_t, ndr, bpos, epos, flags);
	X_NDR_SKIP(uint16_t, ndr, bpos, epos, flags);
	X_NDR_SKIP(uint32_t, ndr, bpos, epos, flags);
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_buffers(const x_ndr_l2s2o4_ptr_t<T> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	x_ndr_off_t ret = bpos;
	if (t.val) {
		ret = x_ndr_pusher_t<T, typename x_ndr_traits_t<T>::has_buffers>()(*t.val, ndr,
				bpos, epos, flags, level);
		if (ret < 0) {
			return ret;
		}
	}
	X_NDR_SCALARS(uint16_t(ret - bpos), ndr, t.__pos_ptr, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(uint16_t(ret - bpos), ndr, t.__pos_ptr, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(uint32_t(bpos - ndr.base), ndr, t.__pos_ptr, epos, flags, X_NDR_SWITCH_NONE);
	return ret;
}

template <typename T>
inline x_ndr_off_t x_ndr_scalars(x_ndr_l2s2o4_ptr_t<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	t.__pos_ptr = bpos;
	X_NDR_SKIP(uint16_t, ndr, bpos, epos, flags);
	X_NDR_SKIP(uint16_t, ndr, bpos, epos, flags);
	X_NDR_SKIP(uint32_t, ndr, bpos, epos, flags);
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_buffers(x_ndr_l2s2o4_ptr_t<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	uint32_t offset = 0;
	uint16_t length, size;
	X_NDR_SCALARS(length, ndr, t.__pos_ptr, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(size, ndr, t.__pos_ptr, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(offset, ndr, t.__pos_ptr, epos, flags, X_NDR_SWITCH_NONE);
	if (offset) {
		// TODO check size and length?
		t.val = x_ndr_allocate_ptr<T>(level);
		bpos = x_ndr_pull_at(*t.val, ndr, bpos, epos, flags, level,
				offset, length);
	}
	return bpos;
}

template <typename T>
inline void x_ndr_ostr(const x_ndr_l2s2o4_ptr_t<T> &t, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	if (t.val) {
		x_ndr_ostr(*t.val, ndr, flags, level);
	} else {
		ndr.os << "NULL";
	}
}

template <typename T>
struct x_ndr_s4o4_ptr_t {
	mutable x_ndr_off_t __pos_ptr;
	std::shared_ptr<T> val;
};

template <typename T>
struct x_ndr_traits_t<x_ndr_s4o4_ptr_t<T>> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};

template <typename T>
inline x_ndr_off_t x_ndr_scalars(const x_ndr_s4o4_ptr_t<T> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	t.__pos_ptr = bpos;
	X_NDR_SKIP(uint32_t, ndr, bpos, epos, flags);
	X_NDR_SKIP(uint32_t, ndr, bpos, epos, flags);
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_buffers(const x_ndr_s4o4_ptr_t<T> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	x_ndr_off_t ret = bpos;
	if (t.val) {
		ret = x_ndr_pusher_t<T, typename x_ndr_traits_t<T>::has_buffers>()(*t.val, ndr,
				bpos, epos, flags, level);
		if (ret < 0) {
			return ret;
		}
	}
	X_NDR_SCALARS(uint32_t(ret - bpos), ndr, t.__pos_ptr, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(uint32_t(bpos - ndr.base), ndr, t.__pos_ptr, epos, flags, X_NDR_SWITCH_NONE);
	return ret;
}

template <typename T>
inline x_ndr_off_t x_ndr_scalars(x_ndr_s4o4_ptr_t<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	t.__pos_ptr = bpos;
	X_NDR_SKIP(uint32_t, ndr, bpos, epos, flags);
	X_NDR_SKIP(uint32_t, ndr, bpos, epos, flags);
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_buffers(x_ndr_s4o4_ptr_t<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	uint32_t size, offset = 0;
	X_NDR_SCALARS(size, ndr, t.__pos_ptr, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(offset, ndr, t.__pos_ptr, epos, flags, X_NDR_SWITCH_NONE);
	if (offset) {
		// TODO check size and length?
		t.val = x_ndr_allocate_ptr<T>(level);
		bpos = x_ndr_pull_at(*t.val, ndr, bpos, epos, flags, level,
				offset, size);
	}
	return bpos;
}

template <typename T>
inline void x_ndr_ostr(const x_ndr_s4o4_ptr_t<T> &t, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	if (t.val) {
		x_ndr_ostr(*t.val, ndr, flags, level);
	} else {
		ndr.os << "NULL";
	}
}

template <typename T>
struct x_ndr_size_unique_ptr_t {
	mutable x_ndr_off_t __pos_ptr;
	std::shared_ptr<T> val;
};

template <typename T>
struct x_ndr_traits_t<x_ndr_size_unique_ptr_t<T>> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};

template <typename T>
inline x_ndr_off_t x_ndr_scalars(const x_ndr_size_unique_ptr_t<T> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	t.__pos_ptr = bpos;
	X_NDR_SCALARS(uint32_t{0}, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(uint3264{0}, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_buffers(const x_ndr_size_unique_ptr_t<T> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	if (t.val) {
		x_ndr_off_t ret = x_ndr_pusher_t<T, typename x_ndr_traits_t<T>::has_buffers>()(
				*t.val, ndr, bpos, epos, flags, level);
		if (ret < 0) {
			return ret;
		}
		X_NDR_SCALARS(uint32_t(ret - bpos), ndr, t.__pos_ptr, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS((uint3264{ndr.next_ptr()}), ndr, t.__pos_ptr, epos, flags, X_NDR_SWITCH_NONE);
		return ret;
	}
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_scalars(x_ndr_size_unique_ptr_t<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	t.__pos_ptr = bpos;
	X_NDR_SKIP(uint32_t, ndr, bpos, epos, flags);
	X_NDR_SKIP(uint3264, ndr, bpos, epos, flags);
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_buffers(x_ndr_size_unique_ptr_t<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	uint32_t size;
	X_NDR_SCALARS(size, ndr, t.__pos_ptr, epos, flags, X_NDR_SWITCH_NONE);
	uint3264 ptr;
	X_NDR_SCALARS(ptr, ndr, t.__pos_ptr, epos, flags, X_NDR_SWITCH_NONE);
	if (ptr.val) {
		epos = X_NDR_CHECK_POS(bpos + size, bpos, epos);
		t.val = x_ndr_allocate_ptr<T>(level);
		bpos = x_ndr_puller_t<T, typename x_ndr_traits_t<T>::has_buffers>()(
				*t.val, ndr, bpos, epos, flags, level);
		if (bpos < 0) {
			return bpos;
		} else {
			return epos;
		}
	}

	return bpos;
}

template <typename T>
inline void x_ndr_ostr(const x_ndr_size_unique_ptr_t<T> &t, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	if (t.val) {
		x_ndr_ostr(*t.val, ndr, flags, level);
	} else {
		ndr.os << "NULL";
	}
}

template <typename T>
struct x_ndr_subndr_t
{
	T val;
};

template <typename T>
struct x_ndr_traits_t<x_ndr_subndr_t<T>> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_struct;
};

/* ndr string with length and EOS */
template <typename VT, typename LT>
struct x_ndr_strlz_t
{
	VT val;
};

template <typename VT, typename LT>
struct x_ndr_traits_t<x_ndr_strlz_t<VT, LT>> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_struct;
};

template <typename VT, typename LT>
inline x_ndr_off_t x_ndr_scalars(const x_ndr_strlz_t<VT, LT> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	using value_type = typename VT::value_type;
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	LT size = (t.val.size() + 1) * sizeof(value_type);
	X_NDR_SCALARS(size, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	/* TODO endian of unicode? */
	bpos = x_ndr_push_bytes(t.val.data(), ndr, bpos, epos,
			t.val.size() * sizeof(value_type));
	if (bpos < 0) {
		return bpos;
	}
	return x_ndr_scalars(value_type(0), ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
}

template <typename VT, typename LT>
inline x_ndr_off_t x_ndr_scalars(x_ndr_strlz_t<VT, LT> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	using value_type = typename VT::value_type;
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	LT size;
	X_NDR_SCALARS(size, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (size > 0) {
		if ((size % sizeof(value_type)) != 0) {
			return -NDR_ERR_STRING;
		}
		epos = X_NDR_CHECK_POS(bpos + size, bpos, epos);
		t.val.assign((const value_type *)ndr.get_data(), (const value_type *)(ndr.get_data() + epos) - 1);
		X_NDR_VALUE(value_type(0), ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}
	return bpos;
}

template <typename VT, typename LT>
inline void x_ndr_ostr(const x_ndr_strlz_t<VT, LT> &t, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	X_TODO; // x_ndr_ostr_u16string(t.val, ndr, flags, level);
}
#endif

#if 0
struct x_ndr_s2_u16string_t
{
	std::u16string val;
};

template <>
struct x_ndr_traits_t<x_ndr_s2_u16string_t> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_struct;
};

template <>
inline x_ndr_off_t x_ndr_scalars(const x_ndr_s2_u16string_t &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	uint16_t size = t.val.size() * 2;
	X_NDR_SCALARS(size, ndr, bpos, epos, flags, level);
	return x_ndr_push_u16string(t.val, ndr, bpos, epos, flags);
}

template <>
inline x_ndr_off_t x_ndr_scalars(x_ndr_s2_u16string_t &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	uint16_t size;
	X_NDR_SCALARS(size, ndr, bpos, epos, flags, level);
	return x_ndr_pull_u16string(t.val, ndr, bpos, epos, flags, size); 
}

template <>
inline void x_ndr_ostr(const x_ndr_s2_u16string_t &t, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	x_ndr_ostr_u16string(t.val, ndr, flags, level);
}

inline void x_ndr_ostr(const std::u16string &t, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	x_ndr_ostr_u16string(t, ndr, flags, level);
}
#endif

}


#endif /* __ndr__hxx__ */

