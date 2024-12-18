
#ifndef __nxdr__hxx__
#define __nxdr__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
#include "include/bits.hxx"
#include "buf.hxx"
#include "smbd.hxx"
#include <string>

#define X_NXDR_CHECK(call) ({ \
	auto _ret = call; \
	if (x_unlikely(!_ret)) { \
		return _ret; \
	} \
	_ret; \
})

struct x_nxdr_pull_t
{
	x_nxdr_pull_t(const uint8_t *buf, size_t offset, size_t length)
		: buf(buf), offset(offset), length(length)
	{
	}

	bool check(size_t l) const
	{
		return offset + l <= length;
	}

	bool pull_bytes(void *bytes, uint32_t l)
	{
		if (!check(l)) {
			return false;
		}
		memcpy(bytes, buf + offset, l);
		offset += l;
		return true;
	}

	bool align(uint32_t align)
	{
		size_t pad = x_pad_len(offset, align);
		if (pad > length) {
			return false;
		}
		offset = pad;
		return true;
	}
	uint8_t const * const buf;
	size_t offset;
	const size_t length;
};

struct x_nxdr_push_t
{
	x_nxdr_push_t(x_bufref_t *head, x_bufref_t *tail)
		: head(head), tail(tail)
	{
	}

	~x_nxdr_push_t()
	{
		x_bufref_list_free(head);
	}

	uint32_t release(x_bufref_t **phead, x_bufref_t **ptail)
	{
		*phead = std::exchange(head, nullptr);
		*ptail = std::exchange(tail, nullptr);
		return std::exchange(total_length, 0);
	}

	bool check(size_t l) const
	{
		return true;
	}
#if 0
	bool reserve(size_t l)
	{
		size_t space = 0;
		x_bufref_t *br = curr;
		while (br) {
			space = br->buf->size - (br->offset + br->length);
			if (space >= l) {
				return true;
			}
			l -= space;
			br = br->next;
		}
		x_buf_t *buf = x_buf_alloc(std::max(l, 1024ul));
		if (!buf) {
			return false;
		}
		x_bufref_t *bufref = new x_bufref_t(buf, 0, 0);
		if (tail) {
			X_ASSERT(head);
			tail->next = bufref;
			tail = bufref;
			if (curr->buf->size == curr->offset + curr->length) {
				curr = curr->next;
			}
		} else {
			X_ASSERT(!head);
			head = tail = curr = bufref;
		}
		return true;
	}
#endif
	bool push_bytes(const void *bytes, uint32_t l)
	{
		for (int i = 0; i < 2; ++i) {
			if (tail && tail->offset + tail->length < tail->buf->size) {
				X_ASSERT(tail->buf->ref == 1);
				uint32_t copy_len = tail->buf->size - (tail->offset + tail->length);
				if (copy_len > l) {
					copy_len = l;
				}
				uint8_t *ptr = tail->get_data() + tail->length;
				memcpy(ptr, bytes, copy_len);
				l -= copy_len;
				tail->length += copy_len;
				total_length += copy_len;
			}

			if (l == 0) {
				return true;
			}

			x_buf_t *buf = x_buf_alloc(std::max(l, 1024u));
			if (!buf) {
				return false;
			}

			x_bufref_t *bufref = new x_bufref_t(buf, 0, 0);
			if (tail) {
				X_ASSERT(head);
				tail->next = bufref;
				tail = bufref;
			} else {
				X_ASSERT(!head);
				head = tail = bufref;
			}
		}
		X_ASSERT(false);
		return false;
	}

	bool align(uint32_t align)
	{
		uint32_t pad = x_convert_assert<uint32_t>(x_pad_len(total_length, align));
		if (pad > total_length) {
			uint8_t zero[8] = {};
			return push_bytes(zero, pad - total_length);
		}
		return true;
	}
	x_bufref_t *head{}, *tail{};
	uint32_t total_length = 0;
};

static inline bool x_nxdr_uint8(x_nxdr_pull_t &nxdr, uint8_t &val)
{
	if (!nxdr.check(sizeof(val))) {
		return false;
	}
	auto ptr = (const uint8_t *)(nxdr.buf + nxdr.offset);
	val = X_LE2H8(*ptr);
	nxdr.offset += sizeof(val);
	return true;
}

static inline bool x_nxdr_uint8(x_nxdr_push_t &nxdr, uint8_t val)
{
	if (!nxdr.check(sizeof(val))) {
		return false;
	}
	uint8_t tmp = X_H2LE8(val);
	return nxdr.push_bytes(&tmp, sizeof(val));
}

static inline bool x_nxdr_uint16(x_nxdr_pull_t &nxdr, uint16_t &val)
{
	if (!nxdr.check(sizeof(val))) {
		return false;
	}
	auto ptr = (const uint16_t *)(nxdr.buf + nxdr.offset);
	val = X_LE2H16(*ptr);
	nxdr.offset += sizeof(val);
	return true;
}

static inline bool x_nxdr_uint16(x_nxdr_push_t &nxdr, uint16_t val)
{
	if (!nxdr.check(sizeof(val))) {
		return false;
	}
	uint16_t tmp = X_H2LE16(val);
	return nxdr.push_bytes(&tmp, sizeof(val));
}

static inline bool x_nxdr_uint32(x_nxdr_pull_t &nxdr, uint32_t &val)
{
	if (!nxdr.check(sizeof(val))) {
		return false;
	}
	auto ptr = (const uint32_t *)(nxdr.buf + nxdr.offset);
	val = X_LE2H32(*ptr);
	nxdr.offset += sizeof(val);
	return true;
}

static inline bool x_nxdr_uint32(x_nxdr_push_t &nxdr, uint32_t val)
{
	if (!nxdr.check(sizeof(val))) {
		return false;
	}
	uint32_t tmp = X_H2LE32(val);
	return nxdr.push_bytes(&tmp, sizeof(val));
}

static inline bool x_nxdr_uint64(x_nxdr_pull_t &nxdr, uint64_t &val)
{
	if (!nxdr.check(sizeof(val))) {
		return false;
	}

	auto ptr = (const uint64_t *)(nxdr.buf + nxdr.offset);
	val = X_LE2H64(*ptr);
	nxdr.offset += sizeof(val);
	return true;
}

static inline bool x_nxdr_uint64(x_nxdr_push_t &nxdr, uint64_t val)
{
	if (!nxdr.check(sizeof(val))) {
		return false;
	}
	uint64_t tmp = X_H2LE64(val);
	return nxdr.push_bytes(&tmp, sizeof(val));
}

template <typename T> struct x_nxdr_traits_t { };

template <typename T, typename XT = x_nxdr_traits_t<T>>
inline bool x_nxdr(x_nxdr_pull_t &xdr, T &t, XT &&xt = XT())
{
	return xt(xdr, t);
}

template <typename T, typename XT = x_nxdr_traits_t<T>>
inline bool x_nxdr(x_nxdr_push_t &xdr, const T &t, XT &&xt = XT())
{
	return xt(xdr, t);
}

template <typename T, typename XT = x_nxdr_traits_t<T>>
inline bool x_nxdr_vector(x_nxdr_pull_t &xdr, std::vector<T> &t, XT &&xt = XT())
{
	uint32_t count;
	if (!x_nxdr_uint32(xdr, count)) {
		return false;
	}
	if (alignof(T) == 8) {
		uint32_t pad;
		x_nxdr_uint32(xdr, pad);
	}
	std::vector<T> ret;
	ret.reserve(count);
	for (uint32_t i = 0; i < count; ++i) {
		T v;
		if (!xt(xdr, v)) {
			return false;
		}
		ret.emplace_back(std::move(v));
	}
	std::swap(t, ret);
	return true;
}

template <typename T, typename XT = x_nxdr_traits_t<T>>
inline bool x_nxdr_vector(x_nxdr_push_t &xdr, const std::vector<T> &t, XT &&xt = XT())
{
	uint32_t count = x_convert_assert<uint32_t>(t.size());
	if (!x_nxdr_uint32(xdr, count)) {
		return false;
	}
	if (alignof(T) == 8) {
		x_nxdr_uint32(xdr, 0);
	}
	for (auto &v: t) {
		if (!xt(xdr, v)) {
			return false;
		}
	}
	return true;
}

bool x_nxdr_utf16string_l2_le(x_nxdr_push_t &nxdr, const std::u16string &val);
bool x_nxdr_utf16string_l2_le(x_nxdr_pull_t &nxdr, std::u16string &val);


#endif /* __nxdr__hxx__ */

