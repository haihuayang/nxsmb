
#ifndef __buf__hxx__
#define __buf__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
#include "include/bits.hxx"
#include <atomic>

struct x_buf_t
{
	std::atomic<int32_t> ref;
	uint32_t size;
	uint8_t data[];
};

/* every buf's capacity is time of 8,
   and the length is also time of 8 except the last one
 */
static inline x_buf_t *x_buf_alloc(size_t size)
{
	size = x_pad_len(size, 8);
	X_ASSERT(size < 0x100000000ul);
	x_buf_t *buf = (x_buf_t *)malloc(sizeof(x_buf_t) + size);
	new (&buf->ref) std::atomic<uint32_t>(1);
	buf->size = x_convert_assert<uint32_t>(size);
	return buf;
}

static inline x_buf_t *x_buf_get(x_buf_t *buf)
{
	X_ASSERT(buf->ref > 0);
	++buf->ref;
	return buf;
}

static inline void x_buf_release(x_buf_t *buf)
{
	X_ASSERT(buf->ref > 0);
	if (--buf->ref == 0) {
		free(buf);
	}
}

struct x_bufref_t
{
	x_bufref_t(x_buf_t *buf, uint32_t offset, uint32_t length) :
		buf(buf), offset(offset), length(length) { }

	~x_bufref_t() {
		if (buf) {
			x_buf_release(buf);
		}
	}
	const uint8_t *get_data() const {
		return buf->data + offset;
	}
	uint8_t *get_data() {
		return buf->data + offset;
	}
	uint8_t *back(uint32_t l) {
		/* only one ref, so we can modify it */
		X_ASSERT(buf->ref == 1);
		X_ASSERT(offset >= l);
		offset -= l;
		length += l;
		return buf->data + offset;
	}

	x_buf_t *buf;
	uint32_t offset, length;
	x_bufref_t *next{};
};

static inline void x_bufref_list_free(x_bufref_t *head)
{
	while (head) {
		auto next = head->next;
		delete head;
		head = next;
	}
}

struct x_out_buf_t
{
	x_out_buf_t() = default;
	x_out_buf_t(x_out_buf_t &&other)
	{
		head = std::exchange(other.head, nullptr);
		tail = std::exchange(other.tail, nullptr);
		length = std::exchange(other.length, 0);
	}
	x_out_buf_t &operator=(x_out_buf_t &&other)
	{
		if (this != &other) {
			x_bufref_list_free(head);
			head = std::exchange(other.head, nullptr);
			tail = std::exchange(other.tail, nullptr);
			length = std::exchange(other.length, 0);
		}
		return *this;
	}

	~x_out_buf_t()
	{
			x_bufref_list_free(head);
	}

	void append(x_out_buf_t &other)
	{
		uint32_t total_length = length + other.length;
		X_ASSERT(total_length >= length);

		if (tail) {
			tail->next = other.head;
			tail = other.tail;
		} else {
			head = other.head;
			tail = other.tail;
		}
		length = total_length;

		other.head = other.tail = nullptr;
		other.length = 0;
	}

	x_bufref_t *head{};
	x_bufref_t *tail{};
	uint32_t length = 0;
};

#endif /* __buf__hxx__ */

