
#ifndef __bits__hxx__
#define __bits__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "utils.hxx"
#include <sys/param.h>
#include <stdint.h>
#include <type_traits>

template <typename TO, typename FROM>
inline TO x_convert(FROM from)
{
	return TO(from);
}

template <typename TO, typename FROM>
inline void x_convert(TO &to, FROM from)
{
	to = x_convert<TO>(from);
}

template <typename TO, typename FROM>
inline TO x_convert_assert(FROM from)
{
	TO ret = TO(from);
	X_ASSERT(TO(from) == from);
	return ret;
}

template <typename TO, typename FROM>
inline void x_convert_assert(TO &to, FROM from)
{
	to = x_convert_assert<TO>(from);
}

#if __BYTE_ORDER == __LITTLE_ENDIAN

static inline void x_put_le8(uint8_t *buf, uint8_t val)
{
	*buf = val;
}

static inline uint8_t x_get_le8(const uint8_t *buf)
{
	return *buf;
}

static inline void x_put_le16(uint8_t *buf, uint16_t val)
{
	x_put_le8(buf, uint8_t(val & 0xffu));
	x_put_le8(buf + 1, uint8_t(val >> 8));
}

static inline uint16_t x_get_le16(const uint8_t *buf)
{
	return uint16_t((buf[1] << 8) | buf[0]);
}

static inline void x_put_le32(uint8_t *buf, uint32_t val)
{
	x_put_le16(buf, uint16_t(val & 0xffffu));
	x_put_le16(buf + 2, uint16_t(val >> 16));
}

static inline uint32_t x_get_le32(const uint8_t *buf)
{
	return (buf[3] << 24) | (buf[2] << 16)  | (buf[1] << 8) | buf[0];
}

static inline void x_put_le64(uint8_t *buf, uint64_t val)
{
	x_put_le32(buf, val & 0xffffffffu);
	x_put_le32(buf + 4, uint32_t(val >> 32));
}

static inline uint64_t x_get_le64(const uint8_t *buf)
{
	uint64_t ret = x_get_le32(buf + 4);
	return (ret << 32) | x_get_le32(buf);
}

static inline void x_put_be8(uint8_t *buf, uint8_t val)
{
	*buf = val;
}

static inline void x_put_be16(uint8_t *buf, uint16_t val)
{
	x_put_be8(buf, uint8_t(val >> 8));
	x_put_be8(buf + 1, uint8_t(val & 0xff));
}

static inline uint16_t x_get_be16(const uint8_t *buf)
{
	return uint16_t((buf[0] << 8) | buf[1]);
}

static inline void x_put_be32(uint8_t *buf, uint32_t val)
{
	x_put_be16(buf, uint16_t(val >> 16));
	x_put_be16(buf + 2, uint16_t(val & 0xffffu));
}

static inline uint32_t x_get_be32(const uint8_t *buf)
{
	return (buf[0] << 24) | (buf[1] << 16)  | (buf[2] << 8) | buf[3];
}

static inline void x_put_be64(uint8_t *buf, uint64_t val)
{
	x_put_be32(buf, uint32_t(val >> 32));
	x_put_be32(buf + 4, uint32_t(val & 0xffffffffu));
}

static inline uint64_t x_get_be64(const uint8_t *buf)
{
	uint64_t ret = x_get_be32(buf);
	return (ret << 32) | x_get_be32(buf + 4);
}

/* below are aligned */
template <class T>
static inline typename std::enable_if_t<std::is_unsigned<T>::value, T> x_le2h(T v)
{
	return v;
}

template <class T>
static inline typename std::enable_if_t<std::is_unsigned<T>::value, T> x_h2le(T v)
{
	return v;
}

static inline uint8_t x_be2h(uint8_t v)
{
	return v;
}

static inline uint8_t x_h2be(uint8_t v)
{
	return v;
}

static inline uint16_t x_be2h(uint16_t v)
{
	return __builtin_bswap16(v);
}

static inline uint16_t x_h2be(uint16_t v)
{
	return __builtin_bswap16(v);
}

static inline uint32_t x_be2h(uint32_t v)
{
	return __builtin_bswap32(v);
}

static inline uint32_t x_h2be(uint32_t v)
{
	return __builtin_bswap32(v);
}

static inline uint64_t x_be2h(uint64_t v)
{
	return __builtin_bswap64(v);
}

static inline uint64_t x_h2be(uint64_t v)
{
	return __builtin_bswap64(v);
}


#define X_LE2H8(v) (v)
#define X_LE2H16(v) (v)
#define X_LE2H32(v) (v)
#define X_LE2H64(v) (v)

#define X_BE2H8(v) (v)
#define X_BE2H16(v) __builtin_bswap16(v)
#define X_BE2H32(v) __builtin_bswap32(v)
#define X_BE2H64(v) __builtin_bswap64(v)

#define X_H2LE8(v) (v)
#define X_H2LE16(v) (v)
#define X_H2LE32(v) (v)
#define X_H2LE64(v) (v)

#define X_H2BE8(v) (v)
#define X_H2BE16(v) __builtin_bswap16(v)
#define X_H2BE32(v) __builtin_bswap32(v)
#define X_H2BE64(v) __builtin_bswap64(v)

#else
#error "Not implemented"
#endif

/* align is 2^n */
static inline size_t x_pad_len(size_t orig, size_t align)
{
	return (orig + align - 1) & ~(align - 1);
}


#endif /* __bits__hxx__ */

