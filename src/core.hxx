
#ifndef __core__hxx__
#define __core__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include <sys/param.h>
#include <stdint.h>

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
	x_put_le8(buf, val & 0xff);
	x_put_le8(buf + 1, val >> 8);
}

static inline uint16_t x_get_le16(const uint8_t *buf)
{
	uint16_t ret = x_get_le8(buf + 1);
	return (ret << 8) | x_get_le8(buf);
}

static inline void x_put_le32(uint8_t *buf, uint32_t val)
{
	x_put_le16(buf, val & 0xffff);
	x_put_le16(buf + 2, val >> 16);
}

static inline uint32_t x_get_le32(const uint8_t *buf)
{
	uint32_t ret = x_get_le16(buf + 2);
	return (ret << 16) | x_get_le16(buf);
}

static inline void x_put_le64(uint8_t *buf, uint64_t val)
{
	x_put_le32(buf, val & 0xffffffff);
	x_put_le32(buf + 4, val >> 32);
}

static inline uint32_t x_get_le64(const uint8_t *buf)
{
	uint64_t ret = x_get_le16(buf + 4);
	return (ret << 32) | x_get_le32(buf);
}

static inline void x_put_be8(uint8_t *buf, uint8_t val)
{
	*buf = val;
}

static inline void x_put_be16(uint8_t *buf, uint16_t val)
{
	x_put_be8(buf, val >> 8);
	x_put_be8(buf + 1, val & 0xff);
}

static inline void x_put_be32(uint8_t *buf, uint32_t val)
{
	x_put_be16(buf, val >> 16);
	x_put_be16(buf + 2, val & 0xffff);
}

static inline uint32_t x_get_be32(const uint8_t *buf)
{
	return (buf[0] << 24) | (buf[1] << 16)  | (buf[2] << 8) | buf[3];
}

static inline void x_put_be64(uint8_t *buf, uint64_t val)
{
	x_put_be32(buf, val >> 32);
	x_put_be32(buf + 4, val & 0xffffffff);
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


#endif /* __core__hxx__ */

