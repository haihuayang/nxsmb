
#ifndef __byteorder__hxx__
#define __byteorder__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include <sys/param.h>
#include <stdint.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN

static inline void put_le8(uint8_t *buf, uint8_t val)
{
	*buf = val;
}

static inline uint8_t get_le8(const uint8_t *buf)
{
	return *buf;
}

static inline void put_le16(uint8_t *buf, uint16_t val)
{
	put_le8(buf, val & 0xff);
	put_le8(buf + 1, val >> 8);
}

static inline uint16_t get_le16(const uint8_t *buf)
{
	uint16_t ret = get_le8(buf + 1);
	return (ret << 8) | get_le8(buf);
}

static inline void put_le32(uint8_t *buf, uint32_t val)
{
	put_le16(buf, val & 0xffff);
	put_le16(buf + 2, val >> 16);
}

static inline uint32_t get_le32(const uint8_t *buf)
{
	uint32_t ret = get_le16(buf + 2);
	return (ret << 16) | get_le16(buf);
}

static inline void put_le64(uint8_t *buf, uint64_t val)
{
	put_le32(buf, val & 0xffffffff);
	put_le32(buf + 4, val >> 32);
}

static inline uint32_t get_le64(const uint8_t *buf)
{
	uint64_t ret = get_le16(buf + 4);
	return (ret << 32) | get_le32(buf);
}

static inline void put_be8(uint8_t *buf, uint8_t val)
{
	*buf = val;
}

static inline void put_be16(uint8_t *buf, uint16_t val)
{
	put_be8(buf, val >> 8);
	put_be8(buf + 1, val & 0xff);
}

static inline void put_be32(uint8_t *buf, uint32_t val)
{
	put_be16(buf, val >> 16);
	put_be16(buf + 2, val & 0xffff);
}

static inline void put_be64(uint8_t *buf, uint64_t val)
{
	put_be32(buf, val >> 32);
	put_be32(buf + 4, val & 0xffffffff);
}

#else
#error "Not implemented"
#endif

#endif /* __byteorder__hxx__ */

