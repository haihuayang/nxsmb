
#include "smb2.hxx"

#define GET_LE32(data, off, size) ({ \
	if ((off) + sizeof(uint32_t) > (size)) { \
		return -EINVAL; \
	} \
	const uint8_t *p = (data) + (off); \
	p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24); \
})

#define GET_LE16(data, off, size) ({ \
	if ((off) + sizeof(uint16_t) > (size)) { \
		return -EINVAL; \
	} \
	const uint8_t *p = (data) + (off); \
	p[0] | (p[1] << 8); \
})

#define GET_LE8(data, off, size) ({ \
	if ((off) + sizeof(uint8_t) > (size)) { \
		return -EINVAL; \
	} \
	(data)[(off)]; \
})

#define PUT_LE8(data, off, size, v) do { \
	if ((off) + 1 > (size)) { \
		return -ENOSPC; \
	} \
	(data)[(off)++] = (v); \
} while (0)

static int x_smb2_lz77_decompress(const uint8_t *in_data, uint32_t in_size,
		uint8_t *out_data, uint32_t out_size)
{
	uint32_t buf_flags = 0, buf_flag_count = 0;
	uint32_t in_off = 0, out_off = 0;
	int last_length_half_byte = 0;
	uint32_t match_bytes, match_len, match_off;
	uint32_t i;

	while (1) {
		if (buf_flag_count == 0) {
			buf_flags = GET_LE32(in_data, in_off, in_size);
			in_off += 4;
			buf_flag_count = 32;
		}
		buf_flag_count--;
		if ((buf_flags & (1u << buf_flag_count)) == 0) {
			uint8_t v = GET_LE8(in_data, in_off, in_size);
			in_off++;
			PUT_LE8(out_data, out_off, out_size, v);
		} else {
			if (in_off == in_size) {
				return out_off;
			}
			match_bytes = GET_LE16(in_data, in_off, in_size);
			in_off += 2;
			match_len = match_bytes % 8;
			match_off = (match_bytes/8) + 1;
			if (match_len == 7) {
				if (last_length_half_byte == 0) {
					match_len = GET_LE8(in_data, in_off, in_size);
					match_len = match_len % 16;
					last_length_half_byte = in_off;
					in_off++;
				} else {
					match_len = GET_LE8(in_data, last_length_half_byte, in_size);
					match_len = match_len / 16;
					last_length_half_byte = 0;
				}
				if (match_len == 15) {
					match_len = GET_LE8(in_data, in_off, in_size);
					in_off++;
					if (match_len == 255) {
						match_len = GET_LE16(in_data, in_off, in_size);
						in_off += 2;
						if (match_len == 0) {
							/* This case isn't documented */
							match_len = GET_LE16(in_data, in_off, in_size);
							in_off += 4;
						}
						if (match_len < 15+7)
							return -EINVAL;
						match_len -= (15 + 7);
					}
					match_len += 15;
				}
				match_len += 7;
			}
			match_len += 3;
			for (i = 0; i < match_len; i++) {
				uint8_t byte;
				if (match_off > out_off) {
					return -EINVAL;
				}

				//if (wmem_array_try_index(obuf, wmem_array_get_count(obuf)-match_off, &byte))
				//	return false;
				//wmem_array_append_one(obuf, byte);
				byte = out_data[out_off - match_off];
				PUT_LE8(out_data, out_off, out_size, byte);
			}
		}
	}

	return out_off;
}

int x_smb2_decompress(uint16_t algo,
		const uint8_t *in_data, uint32_t in_size,
		uint8_t *out_data, uint32_t out_size)
{
	if (algo == X_SMB2_COMPRESSION_LZ77) {
		return x_smb2_lz77_decompress(in_data, in_size, out_data, out_size);
	} else {
		X_TODO_ASSERT(false);
		return -EINVAL;
	}
}
