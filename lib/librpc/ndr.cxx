
#include "include/librpc/ndr.hxx"
#include <assert.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <arpa/inet.h>

namespace idl {

#define DEBUG(level, x) printf x


const static struct {
	unsigned int err;
	const char *string;
} ndr_err_code_strings[] = {
	{ NDR_ERR_SUCCESS, "Success" },
	{ NDR_ERR_ARRAY_SIZE, "Bad Array Size" },
	{ NDR_ERR_BAD_SWITCH, "Bad Switch" },
	{ NDR_ERR_OFFSET, "Offset Error" },
	{ NDR_ERR_RELATIVE, "Relative Pointer Error" },
	{ NDR_ERR_CHARCNV, "Character Conversion Error" },
	{ NDR_ERR_LENGTH, "Length Error" },
	{ NDR_ERR_SUBCONTEXT, "Subcontext Error" },
	{ NDR_ERR_COMPRESSION, "Compression Error" },
	{ NDR_ERR_STRING, "String Error" },
	{ NDR_ERR_VALIDATE, "Validate Error" },
	{ NDR_ERR_BUFSIZE, "Buffer Size Error" },
	{ NDR_ERR_ALLOC, "Allocation Error" },
	{ NDR_ERR_RANGE, "Range Error" },
	{ NDR_ERR_TOKEN, "Token Error" },
	{ NDR_ERR_IPV4ADDRESS, "IPv4 Address Error" },
	{ NDR_ERR_INVALID_POINTER, "Invalid Pointer" },
	{ NDR_ERR_UNREAD_BYTES, "Unread Bytes" },
	{ NDR_ERR_NDR64, "NDR64 assertion error" },
	{ NDR_ERR_INCOMPLETE_BUFFER, "Incomplete Buffer" },
	{ 0, NULL }
};

_PUBLIC_ NTSTATUS x_ndr_map_error2ntstatus(long ndr_err)
{
	switch (ndr_err) {
	case NDR_ERR_SUCCESS:
		return NT_STATUS_OK;
	case NDR_ERR_BUFSIZE:
		return NT_STATUS_BUFFER_TOO_SMALL;
	case NDR_ERR_TOKEN:
		return NT_STATUS_INTERNAL_ERROR;
	case NDR_ERR_ALLOC:
		return NT_STATUS_NO_MEMORY;
	case NDR_ERR_ARRAY_SIZE:
		return NT_STATUS_ARRAY_BOUNDS_EXCEEDED;
	case NDR_ERR_INVALID_POINTER:
		return NT_STATUS_INVALID_PARAMETER_MIX;
	case NDR_ERR_UNREAD_BYTES:
		return NT_STATUS_PORT_MESSAGE_TOO_LONG;
	default:
		break;
	}

	/* we should map all error codes to different status codes */
	return NT_STATUS_INVALID_PARAMETER;
}

_PUBLIC_ const char *x_ndr_map_error2string(unsigned int ndr_err)
{
	int i;
	for (i = 0; ndr_err_code_strings[i].string != NULL; i++) {
		if (ndr_err_code_strings[i].err == ndr_err)
			return ndr_err_code_strings[i].string;
	}
	return "Unknown error";
}

/*
   push some bytes
 */
x_ndr_off_t x_ndr_push_bytes(const void *data, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, size_t size)
{
	x_ndr_off_t new_epos = X_NDR_CHECK_POS(bpos + size, bpos, epos);
	ndr.reserve(new_epos);
	memcpy(ndr.get_data() + bpos, data, size);
	return new_epos;
}

/*
   parse a set of bytes
 */
x_ndr_off_t x_ndr_pull_bytes(void *addr, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, size_t size)
{
	x_ndr_off_t new_epos = X_NDR_CHECK_POS(bpos + size, bpos, epos);
	memcpy(addr, ndr.get_data() + bpos, size);
	return new_epos;
}

x_ndr_off_t x_ndr_pull_bytes(void *addr, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos)
{
	memcpy(addr, ndr.get_data() + bpos, epos - bpos);
	return epos;
}

void x_ndr_ostr_bytes(const void *addr, x_ndr_ostr_t &ndr, size_t size)
{
	const uint8_t *p = (const uint8_t *)addr;
	for (size_t i = 0; i < size; ++i) {
		char buf[4];
		snprintf(buf, 4, "%02x", p[i]);
		ndr.os << buf;
	}
}

/*
   push a uint32_t
 */
_PUBLIC_ x_ndr_off_t x_ndr_push_uint32(uint32_t v,
		x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags)
{
	bpos = x_ndr_align(4, ndr, bpos, epos, flags);
	if (unlikely(bpos + 4 > epos)) {
		return -NDR_ERR_BUFSIZE;
	}
	ndr.reserve(bpos + 4);
	X_NDR_SIVAL(ndr, flags, bpos, v);
	return bpos + 4;
}

/*
   parse a uint32_t
 */
_PUBLIC_ x_ndr_off_t x_ndr_pull_uint32(uint32_t &v, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags)
{
	bpos = x_ndr_align(4, ndr, bpos, epos, flags);
	if (unlikely(bpos + 4 > epos)) {
		return -NDR_ERR_BUFSIZE;
	}
	v = X_NDR_IVAL(ndr, flags, bpos);
	return bpos + 4;
}

/*
   push a uint64_t
 */
_PUBLIC_ x_ndr_off_t x_ndr_push_uint64_align(uint64_t v,
		x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, uint32_t alignment)
{
	bpos = x_ndr_align(alignment, ndr, bpos, epos, flags);
	if (unlikely(bpos + 8 > epos)) {
		return -NDR_ERR_BUFSIZE;
	}
	ndr.reserve(bpos + 8);
	if (X_NDR_BE(flags)) {
		X_NDR_SIVAL(ndr, flags, bpos, (v>>32));
		X_NDR_SIVAL(ndr, flags, bpos + 4, (v & 0xFFFFFFFF));
	} else {
		X_NDR_SIVAL(ndr, flags, bpos, (v & 0xFFFFFFFF));
		X_NDR_SIVAL(ndr, flags, bpos + 4, (v>>32));
	}
	return bpos + 8;
}

/*
   parse a uint64_t
 */
_PUBLIC_ x_ndr_off_t x_ndr_pull_uint64_align(uint64_t &v,
		x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, uint32_t alignment)
{
	bpos = x_ndr_align(alignment, ndr, bpos, epos, flags);
	if (unlikely(bpos + 8 > epos)) {
		return -NDR_ERR_BUFSIZE;
	}
	if (X_NDR_BE(flags)) {
		v = X_NDR_IVAL(ndr, flags, bpos);
		v = (v << 32) | X_NDR_IVAL(ndr, flags, bpos + 4);
	} else {
		v = X_NDR_IVAL(ndr, flags, bpos + 4);
		v = (v << 32) | X_NDR_IVAL(ndr, flags, bpos);
	}
	return bpos + 8;
}

/*
   push a uint16_t
 */
_PUBLIC_ x_ndr_off_t x_ndr_push_uint16(uint16_t v,
		x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags)
{
	bpos = x_ndr_align(2, ndr, bpos, epos, flags);
	if (unlikely(bpos + 2 > epos)) {
		return -NDR_ERR_BUFSIZE;
	}
	ndr.reserve(bpos + 2);
	X_NDR_SSVAL(ndr, flags, bpos, v);
	return bpos + 2;
}

/*
   parse a uint16_t
 */
_PUBLIC_ x_ndr_off_t x_ndr_pull_uint16(uint16_t &v, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags)
{
	bpos = x_ndr_align(2, ndr, bpos, epos, flags);
	if (unlikely(bpos + 2 > epos)) {
		return -NDR_ERR_BUFSIZE;
	}
	v = X_NDR_SVAL(ndr, flags, bpos);
	return bpos + 2;
}

/*
   push a uint8_t
 */
_PUBLIC_ x_ndr_off_t x_ndr_push_uint8(uint8_t v, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags)
{
	if (unlikely(bpos + 1 > epos)) {
		return -NDR_ERR_BUFSIZE;
	}
	ndr.reserve(bpos + 1);
	SCVAL(ndr.get_data(), bpos, v);
	return bpos + 1;
}

/*
   parse a uint8_t
 */
_PUBLIC_ x_ndr_off_t x_ndr_pull_uint8(uint8_t &v,
		x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags)
{
	if (unlikely(bpos + 1 > epos)) {
		return -NDR_ERR_BUFSIZE;
	}
	v = CVAL(ndr.get_data(), bpos);
	return bpos + 1;
}

/*
   push a uint1632
 */
_PUBLIC_ x_ndr_off_t x_ndr_push_uint1632(uint16_t v,
		x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags)
{
	if (unlikely(flags & LIBNDR_FLAG_NDR64)) {
		return x_ndr_push_uint32(v, ndr, bpos, epos, flags);
	}
	return x_ndr_push_uint16(v, ndr, bpos, epos, flags);
}

/*
   parse a uint1632_t
 */
_PUBLIC_ x_ndr_off_t x_ndr_pull_uint1632(uint16_t &v,
		x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags)
{
	if (unlikely(flags & LIBNDR_FLAG_NDR64)) {
		uint32_t v32 = 0;
		x_ndr_off_t ret = x_ndr_pull_uint32(v32, ndr, bpos, epos, flags);
		v = v32;
		if (unlikely(v32 != v)) {
			// DEBUG(0,(__location__ ": non-zero upper 16 bits 0x%08x\n", (unsigned)v32));
			return -NDR_ERR_NDR64;
		}
		return ret;
	}
	return x_ndr_pull_uint16(v, ndr, bpos, epos, flags);
}

#if 0
void ndr_output_uint64(ndr_ostream_t &ndr, uint32_t flags, uint64_t val, const char *name);
void ndr_output_uint32(ndr_ostream_t &ndr, uint32_t flags, uint32_t val, const char *name);
void ndr_output_uint16(ndr_ostream_t &ndr, uint32_t flags, uint16_t val, const char *name);
void ndr_output_uint8(ndr_ostream_t &ndr, uint32_t flags, uint8_t val, const char *name);
#endif

#if 0
#define NDR_BASE_MARSHALL_SIZE 1024

typedef std::vector<std::pair<const void *, uint32_t>> ndr_token_list_t;

/* structure passed to functions that generate NDR formatted data */
struct ndr_push_t {
	ndr_push_t() {
		data.reserve(NDR_BASE_MARSHALL_SIZE);
	}
	uint32_t flags = 0; /* LIBNDR_FLAG_* */
	std::vector<uint8_t> data;
	bool fixed_buf_size;

	uint32_t relative_base_offset;
	uint32_t relative_end_offset;
	ndr_token_list_t relative_base_list;

	ndr_token_list_t switch_list;
	ndr_token_list_t relative_list;
	ndr_token_list_t relative_begin_list;
	ndr_token_list_t nbt_string_list;
	ndr_token_list_t dns_string_list;
	ndr_token_list_t full_ptr_list;

	// struct ndr_compression_state *cstate;

	/* this is used to ensure we generate unique reference IDs */
	uint32_t ptr_count = 0;
};

_PUBLIC_ x_ndr_push_t &ndr_push_create(void)
{
	return new ndr_push_t;
}

_PUBLIC_ void ndr_push_delete(x_ndr_push_t &ndr)
{
	delete ndr;
}

static x_ndr_ret_t ndr_token_store(ndr_token_list_t &list, const void *p, uint32_t val)
{
	list.emplace_back(std::make_pair(p, val));
	return NDR_ERR_SUCCESS;
}

static uint32_t ndr_token_peek(const ndr_token_list_t &list, const void *key)
{
	for (auto it = list.rbegin(); it != list.rend(); ++it) {
		if (it->first == key) {
			return it->second;
		}
	}
	return 0;
}

_PUBLIC_ uint32_t ndr_set_flags(x_ndr_push_t &ndr, uint32_t flags)
{
	uint32_t orig = ndr.flags;
	ndr.flags = flags;
	return orig;
}

_PUBLIC_ uint32_t ndr_get_flags(const x_ndr_push_t &ndr)
{
	return ndr.flags;
}

/*
   store a switch value
 */
_PUBLIC_ x_ndr_ret_t ndr_set_switch_value(x_ndr_push_t &ndr, const void *p, uint32_t val)
{
	return ndr_token_store(ndr.switch_list, p, val);
}


/*
   retrieve a switch value
 */
_PUBLIC_ uint32_t ndr_push_get_switch_value(x_ndr_push_t &ndr, const void *p)
{
	return ndr_token_peek(ndr.switch_list, p);
}

/*
   store a switch value
 */
_PUBLIC_ x_ndr_ret_t ndr_set_switch_value(x_ndr_pull_t &ndr, const void *p, uint32_t val)
{
	return ndr_token_store(ndr.switch_list, p, val);
}


_PUBLIC_ uint32_t ndr_set_flags(x_ndr_pull_t &ndr, uint32_t flags)
{
	uint32_t orig = ndr.flags;
	ndr.flags = flags;
	return orig;
}

_PUBLIC_ uint32_t ndr_get_flags(const x_ndr_pull_t &ndr)
{
	return ndr.flags;
}

/*
   retrieve a switch value
 */
_PUBLIC_ uint32_t ndr_pull_get_switch_value(x_ndr_pull_t &ndr, const void *p)
{
	return ndr_token_peek(ndr.switch_list, p);
}

const void *ndr_push_get_data(x_ndr_push_t &ndr, size_t &length)
{
	length = ndr.data.size();
	return ndr.data.data();
}

/*
  return and possibly log an NDR error
*/
_PUBLIC_ x_ndr_ret_t ndr_error(unsigned int ndr_err,
		const char *format, ...)
{
	char *s=NULL;
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = vasprintf(&s, format, ap);
	va_end(ap);

	if (ret == -1) {
		return -NDR_ERR_ALLOC;
	}

	DEBUG(1,("ndr_push_error(%u): %s\n", ndr_err, s));

	free(s);

	return -ndr_err;
}

#define ndr_error(err, fmt, ...) -(err)

/*
   work out the number of bytes needed to align on a n byte boundary
 */
_PUBLIC_ size_t ndr_align_size(uint32_t offset, size_t n)
{
	if ((offset & (n-1)) == 0) return 0;
	return n - (offset & (n-1));
}

static size_t ndr_align_size_intl(const x_ndr_push_t &ndr, size_t n)
{
	return ndr_align_size(ndr.data.size(), n);
}

static size_t ndr_align_size_intl(const x_ndr_pull_t &ndr, size_t n)
{
	return ndr_align_size(ndr.offset, n);
}

#define NDR_ALIGN(ndr, n) ndr_align_size_intl(ndr, n)
#endif

static inline size_t normalize_align(size_t size, uint32_t flags)
{
	/* this is a nasty hack to make pidl work with NDR64 */
	if (size == 5) {
		if (flags & LIBNDR_FLAG_NDR64) {
			size = 8;
		} else {
			size = 4;
		}
	} else if (size == 3) {
		if (flags & LIBNDR_FLAG_NDR64) {
			size = 4;
		} else {
			size = 2;
		}
	}
	return size;
}

static inline x_ndr_off_t x_ndr_push_align_intl(size_t n, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos)
{
	x_ndr_off_t new_bpos = ndr.base + (((bpos - ndr.base) + (n-1)) & ~(n-1));
	if (unlikely(new_bpos > epos)) {
		return -NDR_ERR_LENGTH;
	}
	ndr.reserve(new_bpos);
	return new_bpos;
}

x_ndr_off_t x_ndr_align(size_t alignment, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags)
{
	if (unlikely((flags & LIBNDR_FLAG_NOALIGN))) {
		return bpos;
	}
	return x_ndr_push_align_intl(normalize_align(alignment, flags), ndr, bpos, epos);
}

static inline x_ndr_off_t x_ndr_pull_align_intl(size_t n, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos)
{
	x_ndr_off_t new_bpos = ndr.base + (((bpos - ndr.base) + (n-1)) & ~(n-1));
	if (unlikely(new_bpos > epos)) {
		return -NDR_ERR_BUFSIZE;
	}
	return new_bpos;
#if 0
	if (unlikely(ndr.flags & LIBNDR_FLAG_PAD_CHECK)) {
		ndr_check_padding(ndr, n);
	}
#endif
#if 0
	if (unlikely(ndr.offset > ndr.data_size)) {		   \
		if (ndr.flags & LIBNDR_FLAG_INCOMPLETE_BUFFER) { \
			uint32_t _missing = ndr.offset - ndr.data_size; \
			ndr.relative_highest_offset = _missing; \
		} \
		return ndr_pull_error(ndr, NDR_ERR_BUFSIZE, "Pull align %u", (unsigned)n); \
	}
#endif
}

x_ndr_off_t x_ndr_align(size_t alignment, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags)
{
	if (unlikely((flags & LIBNDR_FLAG_NOALIGN))) {
		return bpos;
	}
	return x_ndr_pull_align_intl(normalize_align(alignment, flags), ndr, bpos, epos);
}

#if 0
x_ndr_off_t x_ndr_scalars(const x_ndr_subctx_t &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(uint8_t{1}, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	uint8_t drep;
	if (t.flags & LIBNDR_FLAG_BIGENDIAN) {
		drep = 0;
	} else {
		drep = 0x10;
	}
	X_NDR_SCALARS(drep, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(uint16_t{8}, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(uint32_t{0xcccccccc}, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(t.content_size, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(uint32_t{0}, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	return bpos;
}

x_ndr_off_t x_ndr_scalars(x_ndr_subctx_t &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	uint8_t version;
	uint8_t drep;
	uint16_t hdrlen;
	uint32_t filler;
	X_NDR_SCALARS(version, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (version != 1) {
		return -NDR_ERR_SUBCONTEXT;
	}
	X_NDR_SCALARS(drep, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (drep == 0x10) {
		t.flags = LIBNDR_FLAG_LITTLE_ENDIAN;
	} else if (drep == 0) {
		t.flags = LIBNDR_FLAG_BIGENDIAN;
	} else {
		return -NDR_ERR_SUBCONTEXT;
	}
	X_NDR_SCALARS(hdrlen, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (hdrlen != 8) {
		return -NDR_ERR_SUBCONTEXT;
	}
	X_NDR_SCALARS(filler, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(t.content_size, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (t.content_size % 8 != 0) {
		return -NDR_ERR_SUBCONTEXT;
	}
	X_NDR_SCALARS(filler, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	return bpos;
}

x_ndr_ret_t x_ndr_hole_intl(uint32_t alignment, uint32_t size,
		x_ndr_push_t &ndr,
		x_ndr_ret_t bpos, x_ndr_ret_t epos, uint32_t extra_flags, size_t &pos)
{
	x_ndr_ret_t ret = x_ndr_push_align_intl(ndr, bpos, epos, extra_flags, alignment);
	if (ret < 0) {
		return ret;
	}
	if (ndr.data.size() < bpos + size) {
		ndr.data.resize(bpos + size);
	}
	pos = bpos;
	bpos += size;
	return ret + size;
}

/*
   check for data leaks from the server by looking for non-zero pad bytes
   these could also indicate that real structure elements have been
   mistaken for padding in the IDL
 */
_PUBLIC_ void ndr_check_padding(x_ndr_pull_t &ndr, size_t n)
{
	size_t ofs2 = (ndr.offset + (n-1)) & ~(n-1);
	int i;
	for (i=ndr.offset;i<ofs2;i++) {
		if (ndr.data[i] != 0) {
			break;
		}
	}
	if (i<ofs2) {
		DEBUG(0,("WARNING: Non-zero padding to %d: ", (int)n));
		for (i=ndr.offset;i<ofs2;i++) {
			DEBUG(0,("%02x ", ndr.data[i]));
		}
		DEBUG(0,("\n"));
	}

}
#endif
#define ORIG_NDR_PULL_ALIGN(ndr, n) do { \
	if (unlikely(!(ndr.flags & LIBNDR_FLAG_NOALIGN))) {    \
		if (unlikely(ndr.flags & LIBNDR_FLAG_PAD_CHECK)) {     \
			ndr_check_padding(ndr, n); \
		} \
		ndr.offset = (ndr.offset + (n-1)) & ~(n-1); \
	} \
	if (unlikely(ndr.offset > ndr.data_size)) {		   \
		if (ndr.flags & LIBNDR_FLAG_INCOMPLETE_BUFFER) { \
			uint32_t _missing = ndr.offset - ndr.data_size; \
			ndr.relative_highest_offset = _missing; \
		} \
		return ndr_pull_error(ndr, NDR_ERR_BUFSIZE, "Pull align %u", (unsigned)n); \
	} \
} while(0)
#define NDR_PULL_ALIGN(ndr, extra_flags, n) X_NDR_CHECK(x_ndr_pull_align_intl(ndr, extra_flags, n))
#if 0
_PUBLIC_ x_ndr_ret_t x_ndr_do_union_align(x_ndr_push_t &ndr, uint32_t extra_flags, size_t size)
{
	/* MS-RPCE section 2.2.5.3.4.4 */
	if (ndr.flags & LIBNDR_FLAG_NDR64) {
		return x_ndr_do_align(ndr, extra_flags, size);
	}
	return 0;
}

_PUBLIC_ x_ndr_ret_t ndr_do_union_align(x_ndr_pull_t &ndr, uint32_t extra_flags, size_t size)
{
	/* MS-RPCE section 2.2.5.3.4.4 */
	if (ndr.flags & LIBNDR_FLAG_NDR64) {
		return x_ndr_do_align(ndr, extra_flags, size);
	}
	return 0;
}

/*
   push a uint16_t
 */
_PUBLIC_ x_ndr_ret_t x_ndr_push_uint16(x_ndr_push_t &ndr, uint32_t extra_flags, uint16_t v)
{
	size_t ret = x_ndr_push_align_intl(ndr, extra_flags, 2);
	size_t size = ndr.data.size();
	ndr.data.resize(size + 2);
	NDR_SSVAL(ndr, size, v);
	return ret + 2;
}
#endif
#define NDR_PULL_NEED_BYTES(ndr, n) do { \
	if (unlikely((n) > ndr.data_size || ndr.offset + (n) > ndr.data_size)) { \
		if (ndr.flags & LIBNDR_FLAG_INCOMPLETE_BUFFER) { \
			uint32_t _available = ndr.data_size - ndr.offset; \
			uint32_t _missing = n - _available; \
			ndr.relative_highest_offset = _missing; \
		} \
		return -NDR_ERR_BUFSIZE; \
	} \
} while(0)

#if 0
/*
   parse a arch dependent uint32/uint64
 */
_PUBLIC_ x_ndr_ret_t x_ndr_pull_uint3264(x_ndr_pull_t &ndr, uint32_t extra_flags, uint32_t &v)
{
	if (likely(!(ndr.flags & LIBNDR_FLAG_NDR64))) {
		return x_ndr_pull_uint32(ndr, extra_flags, v);
	}
	uint64_t v64;
	x_ndr_ret_t ret = X_NDR_CHECK(x_ndr_pull_hyper(ndr, extra_flags, v64));
	v = (uint32_t)v64;
	if (unlikely(v64 != v)) {
		DEBUG(0,(__location__ ": non-zero upper 32 bits 0x%016llx\n",
					(unsigned long long)v64));
		return ndr_error(NDR_ERR_NDR64, __location__ ": non-zero upper 32 bits 0x%016llx\n",
				(unsigned long long)v64);
	}
	return ret;
}

/*
   parse a uint16_t
 */
_PUBLIC_ x_ndr_ret_t x_ndr_pull_uint16(x_ndr_pull_t &ndr, uint32_t extra_flags, uint16_t &v)
{
	x_ndr_ret_t ret = X_NDR_CHECK(x_ndr_pull_align_intl(ndr, extra_flags, 2));
	NDR_PULL_NEED_BYTES(ndr, 2);
	v = NDR_IVAL(ndr, ndr.offset);
	ndr.offset += 2;
	return ret + 2;
}

/*
   parse a uint8_t
 */
_PUBLIC_ x_ndr_ret_t x_ndr_pull_uint8(x_ndr_pull_t &ndr, uint32_t extra_flags, uint8_t &v)
{
	NDR_PULL_NEED_BYTES(ndr, 1);
	v = CVAL(ndr.data, ndr.offset);
	ndr.offset += 1;
	return 1;
}


/*
   push a udlong
 */
_PUBLIC_ x_ndr_ret_t x_ndr_push_udlong(x_ndr_push_t &ndr, uint32_t extra_flags, uint64_t v)
{
	size_t ret = x_ndr_push_align_intl(ndr, extra_flags, 4);
	size_t size = ndr.data.size();
	ndr.data.resize(size + 8);
	NDR_SIVAL(ndr, size, (v & 0xFFFFFFFF));
	NDR_SIVAL(ndr, size+4, (v >> 32));
	return ret + 8;
}

/*
   parse a udlong
 */
_PUBLIC_ x_ndr_ret_t x_ndr_pull_udlong(x_ndr_pull_t &ndr, uint32_t extra_flags, uint64_t &v)
{
	x_ndr_ret_t ret = NDR_PULL_ALIGN(ndr, extra_flags, 4);
	NDR_PULL_NEED_BYTES(ndr, 8);
	v = NDR_IVAL(ndr, ndr.offset);
	v |= (uint64_t)(NDR_IVAL(ndr, ndr.offset+4)) << 32;
	ndr.offset += 8;
	return ret + 8;
}

/*
   push a udlongr
 */
_PUBLIC_ x_ndr_ret_t x_ndr_push_udlongr(x_ndr_push_t &ndr, uint32_t extra_flags, uint64_t v)
{
	size_t ret = x_ndr_push_align_intl(ndr, extra_flags, 4);
	size_t size = ndr.data.size();
	ndr.data.resize(size + 8);
	NDR_SIVAL(ndr, size, (v >> 32));
	NDR_SIVAL(ndr, size+4, (v & 0xFFFFFFFF));
	return ret + 8;
}

/*
   parse a udlongr
 */
_PUBLIC_ x_ndr_ret_t x_ndr_pull_udlongr(x_ndr_pull_t &ndr, uint32_t extra_flags, uint64_t &v)
{
	x_ndr_ret_t ret = NDR_PULL_ALIGN(ndr, extra_flags, 4);
	NDR_PULL_NEED_BYTES(ndr, 8);
	v = ((uint64_t)NDR_IVAL(ndr, ndr.offset)) << 32;
	v |= NDR_IVAL(ndr, ndr.offset+4);
	ndr.offset += 8;
	return ret + 8;
}

/*
   push a hyper
 */
_PUBLIC_ x_ndr_ret_t x_ndr_push_hyper(x_ndr_push_t &ndr, uint32_t extra_flags, uint64_t v)
{
	size_t ret = x_ndr_push_align_intl(ndr, extra_flags, 8);
	if (NDR_BE(ndr)) {
		return ret + x_ndr_push_udlongr(ndr, extra_flags, v);
	}
	return ret + x_ndr_push_udlong(ndr, extra_flags, v);
}

/*
   parse a hyper
 */
_PUBLIC_ x_ndr_ret_t x_ndr_pull_hyper(x_ndr_pull_t &ndr, uint32_t extra_flags, uint64_t &v)
{
	x_ndr_ret_t ret = NDR_PULL_ALIGN(ndr, extra_flags, 8);
	if (NDR_BE(ndr)) {
		return ret + x_ndr_pull_udlongr(ndr, extra_flags, v);
	}
	return ret + x_ndr_pull_udlong(ndr, extra_flags, v);
}

/*
   push a uint3264
 */
_PUBLIC_ x_ndr_ret_t x_ndr_push_uint3264(x_ndr_push_t &ndr, uint32_t extra_flags, uint32_t v)
{
	if (unlikely(ndr.flags & LIBNDR_FLAG_NDR64)) {
		return x_ndr_push_hyper(ndr, extra_flags, v);
	}
	return x_ndr_push_uint32(ndr, extra_flags, v);
}

/*
   push a NTSTATUS
 */
_PUBLIC_ x_ndr_ret_t x_ndr_push_NTSTATUS(x_ndr_push_t &ndr, uint32_t extra_flags, NTSTATUS status)
{
	return x_ndr_push_uint32(ndr, extra_flags, NT_STATUS_V(status));
}


#if 0
x_ndr_ret_t x_ndr_pull_bytes(x_ndr_pull_t &ndr, uint8_t *data, size_t n)
{
	NDR_PULL_NEED_BYTES(ndr, n);
	memcpy(data, ndr.data + ndr.offset, n);
	ndr.offset += n;
	return n;
}

/*
   push an array of uint8
 */
_PUBLIC_ x_ndr_ret_t x_ndr_push_array_uint8(x_ndr_push_t &ndr, uint32_t extra_flags, const uint8_t *data, size_t n)
{
	return x_ndr_push_bytes(ndr, data, n);
}

/*
   pull an array of uint8
 */
_PUBLIC_ x_ndr_ret_t x_ndr_pull_array_uint8(x_ndr_pull_t &ndr, uint32_t extra_flags, uint8_t *data, size_t n)
{
	return x_ndr_pull_bytes(ndr, data, n);
}

x_ndr_ret_t x_ndr_at(x_ndr_pull_t &ndr, string &val, uint32_t extra_flags, switch_t level, uint32_t off, uint32_t len)
{
	if (off + len < off) {
		return -NDR_ERR_BUFSIZE;
	}
	NDR_PULL_NEED_BYTES(ndr, off + len);
	ssize_t ret = NDR_CHECK(x_ndr_pull_uint32(ndr, ndr_flags, length));
	// TODO
	return ret;
}

void ndr_output_enum(ndr_ostream_t &ndr, uint32_t val, const char *val_name, const char *name, uint32_t flags)
{
	// TODO
	ndr_output(ndr, flags, name, val, 0);
}

/*
 * Push a DATA_BLOB onto the wire.
 * 1) When called with LIBNDR_FLAG_ALIGN* alignment flags set, push padding
 *    bytes _only_. The length is determined by the alignment required and the
 *    current ndr offset.
 * 2) When called with the LIBNDR_FLAG_REMAINING flag, push the byte array to
 *    the ndr buffer.
 * 3) Otherwise, push a uint3264 length _and_ a corresponding byte array to the
 *    ndr buffer.
 */
_PUBLIC_ x_ndr_ret_t x_ndr_push_DATA_BLOB(x_ndr_push_t &ndr, uint32_t extra_flags, const NDR_t_DATA_BLOB &blob)
{
	size_t len = 0;
	if (ndr.flags & LIBNDR_FLAG_REMAINING) {
		/* nothing to do */
	} else if (ndr.flags & (LIBNDR_ALIGN_FLAGS & ~LIBNDR_FLAG_NOALIGN)) {
		size_t padding = 0;
		if (ndr.flags & LIBNDR_FLAG_ALIGN2) {
			padding = NDR_ALIGN(ndr, 2);
		} else if (ndr.flags & LIBNDR_FLAG_ALIGN4) {
			padding = NDR_ALIGN(ndr, 4);
		} else if (ndr.flags & LIBNDR_FLAG_ALIGN8) {
			padding = NDR_ALIGN(ndr, 8);
		}
		ndr.data.resize(ndr.data.size() + padding, 0);
		return padding;
	} else {
		len += NDR_CHECK(x_ndr_push_uint3264(ndr, NDR_SCALARS, blob.val.size()));
	}
	len += NDR_CHECK(x_ndr_push_bytes(ndr, blob.val.data(), blob.val.size()));
	return len;
}

/*
 * Pull a DATA_BLOB from the wire.
 * 1) when called with LIBNDR_FLAG_ALIGN* alignment flags set, pull padding
 *    bytes _only_. The length is determined by the alignment required and the
 *    current ndr offset.
 * 2) When called with the LIBNDR_FLAG_REMAINING flag, pull all remaining bytes
 *    from the ndr buffer.
 * 3) Otherwise, pull a uint3264 length _and_ a corresponding byte array from the
 *    ndr buffer.
 */
_PUBLIC_ x_ndr_ret_t x_ndr_pull_DATA_BLOB(x_ndr_pull_t &ndr, uint32_t extra_flags, NDR_t_DATA_BLOB &blob)
{
	x_ndr_ret_t ret = 0;
	uint32_t length = 0;

	if (ndr.flags & LIBNDR_FLAG_REMAINING) {
		length = ndr.data_size - ndr.offset;
	} else if (ndr.flags & (LIBNDR_ALIGN_FLAGS & ~LIBNDR_FLAG_NOALIGN)) {
		if (ndr.flags & LIBNDR_FLAG_ALIGN2) {
			length = NDR_ALIGN(ndr, 2);
		} else if (ndr.flags & LIBNDR_FLAG_ALIGN4) {
			length = NDR_ALIGN(ndr, 4);
		} else if (ndr.flags & LIBNDR_FLAG_ALIGN8) {
			length = NDR_ALIGN(ndr, 8);
		}
		if (ndr.data_size - ndr.offset < length) {
			length = ndr.data_size - ndr.offset;
		}
	} else {
		ret += NDR_CHECK(x_ndr_pull_uint3264(ndr, NDR_SCALARS, length));
	}
	NDR_PULL_NEED_BYTES(ndr, length);
	blob.val.assign(ndr.data+ndr.offset, ndr.data+ndr.offset + length);
	ndr.offset += length;
	return ret + length;
}


#define IPQUAD_BE(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

void ndr_output_value(ndr_ostream_t &ndr, uint32_t flags, const NDR_t_ipv4address &t)
{
	char buf[32];
	snprintf(buf, sizeof buf, "%d.%d.%d.%d", IPQUAD_BE(t));
	ndr.os << buf;
}

void ndr_output_value(ndr_ostream_t &ndr, uint32_t flags, const NDR_t_ipv6address &t)
{
	char buf[INET_ADDRSTRLEN];
	ndr.os << inet_ntop(AF_INET6, &t, buf, sizeof(buf));
}

void ndr_output_value(ndr_ostream_t &ndr, uint32_t flags, const NDR_t_nstring &t)
{
	ndr.os << t.val;
}

template <>
x_ndr_ret_t ndr_do(x_ndr_push_t &ndr, const NDR_t_nstring &val, uint32_t extra_flags, switch_t level)
{
	ssize_t ret = NDR_CHECK(x_ndr_push_uint32(ndr, ndr_flags, val.val.size()));
	ret += NDR_CHECK(x_ndr_push_bytes(ndr, val.val.data(), val.val.size()));
	return ret;
}

template <>
x_ndr_ret_t ndr_do(x_ndr_pull_t &ndr, NDR_t_nstring &val, uint32_t extra_flags, switch_t level)
{
	uint32_t length;
	ssize_t ret = NDR_CHECK(x_ndr_pull_uint32(ndr, ndr_flags, length));
	// TODO
	return ret;
}


void ndr_output_value(ndr_ostream_t &ndr, uint32_t flags, const NDR_t_nstring_array &t)
{
	assert(0);
}

template <>
x_ndr_ret_t ndr_do(x_ndr_push_t &ndr, const NDR_t_nstring_array &val, uint32_t extra_flags, switch_t level)
{
	assert(0);
	return -1;
}

template <>
x_ndr_ret_t ndr_do(x_ndr_pull_t &ndr, NDR_t_nstring_array &val, uint32_t extra_flags, switch_t level)
{
	assert(0);
	return -1;
}

void ndr_output_value(ndr_ostream_t &ndr, uint32_t flags, const NDR_t_DATA_BLOB &val)
{
	ndr.os << "blob " << val.val.size();
}

template <>
x_ndr_ret_t ndr_do<NDR_t_DOS_strlen_m_term_null_t>(x_ndr_push_t &ndr, const NDR_t_DOS_strlen_m_term_null_t &t, uint32_t extra_flags, switch_t level)
{
	x_ndr_ret_t ret;
	ret = NDR_CHECK(x_ndr_push_bytes(ndr, t.val.data(), t.val.size()));
	ret += NDR_CHECK(x_ndr_push_uint8(ndr, ndr_flags, 0));
	return ret;
}

template <>
x_ndr_ret_t ndr_do<NDR_t_DOS_strlen_m_term_null_t>(x_ndr_pull_t &ndr, NDR_t_DOS_strlen_m_term_null_t &t, uint32_t extra_flags, switch_t level)
{
	char *buf = new char[t.val.size() + 1];
	x_ndr_ret_t ret = x_ndr_pull_bytes(ndr, (uint8_t *)buf, t.val.size() + 1);
	if (ret > 0) {
		assert(buf[t.val.size()] == '\0'); // TODO
		t.val.assign(buf, buf + t.val.size());
	}
	delete []buf;
	return ret;
}
#endif
#endif
} /* namespace idl */

