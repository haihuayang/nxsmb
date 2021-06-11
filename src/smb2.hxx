
#ifndef __smb2__hxx__
#define __smb2__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "samba/include/config.h"
#include <atomic>
#include <memory>
#include "core.hxx"
#include "misc.hxx"

extern "C" {
#include "samba/libcli/smb/smb_constants.h"
#include "samba/libcli/smb/smb2_constants.h"
#include "samba/libcli/util/ntstatus.h"
}

#define X_SMB2_OP_ENUM \
	X_SMB2_OP_DECL(NEGPROT) \
	X_SMB2_OP_DECL(SESSSETUP) \
	X_SMB2_OP_DECL(LOGOFF) \
	X_SMB2_OP_DECL(TCON) \
	X_SMB2_OP_DECL(TDIS) \
	X_SMB2_OP_DECL(CREATE) \
	X_SMB2_OP_DECL(CLOSE) \
	X_SMB2_OP_DECL(FLUSH) \
	X_SMB2_OP_DECL(READ) \
	X_SMB2_OP_DECL(WRITE) \
	X_SMB2_OP_DECL(LOCK) \
	X_SMB2_OP_DECL(IOCTL) \
	X_SMB2_OP_DECL(CANCEL) \
	X_SMB2_OP_DECL(KEEPALIVE) \
	X_SMB2_OP_DECL(QUERY_DIRECTORY) \
	X_SMB2_OP_DECL(NOTIFY) \
	X_SMB2_OP_DECL(GETINFO) \
	X_SMB2_OP_DECL(SETINFO) \
	X_SMB2_OP_DECL(BREAK) \

enum {
        SMB2_FILE_INFO_FILE_DIRECTORY_INFORMATION = 1,
        SMB2_FILE_INFO_FILE_FULL_DIRECTORY_INFORMATION = 2,
        SMB2_FILE_INFO_FILE_BOTH_DIR_INFORMATION = 3,
        SMB2_FILE_INFO_FILE_BASIC_INFORMATION = 4,
        SMB2_FILE_INFO_FILE_STANDARD_INFORMATION = 5,
        SMB2_FILE_INFO_FILE_INTERNAL_INFORMATION = 6,
        SMB2_FILE_INFO_FILE_EA_INFORMATION = 7,
        SMB2_FILE_INFO_FILE_ACCESS_INFORMATION = 8,
        SMB2_FILE_INFO_FILE_NAME_INFORMATION = 9,
        SMB2_FILE_INFO_FILE_RENAME_INFORMATION = 10,
        SMB2_FILE_INFO_FILE_NAMES_INFORMATION = 12,
        SMB2_FILE_INFO_FILE_DISPOSITION_INFORMATION = 13,
        SMB2_FILE_INFO_FILE_POSITION_INFORMATION = 14,
        SMB2_FILE_INFO_FILE_MODE_INFORMATION = 16,
        SMB2_FILE_INFO_FILE_ALIGNMENT_INFORMATION = 17,
        SMB2_FILE_INFO_FILE_ALL_INFORMATION = 18,
        SMB2_FILE_INFO_FILE_ALLOCATION_INFORMATION = 19,
        SMB2_FILE_INFO_FILE_END_OF_FILE_INFORMATION = 20,
        SMB2_FILE_INFO_FILE_STREAM_INFORMATION = 22,
        SMB2_FILE_INFO_FILE_COMPRESSION_INFORMATION = 28,
        SMB2_FILE_INFO_FILE_NETWORK_OPEN_INFORMATION = 34,
        SMB2_FILE_INFO_FILE_ATTRIBUTE_TAG_INFORMATION = 35,
        SMB2_FILE_INFO_FILE_ID_BOTH_DIR_INFORMATION = 37,
        SMB2_FILE_INFO_FILE_ID_FULL_DIR_INFORMATION = 38,
        SMB2_FILE_INFO_FILE_VALID_DATA_LENGTH_INFORMATION = 39,
};

enum {
	SMB2_FILE_INFO_FS_SIZE_INFORMATION = 3,
};

struct x_buf_t
{
	std::atomic<int32_t> ref;
	uint32_t size;
	uint8_t data[];
};

static inline x_buf_t *x_buf_alloc(uint32_t size)
{
	x_buf_t *buf = (x_buf_t *)malloc(sizeof(x_buf_t) + size);
	new (&buf->ref) std::atomic<uint32_t>(1);
	buf->size = size;
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

static inline x_buf_t *x_buf_alloc_out_buf(uint32_t body_size)
{
	return x_buf_alloc(8 + SMB2_HDR_BODY + x_pad_len(body_size, 8));
}

static inline uint8_t *x_buf_get_out_hdr(x_buf_t *buf)
{
	X_ASSERT(buf->size >= SMB2_HDR_BODY + 8);
	return buf->data + 8;
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

	x_buf_t *buf;
	uint32_t offset, length;
	x_bufref_t *next{};
};

static inline x_bufref_t *x_bufref_alloc(uint32_t body_size)
{
	x_buf_t *out_buf = x_buf_alloc_out_buf(body_size);
	x_bufref_t *bufref = new x_bufref_t{out_buf, 8,
		SMB2_HDR_BODY + body_size};
	return bufref;
}

struct x_buflist_t
{
	void merge(x_buflist_t &other);
	void pop();
	x_bufref_t *head{}, *tail{};
};
#if 0
struct x_nbt_t
{
	explicit x_nbt_t(size_t nbt_hdr) : nbt_hdr(nbt_hdr) {
		in_buf = new uint8_t[nbt_hdr & 0xffffff];
	}
	~x_nbt_t() {
		if (in_buf) {
			delete[] in_buf;
		}
		if (out_buf) {
			delete[] out_buf;
		}
	}

	// x_dlink_t dlink;
	uint64_t mid;
	uint32_t hdr_flags;
	uint16_t opcode;
	uint16_t credits_requested;
	bool do_signing{false};
	const uint32_t nbt_hdr;
	enum {
		STATE_READING,
		STATE_PROCESSING,
		STATE_COMPLETE,
		STATE_ABORT,
	} state = STATE_READING;
	unsigned int in_len = 0;
	unsigned int in_off;
	uint8_t *in_buf;
	unsigned int out_len = 0;
	unsigned int out_off;
	uint8_t *out_buf = NULL;
};

struct x_smb2_op_state_t
{
	virtual ~x_smb2_op_state_t() { }
};
#endif

struct x_smb2_preauth_t
{
	std::array<char, 64> data{};
	void update(const void *data, size_t length);
};

using x_smb2_key_t = std::array<uint8_t, 16>;

void x_smb2_key_derivation(const uint8_t *KI, size_t KI_len,
		const x_array_const_t<char> &label,
		const x_array_const_t<char> &context,
		x_smb2_key_t &key);

bool x_smb2_signing_check(uint16_t dialect,
		const x_smb2_key_t &key,
		x_bufref_t *buflist);

void x_smb2_signing_sign(uint16_t dialect,
		const x_smb2_key_t &key,
		x_bufref_t *buflist);



#endif /* __smb2__hxx__ */

