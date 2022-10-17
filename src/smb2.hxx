
#ifndef __smb2__hxx__
#define __smb2__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
#include "samba/include/config.h"
#include <atomic>
#include <memory>
#include "misc.hxx"

extern "C" {
#include "samba/libcli/smb/smb_constants.h"
#include "samba/libcli/smb/smb2_constants.h"
#include "samba/libcli/util/ntstatus.h"
}

enum {
	X_SMB1_MAGIC = '\xffSMB',
	X_SMB2_MAGIC = '\xfeSMB',
	X_SMB2_TF_MAGIC = '\xfdSMB',
};

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

struct x_smb2_header_t
{
	uint32_t protocol_id;
	uint16_t length;
	uint16_t credit_charge;
	uint32_t status;
	uint16_t opcode;
	uint16_t credit;
	uint32_t flags;
	uint32_t next_command;
	uint64_t mid;
	union {
		struct {
			uint32_t pid;
			uint32_t tid;
		};
		uint64_t async_id;
	};
	uint64_t sess_id;
	uint8_t signature[16];
};

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
        SMB2_FILE_INFO_FILE_FULL_EA_INFORMATION = 15,
        SMB2_FILE_INFO_FILE_MODE_INFORMATION = 16,
        SMB2_FILE_INFO_FILE_ALIGNMENT_INFORMATION = 17,
        SMB2_FILE_INFO_FILE_ALL_INFORMATION = 18,
        SMB2_FILE_INFO_FILE_ALLOCATION_INFORMATION = 19,
        SMB2_FILE_INFO_FILE_END_OF_FILE_INFORMATION = 20,
        SMB2_FILE_INFO_FILE_ALTERNATE_NAME_INFORMATION = 21,
        SMB2_FILE_INFO_FILE_STREAM_INFORMATION = 22,
        SMB2_FILE_INFO_FILE_COMPRESSION_INFORMATION = 28,
        SMB2_FILE_INFO_FILE_NETWORK_OPEN_INFORMATION = 34,
        SMB2_FILE_INFO_FILE_ATTRIBUTE_TAG_INFORMATION = 35,
        SMB2_FILE_INFO_FILE_ID_BOTH_DIR_INFORMATION = 37,
        SMB2_FILE_INFO_FILE_ID_FULL_DIR_INFORMATION = 38,
        SMB2_FILE_INFO_FILE_VALID_DATA_LENGTH_INFORMATION = 39,
	SMB2_FILE_INFO_FILE_NORMALIZED_NAME_INFORMATION = 48,
};

enum {
	SMB2_FILE_INFO_FS_VOLUME_INFORMATION = 1,
	SMB2_FILE_INFO_FS_SIZE_INFORMATION = 3,
	SMB2_FILE_INFO_FS_ATTRIBUTE_INFORMATION = 5,
};


/* This maps to 0x1F01FF */
#define FILE_GENERIC_ALL (idl::STANDARD_RIGHTS_REQUIRED_ACCESS|\
		idl::SEC_STD_SYNCHRONIZE|\
		idl::SEC_FILE_ALL)

/* This maps to 0x120089 */
#define FILE_GENERIC_READ (idl::STANDARD_RIGHTS_READ_ACCESS|\
		idl::SEC_FILE_READ_DATA|\
		idl::SEC_FILE_READ_ATTRIBUTE|\
		idl::SEC_FILE_READ_EA|\
		idl::SEC_STD_SYNCHRONIZE)

/* This maps to 0x120116 */
#define FILE_GENERIC_WRITE (idl::SEC_STD_READ_CONTROL|\
		idl::SEC_FILE_WRITE_DATA|\
		idl::SEC_FILE_WRITE_ATTRIBUTE|\
		idl::SEC_FILE_WRITE_EA|\
		idl::SEC_FILE_APPEND_DATA|\
		idl::SEC_STD_SYNCHRONIZE)

#define FILE_GENERIC_EXECUTE (idl::STANDARD_RIGHTS_EXECUTE_ACCESS|\
		idl::SEC_FILE_READ_ATTRIBUTE|\
		idl::SEC_FILE_EXECUTE|\
		idl::SEC_STD_SYNCHRONIZE)


/* ChangeNotify flags. */
#define FILE_NOTIFY_CHANGE_FILE_NAME   0x001u
#define FILE_NOTIFY_CHANGE_DIR_NAME    0x002u
#define FILE_NOTIFY_CHANGE_ATTRIBUTES  0x004u
#define FILE_NOTIFY_CHANGE_SIZE        0x008u
#define FILE_NOTIFY_CHANGE_LAST_WRITE  0x010u
#define FILE_NOTIFY_CHANGE_LAST_ACCESS 0x020u
#define FILE_NOTIFY_CHANGE_CREATION    0x040u
#define FILE_NOTIFY_CHANGE_EA          0x080u
#define FILE_NOTIFY_CHANGE_SECURITY    0x100u
#define FILE_NOTIFY_CHANGE_STREAM_NAME	0x00000200u
#define FILE_NOTIFY_CHANGE_STREAM_SIZE	0x00000400u
#define FILE_NOTIFY_CHANGE_STREAM_WRITE	0x00000800u
/* ChangeNotify flags used internally */
#define X_FILE_NOTIFY_CHANGE_WATCH_TREE	0x40000000u
#define X_FILE_NOTIFY_CHANGE_VALID	0x80000000u


#define FILE_NOTIFY_CHANGE_NAME \
	(FILE_NOTIFY_CHANGE_FILE_NAME|FILE_NOTIFY_CHANGE_DIR_NAME)

#define FILE_NOTIFY_CHANGE_ALL \
	(FILE_NOTIFY_CHANGE_FILE_NAME   | FILE_NOTIFY_CHANGE_DIR_NAME | \
	 FILE_NOTIFY_CHANGE_ATTRIBUTES  | FILE_NOTIFY_CHANGE_SIZE | \
	 FILE_NOTIFY_CHANGE_LAST_WRITE  | FILE_NOTIFY_CHANGE_LAST_ACCESS | \
	 FILE_NOTIFY_CHANGE_CREATION    | FILE_NOTIFY_CHANGE_EA | \
	 FILE_NOTIFY_CHANGE_SECURITY	| FILE_NOTIFY_CHANGE_STREAM_NAME | \
	 FILE_NOTIFY_CHANGE_STREAM_SIZE | FILE_NOTIFY_CHANGE_STREAM_WRITE)

/* change notify action results */
#define NOTIFY_ACTION_ADDED 1
#define NOTIFY_ACTION_REMOVED 2
#define NOTIFY_ACTION_MODIFIED 3
#define NOTIFY_ACTION_OLD_NAME 4
#define NOTIFY_ACTION_NEW_NAME 5
#define NOTIFY_ACTION_ADDED_STREAM 6
#define NOTIFY_ACTION_REMOVED_STREAM 7
#define NOTIFY_ACTION_MODIFIED_STREAM 8

enum {
	X_SMB2_OPLOCK_LEVEL_NONE = 0x00,
	X_SMB2_OPLOCK_LEVEL_II = 0x01,
	X_SMB2_OPLOCK_LEVEL_EXCLUSIVE = 0x08,
	X_SMB2_OPLOCK_LEVEL_BATCH = 0x09,
	X_SMB2_OPLOCK_LEVEL_LEASE = 0xFF,
};

enum {
	X_SMB2_LEASE_NONE = 0x0,
	X_SMB2_LEASE_READ = 0x01,
	X_SMB2_LEASE_HANDLE = 0x02,
	X_SMB2_LEASE_WRITE = 0x04,
};

enum {
	/* SMB2 lease flags */
	X_SMB2_LEASE_FLAG_BREAK_IN_PROGRESS =                0x00000002,
	X_SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET =             0x00000004,
};

enum {
	X_SMB2_CREATE_TAG_EXTA = 'ExtA',
	X_SMB2_CREATE_TAG_MXAC = 'MxAc',
	X_SMB2_CREATE_TAG_SECD = 'SecD',
	X_SMB2_CREATE_TAG_DHNQ = 'DHnQ',
	X_SMB2_CREATE_TAG_DHNC = 'DHnC',
	X_SMB2_CREATE_TAG_ALSI = 'AlSi',
	X_SMB2_CREATE_TAG_TWRP = 'TWrp',
	X_SMB2_CREATE_TAG_QFID = 'QFid',
	X_SMB2_CREATE_TAG_RQLS = 'RqLs',
	X_SMB2_CREATE_TAG_DH2Q = 'DH2Q',
	X_SMB2_CREATE_TAG_DH2C = 'DH2C',
	X_SMB2_CREATE_TAG_AAPL = 'AAPL',
};

struct x_smb2_uuid_t
{
	bool operator==(const x_smb2_uuid_t &other) const {
		return data[0] == other.data[0] && data[1] == other.data[1];
	}
	uint64_t data[2];
};

using x_smb2_uuid_bytes_t = std::array<uint8_t, 16>;

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

using x_smb2_lease_key_t = x_smb2_uuid_t;
struct x_smb2_lease_t
{
	x_smb2_lease_key_t key;
	uint32_t state;
	uint32_t flags;
	uint64_t duration;
	x_smb2_lease_key_t parent_key;
	uint16_t epoch;
	uint8_t version;
	uint8_t unused;
};

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

static inline x_buf_t *x_buf_alloc_out_buf(size_t body_size)
{
	return x_buf_alloc(8 + SMB2_HDR_BODY + body_size);
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

static inline x_bufref_t *x_bufref_alloc(size_t body_size)
{
	X_ASSERT(body_size + SMB2_HDR_BODY < 0x100000000ul);
	x_buf_t *out_buf = x_buf_alloc_out_buf(body_size);
	x_bufref_t *bufref = new x_bufref_t{out_buf, 8,
		x_convert_assert<uint32_t>(SMB2_HDR_BODY + body_size)};
	return bufref;
}

struct x_buflist_t
{
	void merge(x_buflist_t &other);
	void pop();
	x_bufref_t *head{}, *tail{};
};

bool x_smb2_signing_check(uint16_t dialect,
		const x_smb2_key_t *key,
		x_bufref_t *buflist);

void x_smb2_signing_sign(uint16_t dialect,
		const x_smb2_key_t *key,
		x_bufref_t *buflist);

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

NTSTATUS x_smb2_parse_stream_name(std::u16string &stream_name,
		bool &is_dollar_data,
		const char16_t *begin, const char16_t *end);

struct x_smb2_state_negprot_t
{
};

struct x_smb2_create_close_info_t
{
	idl::NTTIME out_create_ts;
	idl::NTTIME out_last_access_ts;
	idl::NTTIME out_last_write_ts;
	idl::NTTIME out_change_ts;
	uint64_t out_allocation_size{0};
	uint64_t out_end_of_file{0};
	uint32_t out_file_attributes{0};
};

struct x_smb2_file_standard_info_t
{
	uint64_t allocation_size;
	uint64_t end_of_file;
	uint32_t nlinks;
	uint8_t delete_pending;
	uint8_t directory;
	uint16_t unused{0};
};

struct x_smb2_file_basic_info_t
{
	idl::NTTIME creation;
	idl::NTTIME last_access;
	idl::NTTIME last_write;
	idl::NTTIME change;
	uint32_t file_attributes;
	uint32_t unused{0};
};

struct x_smb2_file_network_open_info_t
{
	idl::NTTIME creation;
	idl::NTTIME last_access;
	idl::NTTIME last_write;
	idl::NTTIME change;
	uint64_t allocation_size;
	uint64_t end_of_file;
	uint32_t file_attributes;
	uint32_t unused{0};
};

struct x_smb2_file_all_info_t
{
	x_smb2_file_basic_info_t basic_info;
	x_smb2_file_standard_info_t standard_info;
	uint64_t file_id;
	uint32_t ea_size;
	uint32_t access_flags;
	uint64_t current_offset;
	uint32_t mode;
	uint32_t alignment_requirement;
	uint32_t file_name_length;
	uint32_t unused;
};

struct x_smb2_file_normalized_name_info_t
{
	uint32_t name_length;
	char16_t name[];
} __attribute__ ((aligned (8))); /* windows server requires
				    in_output_buffer_length at lease 8 bytes */

struct x_smb2_rename_info_t
{
	uint8_t replace_if_exists;
	uint8_t unused0;
	uint16_t unused1;
	uint32_t unused2;
	uint32_t root_directory_low;
	uint32_t root_directory_high;
	uint32_t file_name_length;
	/* following variable length file_name */
};

struct x_smb2_file_alternate_name_info_t
{
	uint32_t name_length;
	char16_t name[];
} __attribute__ ((aligned (8)));

struct x_smb2_fs_volume_info_t
{
	uint64_t creation_time;
	uint32_t serial_number;
	uint32_t label_length;
	uint16_t unused;  //support_objects;
	char16_t label[];
} __attribute__ ((aligned (8)));

struct x_smb2_fs_size_info_t
{
	uint64_t allocation_size;
	uint64_t free_units;
	uint32_t sectors_per_unit;
	uint32_t bytes_per_sector;
};

struct x_smb2_fs_attr_info_t
{
	uint32_t attributes;
	uint32_t max_name_length;
	uint32_t label_length;
	char16_t label[];
} __attribute__ ((aligned (8)));

struct x_smb2_file_dir_info_t
{
	uint32_t next_offset;
	uint32_t file_index;
	idl::NTTIME creation;
	idl::NTTIME last_access;
	idl::NTTIME last_write;
	idl::NTTIME change;
	uint64_t end_of_file;
	uint64_t allocation_size;
	uint32_t file_attributes;
	uint32_t file_name_length;
	char16_t file_name[]; // variable length
} __attribute__ ((packed));

struct x_smb2_file_both_dir_info_t
{
	uint32_t next_offset;
	uint32_t file_index;
	idl::NTTIME creation;
	idl::NTTIME last_access;
	idl::NTTIME last_write;
	idl::NTTIME change;
	uint64_t end_of_file;
	uint64_t allocation_size;
	uint32_t file_attributes;
	uint32_t file_name_length;
	uint32_t ea_size;
	uint16_t short_name_length;
	char16_t short_name[12];
	char16_t file_name[]; // variable length
} __attribute__ ((packed));

struct x_smb2_file_full_dir_info_t
{
	uint32_t next_offset;
	uint32_t file_index;
	idl::NTTIME creation;
	idl::NTTIME last_access;
	idl::NTTIME last_write;
	idl::NTTIME change;
	uint64_t end_of_file;
	uint64_t allocation_size;
	uint32_t file_attributes;
	uint32_t file_name_length;
	uint32_t ea_size;
	char16_t file_name[]; // variable length
	/* not 8 bytes alignment, have to be packed */
} __attribute__ ((packed));

struct x_smb2_file_id_full_dir_info_t
{
	uint32_t next_offset;
	uint32_t file_index;
	idl::NTTIME creation;
	idl::NTTIME last_access;
	idl::NTTIME last_write;
	idl::NTTIME change;
	uint64_t end_of_file;
	uint64_t allocation_size;
	uint32_t file_attributes;
	uint32_t file_name_length;
	uint32_t ea_size;
	uint32_t unused0;
	uint64_t file_id;
	char16_t file_name[]; // variable length
} __attribute__ ((packed));

struct x_smb2_file_id_both_dir_info_t
{
	uint32_t next_offset;
	uint32_t file_index;
	idl::NTTIME creation;
	idl::NTTIME last_access;
	idl::NTTIME last_write;
	idl::NTTIME change;
	uint64_t end_of_file;
	uint64_t allocation_size;
	uint32_t file_attributes;
	uint32_t file_name_length;
	uint32_t ea_size;
	uint16_t short_name_length;
	char16_t short_name[12];
	uint16_t unused0;
	uint64_t file_id;
	char16_t file_name[]; // variable length
} __attribute__ ((packed));

struct x_smb2_file_names_info_t
{
	uint32_t next_offset;
	uint32_t file_index;
	uint32_t file_name_length;
	char16_t file_name[]; // variable length
} __attribute__ ((packed));

struct x_smb2_file_stream_name_info_t
{
	uint32_t next_offset;
	uint32_t name_length;
	uint64_t size;
	uint64_t allocation_size;
	char16_t name[]; // variable length
};

struct x_smb2_file_full_ea_info_t
{
	uint32_t next_offset;
	uint8_t flags;
	uint8_t name_length;
	uint16_t value_length;
};

struct x_smb2_file_object_id_buffer_t
{
	x_smb2_uuid_t object_id;
	x_smb2_uuid_t birth_volume_id;
	x_smb2_uuid_t birth_object_id;
	x_smb2_uuid_t domain_id;
};

bool x_smb2_file_standard_info_decode(x_smb2_file_standard_info_t &standard_info,
		const std::vector<uint8_t> &in_data);

bool x_smb2_file_basic_info_decode(x_smb2_file_basic_info_t &basic_info,
		const std::vector<uint8_t> &in_data);

NTSTATUS x_smb2_rename_info_decode(bool &replace_if_exists,
		std::u16string &path, std::u16string &stream_name,
		const std::vector<uint8_t> &in_data);

size_t x_smb2_notify_marshall(
		const std::vector<std::pair<uint32_t, std::u16string>> &notify_changes,
		uint8_t *buf, size_t max_offset);

uint16_t x_smb2_dialect_match(const std::vector<uint16_t> &sdialects,
		const uint16_t *dialects,
		size_t dialect_count);

struct x_smb2_chain_marshall_t
{
	uint8_t *pbase, *pend;
	uint32_t alignment;
	uint32_t last_begin{0}, last_end{0};
	uint8_t *get_begin(uint32_t rec_size) {
		uint32_t begin = last_end;
		if (last_end != 0) {
			begin = x_convert_assert<uint32_t>(x_pad_len(last_end, alignment));
		}
		if (pbase + begin + rec_size > pend) {
			return nullptr;
		}
		if (begin != last_end) {
			memset(pbase + last_end, 0, begin - last_end);
		}
		uint32_t *last_next = (uint32_t *)(pbase + last_begin);
		*last_next = X_H2LE32(begin - last_begin);
		last_begin = begin;
		last_end = begin + rec_size;
		return pbase + begin;
	}
	uint32_t get_size() const {
		return last_end;
	}
};

#endif /* __smb2__hxx__ */

