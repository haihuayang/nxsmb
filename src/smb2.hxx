
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

/* SMB2 negotiate dialects */
enum {
	X_SMB2_DIALECT_000	= 0x0000 /* early beta dialect */,
	X_SMB2_DIALECT_202	= 0x0202,
	X_SMB2_DIALECT_210	= 0x0210,
	X_SMB2_DIALECT_222	= 0x0222,
	X_SMB2_DIALECT_224	= 0x0224,
	X_SMB2_DIALECT_300	= 0x0300,
	X_SMB2_DIALECT_302	= 0x0302,
	X_SMB2_DIALECT_310	= 0x0310,
	X_SMB2_DIALECT_311	= 0x0311,
	X_SMB2_DIALECT_2FF	= 0x02FF,
};

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
#define X_SMB2_OP_DECL(x) X_SMB2_OP_##x,
	X_SMB2_OP_ENUM
#undef X_SMB2_OP_DECL
	X_SMB2_OP_MAX
};

enum {
	X_SMB2_HDR_FLAG_REDIRECT		= 0x01,
	X_SMB2_HDR_FLAG_ASYNC			= 0x02,
	X_SMB2_HDR_FLAG_CHAINED			= 0x04,
	X_SMB2_HDR_FLAG_SIGNED			= 0x08,
	X_SMB2_HDR_FLAG_PRIORITY_MASK		= 0x70,
	X_SMB2_HDR_FLAG_DFS			= 0x10000000,
	X_SMB2_HDR_FLAG_REPLAY_OPERATION	= 0x20000000,
};

/* SMB2 negotiate security_mode */
enum {
	X_SMB2_NEGOTIATE_SIGNING_ENABLED	= 0x01,
	X_SMB2_NEGOTIATE_SIGNING_REQUIRED	= 0x02,
};

/* SMB2 global capabilities */
enum {
	X_SMB2_CAP_DFS			= 0x00000001,
	X_SMB2_CAP_LEASING		= 0x00000002 /* only in dialect >= 0x210 */,
	X_SMB2_CAP_LARGE_MTU		= 0x00000004 /* only in dialect >= 0x210 */,
	X_SMB2_CAP_MULTI_CHANNEL	= 0x00000008 /* only in dialect >= 0x222 */,
	X_SMB2_CAP_PERSISTENT_HANDLES	= 0x00000010 /* only in dialect >= 0x222 */,
	X_SMB2_CAP_DIRECTORY_LEASING	= 0x00000020 /* only in dialect >= 0x222 */,
	X_SMB2_CAP_ENCRYPTION		= 0x00000040 /* only in dialect >= 0x222 */,
};

/* Types of SMB2 Negotiate Contexts - only in dialect >= 0x310 */
enum {
	X_SMB2_PREAUTH_INTEGRITY_CAPABILITIES	= 0x0001,
	X_SMB2_ENCRYPTION_CAPABILITIES		= 0x0002,
	X_SMB2_COMPRESSION_CAPABILITIES		= 0x0003,
	X_SMB2_NETNAME_NEGOTIATE_CONTEXT_ID	= 0x0005,
	X_SMB2_TRANSPORT_CAPABILITIES		= 0x0006,
	X_SMB2_RDMA_TRANSFORM_CAPABILITIES	= 0x0007,
	X_SMB2_SIGNING_CAPABILITIES		= 0x0008,
	X_SMB2_POSIX_EXTENSIONS_AVAILABLE	= 0x0100,
};

/* Values for the SMB2_PREAUTH_INTEGRITY_CAPABILITIES Context (>= 0x310) */
enum {
	X_SMB2_PREAUTH_INTEGRITY_SHA512		= 0x0001,
};

/* Values for the SMB2_SIGNING_CAPABILITIES Context (>= 0x311) */
enum {
	X_SMB2_SIGNING_INVALID_ALGO	= 0xffff, /* only used internally */
	X_SMB2_SIGNING_MD5_SMB1		= 0xfffe, /* internally for SMB1 */
	X_SMB2_SIGNING_HMAC_SHA256	= 0x0000, /* default <= 0x210 */
	X_SMB2_SIGNING_AES128_CMAC	= 0x0001, /* default >= 0x224 */
	X_SMB2_SIGNING_AES128_GMAC	= 0x0002, /* only in dialect >= 0x311 */
};

/* Values for the SMB2_ENCRYPTION_CAPABILITIES Context (>= 0x311) */
enum {
	X_SMB2_ENCRYPTION_INVALID_ALGO	= 0xffff, /* only used internally */
	X_SMB2_ENCRYPTION_NONE		= 0x0000, /* only used internally */
	X_SMB2_ENCRYPTION_AES128_CCM	= 0x0001, /* only in dialect >= 0x224 */
	X_SMB2_ENCRYPTION_AES128_GCM	= 0x0002, /* only in dialect >= 0x311 */
	X_SMB2_ENCRYPTION_AES256_CCM	= 0x0003, /* only in dialect >= 0x311 */
	X_SMB2_ENCRYPTION_AES256_GCM	= 0x0004, /* only in dialect >= 0x311 */
};

/* SMB2 session (request) flags */
enum {
	X_SMB2_SESSION_FLAG_BINDING		= 0x01,
};

/* SMB2 session (response) flags */
enum {
	X_SMB2_SESSION_FLAG_IS_GUEST		= 0x0001,
	X_SMB2_SESSION_FLAG_IS_NULL		= 0x0002,
	X_SMB2_SESSION_FLAG_ENCRYPT_DATA	= 0x0004 /* in dialect >= 0x224 */,
};

/* SMB2 sharetype flags */
enum {
	X_SMB2_SHARE_TYPE_DISK		= 0x1,
	X_SMB2_SHARE_TYPE_PIPE		= 0x2,
	X_SMB2_SHARE_TYPE_PRINT		= 0x3,
};

/* SMB2 share flags */
enum {
	X_SMB2_SHAREFLAG_MANUAL_CACHING			= 0x0000,
	X_SMB2_SHAREFLAG_AUTO_CACHING			= 0x0010,
	X_SMB2_SHAREFLAG_VDO_CACHING			= 0x0020,
	X_SMB2_SHAREFLAG_NO_CACHING			= 0x0030,
	X_SMB2_SHAREFLAG_DFS				= 0x0001,
	X_SMB2_SHAREFLAG_DFS_ROOT			= 0x0002,
	X_SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS	= 0x0100,
	X_SMB2_SHAREFLAG_FORCE_SHARED_DELETE		= 0x0200,
	X_SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING	= 0x0400,
	X_SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM	= 0x0800,
	X_SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCKS		= 0x1000,
	X_SMB2_SHAREFLAG_ENABLE_HASH_V1			= 0x2000,
	X_SMB2_SHAREFLAG_ENABLE_HASH_V2			= 0x4000,
	X_SMB2_SHAREFLAG_ENCRYPT_DATA			= 0x8000,
	X_SMB2_SHAREFLAG_ALL				= 0xFF33,
};

/* SMB2 share capabilities */
enum {
	X_SMB2_SHARE_CAP_DFS				= 0x8,
	X_SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY	= 0x10 /* in dialect >= 0x222 */,
	X_SMB2_SHARE_CAP_SCALEOUT			= 0x20 /* in dialect >= 0x222 */,
	X_SMB2_SHARE_CAP_CLUSTER			= 0x40 /* in dialect >= 0x222 */,
	X_SMB2_SHARE_CAP_ASYMMETRIC			= 0x80 /* in dialect >= 0x302 */,
};

enum {
	X_SMB2_FILE_ATTRIBUTE_READONLY		= 0x0001u,
	X_SMB2_FILE_ATTRIBUTE_HIDDEN		= 0x0002u,
	X_SMB2_FILE_ATTRIBUTE_SYSTEM		= 0x0004u,
	X_SMB2_FILE_ATTRIBUTE_VOLUME		= 0x0008u,
	X_SMB2_FILE_ATTRIBUTE_DIRECTORY		= 0x0010u,
	X_SMB2_FILE_ATTRIBUTE_ARCHIVE		= 0x0020u,
	X_SMB2_FILE_ATTRIBUTE_DEVICE		= 0x0040u,
	X_SMB2_FILE_ATTRIBUTE_NORMAL		= 0x0080u,
	X_SMB2_FILE_ATTRIBUTE_TEMPORARY		= 0x0100u,
	X_SMB2_FILE_ATTRIBUTE_SPARSE		= 0x0200u,
	X_SMB2_FILE_ATTRIBUTE_REPARSE_POINT	= 0x0400u,
	X_SMB2_FILE_ATTRIBUTE_COMPRESSED	= 0x0800u,
	X_SMB2_FILE_ATTRIBUTE_OFFLINE		= 0x1000u,
	X_SMB2_FILE_ATTRIBUTE_NONINDEXED	= 0x2000u,
	X_SMB2_FILE_ATTRIBUTE_ENCRYPTED		= 0x4000u,
	X_SMB2_FILE_ATTRIBUTE_ALL_MASK		= 0x7FFFu,

	/* TODO pretend supporting FILE_ATTRIBUTE_ENCRYPTED */
	X_NXSMB_FILE_ATTRIBUTE_MASK		= (X_SMB2_FILE_ATTRIBUTE_READONLY
			| X_SMB2_FILE_ATTRIBUTE_HIDDEN \
			| X_SMB2_FILE_ATTRIBUTE_SYSTEM
			| X_SMB2_FILE_ATTRIBUTE_OFFLINE \
			| X_SMB2_FILE_ATTRIBUTE_NORMAL \
			| X_SMB2_FILE_ATTRIBUTE_TEMPORARY
			| X_SMB2_FILE_ATTRIBUTE_ENCRYPTED),
};

/* ShareAccess field. */
enum {
	X_SMB2_FILE_SHARE_NONE		= 0 /* Cannot be used in bitmask. */,
	X_SMB2_FILE_SHARE_READ		= 1,
	X_SMB2_FILE_SHARE_WRITE		= 2,
	X_SMB2_FILE_SHARE_DELETE	= 4,
};

/* CreateOptions field. */
enum {
	X_SMB2_CREATE_OPTION_DIRECTORY_FILE		= 0x0001,
	X_SMB2_CREATE_OPTION_WRITE_THROUGH		= 0x0002,
	X_SMB2_CREATE_OPTION_SEQUENTIAL_ONLY		= 0x0004,
	X_SMB2_CREATE_OPTION_NO_INTERMEDIATE_BUFFERING	= 0x0008,
	X_SMB2_CREATE_OPTION_SYNCHRONOUS_IO_ALERT	= 0x0010   /* may be ignored */,
	X_SMB2_CREATE_OPTION_SYNCHRONOUS_IO_NONALERT	= 0x0020   /* may be ignored */,
	X_SMB2_CREATE_OPTION_NON_DIRECTORY_FILE		= 0x0040,
	X_SMB2_CREATE_OPTION_CREATE_TREE_CONNECTION	= 0x0080   /* ignore, should be zero */,
	X_SMB2_CREATE_OPTION_COMPLETE_IF_OPLOCKED	= 0x0100   /* ignore, should be zero */,
	X_SMB2_CREATE_OPTION_NO_EA_KNOWLEDGE		= 0x0200,
	X_SMB2_CREATE_OPTION_EIGHT_DOT_THREE_ONLY	= 0x0400 /* aka OPEN_FOR_RECOVERY: ignore, should be zero */,
	X_SMB2_CREATE_OPTION_RANDOM_ACCESS		= 0x0800,
	X_SMB2_CREATE_OPTION_DELETE_ON_CLOSE		= 0x1000,
	X_SMB2_CREATE_OPTION_OPEN_BY_FILE_ID		= 0x2000,
	X_SMB2_CREATE_OPTION_OPEN_FOR_BACKUP_INTENT	= 0x4000,
	X_SMB2_CREATE_OPTION_NO_COMPRESSION		= 0x8000,
	X_SMB2_CREATE_OPTION_RESERVER_OPFILTER		= 0x00100000    /* ignore, should be zero */,
	X_SMB2_CREATE_OPTION_OPEN_REPARSE_POINT		= 0x00200000,
	X_SMB2_CREATE_OPTION_OPEN_NO_RECALL		= 0x00400000,
	X_SMB2_CREATE_OPTION_OPEN_FOR_FREE_SPACE_QUERY	= 0x00800000 /* ignore should be zero */,
};

/* CreateDisposition field. */
enum x_smb2_create_disposition_t : uint32_t {
	SUPERSEDE	= 0 /* File exists overwrite/supersede. File not exist create. */,
	OPEN		= 1 /* File exists open. File not exist fail. */,
	CREATE		= 2 /* File exists fail. File not exist create. */,
	OPEN_IF		= 3 /* File exists open. File not exist create. */,
	OVERWRITE	= 4 /* File exists overwrite. File not exist fail. */,
	OVERWRITE_IF	= 5 /* File exists overwrite. File not exist create. */,
};

/* Responses when opening a file. */
enum x_smb2_create_action_t : uint32_t {
	WAS_SUPERSEDED	= 0,
	WAS_OPENED	= 1,
	WAS_CREATED	= 2,
	WAS_OVERWRITTEN	= 3,
};

enum {
	X_SMB2_CLOSE_FLAGS_FULL_INFORMATION	= 0x01,
};

/* 2.2.31 SMB2 IOCTL Request */
enum {
	X_SMB2_IOCTL_FLAG_IS_FSCTL	= 0x00000001,
};

enum {
	X_SMB2_FSCTL_DFS_GET_REFERRALS			= 0x00060194,
	X_SMB2_FSCTL_DFS_GET_REFERRALS_EX		= 0x000601B0,
	X_SMB2_FSCTL_SET_REPARSE_POINT			= 0x000900A4,
	X_SMB2_FSCTL_CREATE_OR_GET_OBJECT_ID		= 0x000900C0,
	X_SMB2_FSCTL_FILE_LEVEL_TRIM			= 0x00098208,
	X_SMB2_FSCTL_PIPE_PEEK				= 0x0011400C,
	X_SMB2_FSCTL_PIPE_WAIT				= 0x00110018,
	X_SMB2_FSCTL_PIPE_TRANSCEIVE			= 0x0011C017,
	X_SMB2_FSCTL_SRV_COPYCHUNK			= 0x001440F2,
	X_SMB2_FSCTL_SRV_ENUMERATE_SNAPSHOTS		= 0x00144064,
	X_SMB2_FSCTL_SRV_REQUEST_RESUME_KEY		= 0x00140078,
	X_SMB2_FSCTL_SRV_READ_HASH			= 0x001441bb,
	X_SMB2_FSCTL_SRV_COPYCHUNK_WRITE		= 0x001480F2,
	X_SMB2_FSCTL_LMR_REQUEST_RESILIENCY		= 0x001401D4,
	X_SMB2_FSCTL_QUERY_NETWORK_INTERFACE_INFO	= 0x001401FC,
	X_SMB2_FSCTL_VALIDATE_NEGOTIATE_INFO_224	= 0x00140200,
	X_SMB2_FSCTL_VALIDATE_NEGOTIATE_INFO		= 0x00140204,
};

/* flags for SMB2 find */
enum {
	X_SMB2_CONTINUE_FLAG_RESTART	= 0x01,
	X_SMB2_CONTINUE_FLAG_SINGLE	= 0x02,
	X_SMB2_CONTINUE_FLAG_INDEX	= 0x04,
	X_SMB2_CONTINUE_FLAG_REOPEN	= 0x10,
};

/* getinfo classes */
enum {
	X_SMB2_GETINFO_FILE		= 0x01,
	X_SMB2_GETINFO_FS		= 0x02,
	X_SMB2_GETINFO_SECURITY		= 0x03,
	X_SMB2_GETINFO_QUOTA		= 0x04,
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
	SMB2_FILE_INFO_FS_LABEL_INFORMATION = 2,
	SMB2_FILE_INFO_FS_SIZE_INFORMATION = 3,
	SMB2_FILE_INFO_FS_DEVICE_INFORMATION = 4,
	SMB2_FILE_INFO_FS_ATTRIBUTE_INFORMATION = 5,
	SMB2_FILE_INFO_FS_QUOTA_INFORMATION = 6,
	SMB2_FILE_INFO_FS_FULL_SIZE_INFORMATION = 7,
	SMB2_FILE_INFO_FS_OBJECTID_INFORMATION = 8,
	SMB2_FILE_INFO_FS_SECTOR_SIZE_INFORMATION = 11,
};

/* SMB2_FILE_INFO_FS_SECTOR_SIZE_INFORMATION values */
enum {
	X_SMB2_SSINFO_FLAGS_ALIGNED_DEVICE		= 0x00000001,
	X_SMB2_SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE	= 0x00000002,
	X_SMB2_SSINFO_FLAGS_NO_SEEK_PENALTY		= 0x00000004,
	X_SMB2_SSINFO_FLAGS_TRIM_ENABLED		= 0x00000008,
};

/* MS-FSCC 2.5.1 Filesystem Attributes. */
enum {
	X_SMB2_FS_ATTRIBUTE_FILE_CASE_SENSITIVE_SEARCH			= 0x00000001,
	X_SMB2_FS_ATTRIBUTE_FILE_CASE_PRESERVED_NAMES			= 0x00000002,
	X_SMB2_FS_ATTRIBUTE_FILE_UNICODE_ON_DISK			= 0x00000004,
	X_SMB2_FS_ATTRIBUTE_FILE_PERSISTENT_ACLS			= 0x00000008,
	X_SMB2_FS_ATTRIBUTE_FILE_FILE_COMPRESSION			= 0x00000010,
	X_SMB2_FS_ATTRIBUTE_FILE_VOLUME_QUOTAS				= 0x00000020,
	X_SMB2_FS_ATTRIBUTE_FILE_SUPPORTS_SPARSE_FILES			= 0x00000040,
	X_SMB2_FS_ATTRIBUTE_FILE_SUPPORTS_REPARSE_POINTS		= 0x00000080,
	X_SMB2_FS_ATTRIBUTE_FILE_SUPPORTS_REMOTE_STORAGE		= 0x00000100,
	X_SMB2_FS_ATTRIBUTE_FILE_VOLUME_IS_COMPRESSED			= 0x00008000,
	X_SMB2_FS_ATTRIBUTE_FILE_SUPPORTS_OBJECT_IDS			= 0x00010000,
	X_SMB2_FS_ATTRIBUTE_FILE_SUPPORTS_ENCRYPTION			= 0x00020000,
	X_SMB2_FS_ATTRIBUTE_FILE_NAMED_STREAMS				= 0x00040000,
	X_SMB2_FS_ATTRIBUTE_FILE_READ_ONLY_VOLUME			= 0x00080000,
	X_SMB2_FS_ATTRIBUTE_FILE_SEQUENTIAL_WRITE_ONCE			= 0x00100000,
	X_SMB2_FS_ATTRIBUTE_FILE_FILE_SUPPORTS_TRANSACTIONS		= 0x00200000,
	X_SMB2_FS_ATTRIBUTE_FILE_FILE_SUPPORTS_HARD_LINKS		= 0x00400000,
	X_SMB2_FS_ATTRIBUTE_FILE_FILE_SUPPORTS_EXTENDED_ATTRIBUTES	= 0x00800000,
	X_SMB2_FS_ATTRIBUTE_FILE_SUPPORTS_OPEN_BY_FILE_ID		= 0x01000000,
	X_SMB2_FS_ATTRIBUTE_FILE_SUPPORTS_USN_JOURNAL			= 0x02000000,
	X_SMB2_FS_ATTRIBUTE_FILE_SUPPORT_INTEGRITY_STREAMS		= 0x04000000,
	X_SMB2_FS_ATTRIBUTE_FILE_SUPPORTS_BLOCK_REFCOUNTING		= 0x08000000,
	X_SMB2_FS_ATTRIBUTE_FILE_SUPPORTS_SPARSE_VDL			= 0x10000000,
};

/* SMB_FS_DEVICE_INFORMATION device types. */
enum {
	X_SMB2_FILE_DEVICE_CD_ROM	= 0x2,
	X_SMB2_FILE_DEVICE_DISK		= 0x7,
};

/* SMB_FS_DEVICE_INFORMATION characteristics. */
enum {
	X_SMB2_FILE_REMOVABLE_MEDIA	= 0x001,
	X_SMB2_FILE_READ_ONLY_DEVICE	= 0x002,
	X_SMB2_FILE_FLOPPY_DISKETTE	= 0x004,
	X_SMB2_FILE_WRITE_ONCE_MEDIA	= 0x008,
	X_SMB2_FILE_REMOTE_DEVICE	= 0x010,
	X_SMB2_FILE_DEVICE_IS_MOUNTED	= 0x020,
	X_SMB2_FILE_VIRTUAL_VOLUME	= 0x040,
	X_SMB2_FILE_DEVICE_SECURE_OPEN	= 0x100,
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


/* SMB2 notify flags */
enum {
	X_SMB2_WATCH_TREE	= 0x0001,
};

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

/* SMB2 lock flags */
enum {
	X_SMB2_LOCK_FLAG_NONE			= 0x00000000,
	X_SMB2_LOCK_FLAG_SHARED			= 0x00000001,
	X_SMB2_LOCK_FLAG_EXCLUSIVE		= 0x00000002,
	X_SMB2_LOCK_FLAG_UNLOCK			= 0x00000004,
	X_SMB2_LOCK_FLAG_FAIL_IMMEDIATELY	= 0x00000010,
	X_SMB2_LOCK_FLAG_ALL_MASK		= 0x00000017,
};

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

/* SMB2 lease break flags */
enum {
	X_SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED	= 0x01,
};

/* SMB2 impersonation levels */
enum {
	X_SMB2_IMPERSONATION_ANONYMOUS		= 0x00,
	X_SMB2_IMPERSONATION_IDENTIFICATION	= 0x01,
	X_SMB2_IMPERSONATION_IMPERSONATION	= 0x02,
	X_SMB2_IMPERSONATION_DELEGATE		= 0x03,
	X_SMB2_IMPERSONATION_MAX
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
	return x_buf_alloc(8 + sizeof(x_smb2_header_t) + body_size);
}

static inline uint8_t *x_buf_get_out_hdr(x_buf_t *buf)
{
	X_ASSERT(buf->size >= sizeof(x_smb2_header_t) + 8);
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
	X_ASSERT(body_size + sizeof(x_smb2_header_t) < 0x100000000ul);
	x_buf_t *out_buf = x_buf_alloc_out_buf(body_size);
	x_bufref_t *bufref = new x_bufref_t{out_buf, 8,
		x_convert_assert<uint32_t>(sizeof(x_smb2_header_t) + body_size)};
	return bufref;
}

struct x_buflist_t
{
	void merge(x_buflist_t &other);
	void pop();
	x_bufref_t *head{}, *tail{};
};

bool x_smb2_signing_check(uint16_t algo,
		const x_smb2_key_t *key,
		x_bufref_t *buflist);

void x_smb2_signing_sign(uint16_t algo,
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

struct x_smb2_file_compression_info_t
{
	uint64_t file_size;
	uint16_t format;
	uint8_t unit_shift;
	uint8_t chunk_shift;
	uint8_t cluster_shift;
	uint8_t unused0;
	uint16_t unused1;
};

struct x_smb2_file_attribute_tag_info_t
{
	uint32_t file_attributes;
	uint32_t reparse_tag;
};

struct x_smb2_fs_volume_info_t
{
	uint64_t creation_time;
	uint32_t serial_number;
	uint32_t label_length;
	uint16_t unused;  //support_objects;
	char16_t label[];
} __attribute__ ((aligned (8)));

struct x_smb2_fs_label_info_t
{
	uint32_t label_length;
	char16_t label[];
} __attribute__ ((aligned (8)));

struct x_smb2_fs_size_info_t
{
	uint64_t allocation_size;
	uint64_t free_units;
	uint32_t sectors_per_unit;
	uint32_t bytes_per_sector;
};

struct x_smb2_fs_device_info_t
{
	uint32_t device_type;;
	uint32_t characteristics;
};

struct x_smb2_fs_attr_info_t
{
	uint32_t attributes;
	uint32_t max_name_length;
	uint32_t label_length;
	char16_t label[];
} __attribute__ ((aligned (8)));

struct x_smb2_fs_full_size_info_t
{
	uint64_t total_allocation_units;
	uint64_t caller_available_allocation_units;
	uint64_t actual_available_allocation_units;
	uint32_t sectors_per_allocation_unit;
	uint32_t bytes_per_sector;
};

struct x_smb2_fs_object_id_info_t
{
	uint8_t object_id[16];
	uint8_t extended_info[48];
};

struct x_smb2_fs_sector_size_info_t
{
	uint32_t logical_bytes_per_sector;
	uint32_t physical_bytes_per_sector_for_atomicity;
	uint32_t physical_bytes_per_sector_for_performance;
	uint32_t file_system_effective_physical_bytes_per_sector_for_atomicity;
	uint32_t flags;
	uint32_t byte_offset_for_sector_alignment;
	uint32_t byte_offset_for_partition_alignment;
};

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

