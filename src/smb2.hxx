
#ifndef __smb2__hxx__
#define __smb2__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

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

struct x_smb2_preauth_t
{
	std::array<char, 64> data{};
	void update(const void *data, size_t length);
};



#endif /* __smb2__hxx__ */

