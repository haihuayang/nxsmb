
#include "misc.hxx"

void x_smbd_report_nt_status(NTSTATUS status, unsigned int line, const char *file)
{
	X_LOG(SMB, WARN, "error status 0x%x at %s:%d", status.v, file, line);
}

static const struct {
	int unix_error;
	NTSTATUS nt_error;
} unix_nt_errmap[] = {
	{ EAGAIN,       NT_STATUS_MORE_ENTRIES },
	{ EINTR,        NT_STATUS_MORE_ENTRIES },
	{ ENOBUFS,      NT_STATUS_MORE_ENTRIES },
#ifdef EWOULDBLOCK
	{ EWOULDBLOCK,  NT_STATUS_MORE_ENTRIES },
#endif
	{ EINPROGRESS,  NT_STATUS_MORE_PROCESSING_REQUIRED },
	{ EPERM,        NT_STATUS_ACCESS_DENIED },
	{ EACCES,       NT_STATUS_ACCESS_DENIED },
	{ ENOENT,       NT_STATUS_OBJECT_NAME_NOT_FOUND },
	{ ENOTDIR,      NT_STATUS_NOT_A_DIRECTORY },
	{ EIO,          NT_STATUS_IO_DEVICE_ERROR },
	{ EBADF,        NT_STATUS_INVALID_HANDLE },
	{ EINVAL,       NT_STATUS_INVALID_PARAMETER },
	{ EEXIST,       NT_STATUS_OBJECT_NAME_COLLISION},
	{ ENFILE,       NT_STATUS_TOO_MANY_OPENED_FILES },
	{ EMFILE,       NT_STATUS_TOO_MANY_OPENED_FILES },
	{ ENOSPC,       NT_STATUS_DISK_FULL },
	{ ENOTSOCK,     NT_STATUS_INVALID_HANDLE },
	{ EFAULT,       NT_STATUS_INVALID_PARAMETER },
	{ EMSGSIZE,     NT_STATUS_INVALID_BUFFER_SIZE },
	{ ENOMEM,       NT_STATUS_NO_MEMORY },
	{ EISDIR,       NT_STATUS_FILE_IS_A_DIRECTORY},
#ifdef EPIPE
	{ EPIPE,        NT_STATUS_CONNECTION_DISCONNECTED },
#endif
	{ EBUSY,        NT_STATUS_SHARING_VIOLATION },
	{ ENOSYS,	NT_STATUS_INVALID_SYSTEM_SERVICE },
#ifdef EOPNOTSUPP
	{ EOPNOTSUPP,   NT_STATUS_NOT_SUPPORTED},
#endif
	{ EMLINK,       NT_STATUS_TOO_MANY_LINKS },
	{ ENOSYS,       NT_STATUS_NOT_SUPPORTED },
#ifdef ELOOP
	{ ELOOP,        NT_STATUS_OBJECT_PATH_NOT_FOUND },
#endif
#ifdef ENODATA
	{ ENODATA,      NT_STATUS_NOT_FOUND },
#endif
#ifdef EFTYPE
	{ EFTYPE,       NT_STATUS_OBJECT_PATH_NOT_FOUND },
#endif
#ifdef EDQUOT
	{ EDQUOT,       NT_STATUS_DISK_FULL }, /* Windows apps need this, not NT_STATUS_QUOTA_EXCEEDED */
#endif
#ifdef ENOTEMPTY
	{ ENOTEMPTY,    NT_STATUS_DIRECTORY_NOT_EMPTY },
#endif
#ifdef EXDEV
	{ EXDEV,        NT_STATUS_NOT_SAME_DEVICE },
#endif
#ifdef EROFS
	{ EROFS,        NT_STATUS_MEDIA_WRITE_PROTECTED },
#endif
#ifdef ENAMETOOLONG
	{ ENAMETOOLONG, NT_STATUS_NAME_TOO_LONG },
#endif
#ifdef EFBIG
	{ EFBIG,        NT_STATUS_DISK_FULL },
#endif
#ifdef EADDRINUSE
	{ EADDRINUSE,   NT_STATUS_ADDRESS_ALREADY_ASSOCIATED},
#endif
#ifdef ENETUNREACH
	{ ENETUNREACH,  NT_STATUS_NETWORK_UNREACHABLE},
#endif
#ifdef EHOSTUNREACH
        { EHOSTUNREACH, NT_STATUS_HOST_UNREACHABLE},
#endif
#ifdef ECONNREFUSED
	{ ECONNREFUSED, NT_STATUS_CONNECTION_REFUSED},
#endif
#ifdef EADDRNOTAVAIL
	{ EADDRNOTAVAIL,NT_STATUS_ADDRESS_NOT_ASSOCIATED },
#endif
#ifdef ETIMEDOUT
	{ ETIMEDOUT,    NT_STATUS_IO_TIMEOUT},
#endif
#ifdef ESOCKTNOSUPPORT
	{ ESOCKTNOSUPPORT,NT_STATUS_INVALID_PARAMETER_MIX },
#endif
#ifdef EAFNOSUPPORT
	{ EAFNOSUPPORT,	NT_STATUS_INVALID_PARAMETER_MIX },
#endif
#ifdef ECONNABORTED
	{ ECONNABORTED, NT_STATUS_CONNECTION_ABORTED},
#endif
#ifdef ECONNRESET
	{ ECONNRESET,   NT_STATUS_CONNECTION_RESET},
#endif
#ifdef ENOPROTOOPT
	{ ENOPROTOOPT,	NT_STATUS_INVALID_PARAMETER_MIX },
#endif
#ifdef ENODEV
	{ ENODEV,	NT_STATUS_NO_SUCH_DEVICE },
#endif
#ifdef ENOATTR
	{ ENOATTR,      NT_STATUS_NOT_FOUND },
#endif
#ifdef ECANCELED
	{ ECANCELED,    NT_STATUS_CANCELLED},
#endif
#ifdef ENOTSUP
        { ENOTSUP,      NT_STATUS_NOT_SUPPORTED},
#endif

	{ 0, NT_STATUS_UNSUCCESSFUL }
};

/*********************************************************************
 Map an NT error code from a Unix error code.
*********************************************************************/
NTSTATUS x_map_nt_error_from_unix(int unix_error)
{
	/* Look through list */
	for (size_t i=0;i<X_ARRAY_SIZE(unix_nt_errmap);i++) {
		if (unix_nt_errmap[i].unix_error == unix_error) {
			return unix_nt_errmap[i].nt_error;
		}
	}

	/* Default return */
	return NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS x_map_nt_error_from_ndr_err(idl::x_ndr_err_code_t ndr_err)
{
	switch (ndr_err) {
		case idl::NDR_ERR_SUCCESS:
			return NT_STATUS_OK;
		case idl::NDR_ERR_BUFSIZE:
			return NT_STATUS_BUFFER_TOO_SMALL;
		case idl::NDR_ERR_TOKEN:
			return NT_STATUS_INTERNAL_ERROR;
		case idl::NDR_ERR_ALLOC:
			return NT_STATUS_NO_MEMORY;
		case idl::NDR_ERR_ARRAY_SIZE:
			return NT_STATUS_ARRAY_BOUNDS_EXCEEDED;
		case idl::NDR_ERR_INVALID_POINTER:
			return NT_STATUS_INVALID_PARAMETER_MIX;
		case idl::NDR_ERR_UNREAD_BYTES:
			return NT_STATUS_PORT_MESSAGE_TOO_LONG;
		default:
			break;
	}

	/* we should map all error codes to different status codes */
	return NT_STATUS_INVALID_PARAMETER;
}
