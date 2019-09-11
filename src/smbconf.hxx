
#ifndef __smbconf__hxx__
#define __smbconf__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

static inline size_t lp_smb2_max_credits()
{
	return 8192;
}

static inline size_t lp_smb2_max_trans()
{
	return 1024 * 1024;
}

static inline size_t lp_smb2_max_read()
{
	return 1024 * 1024;
}

static inline size_t lp_smb2_max_write()
{
	return 1024 * 1024;
}

#endif /* __smbconf__hxx__ */

