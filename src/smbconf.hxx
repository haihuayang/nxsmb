
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

static inline bool lpcfg_lanman_auth()
{
	return false;
}

static inline bool lpcfg_param_bool(void *service, const char *type, const char *option, bool default_v)
{
	return default_v;
}

static inline const char *lpcfg_netbios_name()
{
	return "HH360U";
}

static inline const char *lpcfg_workgroup()
{
	return "HHDOM2";
}

static inline const char *lpcfg_dnsdomain()
{
	return NULL;
}
	
#endif /* __smbconf__hxx__ */

