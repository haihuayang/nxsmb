
#ifndef __version__hxx__
#define __version__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

extern struct x_build_info_t {
	const char *version;
	const char *date;
	const char *build_type;
	const char *branch;
	const char *git_hash;
} g_build;

#endif /* __version__hxx__ */

