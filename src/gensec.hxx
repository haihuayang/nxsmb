
#ifndef __gensec__hxx__
#define __gensec__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "defines.hxx"
#include <vector>

struct x_gensec_t
{
	explicit x_gensec_t(x_gensec_context_t *context) : context(context) { }

	virtual ~x_gensec_t() { }
	virtual int update(const uint8_t *in_buf, size_t in_len,
			std::vector<uint8_t> &out) = 0;

	x_gensec_context_t *context;
};

struct x_gensec_mech_t
{
	x_oid_t oid;
	x_gensec_t *(*create)(x_gensec_context_t *context);
};

extern const x_gensec_mech_t x_gensec_mech_spnego;

#define OID_SPNEGO "1.3.6.1.5.5.2"
#define OID_NTLMSSP "1.3.6.1.4.1.311.2.2.10"
#define OID_KERBEROS5_OLD "1.2.840.48018.1.2.2"
#define OID_KERBEROS5 "1.2.840.113554.1.2.2"

#define ADS_IGNORE_PRINCIPAL "not_defined_in_RFC4178@please_ignore"


#endif /* __gensec__hxx__ */

