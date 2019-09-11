
#include "gensec.hxx"
#include <stdlib.h>
#include <string.h>
extern "C" {
#include "heimdal/lib/asn1/asn1-common.h"
#include "heimdal/lib/gssapi/gssapi/gssapi.h"
#include "heimdal/lib/gssapi/mech/gssapi_asn1.h"
#include "heimdal/lib/gssapi/spnego/spnego_locl.h"
#include "heimdal/lib/asn1/der.h"
#include "source4/heimdal/lib/gssapi/spnego/spnego_asn1.h"
}

struct x_gensec_spnego_t : x_gensec_t
{
	using x_gensec_t::x_gensec_t;
	int update(const uint8_t *in_buf, size_t in_len,
			std::vector<uint8_t> &out);
	enum state_position_t {
		SERVER_START,
		CLIENT_START,
		SERVER_TARG,
		CLIENT_TARG,
		FALLBACK,
		DONE
	} state_position;
};

static x_gensec_t *x_gensec_spnego_create(x_gensec_context_t *context)
{
	return new x_gensec_spnego_t(context);
};

const struct x_gensec_mech_t x_gensec_mech_spnego = {
	OID_SPNEGO,
	x_gensec_spnego_create,
};

static int add_mech(MechTypeList *mechtypelist, gss_OID mech_type)
{
	MechType mech;
	int ret;

	ret = der_get_oid((const unsigned char *)mech_type->elements, mech_type->length, &mech, NULL);
	if (ret)
		return ret;
	ret = add_MechTypeList(mechtypelist, &mech);
	free_MechType(&mech);
	return ret;
}

#define MY_ASN1_METHOD(type_name) \
static int my_asn1_encode(const type_name &arg, std::vector<uint8_t> &out) \
{ \
	size_t size = length_##type_name(&arg); \
	out.resize(size); \
	size_t consumed; \
	int ret = encode_##type_name(out.data() + size - 1, size, &arg, &consumed); \
	X_ASSERT(consumed == size); \
	return ret; \
}

MY_ASN1_METHOD(NegotiationTokenWin)
MY_ASN1_METHOD(GSSAPIContextToken)

#define MY_ASN1_ALLOC(x) do { (x) = decltype(x)(calloc(1, sizeof *(x))); } while (0)
static int x_gensec_spnego_create_negTokenInit(x_gensec_spnego_t *gensec, std::vector<uint8_t> &out)
{
	size_t size;
	GSSAPIContextToken ct;
	memset(&ct, 0, sizeof ct);
	const gss_OID oid = GSS_SPNEGO_MECHANISM;
	int ret = der_get_oid ((const unsigned char *)oid->elements, oid->length, &ct.thisMech, &size);
	X_ASSERT(ret == 0);

	NegotiationTokenWin spnego_token;
	memset(&spnego_token, 0, sizeof spnego_token);
	spnego_token.element = NegotiationTokenWin::choice_NegotiationTokenWin_negTokenInit;

	const gss_OID oids[] = { &_gss_spnego_mskrb_mechanism_oid_desc, GSS_KRB5_MECHANISM, GSS_NTLM_MECHANISM };

	for (auto const oid: oids) {
		ret = add_mech(&spnego_token.u.negTokenInit.mechTypes, oid);
		X_ASSERT(ret == 0);
	}
	MY_ASN1_ALLOC(spnego_token.u.negTokenInit.negHints);
	X_ASSERT(spnego_token.u.negTokenInit.negHints);
	MY_ASN1_ALLOC(spnego_token.u.negTokenInit.negHints->hintName);
	X_ASSERT(spnego_token.u.negTokenInit.negHints->hintName);
	*spnego_token.u.negTokenInit.negHints->hintName = strdup("not_defined_in_RFC4178@please_ignore");

	std::vector<uint8_t> spnego_data;
	ret = my_asn1_encode(spnego_token, spnego_data);
	X_ASSERT(ret == 0);


	ct.innerContextToken.data = spnego_data.data();
	ct.innerContextToken.length = spnego_data.size();

	ret = my_asn1_encode(ct, out);
	X_ASSERT(ret == 0);

	free_NegotiationTokenWin(&spnego_token);
	der_free_oid(&ct.thisMech);

	return 0;
}

int x_gensec_spnego_t::update(const uint8_t *in_buf, size_t in_len,
		std::vector<uint8_t> &out)
{
	if (state_position == x_gensec_spnego_t::SERVER_START) {
		if (in_len == 0) {
			return x_gensec_spnego_create_negTokenInit(this, out);
		}
	}
	X_TODO;
	return 0;
}

