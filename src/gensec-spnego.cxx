
#include "smbd.hxx"
#include <stdlib.h>
#include <string.h>
#include "include/asn1_wrap.hxx"
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
	NTSTATUS update(const uint8_t *in_buf, size_t in_len,
			std::vector<uint8_t> &out);
	enum state_position_t {
		SERVER_START,
		CLIENT_START,
		SERVER_TARG,
		CLIENT_TARG,
		FALLBACK,
		DONE
	} state_position;

	std::unique_ptr<x_gensec_t> subsec{nullptr};
};

static x_gensec_t *x_gensec_spnego_create(x_gensec_context_t *context)
{
	return new x_gensec_spnego_t(context);
};

const struct x_gensec_mech_t x_gensec_mech_spnego = {
	GSS_SPNEGO_MECHANISM,
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

X_ASN1_METHOD(NegotiationTokenWin)
X_ASN1_METHOD(NegotiationToken)
X_ASN1_METHOD(GSSAPIContextToken)

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
	X_ASN1_ALLOC(spnego_token.u.negTokenInit.negHints);
	X_ASSERT(spnego_token.u.negTokenInit.negHints);
	X_ASN1_ALLOC(spnego_token.u.negTokenInit.negHints->hintName);
	X_ASSERT(spnego_token.u.negTokenInit.negHints->hintName);
	*spnego_token.u.negTokenInit.negHints->hintName = strdup("not_defined_in_RFC4178@please_ignore");

	std::vector<uint8_t> spnego_data;
	ret = x_asn1_encode(spnego_token, spnego_data);
	X_ASSERT(ret == 0);


	ct.innerContextToken.data = spnego_data.data();
	ct.innerContextToken.length = spnego_data.size();

	ret = x_asn1_encode(ct, out);
	X_ASSERT(ret == 0);

	free_NegotiationTokenWin(&spnego_token);
	der_free_oid(&ct.thisMech);

	return 0;
}

static int decode_token(NegotiationToken &nt, const uint8_t *in_buf, size_t in_len)
{
	gss_buffer_desc input{in_len, (void *)in_buf};
	gss_buffer_desc data;
	int err = gss_decapsulate_token(&input, GSS_SPNEGO_MECHANISM, &data);
	if (err) {
		return err;
	}

	err = x_asn1_decode(nt, (const uint8_t *)data.value, data.length, NULL);
	OM_uint32 minor_status;
	gss_release_buffer(&minor_status, &data);
	return err;
}

static bool oid_equal(const heim_oid &hoid, gss_const_OID goid)
{
	gss_OID_desc oid_flat;
	oid_flat.length = der_length_oid(&hoid);
	std::unique_ptr<uint8_t[]> ptr{new uint8_t[oid_flat.length]};
	oid_flat.elements = ptr.get();
	size_t size;
	X_ASSERT(0 == der_put_oid((unsigned char *)oid_flat.elements + oid_flat.length - 1,
				oid_flat.length, &hoid, &size));
	return gss_oid_equal(&oid_flat, goid);
}

static x_gensec_t *match_mech_type(x_gensec_context_t *context, const NegotiationToken &nt)
{
	auto &mech_list = nt.u.negTokenInit.mechTypes;
	for (unsigned int i = 0; i < mech_list.len; ++i) {
		const MechType &mt = mech_list.val[i];
		if (oid_equal(mt, GSS_NTLM_MECHANISM)) {
			return x_gensec_create_ntlmssp(context);
		}
		/* TODO
		if (oid_equal(mt, GSS_KRB5_MECHANISM)) {
			return GSS_KRB5_MECHANISM;
		}*/
	}
	return nullptr;
}

static NTSTATUS spnego_update_start(x_gensec_spnego_t &spnego, const NegotiationToken &nt,
		std::vector<uint8_t> &out)
{
	if (nt.element != NegotiationToken::choice_NegotiationToken_negTokenInit) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	const NegTokenInit &ni = nt.u.negTokenInit;
	x_gensec_t *subsec = match_mech_type(spnego.context, nt);
	if (!subsec) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	spnego.subsec.reset(subsec);
	std::vector<uint8_t> subout;
	NTSTATUS status = subsec->update((uint8_t *)ni.mechToken->data, ni.mechToken->length, subout);

	NegotiationToken resp;
	memset(&resp, 0, sizeof resp);
	resp.element = NegotiationToken::choice_NegotiationToken_negTokenResp;
	// resp.u.negTokenResp;


	return status;
}

NTSTATUS x_gensec_spnego_t::update(const uint8_t *in_buf, size_t in_len,
		std::vector<uint8_t> &out)
{
	if (state_position == x_gensec_spnego_t::SERVER_START) {
		if (in_len > 0) {
			NegotiationToken nt;
			int err = decode_token(nt, in_buf, in_len);
			if (err) {
				return NT_STATUS_INVALID_PARAMETER;
			}
			NTSTATUS status = spnego_update_start(*this, nt, out);
			x_asn1_free(nt);
			return status;
		} else {
			int err = x_gensec_spnego_create_negTokenInit(this, out);
			X_ASSERT(err == 0);
			return NT_STATUS_OK;
		}
	}

	X_TODO;
	return NT_STATUS_OK;
}

