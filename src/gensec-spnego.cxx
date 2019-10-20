
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

// TODO
#define gensec_setting_bool(setting, mech, name, default_value) default_value

struct x_gensec_spnego_t : x_gensec_t
{
	using x_gensec_t::x_gensec_t;
	NTSTATUS update(const uint8_t *in_buf, size_t in_len,
			std::vector<uint8_t> &out);
	virtual NTSTATUS check_packet(const uint8_t *data, size_t data_len,
			const uint8_t *sig, size_t sig_len) override {
		X_ASSERT(false);
		return NT_STATUS_OK;
	}
	virtual NTSTATUS sign_packet(const uint8_t *data, size_t data_len,
			std::vector<uint8_t> &sig) override {
		X_ASSERT(false);
		return NT_STATUS_OK;
	}
	enum state_position_t {
		SERVER_START,
		CLIENT_START,
		SERVER_TARG,
		CLIENT_TARG,
		FALLBACK,
		DONE
	} state_position = SERVER_START;

	bool needs_mic_check = false;
	bool needs_mic_sign = false;
	bool done_mic_check = false;
	bool simulate_w2k = gensec_setting_bool(gensec_security->settings,
			"spnego", "simulate_w2k", false);
	std::vector<uint8_t> mech_types_blob;
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
X_ASN1_METHOD(MechTypeList)
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

	// const gss_OID oids[] = { &_gss_spnego_mskrb_mechanism_oid_desc, GSS_KRB5_MECHANISM, GSS_NTLM_MECHANISM };
	const gss_OID oids[] = { GSS_NTLM_MECHANISM };

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
	if (!err) {
		in_buf = (const uint8_t *)data.value;
		in_len = data.length;	
	}

	err = x_asn1_decode(nt, in_buf, in_len, NULL);
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

static x_gensec_t *match_mech_type(x_gensec_context_t *context, const NegTokenInit &ni, MechType *&mt_match)
{
	auto &mech_list = ni.mechTypes;
	for (unsigned int i = 0; i < mech_list.len; ++i) {
		MechType &mt = mech_list.val[i];
		if (oid_equal(mt, GSS_NTLM_MECHANISM)) {
			mt_match = &mt;
			return x_gensec_create_ntlmssp(context);
		}
		/* TODO
		if (oid_equal(mt, GSS_KRB5_MECHANISM)) {
			return GSS_KRB5_MECHANISM;
		}*/
	}
	return nullptr;
}

static NTSTATUS spnego_update_start(x_gensec_spnego_t &spnego, const NegotiationToken &nt_requ,
		std::vector<uint8_t> &out)
{
	if (nt_requ.element != NegotiationToken::choice_NegotiationToken_negTokenInit) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	const NegTokenInit &ni = nt_requ.u.negTokenInit;
	MechType *mt = NULL;
	x_gensec_t *subsec = match_mech_type(spnego.context, ni, mt);
	if (!subsec) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	int ret = x_asn1_encode(ni.mechTypes, spnego.mech_types_blob);
	spnego.subsec.reset(subsec);
	std::vector<uint8_t> subout;
	NTSTATUS status = subsec->update((uint8_t *)ni.mechToken->data, ni.mechToken->length, subout);

	NegotiationToken nt_resp;
	memset(&nt_resp, 0, sizeof nt_resp);
	nt_resp.element = NegotiationToken::choice_NegotiationToken_negTokenResp;

	NegTokenResp &nt = nt_resp.u.negTokenResp;
	auto negResult = (status == NT_STATUS_OK) ? NegTokenResp::accept_completed : NegTokenResp::accept_incomplete;

	nt.negResult = &negResult;
	nt.supportedMech = mt;
	heim_octet_string resp_token;
	resp_token.data = subout.data();
	resp_token.length = subout.size();
	nt.responseToken = &resp_token;

	spnego.state_position = x_gensec_spnego_t::SERVER_TARG;
	ret = x_asn1_encode(nt_resp, out);

	return status;
}

static NTSTATUS spnego_update_targ(x_gensec_spnego_t &spnego, const NegotiationToken &nt_requ,
		std::vector<uint8_t> &out)
{
	if (nt_requ.element != NegotiationToken::choice_NegotiationToken_negTokenResp) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	assert(spnego.subsec);

	const NegTokenResp &nt = nt_requ.u.negTokenResp;
	std::vector<uint8_t> subout;
	NTSTATUS status = spnego.subsec->update((uint8_t *)nt.responseToken->data, nt.responseToken->length, subout);

	if (status != NT_STATUS_OK) {
		return STATUS;
	}
	
	bool have_sign = spnego.subsec->have_feature(GENSEC_FEATURE_SIGN);
	if (spnego.simulate_w2k) {
		have_sign = false;
	}

	bool new_spnego = spnego.subsec->have_feature(GENSEC_FEATURE_NEW_SPNEGO);
	if (nt.mechListMIC) {
		new_spnego = true;
	}

	if (have_sign && new_spnego) {
		spnego.needs_mic_check = true;
		spnego.needs_mic_sign = true;
	}

	if (have_sign && nt.mechListMIC) {
		status = spnego.subsec->check_packet(
				spnego.mech_types_blob.data(),
				spnego.mech_types_blob.size(),
				(const uint8_t *)nt.mechListMIC->data,
				nt.mechListMIC->length);
		if (!NT_STATUS_IS_OK(status)) {
			return STATUS;
		}
		spnego.needs_mic_check = false;
		spnego.done_mic_check = true;

	}

	std::vector<uint8_t> mech_list_mic;
	if (spnego.needs_mic_sign) {
		status = spnego.subsec->sign_packet(
				spnego.mech_types_blob.data(),
				spnego.mech_types_blob.size(),
				mech_list_mic);
	}

	NegotiationToken nt_resp;
	memset(&nt_resp, 0, sizeof nt_resp);
	nt_resp.element = NegotiationToken::choice_NegotiationToken_negTokenResp;

	NegTokenResp &ntr = nt_resp.u.negTokenResp;
	auto negResult = (status == NT_STATUS_OK) ? NegTokenResp::accept_completed : NegTokenResp::accept_incomplete;

	ntr.negResult = &negResult;
	heim_octet_string resp_token, mic;
	resp_token.data = subout.data();
	resp_token.length = subout.size();
	ntr.responseToken = &resp_token;
	if (mech_list_mic.size()) {
		mic.data = mech_list_mic.data();
		mic.length = mech_list_mic.size();
		ntr.mechListMIC = &mic;
	}

	int ret = x_asn1_encode(nt_resp, out);

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
	} else if (state_position == x_gensec_spnego_t::SERVER_TARG) {
		NegotiationToken nt;
		int err = decode_token(nt, in_buf, in_len);
		if (err) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		NTSTATUS status = spnego_update_targ(*this, nt, out);
		x_asn1_free(nt);
		return status;
	}

	X_TODO;
	return NT_STATUS_OK;
}

