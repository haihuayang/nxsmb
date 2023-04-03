
#include "smbd.hxx"
#include <stdlib.h>
#include <string.h>
#include "include/asn1_wrap.hxx"
#include <gssapi/gssapi_spnego.h>
#include <asn1-common.h>
#include <der.h>
extern "C" {
#include "lib/asn1/spnego_asn1.h"
#include "lib/asn1/gssapi_asn1.h"
}
#if 0
extern "C" {
#include "heimdal/lib/asn1/asn1-common.h"
#include "heimdal/lib/gssapi/gssapi/gssapi.h"
#include "heimdal/lib/gssapi/mech/gssapi_asn1.h"
#include "heimdal/lib/gssapi/spnego/spnego_locl.h"
#include "heimdal/lib/asn1/der.h"
#include "source4/heimdal/lib/gssapi/spnego/spnego_asn1.h"
}
#endif

// TODO
#define gensec_setting_bool(setting, mech, name, default_value) default_value

X_ASN1_METHOD(NegotiationTokenWin)
X_ASN1_METHOD(NegotiationToken)
X_ASN1_METHOD(MechTypeList)
X_ASN1_METHOD(GSSAPIContextToken)

static gss_OID_desc _gss_spnego_mskrb_mechanism_oid_desc =
	{ 9, (void *)"\x2a\x86\x48\x82\xf7\x12\x01\x02\x02" };

struct x_auth_spnego_t
{
	x_auth_spnego_t(x_auth_context_t *context, const x_auth_ops_t *ops);
	~x_auth_spnego_t() {
		if (subauth) {
			x_auth_destroy(subauth);
		}
		free_MechType(&mt_subauth);
		der_free_octet_string(&mechListMIC);
	}

	x_auth_t auth_base;
	x_auth_upcall_t this_auth_upcall;
	x_auth_upcall_t *up_auth_upcall{nullptr};

	enum state_position_t {
		SERVER_START,
		// CLIENT_START,
		SERVER_TARG,
		// CLIENT_TARG,
		// FALLBACK,
		DONE
	} state_position = SERVER_START;

	MechType mt_subauth{};
	heim_octet_string mechListMIC{};

	bool needs_mic_check = false;
	bool needs_mic_sign = false;
	bool done_mic_check = false;
	bool simulate_w2k = gensec_setting_bool(gensec_security->settings,
			"spnego", "simulate_w2k", false);
	std::vector<uint8_t> mech_types_blob;
	x_auth_t *subauth{nullptr};
};

static inline x_auth_spnego_t *auth_spnego_from_base(x_auth_t *base)
{
	return X_CONTAINER_OF(base, x_auth_spnego_t, auth_base);
}

static void spnego_wrap(NTSTATUS status, MechType *mt, void *mic_data,
		uint32_t mic_length, const std::vector<uint8_t> &subout,
		std::vector<uint8_t> &out)
{
	NegotiationToken nt_resp;
	memset(&nt_resp, 0, sizeof nt_resp);
	nt_resp.element = NegotiationToken::choice_NegotiationToken_negTokenResp;

	NegTokenResp &nt = nt_resp.u.negTokenResp;
	auto negResult = NT_STATUS_IS_OK(status) ? NegTokenResp::accept_completed : NegTokenResp::accept_incomplete;

	nt.negResult = &negResult;
	heim_octet_string resp_token, mic;
	if (subout.size() > 0) {
		resp_token.data = (void *)subout.data();
		resp_token.length = subout.size();
		nt.responseToken = &resp_token;
	}
	if (mic_length) {
		mic.data = mic_data;
		mic.length = mic_length;
		nt.mechListMIC = &mic;
	}

	if (mt) {
		nt.supportedMech = mt;
	}
	x_asn1_encode(nt_resp, out);
}

static NTSTATUS x_spnego_auth_start_return(x_auth_spnego_t *spnego, NTSTATUS status,
		std::vector<uint8_t>& subout, std::vector<uint8_t> &out)
{
	if (NT_STATUS_IS_OK(status) || NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		spnego_wrap(status, &spnego->mt_subauth, nullptr, 0, subout, out);
		if (NT_STATUS_IS_OK(status)) {
			spnego->state_position = x_auth_spnego_t::DONE;
		} else {
			spnego->state_position = x_auth_spnego_t::SERVER_TARG;
		}
	} else {
		out.clear();
		spnego->state_position = x_auth_spnego_t::DONE;
	}
	return status;
}

static NTSTATUS x_spnego_auth_targ_return(x_auth_spnego_t *spnego, NTSTATUS status,
		std::vector<uint8_t>& subout, std::vector<uint8_t> &out)
{
	if (NT_STATUS_IS_OK(status)) {
		bool have_sign = spnego->subauth->have_feature(GENSEC_FEATURE_SIGN);
		if (spnego->simulate_w2k) {
			have_sign = false;
		}

		bool new_spnego = spnego->subauth->have_feature(GENSEC_FEATURE_NEW_SPNEGO);
		if (spnego->mechListMIC.data) {
			new_spnego = true;
		}

		if (have_sign && new_spnego) {
			spnego->needs_mic_check = true;
			spnego->needs_mic_sign = true;
		}

		if (have_sign && spnego->mechListMIC.data) {
			status = spnego->subauth->check_packet(
					spnego->mech_types_blob.data(),
					spnego->mech_types_blob.size(),
					spnego->mech_types_blob.data(),
					spnego->mech_types_blob.size(),
					(const uint8_t *)spnego->mechListMIC.data,
					spnego->mechListMIC.length);
			if (!NT_STATUS_IS_OK(status)) {
				der_free_octet_string(&spnego->mechListMIC);
				return status;
			}
			spnego->needs_mic_check = false;
			spnego->done_mic_check = true;

		}

		std::vector<uint8_t> mech_list_mic;
		if (spnego->needs_mic_sign) {
			status = spnego->subauth->sign_packet(
					spnego->mech_types_blob.data(),
					spnego->mech_types_blob.size(),
					spnego->mech_types_blob.data(),
					spnego->mech_types_blob.size(),
					mech_list_mic);
		}

		spnego_wrap(status, nullptr, mech_list_mic.data(), x_convert_assert<uint32_t>(mech_list_mic.size()), subout, out);
		spnego->state_position = x_auth_spnego_t::DONE;
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		spnego_wrap(status, nullptr, nullptr, 0, subout, out);
	} else {
		out.clear();
		spnego->state_position = x_auth_spnego_t::DONE;
	}
	der_free_octet_string(&spnego->mechListMIC);
	return status;
}

static void x_spnego_auth_updated(x_auth_upcall_t *auth_upcall, NTSTATUS status,
		bool is_bind, uint8_t security_mode,
		std::vector<uint8_t> &sub_out_security,
		std::shared_ptr<x_auth_info_t> &auth_info)
{
	x_auth_spnego_t *spnego = X_CONTAINER_OF(auth_upcall, x_auth_spnego_t, this_auth_upcall);

	x_auth_upcall_t *up_auth_upcall = spnego->up_auth_upcall;
	spnego->up_auth_upcall = nullptr;

	std::vector<uint8_t> out_security;
	if (spnego->state_position == x_auth_spnego_t::SERVER_START) {
		status = x_spnego_auth_start_return(spnego, status, sub_out_security, out_security);
	} else {
		status = x_spnego_auth_targ_return(spnego, status, sub_out_security, out_security);
	}

	up_auth_upcall->updated(status, is_bind, security_mode,
			out_security, auth_info);
}

static const struct x_auth_cbs_t spnego_auth_upcall_cbs = {
	x_spnego_auth_updated,
};

x_auth_spnego_t::x_auth_spnego_t(x_auth_context_t *context, const x_auth_ops_t *ops)
	: auth_base{context, ops}
{
	this_auth_upcall.cbs = &spnego_auth_upcall_cbs;
}

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

static int x_auth_spnego_create_negTokenInit(std::vector<uint8_t> &out)
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
#if 1
	const gss_OID oids[] = { &_gss_spnego_mskrb_mechanism_oid_desc, GSS_KRB5_MECHANISM, GSS_NTLM_MECHANISM };
#else
	// disable kerberos
	const gss_OID oids[] = { GSS_NTLM_MECHANISM };
#endif
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
	oid_flat.length = x_convert_assert<uint32_t>(der_length_oid(&hoid));
	std::unique_ptr<uint8_t[]> ptr{new uint8_t[oid_flat.length]};
	oid_flat.elements = ptr.get();
	size_t size;
	X_ASSERT(0 == der_put_oid((unsigned char *)oid_flat.elements + oid_flat.length - 1,
				oid_flat.length, &hoid, &size));
	return gss_oid_equal(&oid_flat, goid);
}

static x_auth_t *match_mech_type(x_auth_context_t *context, const NegTokenInit &ni, MechType *&mt_match)
{
	auto &mech_list = ni.mechTypes;
	for (unsigned int i = 0; i < mech_list.len; ++i) {
		MechType &mt = mech_list.val[i];
		if (oid_equal(mt, GSS_NTLM_MECHANISM)) {
			mt_match = &mt;
			return x_auth_create_ntlmssp(context);
		} else if (oid_equal(mt, GSS_KRB5_MECHANISM) || oid_equal(mt, &_gss_spnego_mskrb_mechanism_oid_desc)) {
			mt_match = &mt;
			return x_auth_create_krb5(context);
		}
	}
	return nullptr;
}

static NTSTATUS spnego_update_start(x_auth_spnego_t *spnego, const NegotiationToken &nt_requ,
		bool is_bind, uint8_t security_mode,
		std::vector<uint8_t> &out, x_auth_upcall_t *auth_upcall,
		std::shared_ptr<x_auth_info_t> &auth_info)
{
	if (nt_requ.element != NegotiationToken::choice_NegotiationToken_negTokenInit) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	const NegTokenInit &ni = nt_requ.u.negTokenInit;
	MechType *mt = NULL;
	X_ASSERT(!spnego->subauth);
	spnego->subauth = match_mech_type(spnego->auth_base.context, ni, mt);
	if (!spnego->subauth) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	copy_MechType(mt, &spnego->mt_subauth);

	int ret = x_asn1_encode(ni.mechTypes, spnego->mech_types_blob);
	(void)ret; // TODO

	X_ASSERT(!spnego->up_auth_upcall);
	spnego->up_auth_upcall = auth_upcall;
	std::vector<uint8_t> subout;
	NTSTATUS status = spnego->subauth->update(
			(uint8_t *)ni.mechToken->data, ni.mechToken->length,
			is_bind, security_mode,
			subout, &spnego->this_auth_upcall, auth_info);

	if (NT_STATUS_EQUAL(status, X_NT_STATUS_INTERNAL_BLOCKED)) {
		return status;
	}

#if 0
	NegotiationToken nt_resp;
	memset(&nt_resp, 0, sizeof nt_resp);
	nt_resp.element = NegotiationToken::choice_NegotiationToken_negTokenResp;

	NegTokenResp &nt = nt_resp.u.negTokenResp;
	auto negResult = NT_STATUS_IS_OK(status) ? NegTokenResp::accept_completed : NegTokenResp::accept_incomplete;

	nt.negResult = &negResult;
	nt.supportedMech = mt;
	heim_octet_string resp_token;
	resp_token.data = subout.data();
	resp_token.length = subout.size();
	nt.responseToken = &resp_token;
	ret = x_asn1_encode(nt_resp, out);
#endif
	spnego->up_auth_upcall = nullptr;
	x_spnego_auth_start_return(spnego, status, subout, out);
	return status;
}

static NTSTATUS spnego_update_targ(x_auth_spnego_t *spnego, const NegotiationToken &nt_requ,
		bool is_bind, uint8_t security_mode,
		std::vector<uint8_t> &out, x_auth_upcall_t *auth_upcall,
		std::shared_ptr<x_auth_info_t> &auth_info)
{
	if (nt_requ.element != NegotiationToken::choice_NegotiationToken_negTokenResp) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	assert(spnego->subauth);

	const NegTokenResp &nt = nt_requ.u.negTokenResp;

	if (nt.mechListMIC) {
		der_copy_octet_string(nt.mechListMIC, &spnego->mechListMIC);
	}

	X_ASSERT(!spnego->up_auth_upcall);
	spnego->up_auth_upcall = auth_upcall;
	std::vector<uint8_t> subout;
	NTSTATUS status = spnego->subauth->update(
			(uint8_t *)nt.responseToken->data, nt.responseToken->length,
			is_bind, security_mode,
			subout, &spnego->this_auth_upcall, auth_info);

	if (NT_STATUS_EQUAL(status, X_NT_STATUS_INTERNAL_BLOCKED)) {
		return status;
	}

	spnego->up_auth_upcall = nullptr;
	return x_spnego_auth_targ_return(spnego, status, subout, out);
#if 0	
	bool have_sign = spnego->subauth->have_feature(GENSEC_FEATURE_SIGN);
	if (spnego->simulate_w2k) {
		have_sign = false;
	}

	bool new_spnego = spnego->subauth->have_feature(GENSEC_FEATURE_NEW_SPNEGO);
	if (nt.mechListMIC) {
		new_spnego = true;
	}

	if (have_sign && new_spnego) {
		spnego->needs_mic_check = true;
		spnego->needs_mic_sign = true;
	}

	if (have_sign && nt->mechListMIC) {
		status = spnego->subauth->check_packet(
				spnego->mech_types_blob.data(),
				spnego->mech_types_blob.size(),
				(const uint8_t *)nt.mechListMIC->data,
				nt.mechListMIC->length);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		spnego->needs_mic_check = false;
		spnego->done_mic_check = true;

	}

	std::vector<uint8_t> mech_list_mic;
	if (spnego.needs_mic_sign) {
		status = spnego.subauth->sign_packet(
				spnego.mech_types_blob.data(),
				spnego.mech_types_blob.size(),
				mech_list_mic);
	}

	NegotiationToken nt_resp;
	memset(&nt_resp, 0, sizeof nt_resp);
	nt_resp.element = NegotiationToken::choice_NegotiationToken_negTokenResp;

	NegTokenResp &ntr = nt_resp.u.negTokenResp;
	auto negResult = NT_STATUS_IS_OK(status) ? NegTokenResp::accept_completed : NegTokenResp::accept_incomplete;

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
#endif
}

static NTSTATUS spnego_update(x_auth_t *auth, const uint8_t *in_buf, size_t in_len,
		bool is_bind, uint8_t security_mode,
		std::vector<uint8_t> &out, x_auth_upcall_t *auth_upcall,
		std::shared_ptr<x_auth_info_t> &auth_info)
{
	x_auth_spnego_t *spnego = auth_spnego_from_base(auth);
	if (spnego->state_position == x_auth_spnego_t::SERVER_START) {
		if (in_len > 0) {
			NegotiationToken nt;
			int err = decode_token(nt, in_buf, in_len);
			if (err) {
				return NT_STATUS_INVALID_PARAMETER;
			}
			NTSTATUS status = spnego_update_start(spnego, nt,
					is_bind, security_mode,
					out, auth_upcall, auth_info);
			x_asn1_free(nt);
			return status;
		} else {
			int err = x_auth_spnego_create_negTokenInit(out);
			X_ASSERT(err == 0);
			return NT_STATUS_OK;
		}
	} else if (spnego->state_position == x_auth_spnego_t::SERVER_TARG) {
		NegotiationToken nt;
		int err = decode_token(nt, in_buf, in_len);
		if (err) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		NTSTATUS status = spnego_update_targ(spnego, nt,
				is_bind, security_mode,
				out, auth_upcall, auth_info);
		x_asn1_free(nt);
		return status;
	}

	X_TODO;
	return NT_STATUS_OK;
}

static void spnego_destroy(x_auth_t *auth)
{
	x_auth_spnego_t *spnego = auth_spnego_from_base(auth);
	delete spnego;
}

static bool spnego_have_feature(x_auth_t *auth, uint32_t feature)
{
	return false;
}

static NTSTATUS spnego_check_packet(x_auth_t *auth, const uint8_t *data, size_t data_len,
		const uint8_t *whole_pdu, size_t pdu_length,
		const uint8_t *sig, size_t sig_len)
{
	X_TODO;
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS spnego_sign_packet(x_auth_t *auth, const uint8_t *data, size_t data_len,
		const uint8_t *whole_pdu, size_t pdu_length,
		std::vector<uint8_t> &sig)
{
	X_TODO;
	return NT_STATUS_NOT_IMPLEMENTED;
}

static const x_auth_ops_t auth_spnego_ops = {
	spnego_update,
	spnego_destroy,
	spnego_have_feature,
	spnego_check_packet,
	spnego_sign_packet,
};

static x_auth_t *x_auth_spnego_create(x_auth_context_t *context)
{
	x_auth_spnego_t *spnego = new x_auth_spnego_t(context, &auth_spnego_ops);
	return &spnego->auth_base;
};

const struct x_auth_mech_t x_auth_mech_spnego = {
	GSS_SPNEGO_MECHANISM,
	x_auth_spnego_create,
};

int x_auth_spnego_init(x_auth_context_t *ctx)
{
	x_auth_register(ctx, &x_auth_mech_spnego);
	return 0;
}


