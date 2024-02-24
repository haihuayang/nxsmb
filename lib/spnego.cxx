
#include "include/spnego.hxx"

int x_spnego_decode_token(NegotiationToken &nt, const uint8_t *in_buf, size_t in_len)
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

int x_spnego_wrap_resp(decltype(NegTokenResp::accept_completed) *negResult,
		MechType *mt, void *mic_data,
		uint32_t mic_length, const std::vector<uint8_t> &subout,
		std::vector<uint8_t> &out)
{
	NegotiationToken nt_resp;
	memset(&nt_resp, 0, sizeof nt_resp);
	nt_resp.element = NegotiationToken::choice_NegotiationToken_negTokenResp;

	NegTokenResp &nt = nt_resp.u.negTokenResp;

	nt.negResult = negResult;
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
	return 0;
}

int x_spnego_wrap_gssapi(const std::vector<uint8_t> &spnego_data,
		std::vector<uint8_t> &out)
{
	GSSAPIContextToken ct;
	memset(&ct, 0, sizeof ct);
	int ret;

	const gss_OID oid = GSS_SPNEGO_MECHANISM;
	size_t size;
	ret = der_get_oid ((const unsigned char *)oid->elements, oid->length, &ct.thisMech, &size);
	X_ASSERT(ret == 0);

	ct.innerContextToken.data = (void *)spnego_data.data();
	ct.innerContextToken.length = spnego_data.size();

	ret = x_asn1_encode(ct, out);
	X_ASSERT(ret == 0);

	der_free_oid(&ct.thisMech);
	return 0;
}

