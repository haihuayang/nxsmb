
#ifndef __spnego__hxx__
#define __spnego__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "xdefines.h"
#include "include/asn1_wrap.hxx"
#include <gssapi/gssapi_spnego.h>
#include <asn1-common.h>
#include <der.h>
extern "C" {
#include "lib/asn1/spnego_asn1.h"
#include "lib/asn1/gssapi_asn1.h"
}
#include <vector>

X_ASN1_METHOD(NegotiationTokenWin)
X_ASN1_METHOD(NegotiationToken)
X_ASN1_METHOD(MechTypeList)
X_ASN1_METHOD(GSSAPIContextToken)

int x_spnego_decode_token(NegotiationToken &nt, const uint8_t *in_buf, size_t in_len);
int x_spnego_wrap_resp(decltype(NegTokenResp::accept_completed) *negResult,
		MechType *mt, void *mic_data,
		uint32_t mic_length, const std::vector<uint8_t> &subout,
		std::vector<uint8_t> &out);
int x_spnego_encode(const MechTypeList &mechTypes, std::vector<uint8_t> &out);

int x_spnego_wrap_gssapi(const std::vector<uint8_t> &spnego_data,
		std::vector<uint8_t> &out);

#endif /* __spnego__hxx__ */

