
extern "C" {
#include "heimdal/lib/asn1/asn1-common.h"
#include "heimdal/lib/gssapi/gssapi/gssapi.h"
#include "heimdal/lib/gssapi/mech/gssapi_asn1.h"
#include "heimdal/lib/gssapi/spnego/spnego_locl.h"
#include "heimdal/lib/asn1/der.h"
#include "heimdal/lib/gssapi/spnego/spnego_asn1.h"
#include "heimdal/lib/ntlm/heimntlm.h"
#include "samba/libcli/util/hresult.h"
#include "samba/lib/util/samba_util.h"
#include "samba/lib/crypto/md5.h"
#include "samba/lib/crypto/arcfour.h"
#include "samba/lib/crypto/hmacmd5.h"
#include "samba/third_party/zlib/zlib.h"
#include "./samba/nsswitch/libwbclient/wbclient.h"

// #include "samba/auth/gensec/gensec.h"
}

#include <stdlib.h>
#include <string.h>

#undef max
#undef min

#include "smbd.hxx"
#include <cctype>
#include <algorithm>
#include "include/asn1_wrap.hxx"
#include "include/librpc/ntlmssp.hxx"
#include "include/charset.hxx"

#define DEBUG(...) do { } while (0)
#define dump_data_pw(...) do { } while (0)
#define dump_data(...) do { } while (0)

static uint32_t crc32_calc_buffer(const uint8_t *data, size_t size)
{
	uint32_t ret = crc32(0, Z_NULL, 0);
	return crc32(ret, data, size);
}

struct str_const_t {
	const uint8_t *data;
	size_t size;
};

struct x_ntlmssp_crypt_direction_t {
	uint32_t seq_num;
	uint8_t sign_key[16];
	struct arcfour_state seal_state;
};

struct x_auth_ntlmssp_t
{
	x_auth_ntlmssp_t(x_auth_context_t *context, const x_auth_ops_t *ops);
	// only server side for now
	bool is_server() const { return true; }

	x_wbcli_t wbcli;
	x_wbrequ_t wbrequ;
	x_wbresp_t wbresp;

	enum state_position_t {
		S_NEGOTIATE,
		S_AUTHENTICATE,
		S_CHECK_TRUSTED_DOMAIN,
		S_CHECK_PASSWORD,
		S_DONE
	} state_position{S_NEGOTIATE};

	x_auth_t auth; // base class
	x_auth_upcall_t *auth_upcall;

	// smbd_smb2_session_setup_send, should in base class
	uint32_t want_features = GENSEC_FEATURE_SESSION_KEY | GENSEC_FEATURE_UNIX_TOKEN;

	bool allow_lm_response;
	bool allow_lm_key;
	bool force_old_spnego;
	bool force_wrap_seal;
	bool is_standalone;
	bool unicode = false;
	bool doing_ntlm2 = false;
	bool new_spnego = false;
	uint32_t neg_flags;
	uint32_t required_flags = 0;

	std::array<uint8_t, 8> chal;
	std::u16string netbios_name, netbios_domain, dns_name, dns_domain;
	std::shared_ptr<idl::AV_PAIR_LIST> server_av_pair_list;

	std::string client_domain;
	std::string client_user;
	std::string client_workstation;
	std::shared_ptr<idl::LM_RESPONSE> client_lm_resp;
	std::shared_ptr<idl::DATA_BLOB> client_nt_resp;
	std::array<uint8_t, 16> encrypted_session_key;
	std::vector<uint8_t> session_key;
	std::vector<uint8_t> msg_negotiate, msg_challenge, msg_authenticate;

	/* for NTLM2, 0-sending, 1-receiving, while NTLM only uses 0 */
	x_ntlmssp_crypt_direction_t crypt_dirs[2];
};

#define AUTHORITY_MASK	(~(0xffffffffffffULL))

/* Convert a character string to a binary SID */
static char *dom_sid_parse(idl::dom_sid &sid, const char *str, char end)
{
	const char *p;
	char *q;
	uint64_t x;

	/* Sanity check for either "S-" or "s-" */

	if (!str
	    || (str[0]!='S' && str[0]!='s')
	    || (str[1]!='-')) {
		return false;
	}

	/* Get the SID revision number */

	p = str+2;
	x = (uint64_t)strtoul(p, &q, 10);
	if (x==0 || x > UINT8_MAX || !q || *q!='-') {
		return false;
	}
	sid.sid_rev_num = (uint8_t)x;

	/*
	 * Next the Identifier Authority.  This is stored big-endian in a
	 * 6 byte array. If the authority value is >= UINT_MAX, then it should
	 * be expressed as a hex value, according to MS-DTYP.
	 */
	p = q+1;
	x = strtoull(p, &q, 0);
	if (!q || *q!='-' || (x & AUTHORITY_MASK)) {
		return false;
	}
	sid.id_auth[5] = (x & 0x0000000000ffULL);
	sid.id_auth[4] = (x & 0x00000000ff00ULL) >> 8;
	sid.id_auth[3] = (x & 0x000000ff0000ULL) >> 16;
	sid.id_auth[2] = (x & 0x0000ff000000ULL) >> 24;
	sid.id_auth[1] = (x & 0x00ff00000000ULL) >> 32;
	sid.id_auth[0] = (x & 0xff0000000000ULL) >> 40;

	/* now read the the subauthorities */
	p = q +1;
	sid.num_auths = 0;
	while (sid.num_auths < sid.sub_auths.size()) {
		x = strtoull(p, &q, 10);
		if (p == q)
			break;
		if (x > UINT32_MAX) {
			return nullptr;
		}
		sid.sub_auths[sid.num_auths++] = x;

		if (*q != '-') {
			break;
		}
		p = q + 1;
	}

	/* IF we ended early, then the SID could not be converted */

	if (q && *q != end) {
		return nullptr;
	}

	return q;
}

static const uint8_t cli_sign_const[] = "session key to client-to-server signing key magic constant";
static const uint8_t cli_seal_const[] = "session key to client-to-server sealing key magic constant";
static const uint8_t srv_sign_const[] = "session key to server-to-client signing key magic constant";
static const uint8_t srv_seal_const[] = "session key to server-to-client sealing key magic constant";

/**
 * Some notes on the NTLM2 code:
 *
 * NTLM2 is a AEAD system.  This means that the data encrypted is not
 * all the data that is signed.  In DCE-RPC case, the headers of the
 * DCE-RPC packets are also signed.  This prevents some of the
 * fun-and-games one might have by changing them.
 *
 */

static void dump_arc4_state(const char *description,
			    struct arcfour_state *state)
{
	dump_data_pw(description, state->sbox, sizeof(state->sbox));
}

static void calc_ntlmv2_key(uint8_t subkey[16],
			    const uint8_t *session_key, size_t session_key_len,
			    const str_const_t &label)
{
	MD5_CTX ctx3;
	MD5Init(&ctx3);
	MD5Update(&ctx3, session_key, session_key_len);
	MD5Update(&ctx3, label.data, label.size);
	MD5Final(subkey, &ctx3);
}

enum ntlmssp_direction {
	NTLMSSP_SEND,
	NTLMSSP_RECEIVE
};

static std::array<uint8_t, 16> ntlmssp_make_packet_signature(x_auth_ntlmssp_t *ntlmssp,
					      const uint8_t *data, size_t length,
					      const uint8_t *whole_pdu, size_t pdu_length,
					      enum ntlmssp_direction direction,
					      bool encrypt_sig)
{
	std::array<uint8_t, 16> sig;
	if (ntlmssp->neg_flags & idl::NTLMSSP_NEGOTIATE_NTLM2) {
		HMACMD5Context ctx;
		uint8_t digest[16];
		uint8_t seq_num[4];

		auto &crypt = ntlmssp->crypt_dirs[direction];
		X_LOG_DBG("%s seq = %u, len = %u, pdu_len = %u\n",
					direction == 0 ? "SEND" : "RECV",
					crypt.seq_num,
					(unsigned int)length,
					(unsigned int)pdu_length);

		SIVAL(seq_num, 0, crypt.seq_num);
		crypt.seq_num++;
		hmac_md5_init_limK_to_64(crypt.sign_key, 16, &ctx);

		dump_data_pw("pdu data ", whole_pdu, pdu_length);

		hmac_md5_update(seq_num, sizeof(seq_num), &ctx);
		hmac_md5_update(whole_pdu, pdu_length, &ctx);
		hmac_md5_final(digest, &ctx);

		if (encrypt_sig && (ntlmssp->neg_flags & idl::NTLMSSP_NEGOTIATE_KEY_EXCH)) {
			arcfour_crypt_sbox(&crypt.seal_state, digest, 8);
		}

		SIVAL(sig.data(), 0, idl::NTLMSSP_SIGN_VERSION);
		memcpy(sig.data() + 4, digest, 8);
		memcpy(sig.data() + 12, seq_num, 4);

		dump_data_pw("ntlmssp v2 sig ", sig.data(), sig.size());

	} else {
		auto &crypt = ntlmssp->crypt_dirs[0];
		uint32_t crc = crc32_calc_buffer(data, length);
		SIVAL(sig.data(), 0, idl::NTLMSSP_SIGN_VERSION);
		SIVAL(sig.data(), 4, 0);
		SIVAL(sig.data(), 4, crc);
		SIVAL(sig.data(), 4, crypt.seq_num);

		crypt.seq_num++;

		dump_arc4_state("ntlmssp hash: \n",
				&crypt.seal_state);
		arcfour_crypt_sbox(&crypt.seal_state,
				   sig.data() + 4, sig.size() - 4);
	}
	return sig;
}

static NTSTATUS ntlmssp_sign_packet(x_auth_ntlmssp_t *ntlmssp,
		const uint8_t *data, size_t length,
		const uint8_t *whole_pdu, size_t pdu_length,
		std::vector<uint8_t> &sig)
{
	if (!(ntlmssp->neg_flags & idl::NTLMSSP_NEGOTIATE_SIGN)) {
		DEBUG(3, ("NTLMSSP Signing not negotiated - cannot sign packet!\n"));
		RETURN_ERR_NT_STATUS(NT_STATUS_INVALID_PARAMETER);
	}

	if (!ntlmssp->session_key.size()) {
		DEBUG(3, ("NO session key, cannot check sign packet\n"));
		RETURN_ERR_NT_STATUS(NT_STATUS_NO_USER_SESSION_KEY);
	}

	std::array<uint8_t, 16> tmp = ntlmssp_make_packet_signature(ntlmssp,
			data, length,
			whole_pdu, pdu_length,
			NTLMSSP_SEND, true);
	sig.assign(tmp.begin(), tmp.end());
	return NT_STATUS_OK;
}

/**
 * Check the signature of an incoming packet
 * @note caller *must* check that the signature is the size it expects
 *
 */

static NTSTATUS ntlmssp_check_packet(x_auth_ntlmssp_t *ntlmssp,
		const uint8_t *data, size_t length,
		const uint8_t *whole_pdu, size_t pdu_length,
		const uint8_t *sig, size_t sig_len)
{
	if (!ntlmssp->session_key.size()) {
		DEBUG(3, ("NO session key, cannot check packet signature\n"));
		RETURN_ERR_NT_STATUS(NT_STATUS_NO_USER_SESSION_KEY);
	}

	if (sig_len < 8) {
		DEBUG(0, ("NTLMSSP packet check failed due to short signature (%lu bytes)!\n",
			  (unsigned long)sig_len));
	}

	std::array<uint8_t, 16> local_sig = ntlmssp_make_packet_signature(ntlmssp,
						  data, length,
						  whole_pdu, pdu_length,
						  NTLMSSP_RECEIVE,
						  true);

	if (ntlmssp->neg_flags & idl::NTLMSSP_NEGOTIATE_NTLM2) {
		if (local_sig.size() != sig_len ||
		    memcmp(local_sig.data(), sig, sig_len) != 0) {
			DEBUG(5, ("BAD SIG NTLM2: wanted signature of\n"));
			dump_data(5, local_sig.data(), local_sig.size());

			DEBUG(5, ("BAD SIG: got signature of\n"));
			dump_data(5, sig, sig_len);

			DEBUG(0, ("NTLMSSP NTLM2 packet check failed due to invalid signature!\n"));
			RETURN_ERR_NT_STATUS(NT_STATUS_ACCESS_DENIED);
		}
	} else {
		if (local_sig.size() != sig_len ||
		    memcmp(local_sig.data() + 8, sig + 8, sig_len - 8) != 0) {
			DEBUG(5, ("BAD SIG NTLM1: wanted signature of\n"));
			dump_data(5, local_sig.data(), local_sig.size());

			DEBUG(5, ("BAD SIG: got signature of\n"));
			dump_data(5, sig, sig_len);

			DEBUG(0, ("NTLMSSP NTLM1 packet check failed due to invalid signature!\n"));
			RETURN_ERR_NT_STATUS(NT_STATUS_ACCESS_DENIED);
		}
	}
	dump_data_pw("checked ntlmssp signature\n", sig, sig_len);
	DEBUG(10,("ntlmssp_check_packet: NTLMSSP signature OK !\n"));

	return NT_STATUS_OK;
}

#if 0
/**
 * Seal data with the NTLMSSP algorithm
 *
 */

static NTSTATUS ntlmssp_seal_packet(struct ntlmssp_state *ntlmssp_state,
			     TALLOC_CTX *sig_mem_ctx,
			     uint8_t *data, size_t length,
			     const uint8_t *whole_pdu, size_t pdu_length,
			     DATA_BLOB *sig)
{
	if (!(ntlmssp->neg_flags & NTLMSSP_NEGOTIATE_SEAL)) {
		DEBUG(3, ("NTLMSSP Sealing not negotiated - cannot seal packet!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!(ntlmssp->neg_flags & NTLMSSP_NEGOTIATE_SIGN)) {
		DEBUG(3, ("NTLMSSP Sealing not negotiated - cannot seal packet!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!ntlmssp->session_key.length) {
		DEBUG(3, ("NO session key, cannot seal packet\n"));
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	DEBUG(10,("ntlmssp_seal_data: seal\n"));
	dump_data_pw("ntlmssp clear data\n", data, length);
	if (ntlmssp->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		NTSTATUS nt_status;
		/*
		 * The order of these two operations matters - we
		 * must first seal the packet, then seal the
		 * sequence number - this is because the
		 * send_seal_hash is not constant, but is is rather
		 * updated with each iteration
		 */
		nt_status = ntlmssp_make_packet_signature(ntlmssp_state,
							  sig_mem_ctx,
							  data, length,
							  whole_pdu, pdu_length,
							  NTLMSSP_SEND,
							  sig, false);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}

		arcfour_crypt_sbox(&ntlmssp_state->crypt->ntlm2.sending.seal_state,
				   data, length);
		if (ntlmssp->neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH) {
			arcfour_crypt_sbox(&ntlmssp_state->crypt->ntlm2.sending.seal_state,
					   sig->data+4, 8);
		}
	} else {
		NTSTATUS status;
		uint32_t crc;

		crc = crc32_calc_buffer(data, length);

		status = msrpc_gen(sig_mem_ctx,
			       sig, "dddd",
			       NTLMSSP_SIGN_VERSION, 0, crc,
			       ntlmssp_state->crypt->ntlm.seq_num);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		/*
		 * The order of these two operations matters - we
		 * must first seal the packet, then seal the
		 * sequence number - this is because the ntlmv1_arc4_state
		 * is not constant, but is is rather updated with
		 * each iteration
		 */

		dump_arc4_state("ntlmv1 arc4 state:\n",
				&ntlmssp_state->crypt->ntlm.seal_state);
		arcfour_crypt_sbox(&ntlmssp_state->crypt->ntlm.seal_state,
				   data, length);

		dump_arc4_state("ntlmv1 arc4 state:\n",
				&ntlmssp_state->crypt->ntlm.seal_state);

		arcfour_crypt_sbox(&ntlmssp_state->crypt->ntlm.seal_state,
				   sig->data+4, sig->length-4);

		ntlmssp_state->crypt->ntlm.seq_num++;
	}
	dump_data_pw("ntlmssp signature\n", sig->data, sig->length);
	dump_data_pw("ntlmssp sealed data\n", data, length);

	return NT_STATUS_OK;
}

/**
 * Unseal data with the NTLMSSP algorithm
 *
 */

NTSTATUS ntlmssp_unseal_packet(struct ntlmssp_state *ntlmssp_state,
			       uint8_t *data, size_t length,
			       const uint8_t *whole_pdu, size_t pdu_length,
			       const DATA_BLOB *sig)
{
	NTSTATUS status;
	if (!ntlmssp_state->session_key.length) {
		DEBUG(3, ("NO session key, cannot unseal packet\n"));
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	DEBUG(10,("ntlmssp_unseal_packet: seal\n"));
	dump_data_pw("ntlmssp sealed data\n", data, length);

	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		/* First unseal the data. */
		arcfour_crypt_sbox(&ntlmssp_state->crypt->ntlm2.receiving.seal_state,
				   data, length);
		dump_data_pw("ntlmv2 clear data\n", data, length);
	} else {
		arcfour_crypt_sbox(&ntlmssp_state->crypt->ntlm.seal_state,
				   data, length);
		dump_data_pw("ntlmv1 clear data\n", data, length);
	}
	status = ntlmssp_check_packet(ntlmssp_state,
				      data, length,
				      whole_pdu, pdu_length,
				      sig);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1,("NTLMSSP packet check for unseal failed due to invalid signature on %llu bytes of input:\n",
			 (unsigned long long)length));
	}
	return status;
}

NTSTATUS ntlmssp_wrap(struct ntlmssp_state *ntlmssp_state,
		      TALLOC_CTX *out_mem_ctx,
		      const DATA_BLOB *in,
		      DATA_BLOB *out)
{
	NTSTATUS nt_status;
	DATA_BLOB sig;

	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_SEAL) {
		if (in->length + NTLMSSP_SIG_SIZE < in->length) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		*out = data_blob_talloc(out_mem_ctx, NULL, in->length + NTLMSSP_SIG_SIZE);
		if (!out->data) {
			return NT_STATUS_NO_MEMORY;
		}
		memcpy(out->data + NTLMSSP_SIG_SIZE, in->data, in->length);

		nt_status = ntlmssp_seal_packet(ntlmssp_state, out_mem_ctx,
						out->data + NTLMSSP_SIG_SIZE,
						out->length - NTLMSSP_SIG_SIZE,
						out->data + NTLMSSP_SIG_SIZE,
						out->length - NTLMSSP_SIG_SIZE,
						&sig);

		if (NT_STATUS_IS_OK(nt_status)) {
			memcpy(out->data, sig.data, NTLMSSP_SIG_SIZE);
			talloc_free(sig.data);
		}
		return nt_status;

	} else if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_SIGN) {
		if (in->length + NTLMSSP_SIG_SIZE < in->length) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		*out = data_blob_talloc(out_mem_ctx, NULL, in->length + NTLMSSP_SIG_SIZE);
		if (!out->data) {
			return NT_STATUS_NO_MEMORY;
		}
		memcpy(out->data + NTLMSSP_SIG_SIZE, in->data, in->length);

		nt_status = ntlmssp_sign_packet(ntlmssp_state, out_mem_ctx,
						out->data + NTLMSSP_SIG_SIZE,
						out->length - NTLMSSP_SIG_SIZE,
						out->data + NTLMSSP_SIG_SIZE,
						out->length - NTLMSSP_SIG_SIZE,
						&sig);

		if (NT_STATUS_IS_OK(nt_status)) {
			memcpy(out->data, sig.data, NTLMSSP_SIG_SIZE);
			talloc_free(sig.data);
		}
		return nt_status;
	} else {
		*out = data_blob_talloc(out_mem_ctx, in->data, in->length);
		if (!out->data) {
			return NT_STATUS_NO_MEMORY;
		}
		return NT_STATUS_OK;
	}
}

NTSTATUS ntlmssp_unwrap(struct ntlmssp_state *ntlmssp_state,
			TALLOC_CTX *out_mem_ctx,
			const DATA_BLOB *in,
			DATA_BLOB *out)
{
	DATA_BLOB sig;

	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_SEAL) {
		if (in->length < NTLMSSP_SIG_SIZE) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		sig.data = in->data;
		sig.length = NTLMSSP_SIG_SIZE;

		*out = data_blob_talloc(out_mem_ctx, in->data + NTLMSSP_SIG_SIZE, in->length - NTLMSSP_SIG_SIZE);

		return ntlmssp_unseal_packet(ntlmssp_state,
					     out->data, out->length,
					     out->data, out->length,
					     &sig);

	} else if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_SIGN) {
		if (in->length < NTLMSSP_SIG_SIZE) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		sig.data = in->data;
		sig.length = NTLMSSP_SIG_SIZE;

		*out = data_blob_talloc(out_mem_ctx, in->data + NTLMSSP_SIG_SIZE, in->length - NTLMSSP_SIG_SIZE);

		return ntlmssp_check_packet(ntlmssp_state,
					    out->data, out->length,
					    out->data, out->length,
					    &sig);
	} else {
		*out = data_blob_talloc(out_mem_ctx, in->data, in->length);
		if (!out->data) {
			return NT_STATUS_NO_MEMORY;
		}
		return NT_STATUS_OK;
	}
}
#endif
/**
   Initialise the state for NTLMSSP signing.
*/
static void ntlmssp_sign_reset(x_auth_ntlmssp_t *ntlmssp,
			    bool reset_seqnums)
{
	DEBUG(3, ("NTLMSSP Sign/Seal - Initialising with flags:\n"));
	// debug_ntlmssp_flags(ntlmssp->neg_flags);

	if (ntlmssp->force_wrap_seal &&
			(ntlmssp->neg_flags & idl::NTLMSSP_NEGOTIATE_SIGN)) {
		/*
		 * We need to handle NTLMSSP_NEGOTIATE_SIGN as
		 * NTLMSSP_NEGOTIATE_SEAL if GENSEC_FEATURE_LDAP_STYLE
		 * is requested.
		 *
		 * The negotiation of flags (and authentication)
		 * is completed when ntlmssp_sign_init() is called
		 * so we can safely pretent NTLMSSP_NEGOTIATE_SEAL
		 * was negotiated.
		 */
		ntlmssp->neg_flags |= idl::NTLMSSP_NEGOTIATE_SEAL;
	}

	if (ntlmssp->neg_flags & idl::NTLMSSP_NEGOTIATE_NTLM2) {
		const uint8_t *weak_session_key_data = ntlmssp->session_key.data();
		size_t weak_session_key_size = ntlmssp->session_key.size();

		uint8_t seal_key[16];
		DATA_BLOB seal_blob = { seal_key, sizeof(seal_key) };

		struct {
			str_const_t sign_const;
			str_const_t seal_const;
		} send_recv_const[2];

#define ASSIGN_STR_CONST(name, str_const) \
	name = { str_const, sizeof(str_const) };
		if (ntlmssp->is_server()) {
			ASSIGN_STR_CONST(send_recv_const[0].sign_const, srv_sign_const);
			ASSIGN_STR_CONST(send_recv_const[0].seal_const, srv_seal_const);
			ASSIGN_STR_CONST(send_recv_const[1].sign_const, cli_sign_const);
			ASSIGN_STR_CONST(send_recv_const[1].seal_const, cli_seal_const);
		} else {
			ASSIGN_STR_CONST(send_recv_const[1].sign_const, srv_sign_const);
			ASSIGN_STR_CONST(send_recv_const[1].seal_const, srv_seal_const);
			ASSIGN_STR_CONST(send_recv_const[0].sign_const, cli_sign_const);
			ASSIGN_STR_CONST(send_recv_const[0].seal_const, cli_seal_const);
		}

		/*
		 * Weaken NTLMSSP keys to cope with down-level
		 * clients, servers and export restrictions.
		 *
		 * We probably should have some parameters to
		 * control this, once we get NTLM2 working.
		 *
		 * Key weakening was not performed on the master key
		 * for NTLM2, but must be done on the encryption subkeys only.
		 */

		if (ntlmssp->neg_flags & idl::NTLMSSP_NEGOTIATE_128) {
			/* nothing to do */
		} else if (ntlmssp->neg_flags & idl::NTLMSSP_NEGOTIATE_56) {
			weak_session_key_size = 7;
		} else { /* forty bits */
			weak_session_key_size = 5;
		}

		dump_data_pw("NTLMSSP weakend master key:\n",
			     weak_session_key_data,
			     weak_session_key_size);

		for (int i = 0; i < 2; ++i) {
			/* sign key */
			calc_ntlmv2_key(ntlmssp->crypt_dirs[i].sign_key,
					ntlmssp->session_key.data(), 
					ntlmssp->session_key.size(), 
					send_recv_const[i].sign_const);
			dump_data_pw("NTLMSSP sign key:\n",
					ntlmssp->crypt_dirs[i].sign_key, 16);

			/* seal ARCFOUR pad */
			calc_ntlmv2_key(seal_key,
					weak_session_key_data,
					weak_session_key_size,
					send_recv_const[i].seal_const);
			dump_data_pw("NTLMSSP seal key:\n",
					seal_key, 16);

			arcfour_init(&ntlmssp->crypt_dirs[i].seal_state,
					&seal_blob);

			dump_arc4_state("NTLMSSP seal arc4 state:\n",
					&ntlmssp->crypt_dirs[i].seal_state);

			/* seq num */
			if (reset_seqnums) {
				ntlmssp->crypt_dirs[i].seq_num = 0;
			}
		}
	} else {
		uint8_t weak_session_key[8];
		DATA_BLOB seal_session_key = {
			ntlmssp->session_key.data(),
			ntlmssp->session_key.size()
		};

		bool do_weak = false;

		DEBUG(5, ("NTLMSSP Sign/Seal - using NTLM1\n"));

		/*
		 * Key weakening not performed on the master key for NTLM2
		 * and does not occour for NTLM1. Therefore we only need
		 * to do this for the LM_KEY.
		 */
		if (ntlmssp->neg_flags & idl::NTLMSSP_NEGOTIATE_LM_KEY) {
			do_weak = true;
		}

		/*
		 * Nothing to weaken.
		 * We certainly don't want to 'extend' the length...
		 */
		if (seal_session_key.length < 16) {
			/* TODO: is this really correct? */
			do_weak = false;
		}

		if (do_weak) {
			memcpy(weak_session_key, seal_session_key.data, 8);
			seal_session_key = { weak_session_key, 8 };

			/*
			 * LM key doesn't support 128 bit crypto, so this is
			 * the best we can do. If you negotiate 128 bit, but
			 * not 56, you end up with 40 bit...
			 */
			if (ntlmssp->neg_flags & idl::NTLMSSP_NEGOTIATE_56) {
				weak_session_key[7] = 0xa0;
			} else { /* forty bits */
				weak_session_key[5] = 0xe5;
				weak_session_key[6] = 0x38;
				weak_session_key[7] = 0xb0;
			}
		}

		arcfour_init(&ntlmssp->crypt_dirs[0].seal_state,
			     &seal_session_key);

		dump_arc4_state("NTLMv1 arc4 state:\n",
				&ntlmssp->crypt_dirs[0].seal_state);

		if (reset_seqnums) {
			ntlmssp->crypt_dirs[0].seq_num = 0;
		}
	}
}

static void ntlmssp_sign_init(x_auth_ntlmssp_t *ntlmssp)
{
	if (ntlmssp->session_key.size() < 8) {
		DEBUG(3, ("NO session key, cannot intialise signing\n"));
		X_ASSERT(false);
	}

	ntlmssp_sign_reset(ntlmssp, true);
}

static bool ntlmssp_have_feature(x_auth_ntlmssp_t *ntlmssp, uint32_t feature)
{
	if (feature & GENSEC_FEATURE_SIGN) {
		if (!ntlmssp->session_key.size()) {
			return false;
		}
		if (ntlmssp->neg_flags & idl::NTLMSSP_NEGOTIATE_SIGN) {
			return true;
		}
	}
	if (feature & GENSEC_FEATURE_SEAL) {
		if (!ntlmssp->session_key.size()) {
			return false;
		}
		if (ntlmssp->neg_flags & idl::NTLMSSP_NEGOTIATE_SEAL) {
			return true;
		}
	}
	if (feature & GENSEC_FEATURE_SESSION_KEY) {
		if (ntlmssp->session_key.size()) {
			return true;
		}
	}
	if (feature & GENSEC_FEATURE_DCE_STYLE) {
		return true;
	}
	if (feature & GENSEC_FEATURE_ASYNC_REPLIES) {
		if (ntlmssp->neg_flags & idl::NTLMSSP_NEGOTIATE_NTLM2) {
			return true;
		}
	}
	if (feature & GENSEC_FEATURE_SIGN_PKT_HEADER) {
		return true;
	}
	if (feature & GENSEC_FEATURE_NEW_SPNEGO) {
		if (!ntlmssp->session_key.size()) {
			return false;
		}
		if (!(ntlmssp->neg_flags & idl::NTLMSSP_NEGOTIATE_SIGN)) {
			return false;
		}
		return ntlmssp->new_spnego;
	}

	return false;
}

static NTSTATUS ntlmssp_post_auth(x_auth_ntlmssp_t *ntlmssp, x_auth_info_t &auth_info, const x_wbresp_t &wbresp)
{
	if (wbresp.header.result != WINBINDD_OK) {
		RETURN_ERR_NT_STATUS(NT_STATUS_LOGON_FAILURE);
	}

	// wbc_create_auth_info
	const auto &auth = wbresp.header.data.auth;
	auth_info.user_flags = auth.info3.user_flgs;
	auth_info.account_name = auth.info3.user_name;
	auth_info.full_name = auth.info3.full_name;
	auth_info.logon_domain = auth.info3.logon_dom;
	auth_info.acct_flags = auth.info3.acct_flags;
#if 0
	memcpy(auth_info.user_session_key,
			auth.user_session_key,
			sizeof(auth_info.user_session_key));
	memcpy(auth_info.lm_session_key,
			auth.first_8_lm_hash,
			sizeof(auth_info.lm_session_key));
#endif
	auth_info.logon_count		= auth.info3.logon_count;
	auth_info.bad_password_count	= auth.info3.bad_pw_count;

	auth_info.logon_time		= x_unix_to_nttime(auth.info3.logon_time);
	auth_info.logoff_time		= x_unix_to_nttime(auth.info3.logoff_time);
	auth_info.kickoff_time		= x_unix_to_nttime(auth.info3.kickoff_time);
	auth_info.pass_last_set_time	= x_unix_to_nttime(auth.info3.pass_last_set_time);
	auth_info.pass_can_change_time	= x_unix_to_nttime(auth.info3.pass_can_change_time);
	auth_info.pass_must_change_time	= x_unix_to_nttime(auth.info3.pass_must_change_time);

	auth_info.logon_server	= auth.info3.logon_srv;
	auth_info.logon_script	= auth.info3.logon_script;
	auth_info.profile_path	= auth.info3.profile_path;
	auth_info.home_directory= auth.info3.home_dir;
	auth_info.home_drive	= auth.info3.dir_drive;

	idl::dom_sid domain_sid;
	if (!dom_sid_parse(domain_sid, auth.info3.dom_sid, '\0')) {
		/* WBC_ERR_INVALID_SID */
		RETURN_ERR_NT_STATUS(NT_STATUS_LOGON_FAILURE);
	}

	if (domain_sid.num_auths >= domain_sid.sub_auths.size() - 1) {
		/* WBC_ERR_INVALID_SID */
		RETURN_ERR_NT_STATUS(NT_STATUS_LOGON_FAILURE);
	}

	auth_info.domain_sid = domain_sid;
	auth_info.rid = auth.info3.user_rid;
	auth_info.primary_gid = auth.info3.group_rid;

	const auto &extra = wbresp.extra;
	if (extra.empty() || extra.back() != 0) {
		/* WBC_ERR_INVALID_RESPONSE */
		RETURN_ERR_NT_STATUS(NT_STATUS_LOGON_FAILURE);
	}
	const char *p = (const char *)extra.data(); 
	char *end;
	for (uint32_t j = 0; j < auth.info3.num_groups; ++j) {
		idl::samr_RidWithAttribute rid_with_attr;
		rid_with_attr.rid = strtoul(p, &end, 0);
		if (!end || *end != ':') {
			RETURN_ERR_NT_STATUS(NT_STATUS_LOGON_FAILURE);
		}
		p = end + 1;
		rid_with_attr.attributes = idl::samr_GroupAttrs(strtoul(p, &end, 0));
		if (!end || *end != '\n') {
			RETURN_ERR_NT_STATUS(NT_STATUS_LOGON_FAILURE);
		}
		p = end + 1;
		auth_info.group_rids.push_back(rid_with_attr);
	}

	for (uint32_t j=0; j < auth.info3.num_other_sids; j++) {
		x_dom_sid_with_attrs_t sid_attr;
		end = dom_sid_parse(sid_attr.sid, p, ':');
		if (!end) {
			RETURN_ERR_NT_STATUS(NT_STATUS_LOGON_FAILURE);
		}
		p = end + 1;
		sid_attr.attrs = strtoul(p, &end, 0);
		if (!end || *end != '\n') {
			RETURN_ERR_NT_STATUS(NT_STATUS_LOGON_FAILURE);
		}
		auth_info.other_sids.push_back(sid_attr);
	}
	// ntlmssp_server_postauth
	const uint8_t *session_key_data = nullptr;
	size_t session_key_length = 0;
	static const uint8_t zeros[16] = {0, };
	if (ntlmssp->doing_ntlm2) {
		X_TODO;
		if (memcmp(auth.user_session_key, zeros, 16) == 0) {
			X_LOG_DBG("user_session_key is zero");
		} else {

		}
	} else if ((ntlmssp->neg_flags & idl::NTLMSSP_NEGOTIATE_LM_KEY) && (!ntlmssp->client_nt_resp || ntlmssp->client_nt_resp->val.size() == 0x18)) {
		X_TODO;
		if (memcmp(auth.first_8_lm_hash, zeros, 8) == 0) {
			X_LOG_DBG("lm_session_key is zero");
		}
	} else if (memcmp(auth.user_session_key, zeros, 16) != 0) {
		session_key_data = (const uint8_t *)auth.user_session_key;
		session_key_length = 16;
	} else if (memcmp(auth.first_8_lm_hash, zeros, 8) != 0) {
		session_key_data = (const uint8_t *)auth.first_8_lm_hash;
		session_key_length = 8;
	} else {
		X_LOG_ERR("Failed to create unmodified session key.");
	}

	if ((ntlmssp->neg_flags & idl::NTLMSSP_NEGOTIATE_KEY_EXCH) != 0 && session_key_length == 16) {
		std::array<uint8_t, 16> tmp = ntlmssp->encrypted_session_key;
		arcfour_crypt(tmp.data(), session_key_data, 16);
		auth_info.session_key.assign(tmp.begin(), tmp.end());
	} else {
		auth_info.session_key.assign(session_key_data, session_key_data + session_key_length);
	}
	ntlmssp->session_key = auth_info.session_key;

	if (ntlmssp->new_spnego) {
		HMACMD5Context ctx;
		uint8_t mic_buffer[idl::NTLMSSP_MIC_SIZE] = { 0, };

		hmac_md5_init_limK_to_64(auth_info.session_key.data(),
					 auth_info.session_key.size(),
					 &ctx);

		hmac_md5_update(ntlmssp->msg_negotiate.data(),
				ntlmssp->msg_negotiate.size(),
				&ctx);
		hmac_md5_update(ntlmssp->msg_challenge.data(),
				ntlmssp->msg_challenge.size(),
				&ctx);

		/* checked were we set ntlmssp_state->new_spnego */
		X_ASSERT(ntlmssp->msg_authenticate.size() >
			   (idl::NTLMSSP_MIC_OFFSET + idl::NTLMSSP_MIC_SIZE));

		hmac_md5_update(ntlmssp->msg_authenticate.data(), idl::NTLMSSP_MIC_OFFSET, &ctx);
		hmac_md5_update(mic_buffer, idl::NTLMSSP_MIC_SIZE, &ctx);
		hmac_md5_update(ntlmssp->msg_authenticate.data() +
				(idl::NTLMSSP_MIC_OFFSET + idl::NTLMSSP_MIC_SIZE),
				ntlmssp->msg_authenticate.size() -
				(idl::NTLMSSP_MIC_OFFSET + idl::NTLMSSP_MIC_SIZE),
				&ctx);
		hmac_md5_final(mic_buffer, &ctx);

		if (memcmp(ntlmssp->msg_authenticate.data() + idl::NTLMSSP_MIC_OFFSET,
			     mic_buffer, idl::NTLMSSP_MIC_SIZE) != 0) {
#if 0
			DEBUG(1,("%s: invalid NTLMSSP_MIC for "
				 "user=[%s] domain=[%s] workstation=[%s]\n",
				 __func__,
				 ntlmssp_state->user,
				 ntlmssp_state->domain,
				 ntlmssp_state->client.netbios_name));
			dump_data(1, request.data + NTLMSSP_MIC_OFFSET,
				  NTLMSSP_MIC_SIZE);
			dump_data(1, mic_buffer,
				  NTLMSSP_MIC_SIZE);
#endif
			RETURN_ERR_NT_STATUS(NT_STATUS_INVALID_PARAMETER);
		}
	}

	if (ntlmssp_have_feature(ntlmssp, GENSEC_FEATURE_SIGN)) {
		ntlmssp_sign_init(ntlmssp);
	}

	ntlmssp->state_position = x_auth_ntlmssp_t::S_DONE;
	return NT_STATUS_OK;
}

static void ntlmssp_check_password_cb_reply(x_wbcli_t *wbcli, int err)
{
	x_auth_ntlmssp_t *ntlmssp = X_CONTAINER_OF(wbcli, x_auth_ntlmssp_t, wbcli);
	X_ASSERT(ntlmssp->state_position == x_auth_ntlmssp_t::S_CHECK_PASSWORD);

	x_auth_upcall_t *auth_upcall = ntlmssp->auth_upcall;
	ntlmssp->auth_upcall = nullptr;
	if (err < 0) {
		std::vector<uint8_t> out_security;
		auth_upcall->updated(NT_STATUS_INTERNAL_ERROR, out_security, std::shared_ptr<x_auth_info_t>());
		return;
	}

	std::shared_ptr<x_auth_info_t> auth_info = std::make_shared<x_auth_info_t>();
	NTSTATUS status = ntlmssp_post_auth(ntlmssp, *auth_info, ntlmssp->wbresp);

	std::vector<uint8_t> out_security;
	auth_upcall->updated(status, out_security, auth_info);
}

static const x_wb_cbs_t ntlmssp_check_password_cbs = {
	ntlmssp_check_password_cb_reply,
};

static void ntlmssp_check_password(x_auth_ntlmssp_t &ntlmssp, bool trusted, x_auth_upcall_t *auth_upcall)
{
	std::string domain;
	if (trusted) {
		domain = ntlmssp.client_domain;
	} else {
		domain = x_convert_utf16_to_utf8(ntlmssp.netbios_name);
	}
	ntlmssp.state_position = x_auth_ntlmssp_t::S_CHECK_PASSWORD;
	// ntlmssp->

	/* check_winbind_security */
	auto &wbrequ = ntlmssp.wbrequ;
	memset(&wbrequ.header, 0, sizeof(wbrequ.header));
	wbrequ.header.cmd = WINBINDD_PAM_AUTH_CRAP;
	wbrequ.header.flags = WBFLAG_PAM_INFO3_TEXT |
		WBFLAG_PAM_USER_SESSION_KEY |
		WBFLAG_PAM_LMKEY;

	/* wbcCtxAuthenticateUserEx */
	auto &auth_crap = wbrequ.header.data.auth_crap;
	strncpy(auth_crap.user, ntlmssp.client_user.c_str(),
			sizeof(auth_crap.user)-1);
	if (!domain.empty()) {
		strncpy(auth_crap.domain, domain.c_str(),
				sizeof(auth_crap.domain)-1);
	}
	if (!ntlmssp.client_workstation.empty()) {
		strncpy(auth_crap.workstation,
				ntlmssp.client_workstation.c_str(),
				sizeof(auth_crap.workstation)-1);
	}

	auth_crap.logon_parameters = WBC_MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT |
		WBC_MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT;

	memcpy(auth_crap.chal, ntlmssp.chal.data(),
			sizeof(auth_crap.chal));

	if (ntlmssp.client_lm_resp) {
		auth_crap.lm_resp_len =
			std::min(ntlmssp.client_lm_resp->Response.size(), 
					sizeof(auth_crap.lm_resp));
		if (auth_crap.lm_resp_len) {
			memcpy(auth_crap.lm_resp,
					ntlmssp.client_lm_resp->Response.data(),
					auth_crap.lm_resp_len);
		}
	}

	if (ntlmssp.client_nt_resp) {
		auth_crap.nt_resp_len = ntlmssp.client_nt_resp->val.size();
		if (auth_crap.nt_resp_len > sizeof(auth_crap.nt_resp)) {
			wbrequ.extra = ntlmssp.client_nt_resp->val;
			wbrequ.header.flags |= WBFLAG_BIG_NTLMV2_BLOB;
			wbrequ.header.extra_len = wbrequ.extra.size();
			wbrequ.header.extra_data.data = (char *)wbrequ.extra.data();
		} else if (auth_crap.nt_resp_len > 0) {
			memcpy(auth_crap.nt_resp,
					ntlmssp.client_nt_resp->val.data(),
					auth_crap.nt_resp_len);
		}
	}

	ntlmssp.wbcli.cbs = &ntlmssp_check_password_cbs;
	ntlmssp.auth_upcall = auth_upcall;
	x_smbd_wbpool_request(&ntlmssp.wbcli);
}

static void ntlmssp_domain_info_cb_reply(x_wbcli_t *wbcli, int err)
{
	x_auth_ntlmssp_t *ntlmssp = X_CONTAINER_OF(wbcli, x_auth_ntlmssp_t, wbcli);
	X_ASSERT(ntlmssp->state_position == x_auth_ntlmssp_t::S_CHECK_TRUSTED_DOMAIN);

	x_auth_upcall_t *auth_upcall = ntlmssp->auth_upcall;
	ntlmssp->auth_upcall = nullptr;
	if (err < 0) {
		std::vector<uint8_t> out_security;
		auth_upcall->updated(NT_STATUS_INTERNAL_ERROR, out_security, std::shared_ptr<x_auth_info_t>());
		return;
	}

	const auto &domain_info = ntlmssp->wbresp.header.data.domain_info;
	X_LOG_DBG("err=%d, result=%d, name='%s', alt_name='%s', sid=%s, native_mode=%d, active_directory=%d, primary=%d", err, ntlmssp->wbresp.header.result,
			domain_info.name, domain_info.alt_name,
			domain_info.sid,
			domain_info.native_mode,
			domain_info.active_directory,
			domain_info.primary);

	bool is_trusted = err == 0 && ntlmssp->wbresp.header.result == WINBINDD_OK;

	ntlmssp_check_password(*ntlmssp, is_trusted, auth_upcall);
}

static const x_wb_cbs_t ntlmssp_domain_info_cbs = {
	ntlmssp_domain_info_cb_reply,
};

static void x_ntlmssp_is_trusted_domain(x_auth_ntlmssp_t &ntlmssp, x_auth_upcall_t *auth_upcall)
{
	ntlmssp.state_position = x_auth_ntlmssp_t::S_CHECK_TRUSTED_DOMAIN;
	auto &requ = ntlmssp.wbrequ.header;
	requ.cmd = WINBINDD_DOMAIN_INFO;
	strncpy(requ.domain_name, ntlmssp.client_domain.c_str(), sizeof(requ.domain_name) - 1);

	ntlmssp.wbcli.cbs = &ntlmssp_domain_info_cbs;
	ntlmssp.auth_upcall = auth_upcall;
	x_smbd_wbpool_request(&ntlmssp.wbcli);
}


x_auth_ntlmssp_t::x_auth_ntlmssp_t(x_auth_context_t *context, const x_auth_ops_t *ops)
	: auth{context, ops}
{
	wbcli.requ = &wbrequ;
	wbcli.resp = &wbresp;

	const auto smbd_conf = x_smbd_conf_get();
	// gensec_ntlmssp_server_start
	allow_lm_response = smbd_conf->lanman_auth;
	allow_lm_key = (allow_lm_response && lpcfg_param_bool(NULL, "ntlmssp_server", "allow_lm_key", false));
	force_old_spnego = lpcfg_param_bool(NULL, "ntlmssp_server", "force_old_spnego", false);

	neg_flags = idl::NTLMSSP_NEGOTIATE_NTLM | idl::NTLMSSP_NEGOTIATE_VERSION;
	if (lpcfg_param_bool(NULL, "ntlmssp_server", "128bit", true)) {
		neg_flags |= idl::NTLMSSP_NEGOTIATE_128;
	}

	if (lpcfg_param_bool(NULL, "ntlmssp_server", "56bit", true)) {
		neg_flags |= idl::NTLMSSP_NEGOTIATE_56;
	}

	if (lpcfg_param_bool(NULL, "ntlmssp_server", "keyexchange", true)) {
		neg_flags |= idl::NTLMSSP_NEGOTIATE_KEY_EXCH;
	}

	if (lpcfg_param_bool(NULL, "ntlmssp_server", "alwayssign", true)) {
		neg_flags |= idl::NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
	}

	if (lpcfg_param_bool(NULL, "ntlmssp_server", "ntlm2", true)) {
		neg_flags |= idl::NTLMSSP_NEGOTIATE_NTLM2;
	}

	if (allow_lm_key) {
		neg_flags |= idl::NTLMSSP_NEGOTIATE_LM_KEY;
	}

	if (lpcfg_param_bool(NULL, "ntlmssp_server", "keyexchange", true)) {
		neg_flags |= idl::NTLMSSP_NEGOTIATE_KEY_EXCH;
	}

	if (want_features & GENSEC_FEATURE_SESSION_KEY) {
		neg_flags |= idl::NTLMSSP_NEGOTIATE_SIGN;
	}
	if (want_features & GENSEC_FEATURE_SIGN) {
		neg_flags |= idl::NTLMSSP_NEGOTIATE_SIGN;
		/*
		 * We need to handle idl::NTLMSSP_NEGOTIATE_SIGN as
		 * idl::NTLMSSP_NEGOTIATE_SEAL if GENSEC_FEATURE_LDAP_STYLE
		 * is requested.
		 */
		force_wrap_seal = ((want_features & GENSEC_FEATURE_LDAP_STYLE) != 0);
	}

	if (want_features & GENSEC_FEATURE_SEAL) {
		neg_flags |= idl::NTLMSSP_NEGOTIATE_SIGN | idl::NTLMSSP_NEGOTIATE_SEAL;
	}

	/* TODO
	   if (role == ROLE_STANDALONE) {
	   ntlmssp_state->server.is_standalone = true;
	   } else {
	   ntlmssp_state->server.is_standalone = false;
	   }
	   */
	is_standalone = false;
	netbios_name = x_convert_utf8_to_utf16(smbd_conf->netbios_name);
	netbios_domain = x_convert_utf8_to_utf16(smbd_conf->workgroup);

	dns_domain = x_convert_utf8_to_utf16(smbd_conf->dns_domain);
	std::u16string tmp_dns_name = netbios_name;
	if (dns_domain.size()) {
		tmp_dns_name += u".";
		tmp_dns_name += dns_domain;
	}

	dns_name.resize(tmp_dns_name.size());
	std::transform(tmp_dns_name.begin(), tmp_dns_name.end(), dns_name.begin(),
			[](unsigned char c) { return std::tolower(c); });
	/* TODO
	   ntlmssp_state->neg_flags |= ntlmssp_state->required_flags;
	   ntlmssp_state->conf_flags = ntlmssp_state->neg_flags;
	   */
}
#if 0
const DATA_BLOB ntlmssp_version_blob(void)
{
	/*
	 * This is a simplified version of
	 *
	 * enum ndr_err_code err;
	 * struct ntlmssp_VERSION vers;
	 *
	 * ZERO_STRUCT(vers);
	 * vers.ProductMajorVersion = NTLMSSP_WINDOWS_MAJOR_VERSION_6;
	 * vers.ProductMinorVersion = NTLMSSP_WINDOWS_MINOR_VERSION_1;
	 * vers.ProductBuild = 0;
	 * vers.NTLMRevisionCurrent = NTLMSSP_REVISION_W2K3;
	 *
	 * err = ndr_push_struct_blob(&version_blob,
	 * 			ntlmssp_state,
	 * 			&vers,
	 * 			(ndr_push_flags_fn_t)ndr_push_ntlmssp_VERSION);
	 *
	 * if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
	 * 	data_blob_free(&struct_blob);
	 * 	return NT_STATUS_NO_MEMORY;
	 * }
	 */
	static const uint8_t version_buffer[8] = {
		NTLMSSP_WINDOWS_MAJOR_VERSION_6,
		NTLMSSP_WINDOWS_MINOR_VERSION_1,
		0x00, 0x00, /* product build */
		0x00, 0x00, 0x00, /* reserved */
		NTLMSSP_REVISION_W2K3
	};

	return data_blob_const(version_buffer, ARRAY_SIZE(version_buffer));
}
#endif
// ntlmssp_handle_neg_flags
static NTSTATUS handle_neg_flags(x_auth_ntlmssp_t &auth_ntlmssp,
		uint32_t flags, const char *name)
{
	uint32_t missing_flags = auth_ntlmssp.required_flags;
	if (flags & idl::NTLMSSP_NEGOTIATE_UNICODE) {
		auth_ntlmssp.neg_flags |= idl::NTLMSSP_NEGOTIATE_UNICODE;
		auth_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_OEM;
		auth_ntlmssp.unicode = true;
	} else {
		auth_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_UNICODE;
		auth_ntlmssp.neg_flags |= idl::NTLMSSP_NEGOTIATE_OEM;
		auth_ntlmssp.unicode = false;
	}

	/*
	 * NTLMSSP_NEGOTIATE_NTLM2 (NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
	 * has priority over NTLMSSP_NEGOTIATE_LM_KEY
	 */
	if (!(flags & idl::NTLMSSP_NEGOTIATE_NTLM2)) {
		auth_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_NTLM2;
	}

	if (auth_ntlmssp.neg_flags & idl::NTLMSSP_NEGOTIATE_NTLM2) {
		auth_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_LM_KEY;
	}

	if (!(flags & idl::NTLMSSP_NEGOTIATE_LM_KEY)) {
		auth_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_LM_KEY;
	}

	if (!(flags & idl::NTLMSSP_NEGOTIATE_ALWAYS_SIGN)) {
		auth_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
	}

	if (!(flags & idl::NTLMSSP_NEGOTIATE_128)) {
		auth_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_128;
	}

	if (!(flags & idl::NTLMSSP_NEGOTIATE_56)) {
		auth_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_56;
	}

	if (!(flags & idl::NTLMSSP_NEGOTIATE_KEY_EXCH)) {
		auth_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_KEY_EXCH;
	}

	if (!(flags & idl::NTLMSSP_NEGOTIATE_SIGN)) {
		auth_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_SIGN;
	}

	if (!(flags & idl::NTLMSSP_NEGOTIATE_SEAL)) {
		auth_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_SEAL;
	}

	if ((flags & idl::NTLMSSP_REQUEST_TARGET)) {
		auth_ntlmssp.neg_flags |= idl::NTLMSSP_REQUEST_TARGET;
	}

	missing_flags &= ~auth_ntlmssp.neg_flags;
	if (missing_flags != 0) {
		HRESULT hres = HRES_SEC_E_UNSUPPORTED_FUNCTION;
		NTSTATUS status = NT_STATUS(HRES_ERROR_V(hres));
#if 0
		DEBUG(1, ("%s: Got %s flags[0x%08x] "
			  "- possible downgrade detected! "
			  "missing_flags[0x%08x] - %s\n",
			  __func__, name,
			  (unsigned)flags,
			  (unsigned)missing_flags,
			  nt_errstr(status)));
		debug_ntlmssp_flags_raw(1, missing_flags);
		DEBUGADD(4, ("neg_flags[0x%08x]\n",
			     (unsigned)ntlmssp_state->neg_flags));
		debug_ntlmssp_flags_raw(4, ntlmssp_state->neg_flags);
#endif
		return status;
	}
	return NT_STATUS_OK;
}

static const uint32_t max_lifetime = 30 * 60 * 1000;
static inline NTSTATUS handle_negotiate(x_auth_ntlmssp_t &auth_ntlmssp,
		const uint8_t *in_buf, size_t in_len, std::vector<uint8_t> &out,
		x_auth_upcall_t *auth_upcall)
{
	// samba gensec_ntlmssp_server_negotiate
	idl::NEGOTIATE_MESSAGE nego_msg;
	idl::x_ndr_off_t ret = idl::x_ndr_pull(nego_msg, in_buf, in_len, 0);

	if (ret < 0) {
		RETURN_ERR_NT_STATUS(NT_STATUS_INVALID_PARAMETER);
	}

	NTSTATUS status = handle_neg_flags(auth_ntlmssp, nego_msg.NegotiateFlags, "negotiate");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	std::array<uint8_t, 8> cryptkey;
	generate_random_buffer(cryptkey.data(), cryptkey.size());

	uint32_t chal_flags = auth_ntlmssp.neg_flags;
	std::u16string target_name;

	if (nego_msg.NegotiateFlags & idl::NTLMSSP_REQUEST_TARGET) {
		chal_flags |= idl::NTLMSSP_NEGOTIATE_TARGET_INFO |
			idl::NTLMSSP_REQUEST_TARGET;
		if (auth_ntlmssp.is_standalone) {
			chal_flags |= idl::NTLMSSP_TARGET_TYPE_SERVER;
			target_name = auth_ntlmssp.netbios_name;
		} else {
			chal_flags |= idl::NTLMSSP_TARGET_TYPE_DOMAIN;
			target_name = auth_ntlmssp.netbios_domain;
		};
	}

	auth_ntlmssp.chal = cryptkey;
	// TODO auth_ntlmssp.internal_chal = cryptkey;

	idl::CHALLENGE_MESSAGE chal_msg;

	if (chal_flags & idl::NTLMSSP_NEGOTIATE_TARGET_INFO) {
		chal_msg.TargetInfo = std::make_shared<idl::AV_PAIR_LIST>();
		auto &av_pair_list = chal_msg.TargetInfo;
		idl::AV_PAIR pair;

		pair.set_AvId(idl::MsvAvNbDomainName);
		pair.Value.AvNbDomainName = target_name;
		av_pair_list->pair.push_back(std::move(pair));

		pair.set_AvId(idl::MsvAvNbComputerName);
		pair.Value.AvNbComputerName = auth_ntlmssp.netbios_name;
		av_pair_list->pair.push_back(std::move(pair));

		pair.set_AvId(idl::MsvAvDnsDomainName);
		pair.Value.AvDnsDomainName = auth_ntlmssp.dns_domain;
		av_pair_list->pair.push_back(std::move(pair));

		pair.set_AvId(idl::MsvAvDnsComputerName);
		pair.Value.AvDnsComputerName = auth_ntlmssp.dns_name;
		av_pair_list->pair.push_back(std::move(pair));

		if (auth_ntlmssp.force_old_spnego) {
			pair.set_AvId(idl::MsvAvTimestamp);
			pair.Value.AvTimestamp = x_tick_to_nttime(tick_now);
			av_pair_list->pair.push_back(std::move(pair));
		}

		pair.set_AvId(idl::MsvAvEOL);
		av_pair_list->pair.push_back(std::move(pair));

		auth_ntlmssp.server_av_pair_list = chal_msg.TargetInfo;
	}

	chal_msg.TargetName = std::make_shared<std::string>(x_convert_utf16_to_utf8(target_name));
	chal_msg.NegotiateFlags = idl::NEGOTIATE(chal_flags);
	chal_msg.ServerChallenge = cryptkey;

	ret = idl::x_ndr_push(chal_msg, out, 0);
#if 0
	{
		/* Marshal the packet in the right format, be it unicode or ASCII */
		const char *gen_string;
		const DATA_BLOB version_blob = ntlmssp_version_blob();

		if (ntlmssp_state->unicode) {
			gen_string = "CdUdbddBb";
		} else {
			gen_string = "CdAdbddBb";
		}

		status = msrpc_gen(out_mem_ctx, reply, gen_string,
			"NTLMSSP",
			idl::NTLMSSP_CHALLENGE,
			target_name,
			chal_flags,
			cryptkey, 8,
			0, 0,
			struct_blob.data, struct_blob.length,
			version_blob.data, version_blob.length);

		if (!NT_STATUS_IS_OK(status)) {
			data_blob_free(&struct_blob);
			return status;
		}

		if (DEBUGLEVEL >= 10) {
			struct CHALLENGE_MESSAGE *challenge = talloc(
				ntlmssp_state, struct CHALLENGE_MESSAGE);
			if (challenge != NULL) {
				challenge->NegotiateFlags = chal_flags;
				status = ntlmssp_pull_CHALLENGE_MESSAGE(
					reply, challenge, challenge);
				if (NT_STATUS_IS_OK(status)) {
					NDR_PRINT_DEBUG(CHALLENGE_MESSAGE,
							challenge);
				}
				TALLOC_FREE(challenge);
			}
		}
	}
#endif
	auth_ntlmssp.msg_negotiate.assign(in_buf, in_buf + in_len);
	auth_ntlmssp.msg_challenge = out;
	auth_ntlmssp.state_position = x_auth_ntlmssp_t::S_AUTHENTICATE;

	return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

static const idl::AV_PAIR *av_pair_find(const idl::AV_PAIR_LIST &av_pair_list, idl::ntlmssp_AvId avid)
{
	for (const auto &p: av_pair_list.pair) {
		if (p.AvId == avid) {
			return &p;
		}
	}
	return nullptr;
}

static inline NTSTATUS handle_authenticate(x_auth_ntlmssp_t &auth_ntlmssp,
		const uint8_t *in_buf, size_t in_len, std::vector<uint8_t> &out,
		x_auth_upcall_t *auth_upcall)
{
	/* TODO ntlmssp.idl, version & mic may not present,
	 * samba/auth/ntlmssp/ntlmssp_server.c ntlmssp_server_preauth try
	 * long format and fail back to short format */
	idl::AUTHENTICATE_MESSAGE msg;
	idl::x_ndr_off_t err = x_ndr_pull(msg, in_buf, in_len, 0);
	if (err < 0) {
		RETURN_ERR_NT_STATUS(NT_STATUS_INVALID_PARAMETER);
	}

	NTSTATUS status;
	if (msg.NegotiateFlags != 0) {
		status = handle_neg_flags(auth_ntlmssp, msg.NegotiateFlags, "authenticate");
		if (!NT_STATUS_IS_OK(status)){
			return status;
		}
	}

	if (msg.NtChallengeResponse && msg.NtChallengeResponse->val.size() > 0x18) {
		idl::NTLMv2_RESPONSE v2_resp;
		err = x_ndr_pull(v2_resp, msg.NtChallengeResponse->val.data(),
				msg.NtChallengeResponse->val.size(), 0);
		if (err < 0) {
			RETURN_ERR_NT_STATUS(NT_STATUS_INVALID_PARAMETER);
		}
		
		auto &server_av_pair_list = auth_ntlmssp.server_av_pair_list;
		if (server_av_pair_list) {
		       	if (v2_resp.Challenge.AvPairs.pair.size() < server_av_pair_list->pair.size()) {
				RETURN_ERR_NT_STATUS(NT_STATUS_INVALID_PARAMETER);
			}
			for (auto &av: auth_ntlmssp.server_av_pair_list->pair) {
				if (av.AvId == idl::MsvAvEOL) {
					continue;
				}

				auto cpair = av_pair_find(v2_resp.Challenge.AvPairs, av.AvId);
				if (cpair == nullptr) {
					RETURN_ERR_NT_STATUS(NT_STATUS_INVALID_PARAMETER);
				}

				if (false) {
				} else if (av.AvId == idl::MsvAvNbComputerName) {
					if (av.Value.AvNbComputerName != cpair->Value.AvNbComputerName) {
						RETURN_ERR_NT_STATUS(NT_STATUS_INVALID_PARAMETER);
					}
				} else if (av.AvId == idl::MsvAvNbDomainName) {
					if (av.Value.AvNbDomainName != cpair->Value.AvNbDomainName) {
						RETURN_ERR_NT_STATUS(NT_STATUS_INVALID_PARAMETER);
					}
				} else if (av.AvId == idl::MsvAvDnsComputerName) {
					if (av.Value.AvDnsComputerName != cpair->Value.AvDnsComputerName) {
						RETURN_ERR_NT_STATUS(NT_STATUS_INVALID_PARAMETER);
					}
				} else if (av.AvId == idl::MsvAvDnsDomainName) {
					if (av.Value.AvDnsDomainName != cpair->Value.AvDnsDomainName) {
						RETURN_ERR_NT_STATUS(NT_STATUS_INVALID_PARAMETER);
					}
				} else if (av.AvId == idl::MsvAvDnsTreeName) {
					if (av.Value.AvDnsTreeName != cpair->Value.AvDnsTreeName) {
						RETURN_ERR_NT_STATUS(NT_STATUS_INVALID_PARAMETER);
					}
				} else if (av.AvId == idl::MsvAvTimestamp) {
					if (av.Value.AvTimestamp.val != cpair->Value.AvTimestamp.val) {
						RETURN_ERR_NT_STATUS(NT_STATUS_INVALID_PARAMETER);
					}
				} else {
					/*
					 * This can't happen as we control
					 * ntlmssp_state->server.av_pair_list
					 */
					RETURN_ERR_NT_STATUS(NT_STATUS_INTERNAL_ERROR);
				}
			}
		}

		uint32_t av_flags = 0;
		for (auto &av: v2_resp.Challenge.AvPairs.pair) {
			if (av.AvId == idl::MsvAvEOL) {
				break;
			} else if (av.AvId == idl::MsvAvFlags) {
				av_flags = av.Value.AvFlags;
			}
		}
		/* mic presents if flag NTLMSSP_AVFLAG_MIC_IN_AUTHENTICATE_MESSAGE,
		 * but in idl it is unconditional, since the server always send
		 * target_info, and client should send back. so the mic range is
		 * valid although it may not present */
		if (av_flags & idl::NTLMSSP_AVFLAG_MIC_IN_AUTHENTICATE_MESSAGE) {
			if (in_len < idl::NTLMSSP_MIC_OFFSET + idl::NTLMSSP_MIC_SIZE) {
				RETURN_ERR_NT_STATUS(NT_STATUS_INVALID_PARAMETER);
			}
			auth_ntlmssp.new_spnego = true;
		}
	}


	/* NTLM2 uses a 'challenge' that is made of up both the server challenge, and a
	   client challenge

	   However, the NTLM2 flag may still be set for the real NTLMv2 logins, be careful.
	*/
	if (auth_ntlmssp.neg_flags & idl::NTLMSSP_NEGOTIATE_NTLM2) {
		if (msg.NtChallengeResponse && msg.NtChallengeResponse->val.size() == 0x18) {
			auth_ntlmssp.doing_ntlm2 = true;
			X_TODO; /*
			uint8_t session_nonce_hash[16];
			MD5_CTX md5_session_nonce_ctx;
			MD5Init(&md5_session_nonce_ctx);
			MD5Update();
			MD5Final(session_nonce_hash, &md5_session_nonce_ctx);
			*/
		}
	}

	/* ntlmssp_server_check_password */
	if (msg.DomainName) {
		auth_ntlmssp.client_domain = *msg.DomainName;
	}
	if (msg.UserName) {
		auth_ntlmssp.client_user = *msg.UserName;
	}
	if (msg.Workstation) {
		auth_ntlmssp.client_workstation = *msg.Workstation;
	}
	if (msg.LmChallengeResponse) {
		auth_ntlmssp.client_lm_resp = msg.LmChallengeResponse;
	}
	if (msg.NtChallengeResponse) {
		auth_ntlmssp.client_nt_resp = msg.NtChallengeResponse;
	}

	if (auth_ntlmssp.neg_flags & idl::NTLMSSP_NEGOTIATE_KEY_EXCH) {
		if (msg.EncryptedRandomSessionKey->val.size() != auth_ntlmssp.encrypted_session_key.size()) {
			RETURN_ERR_NT_STATUS(NT_STATUS_INVALID_PARAMETER);
		}
		memcpy(auth_ntlmssp.encrypted_session_key.data(), msg.EncryptedRandomSessionKey->val.data(), auth_ntlmssp.encrypted_session_key.size());
	}

	auth_ntlmssp.msg_authenticate.assign(in_buf, in_buf + in_len);

	bool upn_form = auth_ntlmssp.client_domain.empty() &&
		(auth_ntlmssp.client_user.find('@') != std::string::npos);

	if (!upn_form) {
		std::string netbios_name = x_convert_utf16_to_utf8(auth_ntlmssp.netbios_name);
		if (auth_ntlmssp.client_domain != netbios_name) {
			x_ntlmssp_is_trusted_domain(auth_ntlmssp, auth_upcall);
			return X_NT_STATUS_INTERNAL_BLOCKED;
			return NT_STATUS(2); // TODO introduce error
		}
	}

	ntlmssp_check_password(auth_ntlmssp, false, auth_upcall);
	return X_NT_STATUS_INTERNAL_BLOCKED;
}

static NTSTATUS auth_ntlmssp_update(x_auth_t *auth, const uint8_t *in_buf, size_t in_len,
		std::vector<uint8_t> &out, x_auth_upcall_t *auth_upcall,
		std::shared_ptr<x_auth_info_t> &auth_info)
{
	x_auth_ntlmssp_t *ntlmssp = X_CONTAINER_OF(auth, x_auth_ntlmssp_t, auth);
	if (ntlmssp->state_position == x_auth_ntlmssp_t::S_NEGOTIATE) {
		return handle_negotiate(*ntlmssp, in_buf, in_len, out, auth_upcall);
	} else if (ntlmssp->state_position == x_auth_ntlmssp_t::S_AUTHENTICATE) {
		return handle_authenticate(*ntlmssp, in_buf, in_len, out, auth_upcall);
	} else {
		X_ASSERT(false);
		RETURN_ERR_NT_STATUS(NT_STATUS_INTERNAL_ERROR);
	}
}

static void auth_ntlmssp_destroy(x_auth_t *auth)
{
	x_auth_ntlmssp_t *ntlmssp = X_CONTAINER_OF(auth, x_auth_ntlmssp_t, auth);
	delete ntlmssp;
}

static bool auth_ntlmssp_have_feature(x_auth_t *auth, uint32_t feature)
{
	x_auth_ntlmssp_t *ntlmssp = X_CONTAINER_OF(auth, x_auth_ntlmssp_t, auth);
	return ntlmssp_have_feature(ntlmssp, feature);
}

static NTSTATUS auth_ntlmssp_check_packet(x_auth_t *auth, const uint8_t *data, size_t data_len,
		const uint8_t *whole_pdu, size_t pdu_length,
		const uint8_t *sig, size_t sig_len)
{
	x_auth_ntlmssp_t *ntlmssp = X_CONTAINER_OF(auth, x_auth_ntlmssp_t, auth);
	return ntlmssp_check_packet(ntlmssp, data, data_len,
			whole_pdu, pdu_length,
			sig, sig_len);
}

static NTSTATUS auth_ntlmssp_sign_packet(x_auth_t *auth, const uint8_t *data, size_t data_len,
		const uint8_t *whole_pdu, size_t pdu_length,
		std::vector<uint8_t> &sig)
{
	x_auth_ntlmssp_t *ntlmssp = X_CONTAINER_OF(auth, x_auth_ntlmssp_t, auth);
	return ntlmssp_sign_packet(ntlmssp, data, data_len,
			whole_pdu, pdu_length,
			sig);
}

static const x_auth_ops_t auth_ntlmssp_ops = {
	auth_ntlmssp_update,
	auth_ntlmssp_destroy,
	auth_ntlmssp_have_feature,
	auth_ntlmssp_check_packet,
	auth_ntlmssp_sign_packet,
};


x_auth_t *x_auth_create_ntlmssp(x_auth_context_t *context)
{
	x_auth_ntlmssp_t *ntlmssp = new x_auth_ntlmssp_t(context, &auth_ntlmssp_ops);
	return &ntlmssp->auth;
}

int x_auth_ntlmssp_init(x_auth_context_t *ctx)
{
	return 0;
}

#if 0
static x_auth_t *x_auth_ntlmssp_create(x_auth_context_t *context)
{
	return new x_auth_ntlmssp_t(context);
};

const struct x_auth_mech_t x_auth_mech_ntlmssp = {
	GSS_SPNEGO_MECHANISM,
	x_auth_ntlmssp_create,
};
#endif

