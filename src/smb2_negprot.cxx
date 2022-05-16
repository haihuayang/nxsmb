#include "smbd.hxx"
extern "C" {
#include "samba/lib/util/samba_util.h"
}

namespace {

struct x_smb2_negprot_requ_t
{
	uint16_t struct_size;
	uint16_t dialect_count;
	uint16_t security_mode;
	uint16_t unused0;
	uint32_t capabilites;
	x_smb2_uuid_bytes_t client_guid;
	uint32_t context_offset;
	uint16_t context_count;
	uint16_t unused1;
};

struct x_smb2_negprot_resp_t
{
	uint16_t struct_size;
	uint16_t security_mode;
	uint16_t dialect;
	uint16_t context_count;
	x_smb2_uuid_bytes_t server_guid;
	uint32_t capabilites;
	uint32_t max_trans_size;
	uint32_t max_read_size;
	uint32_t max_write_size;
	uint64_t system_time;
	uint64_t server_start_time;
	uint16_t security_buffer_offset;
	uint16_t security_buffer_length;
	uint32_t context_offset;
};

#if 0
enum {
	X_SMB2_NEGPROT_REQU_BODY_LEN = 0x24,
	X_SMB2_NEGPROT_RESP_BODY_LEN = 0x40,
};
#endif
struct x_smb2_negprot_t 
{
	uint16_t out_dialect;
	uint16_t out_security_mode;
	uint16_t out_cipher = 0;
	uint16_t out_context_count = 0;
	uint32_t out_capabilities;
	std::vector<uint8_t> out_context;
};

}

static inline uint16_t get_security_mode(const x_smbd_conf_t &smbd_conf)
{
	uint16_t security_mode = SMB2_NEGOTIATE_SIGNING_ENABLED;
	if (smbd_conf.signing_required) {
		security_mode |= SMB2_NEGOTIATE_SIGNING_REQUIRED;
	}
	return security_mode;
}

static NTSTATUS x_smbd_conn_reply_negprot(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		const x_smbd_conf_t &smbd_conf,
		const x_smb2_negprot_t &negprot)
{
	X_LOG_OP("%ld RESP SUCCESS dialect=%x", smbd_requ->in_mid, negprot.out_dialect);

	idl::NTTIME now = x_tick_to_nttime(tick_now);

	const std::vector<uint8_t> &security_blob = x_smbd_get_negprot_spnego();
	size_t dyn_len = security_blob.size();

	if (negprot.out_context.size() != 0) {
		dyn_len = x_pad_len(security_blob.size(), 8);
		dyn_len += negprot.out_context.size();
	}

#if 0
	// TODO should it consider client capabilities?
	uint32_t server_capabilities = smbd_conf->capabilities;
	if (negprot->out_dialect < SMB3_DIALECT_REVISION_300) {
		server_capabilities &= ~(SMB2_CAP_DIRECTORY_LEASING |
				SMB2_CAP_MULTI_CHANNEL);
	}
	x_smbd_conn_set_negprot(smbd_conn, negprot->out_dialect,
			security_mode, server_capabilities);
	smbd_conn->dialect = negprot->out_dialect;
	smbd_conn->server_security_mode = security_mode;
	smbd_conn->server_capabilities = smbd_conf->capabilities;

#endif	

	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_negprot_resp_t) + dyn_len);
	uint8_t *out_hdr = bufref->get_data();
	x_smb2_negprot_resp_t *out_resp = (x_smb2_negprot_resp_t *)(out_hdr + SMB2_HDR_BODY);

	out_resp->struct_size = X_H2LE16(sizeof(x_smb2_negprot_resp_t) + 1);
	out_resp->security_mode = X_H2LE16(negprot.out_security_mode);
	out_resp->dialect = X_H2LE16(negprot.out_dialect);
	out_resp->context_count = X_H2LE16(negprot.out_context_count);
	memcpy(&out_resp->server_guid, &smbd_conf.guid, 16);
	out_resp->capabilites = X_H2LE32(negprot.out_capabilities);
	out_resp->max_trans_size = X_H2LE32(smbd_conf.max_trans_size);
	out_resp->max_read_size = X_H2LE32(smbd_conf.max_read_size);
	out_resp->max_write_size = X_H2LE32(smbd_conf.max_write_size);
	out_resp->system_time = X_H2LE64(now.val);
	out_resp->server_start_time = 0;

	size_t offset = SMB2_HDR_BODY + sizeof(x_smb2_negprot_resp_t);
	out_resp->security_buffer_offset = X_H2LE16(x_convert_assert<uint16_t>(offset));
	out_resp->security_buffer_length = X_H2LE16(x_convert_assert<uint16_t>(security_blob.size()));

	if (security_blob.size()) {
		memcpy(out_resp + 1, security_blob.data(), security_blob.size());
		offset += security_blob.size();
	}

	if (negprot.out_context_count != 0) {
		size_t padlen = x_pad_len(offset, 8);
		memset(out_hdr + offset, 0, padlen - offset);
		offset = padlen;
		out_resp->context_offset = X_H2LE32(x_convert_assert<uint32_t>(offset));
		memcpy(out_hdr + offset, negprot.out_context.data(), negprot.out_context.size());
	} else {
		out_resp->context_offset = 0;
	}

	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, NT_STATUS_OK, 
			SMB2_HDR_BODY + sizeof(x_smb2_negprot_resp_t) + dyn_len);
	if (negprot.out_dialect >= SMB3_DIALECT_REVISION_310) {
		x_smbd_conn_update_preauth(smbd_conn, out_hdr,
				SMB2_HDR_BODY + sizeof(x_smb2_negprot_resp_t) + dyn_len);
	}

	return NT_STATUS_OK;
}

int x_smbd_conn_process_smb1negprot(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	const uint8_t *in_buf = smbd_requ->in_buf->data;
	uint32_t len = smbd_requ->in_buf->size;
	if (len < HDR_VWV + sizeof(uint16_t)) {
		return -EBADMSG;
	}

	uint8_t wct = in_buf[HDR_WCT];
	uint16_t vwv = x_get_le16(in_buf + HDR_VWV);
	if (len < (size_t)HDR_WCT + 2 *wct + vwv) {
		return -EBADMSG;
	}

	if (vwv == 0) {
		// TODO reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return -EBADMSG;
	}
	const uint8_t *negobuf = in_buf + HDR_WCT + 3 + 2 * wct;
	if (negobuf[vwv - 1] != '\0') {
		// TODO reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return -EBADMSG;
	}

	int err = x_smbd_conn_negprot_smb1(smbd_conn);
	if (err) {
		return err;
	}

	const std::shared_ptr<x_smbd_conf_t> smbd_conf = x_smbd_conf_get();
	x_smb2_negprot_t negprot;
	negprot.out_dialect = 0x2ff;
	negprot.out_security_mode = get_security_mode(*smbd_conf);
	negprot.out_capabilities = smbd_conf->capabilities & 
		~(SMB2_CAP_DIRECTORY_LEASING | SMB2_CAP_MULTI_CHANNEL);
	x_smbd_conn_reply_negprot(smbd_conn, smbd_requ, *smbd_conf, negprot);
	return 0;
}

enum {
	AES128_GCM = 1,
	AES128_CCM = 2,
};

static NTSTATUS parse_context(const uint8_t *in_context, uint32_t in_context_length,
		uint32_t in_context_count, uint32_t &ciphers)
{
	size_t offset = 0;
	for (uint32_t ci = 0; ci < in_context_count; ++ci) {
		if (offset + 8 > in_context_length) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		uint16_t type = x_get_le16(in_context + offset);
		uint16_t length = x_get_le16(in_context + offset + 2);
		size_t end = offset + 8 + length;
		if (end > in_context_length) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		
		offset += 8;
		if (type == SMB2_PREAUTH_INTEGRITY_CAPABILITIES) {
			if (length < 4) {
				return NT_STATUS_INVALID_PARAMETER;
			}
			uint16_t hash_count = x_get_le16(in_context + offset);
			uint16_t salt_length = x_get_le16(in_context + offset + 2);
			if (hash_count == 0) {
				return NT_STATUS_INVALID_PARAMETER;
			}
			if (4 + hash_count * 2 + salt_length > length) {
				return NT_STATUS_INVALID_PARAMETER;
			}

			offset += 4;
			bool hash_matched = false;
			for (uint16_t i = 0; i < hash_count; ++i) {
				uint16_t hash = x_get_le16(in_context + offset + 2 * i);
				if (hash == SMB2_PREAUTH_INTEGRITY_SHA512) {
					hash_matched = true;
					break;
				}
			}
			if (!hash_matched) {
				return NT_STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP;
			}

		} else if (type == SMB2_ENCRYPTION_CAPABILITIES) {
			if (length < 2) {
				return NT_STATUS_INVALID_PARAMETER;
			}
			uint16_t cipher_count = x_get_le16(in_context + offset);
			if (cipher_count == 0) {
				return NT_STATUS_INVALID_PARAMETER;
			}
			if (2 + cipher_count * 2 > length) {
				return NT_STATUS_INVALID_PARAMETER;
			}
			offset += 2;
			for (uint16_t i = 0; i < cipher_count; ++i) {
				uint16_t cipher = x_get_le16(in_context + offset);
				if (cipher == SMB2_ENCRYPTION_AES128_GCM) {
					ciphers |= AES128_GCM;
				} else if (cipher == SMB2_ENCRYPTION_AES128_CCM) {
					ciphers |= AES128_CCM;
				}
				offset += 2;
			}
		}

		offset = x_pad_len(end, 8);
	}
	return NT_STATUS_OK;
}

static void generate_context(x_smb2_negprot_t &negprot, uint16_t cipher)
{
	auto &output = negprot.out_context;
	output.resize(128); // 128 should be enough
	uint8_t *data = output.data();
	x_put_le16(data, SMB2_PREAUTH_INTEGRITY_CAPABILITIES);
	data += 2;
	x_put_le16(data, 38);
	data += 2;
	data += 4;
	x_put_le16(data, 1);
	data += 2;
	x_put_le16(data, 32);
	data += 2;
	x_put_le16(data, SMB2_PREAUTH_INTEGRITY_SHA512);
	data += 2;
	generate_random_buffer(data, 32);
	data += 32;
	size_t ctx_len = x_pad_len(data - output.data(), 8);
	data = output.data() + ctx_len;
	x_put_le16(data, SMB2_ENCRYPTION_CAPABILITIES);
	data += 2;
	x_put_le16(data, 4);
	data += 2;
	data += 4;
	x_put_le16(data, 1);
	data += 2;
	x_put_le16(data, cipher);
	data += 2;
	ctx_len = data - output.data();
	output.resize(ctx_len);
	negprot.out_context_count = 2;
}

/* return < 0, shutdown immediately
 */
NTSTATUS x_smb2_process_negprot(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	X_LOG_OP("%ld NEGPROT", smbd_requ->in_mid);

	// x_smb2_verify_size(smbd_requ, X_SMB2_NEGPROT_BODY_LEN);
	if (smbd_requ->in_requ_len < SMB2_HDR_BODY + sizeof(x_smb2_negprot_requ_t)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_buf = smbd_requ->get_in_data();
	const uint8_t *in_body = in_buf + SMB2_HDR_BODY;

	const x_smb2_negprot_requ_t *in_requ = (const x_smb2_negprot_requ_t *)in_body;
	uint16_t dialect_count = X_LE2H16(in_requ->dialect_count);
	if (dialect_count == 0) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}
	if (SMB2_HDR_BODY + sizeof(x_smb2_negprot_requ_t) + dialect_count * sizeof(uint16_t)
			> smbd_requ->in_requ_len) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	const std::shared_ptr<x_smbd_conf_t> smbd_conf = x_smbd_conf_get();

	x_smb2_negprot_t negprot;
	negprot.out_dialect = x_smb2_dialect_match(smbd_conf->dialects,
			(const uint16_t *)(in_requ + 1), dialect_count);
	if (negprot.out_dialect == SMB2_DIALECT_REVISION_000) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_NOT_SUPPORTED);
	}

	uint16_t in_security_mode = x_get_le16(in_body + 0x04);
	uint32_t in_capabilities = x_get_le32(in_body + 0x08);

	x_smb2_uuid_t in_client_guid;
	memcpy(&in_client_guid, &in_requ->client_guid, sizeof in_client_guid);
#if 0
	const uint8_t *in_dyn = in_body + X_SMB2_NEGPROT_REQU_BODY_LEN;
	
	negprot.out_dialect = x_smb2_dialect_match(smbd_conn, in_dyn, dialect_count);
	if (negprot.out_dialect == SMB2_DIALECT_REVISION_000) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_NOT_SUPPORTED);
	}
	smbd_conn->client_security_mode = in_security_mode;
	smbd_conn->client_capabilities = in_capabilities;
	idl::x_ndr_pull(smbd_conn->client_guid, in_body + 0x0c, 0x24, 0);
#endif
	
	// uint16_t out_negotiate_context_count = 0;
	// std::vector<uint8_t> out_negotiate_context;
	if (negprot.out_dialect >= SMB3_DIALECT_REVISION_310) {
		uint32_t in_context_offset = X_LE2H32(in_requ->context_offset);
		uint16_t in_context_count = X_LE2H16(in_requ->context_count);
		if (!x_check_range<uint32_t>(in_context_offset, 0, 
					SMB2_HDR_BODY + sizeof(x_smb2_negprot_requ_t),
					smbd_requ->in_requ_len)) {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
		}

		const uint8_t *in_context = in_buf + in_context_offset;

		uint32_t ciphers = 0;
		NTSTATUS status = parse_context(in_context, smbd_requ->in_requ_len - in_context_offset,
				in_context_count, ciphers);
		if (!NT_STATUS_IS_OK(status)) {
			RETURN_OP_STATUS(smbd_requ, status);
		}

		if (ciphers & AES128_GCM) {
			negprot.out_cipher = SMB2_ENCRYPTION_AES128_GCM;
		} else if (ciphers & AES128_CCM) {
			negprot.out_cipher = SMB2_ENCRYPTION_AES128_CCM;
		}

		x_smbd_conn_update_preauth(smbd_conn, 
				in_buf, smbd_requ->in_requ_len);

		generate_context(negprot, negprot.out_cipher);
	}

	// TODO should it consider client capabilities?
	negprot.out_capabilities = smbd_conf->capabilities;
	if (negprot.out_dialect < SMB3_DIALECT_REVISION_300) {
		negprot.out_capabilities &= ~(SMB2_CAP_DIRECTORY_LEASING |
				SMB2_CAP_MULTI_CHANNEL);
	}
	x_smbd_conn_negprot(smbd_conn, negprot.out_dialect, negprot.out_cipher,
			in_security_mode,
			negprot.out_security_mode,
			in_capabilities,
			negprot.out_capabilities,
			in_client_guid);
	return x_smbd_conn_reply_negprot(smbd_conn, smbd_requ, *smbd_conf, negprot);
}


