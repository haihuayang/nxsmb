#include "smbd.hxx"
#include "smbd_conf.hxx"
#include "include/nttime.hxx"

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

struct x_smb2_negprot_t 
{
	uint16_t out_dialect;
	uint16_t out_security_mode;
	uint16_t out_encryption_algo = X_SMB2_ENCRYPTION_INVALID_ALGO;
	uint16_t out_signing_algo = X_SMB2_SIGNING_INVALID_ALGO;
	uint16_t out_context_count = 0;
	uint32_t out_capabilities;
	std::vector<uint8_t> out_context;
};

}

static NTSTATUS x_smbd_conn_reply_negprot(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		const x_smbd_conf_t &smbd_conf,
		const x_smb2_negprot_t &negprot)
{
	X_LOG_OP("%ld RESP SUCCESS dialect=%x", smbd_requ->in_smb2_hdr.mid, negprot.out_dialect);

	const std::vector<uint8_t> &security_blob = x_smbd_get_negprot_spnego();
	size_t dyn_len = security_blob.size();

	if (negprot.out_context.size() != 0) {
		dyn_len = x_pad_len(security_blob.size(), 8);
		dyn_len += negprot.out_context.size();
	}

#if 0
	// TODO should it consider client capabilities?
	uint32_t server_capabilities = smbd_conf->capabilities;
	if (negprot->out_dialect < X_SMB2_DIALECT_300) {
		server_capabilities &= ~(X_SMB2_CAP_DIRECTORY_LEASING |
				X_SMB2_CAP_MULTI_CHANNEL);
	}
	x_smbd_conn_set_negprot(smbd_conn, negprot->out_dialect,
			security_mode, server_capabilities);
	smbd_conn->dialect = negprot->out_dialect;
	smbd_conn->server_security_mode = security_mode;
	smbd_conn->server_capabilities = smbd_conf->capabilities;

#endif	

	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_negprot_resp_t) + dyn_len);
	uint8_t *out_hdr = bufref->get_data();
	x_smb2_negprot_resp_t *out_resp = (x_smb2_negprot_resp_t *)(out_hdr + sizeof(x_smb2_header_t));

	auto [tick_start, tick_system ] = x_smbd_get_time();

	out_resp->struct_size = X_H2LE16(sizeof(x_smb2_negprot_resp_t) + 1);
	out_resp->security_mode = X_H2LE16(negprot.out_security_mode);
	out_resp->dialect = X_H2LE16(negprot.out_dialect);
	out_resp->context_count = X_H2LE16(negprot.out_context_count);
	memcpy(&out_resp->server_guid, &smbd_conf.guid, 16);
	out_resp->capabilites = X_H2LE32(negprot.out_capabilities);
	out_resp->max_trans_size = X_H2LE32(smbd_conf.max_trans_size);
	out_resp->max_read_size = X_H2LE32(smbd_conf.max_read_size);
	out_resp->max_write_size = X_H2LE32(smbd_conf.max_write_size);
	out_resp->system_time = X_H2LE64(x_tick_to_nttime(tick_system).val);
	out_resp->server_start_time = X_H2LE64(x_tick_to_nttime(tick_start).val);

	size_t offset = sizeof(x_smb2_header_t) + sizeof(x_smb2_negprot_resp_t);
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
			sizeof(x_smb2_header_t) + sizeof(x_smb2_negprot_resp_t) + dyn_len);
	if (negprot.out_dialect >= X_SMB2_DIALECT_310) {
		x_smbd_conn_update_preauth(smbd_conn, out_hdr,
				sizeof(x_smb2_header_t) + sizeof(x_smb2_negprot_resp_t) + dyn_len);
	}

	return NT_STATUS_OK;
}

#define HDR_WCT 32
#define HDR_VWV 33
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

	const x_smbd_conf_t &smbd_conf = x_smbd_conf_get_curr();

	x_smb2_negprot_t negprot;
	negprot.out_dialect = 0x2ff;
	negprot.out_security_mode = smbd_conf.security_mode;
	negprot.out_capabilities = smbd_conf.capabilities & 
		~(X_SMB2_CAP_DIRECTORY_LEASING | X_SMB2_CAP_MULTI_CHANNEL);
	x_smbd_conn_reply_negprot(smbd_conn, smbd_requ, smbd_conf, negprot);
	return 0;
}

static NTSTATUS parse_context(const uint8_t *in_context, uint32_t in_context_length,
		uint32_t in_context_count, uint32_t &encryption_algos,
		uint32_t &signing_algos)
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
		if (type == X_SMB2_PREAUTH_INTEGRITY_CAPABILITIES) {
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
				if (hash == X_SMB2_PREAUTH_INTEGRITY_SHA512) {
					hash_matched = true;
					break;
				}
			}
			if (!hash_matched) {
				return NT_STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP;
			}

		} else if (type == X_SMB2_ENCRYPTION_CAPABILITIES) {
			if (length < 2) {
				return NT_STATUS_INVALID_PARAMETER;
			}
			uint16_t algo_count = x_get_le16(in_context + offset);
			if (algo_count == 0) {
				return NT_STATUS_INVALID_PARAMETER;
			}
			if (2 + algo_count * 2 > length) {
				return NT_STATUS_INVALID_PARAMETER;
			}
			offset += 2;
			uint32_t algos = 0;
			for (uint16_t i = 0; i < algo_count; ++i) {
				uint16_t algo = x_get_le16(in_context + offset);
				if (algo == X_SMB2_ENCRYPTION_AES128_GCM) {
					algos |= (1 << X_SMB2_ENCRYPTION_AES128_GCM);
				} else if (algo == X_SMB2_ENCRYPTION_AES128_CCM) {
					algos |= (1 << X_SMB2_ENCRYPTION_AES128_CCM);
				} else if (algo == X_SMB2_ENCRYPTION_AES256_GCM) {
					algos |= (1 << X_SMB2_ENCRYPTION_AES256_GCM);
				} else if (algo == X_SMB2_ENCRYPTION_AES256_CCM) {
					algos |= (1 << X_SMB2_ENCRYPTION_AES256_CCM);
				}
				offset += 2;
			}
			encryption_algos = algos;

		} else if (type == X_SMB2_SIGNING_CAPABILITIES) {
			if (length < 2) {
				return NT_STATUS_INVALID_PARAMETER;
			}
			uint16_t algo_count = x_get_le16(in_context + offset);
			if (algo_count == 0) {
				return NT_STATUS_INVALID_PARAMETER;
			}
			if (2 + algo_count * 2 > length) {
				return NT_STATUS_INVALID_PARAMETER;
			}
			offset += 2;
			uint32_t algos = 0;
			for (uint16_t i = 0; i < algo_count; ++i) {
				uint16_t algo = x_get_le16(in_context + offset);
				if (algo == X_SMB2_SIGNING_AES128_GMAC) {
					algos |= (1 << X_SMB2_SIGNING_AES128_GMAC);
				} else if (algo == X_SMB2_SIGNING_AES128_CMAC) {
					algos |= (1 << X_SMB2_SIGNING_AES128_CMAC);
				} else if (algo == X_SMB2_SIGNING_HMAC_SHA256) {
					algos |= (1 << X_SMB2_SIGNING_HMAC_SHA256);
				}
				offset += 2;
			}
			signing_algos = algos;
		}

		offset = x_pad_len(end, 8);
	}
	return NT_STATUS_OK;
}

static void generate_context(x_smb2_negprot_t &negprot,
		uint16_t encryption_algo, uint16_t signing_algo)
{
	auto &output = negprot.out_context;
	output.resize(128); // 128 should be enough
	uint16_t context_count = 0;
	uint8_t *data = output.data();

	x_put_le16(data, X_SMB2_PREAUTH_INTEGRITY_CAPABILITIES);
	data += 2;
	x_put_le16(data, 38);
	data += 2;
	data += 4;
	x_put_le16(data, 1);
	data += 2;
	x_put_le16(data, 32);
	data += 2;
	x_put_le16(data, X_SMB2_PREAUTH_INTEGRITY_SHA512);
	data += 2;
	x_rand_bytes(data, 32);
	data += 32;
	++context_count;

	if (encryption_algo != X_SMB2_ENCRYPTION_INVALID_ALGO) {
		size_t ctx_len = x_pad_len(data - output.data(), 8);
		data = output.data() + ctx_len;
		x_put_le16(data, X_SMB2_ENCRYPTION_CAPABILITIES);
		data += 2;
		x_put_le16(data, 4);
		data += 2;
		data += 4;
		x_put_le16(data, 1);
		data += 2;
		x_put_le16(data, encryption_algo);
		data += 2;
		++context_count;
	}

	if (signing_algo != X_SMB2_SIGNING_INVALID_ALGO) {
		size_t ctx_len = x_pad_len(data - output.data(), 8);
		data = output.data() + ctx_len;
		x_put_le16(data, X_SMB2_SIGNING_CAPABILITIES);
		data += 2;
		x_put_le16(data, 4);
		data += 2;
		data += 4;
		x_put_le16(data, 1);
		data += 2;
		x_put_le16(data, signing_algo);
		data += 2;
		++context_count;
	}

	output.resize(data - output.data());
	negprot.out_context_count = context_count;
}

/* return < 0, shutdown immediately
 */
NTSTATUS x_smb2_process_negprot(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	X_LOG_OP("%ld NEGPROT", smbd_requ->in_smb2_hdr.mid);

	// x_smb2_verify_size(smbd_requ, X_SMB2_NEGPROT_BODY_LEN);
	if (smbd_requ->in_requ_len < sizeof(x_smb2_header_t) + sizeof(x_smb2_negprot_requ_t)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_buf = smbd_requ->get_in_data();
	const uint8_t *in_body = in_buf + sizeof(x_smb2_header_t);

	const x_smb2_negprot_requ_t *in_requ = (const x_smb2_negprot_requ_t *)in_body;
	uint16_t dialect_count = X_LE2H16(in_requ->dialect_count);
	if (dialect_count == 0) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}
	if (sizeof(x_smb2_header_t) + sizeof(x_smb2_negprot_requ_t) + dialect_count * sizeof(uint16_t)
			> smbd_requ->in_requ_len) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	const x_smbd_conf_t &smbd_conf = x_smbd_conf_get_curr();

	x_smb2_negprot_t negprot;
	negprot.out_dialect = x_smb2_dialect_match(smbd_conf.dialects,
			(const uint16_t *)(in_requ + 1), dialect_count);
	if (negprot.out_dialect == X_SMB2_DIALECT_000) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_NOT_SUPPORTED);
	}

	uint16_t in_security_mode = x_get_le16(in_body + 0x04);
	uint32_t in_capabilities = x_get_le32(in_body + 0x08);

	x_smb2_uuid_t in_client_guid;
	in_client_guid.from_bytes(in_requ->client_guid);
#if 0
	const uint8_t *in_dyn = in_body + X_SMB2_NEGPROT_REQU_BODY_LEN;
	
	negprot.out_dialect = x_smb2_dialect_match(smbd_conn, in_dyn, dialect_count);
	if (negprot.out_dialect == X_SMB2_DIALECT_000) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_NOT_SUPPORTED);
	}
	smbd_conn->client_security_mode = in_security_mode;
	smbd_conn->client_capabilities = in_capabilities;
	idl::x_ndr_pull(smbd_conn->client_guid, in_body + 0x0c, 0x24, 0);
#endif
	
	// uint16_t out_negotiate_context_count = 0;
	// std::vector<uint8_t> out_negotiate_context;
	if (negprot.out_dialect >= X_SMB2_DIALECT_310) {
		uint32_t in_context_offset = X_LE2H32(in_requ->context_offset);
		uint16_t in_context_count = X_LE2H16(in_requ->context_count);
		if (!x_check_range<uint32_t>(in_context_offset, 0, 
					sizeof(x_smb2_header_t) + sizeof(x_smb2_negprot_requ_t),
					smbd_requ->in_requ_len)) {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
		}

		const uint8_t *in_context = in_buf + in_context_offset;

		uint32_t encryption_algos = 0, signing_algos = 0;
		NTSTATUS status = parse_context(in_context,
				smbd_requ->in_requ_len - in_context_offset,
				in_context_count,
				encryption_algos, signing_algos);
		if (!NT_STATUS_IS_OK(status)) {
			RETURN_OP_STATUS(smbd_requ, status);
		}

		if (encryption_algos & (1 << X_SMB2_ENCRYPTION_AES128_GCM)) {
			negprot.out_encryption_algo = X_SMB2_ENCRYPTION_AES128_GCM;
		} else if (encryption_algos & (1 << X_SMB2_ENCRYPTION_AES128_CCM)) {
			negprot.out_encryption_algo = X_SMB2_ENCRYPTION_AES128_CCM;
		} else if (encryption_algos & (1 << X_SMB2_ENCRYPTION_AES256_GCM)) {
			negprot.out_encryption_algo = X_SMB2_ENCRYPTION_AES256_GCM;
		} else if (encryption_algos & (1 << X_SMB2_ENCRYPTION_AES256_CCM)) {
			negprot.out_encryption_algo = X_SMB2_ENCRYPTION_AES256_CCM;
		} else {
			negprot.out_encryption_algo = X_SMB2_ENCRYPTION_INVALID_ALGO;
		}

		if (signing_algos & (1 << X_SMB2_SIGNING_AES128_GMAC)) {
			negprot.out_signing_algo = X_SMB2_SIGNING_AES128_GMAC;
		} else if (signing_algos & (1 << X_SMB2_SIGNING_AES128_CMAC)) {
			negprot.out_signing_algo = X_SMB2_SIGNING_AES128_CMAC;
		} else if (signing_algos & (1 << X_SMB2_SIGNING_HMAC_SHA256)) {
			negprot.out_signing_algo = X_SMB2_SIGNING_HMAC_SHA256;
		} else {
			negprot.out_signing_algo = X_SMB2_SIGNING_INVALID_ALGO;
		}

		x_smbd_conn_update_preauth(smbd_conn, 
				in_buf, smbd_requ->in_requ_len);

		generate_context(negprot, negprot.out_encryption_algo,
				negprot.out_signing_algo);
	} else if (negprot.out_dialect >= X_SMB2_DIALECT_300) {
		negprot.out_encryption_algo = X_SMB2_ENCRYPTION_AES128_CCM;
	}

	negprot.out_security_mode = smbd_conf.security_mode;
	// TODO should it consider client capabilities?
	negprot.out_capabilities = smbd_conf.capabilities;
	if (negprot.out_dialect < X_SMB2_DIALECT_300) {
		negprot.out_capabilities &= ~(X_SMB2_CAP_DIRECTORY_LEASING |
				X_SMB2_CAP_MULTI_CHANNEL | X_SMB2_CAP_ENCRYPTION);
	}
	x_smbd_conn_negprot(smbd_conn, negprot.out_dialect,
			negprot.out_encryption_algo,
			negprot.out_signing_algo,
			in_security_mode,
			negprot.out_security_mode,
			in_capabilities,
			negprot.out_capabilities,
			in_client_guid);
	return x_smbd_conn_reply_negprot(smbd_conn, smbd_requ, smbd_conf, negprot);
}


