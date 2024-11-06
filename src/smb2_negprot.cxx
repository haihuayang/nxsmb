#include "smbd.hxx"
#include "smbd_requ.hxx"
#include "smbd_conf.hxx"
#include "include/nttime.hxx"

namespace {

struct x_smb2_negprot_context_header_t
{
	uint16_t type;
	uint16_t length;
	uint32_t unused0;
};

struct x_smb2_negprot_context_compression_t
{
	uint16_t count;
	uint16_t unused0;
	uint32_t flags;
};

}

static const uint16_t preferred_compression_algos[] = {
	X_SMB2_COMPRESSION_LZ77,
};


static NTSTATUS x_smbd_conn_reply_negprot(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		const x_smbd_conf_t &smbd_conf,
		const x_smbd_negprot_t &negprot,
		uint16_t out_context_count,
		const std::vector<uint8_t> &out_context)
{
	X_SMBD_REQU_LOG(OP, smbd_requ,  " dialect=%x", negprot.dialect);

	const std::vector<uint8_t> &security_blob = x_smbd_get_negprot_spnego();
	size_t dyn_len = security_blob.size();

	if (out_context.size() != 0) {
		dyn_len = x_pad_len(security_blob.size(), 8);
		dyn_len += out_context.size();
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

	x_bufref_t *bufref = x_smb2_bufref_alloc(sizeof(x_smb2_negprot_resp_t) + dyn_len);
	uint8_t *out_hdr = bufref->get_data();
	x_smb2_negprot_resp_t *out_resp = (x_smb2_negprot_resp_t *)(out_hdr + sizeof(x_smb2_header_t));

	auto [tick_start, tick_system ] = x_smbd_get_time();

	out_resp->struct_size = X_H2LE16(sizeof(x_smb2_negprot_resp_t) + 1);
	out_resp->security_mode = X_H2LE16(negprot.server_security_mode);
	out_resp->dialect = X_H2LE16(negprot.dialect);
	out_resp->context_count = X_H2LE16(out_context_count);
	memcpy(&out_resp->server_guid, &smbd_conf.guid, 16);
	out_resp->capabilities = X_H2LE32(negprot.server_capabilities);
	out_resp->max_trans_size = X_H2LE32(negprot.max_trans_size);
	out_resp->max_read_size = X_H2LE32(negprot.max_read_size);
	out_resp->max_write_size = X_H2LE32(negprot.max_write_size);
	out_resp->system_time = X_H2LE64(x_tick_to_nttime(tick_system).val);
	out_resp->server_start_time = X_H2LE64(x_tick_to_nttime(tick_start).val);

	size_t offset = sizeof(x_smb2_header_t) + sizeof(x_smb2_negprot_resp_t);
	out_resp->security_buffer_offset = X_H2LE16(x_convert_assert<uint16_t>(offset));
	out_resp->security_buffer_length = X_H2LE16(x_convert_assert<uint16_t>(security_blob.size()));

	if (security_blob.size()) {
		memcpy(out_resp + 1, security_blob.data(), security_blob.size());
		offset += security_blob.size();
	}

	if (out_context_count != 0) {
		size_t padlen = x_pad_len(offset, 8);
		memset(out_hdr + offset, 0, padlen - offset);
		offset = padlen;
		out_resp->context_offset = X_H2LE32(x_convert_assert<uint32_t>(offset));
		memcpy(out_hdr + offset, out_context.data(), out_context.size());
	} else {
		out_resp->context_offset = 0;
	}

	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, NT_STATUS_OK, 
			sizeof(x_smb2_header_t) + sizeof(x_smb2_negprot_resp_t) + dyn_len);
	if (negprot.dialect >= X_SMB2_DIALECT_310) {
		x_smbd_conn_update_preauth(smbd_conn, out_hdr,
				sizeof(x_smb2_header_t) + sizeof(x_smb2_negprot_resp_t) + dyn_len);
	}

	return NT_STATUS_OK;
}

static const struct {
	const char *name;
	uint16_t dialect;
} smb1_supported[] = {
        { "SMB 2.???", X_SMB2_DIALECT_2FF, },
	{ "SMB 2.002", X_SMB2_DIALECT_202, },
};

#define HDR_WCT 32
#define HDR_VWV 33
int x_smbd_conn_process_smb1negprot(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	const uint8_t *in_buf = smbd_requ->base.in_buf->data;
	uint32_t len = smbd_requ->base.in_buf->size;
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
	const char *negobuf = (const char *)in_buf + HDR_WCT + 3 + 2 * wct;
	if (negobuf[vwv - 1] != '\0') {
		// TODO reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return -EBADMSG;
	}

	uint16_t choice = 0;
	const char *nego_end = negobuf + vwv;
	for (auto [name, dialect] : smb1_supported) {
		for (const char *p = negobuf; p < nego_end; p += strlen(p) + 1) {
			if (*p == 0x2 && strcmp(p + 1, name) == 0) {
				choice = dialect;
				break;
			}
		}
		if (choice) {
			break;
		}
	}

	if (choice == 0) {
		choice = X_SMB2_DIALECT_2FF;
	}

	const x_smbd_conf_t &smbd_conf = x_smbd_conf_get_curr();

	x_smbd_negprot_t negprot;
	negprot.dialect = choice;
	negprot.cryption_algo = X_SMB2_ENCRYPTION_INVALID_ALGO;
	negprot.signing_algo = X_SMB2_SIGNING_INVALID_ALGO;
	negprot.client_security_mode = negprot.server_security_mode = 0;
	negprot.client_capabilities = 0;
	negprot.server_capabilities = smbd_conf.capabilities & X_SMB2_CAP_DFS;
	negprot.max_trans_size = std::min(smbd_conf.max_trans_size, 0x10000u);
	negprot.max_read_size = std::min(smbd_conf.max_read_size, 0x10000u);
	negprot.max_write_size = std::min(smbd_conf.max_write_size, 0x10000u);
	negprot.client_guid = { };

	int err = x_smbd_conn_negprot(smbd_conn, negprot, true);
	if (err) {
		X_SMBD_REQU_LOG(ERR, smbd_requ,  "err=%d", err);
		return err;
	}

	x_smbd_conn_reply_negprot(smbd_conn, smbd_requ, smbd_conf, negprot, 0, {});
	return 0;
}

static NTSTATUS parse_context(const uint8_t *in_context, uint32_t in_context_length,
		uint32_t in_context_count, uint32_t &hash_algos,
		uint32_t &encryption_algos,
		uint32_t &signing_algos,
		uint32_t &compression_algos,
		uint32_t &compression_flags)
{
	size_t offset = 0;
	for (uint32_t ci = 0; ci < in_context_count; ++ci) {
		if (offset + sizeof(x_smb2_negprot_context_header_t) > in_context_length) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		auto ctx_hdr = (const x_smb2_negprot_context_header_t *)(in_context + offset);
		offset += sizeof(x_smb2_negprot_context_header_t);

		uint16_t type = X_LE2H16(ctx_hdr->type);
		uint16_t length = X_LE2H16(ctx_hdr->length);
		size_t end = offset + length;
		if (end > in_context_length) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		
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
			uint32_t algos = 0;
			for (uint16_t i = 0; i < hash_count; ++i) {
				uint16_t hash = x_get_le16(in_context + offset + 2 * i);
				if (hash == X_SMB2_PREAUTH_INTEGRITY_SHA512) {
					algos |= (1 << X_SMB2_PREAUTH_INTEGRITY_SHA512);
				}
			}
			if (!algos) {
				return NT_STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP;
			}
			hash_algos = algos;

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

		} else if (type == X_SMB2_COMPRESSION_CAPABILITIES) {
			if (length < sizeof(x_smb2_negprot_context_compression_t)) {
				return NT_STATUS_INVALID_PARAMETER;
			}
			auto ctx = (const x_smb2_negprot_context_compression_t *)(in_context + offset);
			uint32_t flags = X_LE2H32(ctx->flags);
			if (flags > 1) {
				return NT_STATUS_INVALID_PARAMETER;
			}

			uint16_t count = X_LE2H16(ctx->count);
			if (count == 0) {
				return NT_STATUS_INVALID_PARAMETER;
			}
			if (sizeof(x_smb2_negprot_context_compression_t) +  count * 2 > length) {
				return NT_STATUS_INVALID_PARAMETER;
			}
			auto ptr = (const uint16_t *)(ctx + 1);
			uint32_t algos = 0;
			for (uint16_t i = 0; i < count; ++i, ++ptr) {
				uint16_t algo = X_LE2H16(*ptr);
				if (algo < X_SMB2_COMPRESSION_MAX) {
					algos |= (1 << algo);
				}
			}
			compression_algos = algos;
			compression_flags = flags;
		}

		offset = x_pad_len(end, 8);
	}
	return NT_STATUS_OK;
}

static void generate_context(uint16_t &out_context_count,
		std::vector<uint8_t> &out_context,
		uint16_t encryption_algo, uint16_t signing_algo,
		uint32_t compression_algos, uint32_t compression_flags)
{
	auto &output = out_context;
	output.resize(128); // 128 should be enough
	uint16_t context_count = 0;
	uint8_t *data = output.data();
	x_smb2_negprot_context_header_t *ctx_hdr;

	ctx_hdr = (x_smb2_negprot_context_header_t *)data;
	ctx_hdr->type = X_H2LE16(X_SMB2_PREAUTH_INTEGRITY_CAPABILITIES);
	ctx_hdr->unused0 = 0;
	data = (uint8_t *)(ctx_hdr + 1);
	x_put_le16(data, 1);
	data += 2;
	x_put_le16(data, 32);
	data += 2;
	x_put_le16(data, X_SMB2_PREAUTH_INTEGRITY_SHA512);
	data += 2;
	x_rand_bytes(data, 32);
	data += 32;
	ctx_hdr->length = X_H2LE16(uint16_t(data - (uint8_t *)(ctx_hdr + 1)));
	++context_count;

	if (encryption_algo != X_SMB2_ENCRYPTION_INVALID_ALGO) {
		size_t ctx_len = x_pad_len(data - output.data(), 8);
		data = output.data() + ctx_len;
		ctx_hdr = (x_smb2_negprot_context_header_t *)data;
		ctx_hdr->type = X_H2LE16(X_SMB2_ENCRYPTION_CAPABILITIES);
		ctx_hdr->length = X_H2LE16(4);
		ctx_hdr->unused0 = 0;

		data = (uint8_t *)(ctx_hdr + 1);
		x_put_le16(data, 1);
		data += 2;
		x_put_le16(data, encryption_algo);
		data += 2;
		++context_count;
	}

	if (signing_algo != X_SMB2_SIGNING_INVALID_ALGO) {
		size_t ctx_len = x_pad_len(data - output.data(), 8);
		data = output.data() + ctx_len;
		ctx_hdr = (x_smb2_negprot_context_header_t *)data;
		ctx_hdr->type = X_H2LE16(X_SMB2_SIGNING_CAPABILITIES);
		ctx_hdr->length = X_H2LE16(4);
		ctx_hdr->unused0 = 0;

		data = (uint8_t *)(ctx_hdr + 1);
		x_put_le16(data, 1);
		data += 2;
		x_put_le16(data, signing_algo);
		data += 2;
		++context_count;
	}

	if (compression_algos != 0) {
		size_t ctx_len = x_pad_len(data - output.data(), 8);
		data = output.data() + ctx_len;
		ctx_hdr = (x_smb2_negprot_context_header_t *)data;
		ctx_hdr->type = X_H2LE16(X_SMB2_COMPRESSION_CAPABILITIES);
		ctx_hdr->unused0 = 0;

		x_put_le16(data, X_SMB2_COMPRESSION_CAPABILITIES);
		data += 2;
		auto ctx = (x_smb2_negprot_context_compression_t *)(ctx_hdr + 1);
		ctx->unused0 = 0;
		ctx->flags = X_H2LE32(compression_flags);
		uint16_t *p = (uint16_t *)(ctx + 1);
		uint16_t count = 0;
		for (auto algo: preferred_compression_algos) {
			if (compression_algos & (1 << algo)) {
				*p++ = X_H2LE16(algo);
				++count;
			}
		}
		X_ASSERT(count != 0);
		ctx->count = X_H2LE16(count);
		ctx_hdr->length = X_H2LE16(uint16_t((uint8_t *)p - (uint8_t *)ctx));

		data = (uint8_t *)p;
		++context_count;
	}

	output.resize(data - output.data());
	out_context_count = context_count;
}

/* return < 0, shutdown immediately
 */
NTSTATUS x_smb2_process_negprot(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	X_SMBD_REQU_LOG(OP, smbd_requ,  "");

	// x_smb2_verify_size(smbd_requ, X_SMB2_NEGPROT_BODY_LEN);
	auto [ in_buf, in_requ_len ] = smbd_requ->base.get_in_data();
	if (in_requ_len < sizeof(x_smb2_header_t) + sizeof(x_smb2_negprot_requ_t)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_body = in_buf + sizeof(x_smb2_header_t);

	const x_smb2_negprot_requ_t *in_requ = (const x_smb2_negprot_requ_t *)in_body;
	uint16_t dialect_count = X_LE2H16(in_requ->dialect_count);
	if (dialect_count == 0) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}
	if (sizeof(x_smb2_header_t) + sizeof(x_smb2_negprot_requ_t) +
			dialect_count * sizeof(uint16_t) > in_requ_len) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	const x_smbd_conf_t &smbd_conf = x_smbd_conf_get_curr();

	x_smbd_negprot_t negprot;
	negprot.dialect = x_smb2_dialect_match(smbd_conf.dialects,
			(const uint16_t *)(in_requ + 1), dialect_count);
	if (negprot.dialect == X_SMB2_DIALECT_000) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_NOT_SUPPORTED);
	}

	uint16_t in_security_mode = x_get_le16(in_body + 0x04);
	uint32_t in_capabilities = x_get_le32(in_body + 0x08);

	x_smb2_uuid_t in_client_guid;
	in_client_guid.from_bytes(in_requ->client_guid);
#if 0
	const uint8_t *in_dyn = in_body + X_SMB2_NEGPROT_REQU_BODY_LEN;
	
	negprot.out_dialect = x_smb2_dialect_match(smbd_conn, in_dyn, dialect_count);
	if (negprot.out_dialect == X_SMB2_DIALECT_000) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_NOT_SUPPORTED);
	}
	smbd_conn->client_security_mode = in_security_mode;
	smbd_conn->client_capabilities = in_capabilities;
	idl::x_ndr_pull(smbd_conn->client_guid, in_body + 0x0c, 0x24, 0);
#endif
	
	uint16_t out_context_count = 0;
	std::vector<uint8_t> out_context;
	if (negprot.dialect >= X_SMB2_DIALECT_310) {
		uint32_t in_context_offset = X_LE2H32(in_requ->context_offset);
		uint16_t in_context_count = X_LE2H16(in_requ->context_count);
		if (!x_check_range<uint32_t>(in_context_offset, 0, 
					sizeof(x_smb2_header_t) + sizeof(x_smb2_negprot_requ_t),
					in_requ_len)) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
		}

		const uint8_t *in_context = in_buf + in_context_offset;

		uint32_t hash_algos = 0, encryption_algos = 0, signing_algos = 0;
		uint32_t compression_algos = 0, compression_flags = 0;
		NTSTATUS status = parse_context(in_context,
				in_requ_len - in_context_offset,
				in_context_count, hash_algos,
				encryption_algos, signing_algos,
				compression_algos, compression_flags);
		if (!NT_STATUS_IS_OK(status)) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, status);
		}

		if (encryption_algos & (1 << X_SMB2_ENCRYPTION_AES128_GCM)) {
			negprot.cryption_algo = X_SMB2_ENCRYPTION_AES128_GCM;
		} else if (encryption_algos & (1 << X_SMB2_ENCRYPTION_AES128_CCM)) {
			negprot.cryption_algo = X_SMB2_ENCRYPTION_AES128_CCM;
		} else if (encryption_algos & (1 << X_SMB2_ENCRYPTION_AES256_GCM)) {
			negprot.cryption_algo = X_SMB2_ENCRYPTION_AES256_GCM;
		} else if (encryption_algos & (1 << X_SMB2_ENCRYPTION_AES256_CCM)) {
			negprot.cryption_algo = X_SMB2_ENCRYPTION_AES256_CCM;
		} else {
			negprot.cryption_algo = X_SMB2_ENCRYPTION_INVALID_ALGO;
		}

		if (signing_algos & (1 << X_SMB2_SIGNING_AES128_GMAC)) {
			negprot.signing_algo = X_SMB2_SIGNING_AES128_GMAC;
		} else if (signing_algos & (1 << X_SMB2_SIGNING_AES128_CMAC)) {
			negprot.signing_algo = X_SMB2_SIGNING_AES128_CMAC;
		} else if (signing_algos & (1 << X_SMB2_SIGNING_HMAC_SHA256)) {
			negprot.signing_algo = X_SMB2_SIGNING_HMAC_SHA256;
		} else {
			negprot.signing_algo = X_SMB2_SIGNING_INVALID_ALGO;
		}

		if (hash_algos == 0) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
		}


		if (compression_algos) {
			negprot.compression_algos = 0;
			for (auto algo: preferred_compression_algos) {
				if (compression_algos & (1 << algo)) {
					negprot.compression_algos |= (1 << algo);
				}
			}
			negprot.compression_flags = compression_flags;
		}

		x_smbd_conn_update_preauth(smbd_conn, 
				in_buf, in_requ_len);

		generate_context(out_context_count, out_context,
				negprot.cryption_algo,
				negprot.signing_algo,
				negprot.compression_algos,
				negprot.compression_flags);

	} else if (negprot.dialect >= X_SMB2_DIALECT_300) {
		if (in_capabilities & X_SMB2_CAP_ENCRYPTION) {
			negprot.cryption_algo = X_SMB2_ENCRYPTION_AES128_CCM;
		} else {
			negprot.cryption_algo = X_SMB2_ENCRYPTION_INVALID_ALGO;
		}
	}

	negprot.client_security_mode = in_security_mode;
	negprot.server_security_mode = x_convert<uint16_t>(smbd_conf.security_mode |
		(in_security_mode & X_SMB2_NEGOTIATE_SIGNING_REQUIRED));

	negprot.client_capabilities = in_capabilities;

	static const uint32_t bits_300 = X_SMB2_CAP_MULTI_CHANNEL
		| X_SMB2_CAP_PERSISTENT_HANDLES
		| X_SMB2_CAP_DIRECTORY_LEASING
		| X_SMB2_CAP_ENCRYPTION;

	negprot.server_capabilities = smbd_conf.capabilities &
		((bits_300 & in_capabilities) | ~(bits_300));
	/* [MS-SMB2] 3.3.5.4: CAP_ENCRYPTION is set only in 3.0 or 3.0.2 */
	if (negprot.dialect >= X_SMB2_DIALECT_310) {
		negprot.server_capabilities &= ~X_SMB2_CAP_ENCRYPTION;
	}
	if (negprot.dialect < X_SMB2_DIALECT_300) {
		negprot.server_capabilities &= ~bits_300;
	}
	if (negprot.dialect < X_SMB2_DIALECT_210) {
		negprot.server_capabilities &= ~(X_SMB2_CAP_LEASING |
				X_SMB2_CAP_LARGE_MTU);
	}

	negprot.client_guid = in_client_guid;
	negprot.max_trans_size = smbd_conf.max_trans_size;
	negprot.max_read_size = smbd_conf.max_read_size;
	negprot.max_write_size = smbd_conf.max_write_size;

	x_smbd_conn_negprot(smbd_conn, negprot, false);
	return x_smbd_conn_reply_negprot(smbd_conn, smbd_requ, smbd_conf, negprot,
			out_context_count, out_context);
}


