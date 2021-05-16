#include "smbd.hxx"
#include "core.hxx"
extern "C" {
#include "samba/lib/util/samba_util.h"
}

static int x_smbd_conn_reply_negprot(x_smbd_conn_t *smbd_conn, x_msg_t *msg,
		uint16_t dialect, uint16_t negotiate_context_count,
		const std::vector<uint8_t> &negotiate_context)
{
	X_LOG_OP("%ld RESP SUCCESS dialect=%x", msg->mid, dialect);

	const x_smbd_t *smbd = smbd_conn->smbd;
	const std::shared_ptr<x_smbconf_t> smbconf = smbd_conn->get_smbconf();
	idl::NTTIME now = x_tick_to_nttime(tick_now);
	// x_nttime_t now = x_nttime_current();

	smbd_conn->dialect = dialect;

	uint16_t security_mode = SMB2_NEGOTIATE_SIGNING_ENABLED;
	if (smbconf->signing_required) {
		security_mode |= SMB2_NEGOTIATE_SIGNING_REQUIRED;
	}

	const std::vector<uint8_t> &security_blob = smbd->negprot_spnego;
	size_t dyn_len = security_blob.size();
#if 0
	if (negotiate_context.size() != 0) {
		dyn_len = negotiate_context_off = x_pad_len(security_blob.size(), 8);
		for (auto &nc: negotiate_context) {
			dyn_len += nc.second;
		}
	}
#else
	if (negotiate_context.size() != 0) {
		dyn_len = x_pad_len(security_blob.size(), 8);
		dyn_len += negotiate_context.size();
	}
#endif
	uint8_t *outbuf = new uint8_t[8 + 0x40 + 0x40 + dyn_len];
	uint8_t *outhdr = outbuf + 8;
	uint8_t *outbody = outhdr + 0x40;

	x_put_le16(outbody, 0x41);
	x_put_le16(outbody + 2, security_mode);
	x_put_le16(outbody + 4, dialect);
	x_put_le16(outbody + 6, negotiate_context_count);
	memcpy(outbody + 8, smbconf->guid, 16);
	x_put_le32(outbody + 0x18, smbd->capabilities);
	x_put_le32(outbody + 0x1c, smbconf->max_trans);
	x_put_le32(outbody + 0x20, smbconf->max_read);
	x_put_le32(outbody + 0x24, smbconf->max_write);

	x_put_le64(outbody + 0x28, now.val);	 /* system time */
	x_put_le64(outbody + 0x30, 0);	   /* server start time */

	size_t security_offset = SMB2_HDR_BODY + 0x40;

	x_put_le16(outbody + 0x38, security_offset);
	x_put_le16(outbody + 0x3a, security_blob.size());

	x_put_le32(outbody + 0x3c, 0);
	uint32_t offset = SMB2_HDR_BODY + 0x40;
	if (security_blob.size()) {
		memcpy(outhdr + offset, security_blob.data(), security_blob.size());
		offset += security_blob.size();
	}
#if 0
	if (negotiate_context.size() != 0) {
		size_t padlen = x_pad_len(dyn_off, 8);
		memset(outdyn + dyn_off, 0, padlen - dyn_off);
		dyn_off += padlen - dyn_off;
	}
	for (auto &nc: negotiate_context) {
		memcpy(outdyn + dyn_off, nc.first, nc.second);
		dyn_off += nc.second;
	}
#else
	if (negotiate_context.size() != 0) {
		uint32_t padlen = x_pad_len(offset, 8);
		memset(outhdr + offset, 0, padlen - offset);
		offset = padlen;
		x_put_le32(outbody + 0x3c, offset);
		memcpy(outhdr + offset, negotiate_context.data(), negotiate_context.size());
		offset += negotiate_context.size();
	}
#endif
	if (dialect != SMB2_DIALECT_REVISION_2FF) {
		smbd_conn->server_security_mode = security_mode;
		smbd_conn->server_capabilities = smbd->capabilities;
	}

	x_smbd_conn_reply(smbd_conn, msg, nullptr,
			dialect >= SMB3_DIALECT_REVISION_310 ? &smbd_conn->preauth : nullptr,
			outbuf, 0, NT_STATUS_OK, offset - 0x40);
	return 0;
}

int x_smbd_conn_process_smb1negoprot(x_smbd_conn_t *smbd_conn, x_msg_t *msg,
		const uint8_t *buf, size_t len)
{
	uint8_t wct = buf[HDR_WCT];
	uint16_t vwv = buf[HDR_VWV] + (buf[HDR_VWV + 1] << 8);
	if (len < (size_t)HDR_WCT + 2 *wct + vwv) {
		return -EBADMSG;
	}
	if (vwv == 0) {
		// TODO reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return -EBADMSG;
	}
	const uint8_t *negobuf = buf + HDR_WCT + 3 + 2 * wct;
	if (negobuf[vwv - 1] != '\0') {
		// TODO reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return -EBADMSG;
	}
	// const uint8_t *p = negobuf + 1;
	// TODO check if support smb2
	

	return x_smbd_conn_reply_negprot(smbd_conn, msg, 0x2ff, 0, {});
}

uint16_t x_smb2_dialect_match(x_smbd_conn_t *smbd_conn,
		const void *dialects,
		size_t dialect_count)
{
	const std::shared_ptr<x_smbconf_t> smbconf = smbd_conn->get_smbconf();
	for (auto sdialect: smbconf->dialects) {
		const uint8_t *data = (const uint8_t *)dialects;
		for (unsigned int di = 0; di < dialect_count; ++di) {
			uint16_t cdialect = x_get_le16(data);
			if (sdialect == cdialect) {
				return sdialect;
			}
			data += 2;
		}
	}
	return SMB2_DIALECT_REVISION_000;
}

enum {
	AES128_GCM = 1,
	AES128_CCM = 2,
};

static NTSTATUS parse_context(const uint8_t *in_context, uint32_t in_context_length,
		uint32_t in_context_count, uint32_t &ciphers)
{
	uint32_t offset = 0;
	for (uint32_t ci = 0; ci < in_context_count; ++ci) {
		if (offset + 8 > in_context_length) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		uint16_t type = x_get_le16(in_context + offset);
		uint16_t length = x_get_le16(in_context + offset + 2);
		uint32_t end = offset + 8 + length;
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

static uint16_t generate_context(
	std::vector<uint8_t> &output,
	uint16_t cipher)
{
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
	uint32_t ctx_len = x_pad_len(data - output.data(), 8);
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
	return 2;
}




enum { SMB2_NEGPROT_BODY_LEN = 0x24, };
int x_smb2_process_NEGPROT(x_smbd_conn_t *smbd_conn, x_msg_t *msg,
		const uint8_t *in_buf, size_t in_len)
{
	// x_smb2_verify_size(msg, X_SMB2_NEGPROT_BODY_LEN);
	if (in_len < 0x40 + 0x24) {
		return -EBADMSG;
	}

	const uint8_t *in_body = in_buf + 0x40;
	uint16_t dialect_count = x_get_le16(in_body + 0x2);
	if (dialect_count == 0) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, 0, NT_STATUS_INVALID_PARAMETER);
	}
	size_t dyn_len = in_len - SMB2_HDR_LENGTH - SMB2_NEGPROT_BODY_LEN;
	if (dialect_count * 2 > dyn_len) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, 0, NT_STATUS_INVALID_PARAMETER);
	}

	uint16_t in_security_mode = x_get_le16(in_body + 0x04);
	uint32_t in_capabilities = x_get_le32(in_body + 0x08);

	X_LOG_OP("%ld NEGPROT", msg->mid);

	const uint8_t *in_dyn = in_body + SMB2_NEGPROT_BODY_LEN;
	uint16_t dialect = x_smb2_dialect_match(smbd_conn, in_dyn, dialect_count);
	if (dialect == SMB2_DIALECT_REVISION_000) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, 0, NT_STATUS_NOT_SUPPORTED);
	}

	smbd_conn->client_security_mode = in_security_mode;
	smbd_conn->client_capabilities = in_capabilities;
	idl::x_ndr_pull(smbd_conn->client_guid, in_body + 0x0c, 0x24, 0);
	
	uint16_t out_negotiate_context_count = 0;
	std::vector<uint8_t> out_negotiate_context;
	if (dialect >= SMB3_DIALECT_REVISION_310) {
		uint32_t in_context_offset = x_get_le32(in_body + 0x1c);
		uint32_t in_context_count = x_get_le16(in_body + 0x20);
		if (!x_check_range(in_context_offset, 0, 
					0x40 + SMB2_NEGPROT_BODY_LEN, in_len)) {
			return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, 0, NT_STATUS_INVALID_PARAMETER);
		}

		const uint8_t *in_context = in_buf + in_context_offset;

		uint32_t ciphers = 0;
		NTSTATUS status = parse_context(in_context, in_len - in_context_offset,
				in_context_count, ciphers);
		if (!NT_STATUS_IS_OK(status)) {
			return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, 0, status);
		}

		smbd_conn->preauth.update(in_buf, in_len);
		if (ciphers & AES128_GCM) {
			smbd_conn->cipher = SMB2_ENCRYPTION_AES128_GCM;
		} else if (ciphers & AES128_CCM) {
			smbd_conn->cipher = SMB2_ENCRYPTION_AES128_CCM;
		}

		out_negotiate_context_count = generate_context(out_negotiate_context, smbd_conn->cipher);
	}

	return x_smbd_conn_reply_negprot(smbd_conn, msg, dialect, out_negotiate_context_count, out_negotiate_context);
}


