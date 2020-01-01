#include "smbd.hxx"
#include "core.hxx"

static int x_smbdconn_reply_negprot(x_smbdconn_t *smbdconn, x_msg_t *msg,
		uint16_t dialect,
		const std::vector<std::pair<const uint8_t *, size_t>> &negotiate_context)
{
	const x_smbd_t *smbd = smbdconn->smbd;
	const x_smbconf_t &conf = smbdconn->get_conf();
	x_nttime_t now = x_nttime_current();

	smbdconn->dialect = dialect;

	uint16_t security_mode = SMB2_NEGOTIATE_SIGNING_ENABLED;
	uint32_t capabilities = SMB2_CAP_DFS | SMB2_CAP_LARGE_MTU | SMB2_CAP_LEASING;

	uint16_t negotiate_context_off = 0;
	const std::vector<uint8_t> &security_blob = smbd->negprot_spnego;
	size_t dyn_len = security_blob.size();
	if (negotiate_context.size() != 0) {
		dyn_len = negotiate_context_off = x_pad_len(security_blob.size(), 8);
		for (auto &nc: negotiate_context) {
			dyn_len += nc.second;
		}
	}

	uint8_t *outbuf = new uint8_t[8 + 0x40 + 0x40 + dyn_len];
	uint8_t *outhdr = outbuf + 8;
	uint8_t *outbody = outhdr + 0x40;

	x_put_le16(outbody, 0x41);
	x_put_le16(outbody + 2, security_mode);
	x_put_le16(outbody + 4, dialect);
	x_put_le16(outbody + 6, negotiate_context.size());
	memcpy(outbody + 8, conf.guid, 16);
	x_put_le32(outbody + 0x18, capabilities);
	x_put_le32(outbody + 0x1c, conf.max_trans);
	x_put_le32(outbody + 0x20, conf.max_read);
	x_put_le32(outbody + 0x24, conf.max_write);

	x_put_le64(outbody + 0x28, now);         /* system time */
	x_put_le64(outbody + 0x30, 0);           /* server start time */

	size_t security_offset = SMB2_HDR_BODY + 0x40;

	x_put_le16(outbody + 0x38, security_offset);
	x_put_le16(outbody + 0x3a, security_blob.size());

	x_put_le32(outbody + 0x3c, negotiate_context_off);
	uint8_t *outdyn = outbody + 0x40;
	size_t dyn_off = 0;
	if (security_blob.size()) {
		memcpy(outdyn, security_blob.data(), security_blob.size());
		dyn_off += security_blob.size();
	}

	if (negotiate_context.size() != 0) {
		size_t padlen = x_pad_len(dyn_off, 8);
		memset(outdyn + dyn_off, 0, padlen - dyn_off);
		dyn_off += padlen - dyn_off;
	}
	for (auto &nc: negotiate_context) {
		memcpy(outdyn + dyn_off, nc.first, nc.second);
		dyn_off += nc.second;
	}

	// smbd_smb2_request_done_ex
	memset(outhdr, 0, 0x40);
	x_put_le32(outhdr + SMB2_HDR_PROTOCOL_ID, SMB2_MAGIC);
	x_put_le16(outhdr + SMB2_HDR_LENGTH,  SMB2_HDR_BODY);
	x_put_le16(outhdr + SMB2_HDR_CREDIT_CHARGE,  0);
	x_put_le32(outhdr + SMB2_HDR_STATUS, 0);
	x_put_le16(outhdr + SMB2_HDR_OPCODE, SMB2_OP_NEGPROT);
	x_put_le16(outhdr + SMB2_HDR_CREDIT, 1);
	x_put_le32(outhdr + SMB2_HDR_FLAGS, SMB2_HDR_FLAG_REDIRECT);
	x_put_le32(outhdr + SMB2_HDR_NEXT_COMMAND, 0);
	x_put_le64(outhdr + SMB2_HDR_MESSAGE_ID, msg->mid);

	uint8_t *outnbt = outbuf + 4;
	x_put_be32(outnbt, 0x80 + dyn_off);

	msg->out_buf = outbuf;
	msg->out_off = 4;
	msg->out_len = 4 + 0x80 + dyn_off;

	msg->state = x_msg_t::STATE_COMPLETE;
	x_smbdconn_reply(smbdconn, msg);
	return 0;
}

int x_smbdconn_process_smb1negoprot(x_smbdconn_t *smbdconn, x_msg_t *msg,
		const uint8_t *buf, size_t len)
{
	uint8_t wct = buf[HDR_WCT];
	uint16_t vwv = buf[HDR_VWV] + (buf[HDR_VWV + 1] << 8);
	if (len < HDR_WCT + 2 *wct + vwv) {
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
	

	return x_smbdconn_reply_negprot(smbdconn, msg, 0x2ff, {});
}

static uint16_t x_smb2_dialect_match(x_smbdconn_t *smbdconn,
		const uint8_t *in_dyn,
		size_t dialect_count)
{
	const x_smbconf_t &smbconf = smbdconn->get_conf();
	for (auto sdialect: smbconf.dialects) {
		for (unsigned int di = 0; di < dialect_count; ++di) {
			uint16_t cdialect = x_get_le16(in_dyn + di * 2);
			if (sdialect == cdialect) {
				return sdialect;
			}
		}
	}
	return SMB2_DIALECT_REVISION_000;
}

enum { SMB2_NEGPROT_BODY_LEN = 0x24, };
int x_smb2_process_NEGPROT(x_smbdconn_t *smbdconn, x_msg_t *msg,
		const uint8_t *in_buf, size_t in_len)
{
	// x_smb2_verify_size(msg, X_SMB2_NEGPROT_BODY_LEN);
	if (in_len < 0x40 + 0x24) {
		return -EBADMSG;
	}

	const uint8_t *in_body = in_buf + 0x40;
	uint16_t dialect_count = x_get_le16(in_body + 0x2);
	if (dialect_count == 0) {
		return x_smb2_reply_error(smbdconn, msg, NT_STATUS_INVALID_PARAMETER);
	}
	size_t dyn_len = in_len - SMB2_HDR_LENGTH - SMB2_NEGPROT_BODY_LEN;
	if (dialect_count * 2 > dyn_len) {
		return x_smb2_reply_error(smbdconn, msg, NT_STATUS_INVALID_PARAMETER);
	}

	// TODO uint16_t in_security_mode = x_get_le16(in_body + 0x04);
	// TODO uint32_t in_capabilities = x_get_le32(in_body + 0x08);

	const uint8_t *in_dyn = in_body + SMB2_NEGPROT_BODY_LEN;
	uint16_t dialect = x_smb2_dialect_match(smbdconn, in_dyn, dialect_count);
	if (dialect == SMB2_DIALECT_REVISION_000) {
		return x_smb2_reply_error(smbdconn, msg, NT_STATUS_NOT_SUPPORTED);
	}
#if 0
	if (dialect >= SMB2_DIALECT_310) {
		// TODO preauth
		X_ASSERT(false);
	}
#endif
	return x_smbdconn_reply_negprot(smbdconn, msg, dialect, {});
}


