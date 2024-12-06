
#include "include/charset.hxx"
#include "smb2.hxx"

static bool name_is_dollar_data(const char16_t *begin, const char16_t *end)
{
	static const char16_t dollar_data[] = u"$DATA";
	if (end - begin == 5) {
		const char16_t *dd = dollar_data;
		for ( ; begin != end; ++begin, ++dd) {
			if (*dd == *begin) {
				continue;
			}
			/* we do not need to convert to codepoint to compare
			 * dollar_data
			 */
			auto upper = x_toupper(*begin);
			if (upper != *dd) {
				return false;
			}
		}
		return true;
	}
	return false;
}

NTSTATUS x_smb2_parse_stream_name(std::u16string &stream_name,
		bool &is_dollar_data,
		const char16_t *begin, const char16_t *end)
{
	// check_path_syntax_internal
	const char16_t *sep = nullptr;
	const char16_t *pch;
	for (pch = begin ; pch < end; ++pch) {
		char16_t ch = *pch;
		if (ch == u'/' || ch == u'\\') {
			return NT_STATUS_OBJECT_NAME_INVALID;
		}
		if (ch == u':') {
			if (sep) {
				return NT_STATUS_OBJECT_NAME_INVALID;
			}
			sep = pch;
		}
	}

	if (sep) {
		if (!name_is_dollar_data(sep + 1, end)) {
			return NT_STATUS_OBJECT_NAME_INVALID;
		}
		stream_name = x_utf16le_decode(begin, sep);
		/* is_dollar_data is true when stream name is empty */
		is_dollar_data = (begin == sep);
	} else {
		if (begin == end) {
			return NT_STATUS_OBJECT_NAME_INVALID;
		}
		stream_name = x_utf16le_decode(begin, end);
		is_dollar_data = false;
	}
	return NT_STATUS_OK;
}

bool x_smb2_file_basic_info_decode(x_smb2_file_basic_info_t &basic_info,
		const std::vector<uint8_t> &in_data)
{
	if (in_data.size() < sizeof(x_smb2_file_basic_info_t)) {
		return false;
	}
	/* TODO bigendian */
	x_smb2_file_basic_info_t *in_info = (x_smb2_file_basic_info_t *)in_data.data();
	basic_info.creation = in_info->creation;
	basic_info.last_access = in_info->last_access;
	basic_info.last_write = in_info->last_write;
	basic_info.change = in_info->change;
	basic_info.file_attributes = in_info->file_attributes;
	return true;
}

NTSTATUS x_smb2_rename_info_decode(bool &replace_if_exists,
		std::u16string &path, std::u16string &stream_name,
		const std::vector<uint8_t> &in_data)
{
	if (in_data.size() < sizeof(x_smb2_rename_info_t)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	const x_smb2_rename_info_t *in_info = (x_smb2_rename_info_t *)in_data.data();
	uint32_t file_name_length = X_LE2H32(in_info->file_name_length);
	if ((file_name_length % 2) != 0 || file_name_length + sizeof(x_smb2_rename_info_t) > in_data.size()) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (file_name_length == 0) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	}

	const char16_t *in_name_begin = (const char16_t *)(in_info + 1);
	const char16_t *in_name_end = in_name_begin + file_name_length / 2;
	const char16_t *sep = x_next_sep(in_name_begin, in_name_end, u':');
	if (sep == in_name_end) {
		path = x_utf16le_decode(in_name_begin, in_name_end);
		stream_name.clear();
	} else if (sep == in_name_begin) {
		bool is_dollar_data;
		NTSTATUS status = x_smb2_parse_stream_name(stream_name,
				is_dollar_data, sep + 1, in_name_end);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		path.clear();
	} else {
		/* rename not allow both path and stream */
		return NT_STATUS_NOT_SUPPORTED;
	}

	replace_if_exists = in_info->replace_if_exists;
	return NT_STATUS_OK;
}

struct x_smb2_file_notify_info_t
{
	uint32_t next_offset;
	uint32_t action;
	uint32_t file_name_length;
	char16_t file_name[];
};

size_t x_smb2_notify_marshall(
		const std::vector<std::pair<uint32_t, std::u16string>> &notify_changes,
		uint8_t *buf, size_t max_offset)
{
	x_smb2_chain_marshall_t marshall{buf, buf + max_offset, 4};
	uint8_t *pbegin;
	uint32_t rec_size = 0;
	for (const auto &change: notify_changes) {
		rec_size = x_convert_assert<uint32_t>(sizeof(x_smb2_file_notify_info_t) + 2 * change.second.size());
		pbegin = marshall.get_begin(rec_size);
		if (!pbegin) {
			return 0;
		}
		
		x_smb2_file_notify_info_t *info = (x_smb2_file_notify_info_t *)pbegin;
		info->next_offset = 0;
		info->action = X_H2LE32(change.first);
		info->file_name_length = X_H2LE32(x_convert_assert<uint32_t>(change.second.size() * 2));
		x_utf16le_encode(change.second, info->file_name);
	}
	return marshall.get_size();
}

uint16_t x_smb2_dialect_match(const std::vector<uint16_t> &sdialects,
		const uint16_t *dialects,
		size_t dialect_count)
{
	for (auto sdialect: sdialects) {
		for (unsigned int di = 0; di < dialect_count; ++di) {
			uint16_t cdialect = X_LE2H16(dialects[di]);
			if (sdialect == cdialect) {
				return sdialect;
			}
		}
	}
	return X_SMB2_DIALECT_000;
}

std::ostream &operator<<(std::ostream &os, const x_smb2_uuid_t &val)
{
	char buf[80];
	snprintf(buf, sizeof buf, "%016lx-%016lx", val.data[0], val.data[1]);
	return os << buf;
}

struct x_smb2_create_context_header_t
{
	uint32_t chain_offset;
	uint16_t tag_offset;
	uint16_t tag_length;
	uint16_t unused0;
	uint16_t data_offset;
	uint32_t data_length;
};

static const uint8_t X_SMB2_CREATE_TAG_APP_INSTANCE_ID[] = {
	0x45, 0xBC, 0xA6, 0x6A, 0xEF, 0xA7, 0xF7, 0x4A,
	0x90, 0x08, 0xFA, 0x46, 0x2E, 0x14, 0x4D, 0x74,
};

static const uint8_t X_SMB2_CREATE_TAG_APP_INSTANCE_VERSION[] = {
	0xB9, 0x82, 0xD0, 0xB7, 0x3B, 0x56, 0x07, 0x4F,
	0xA0, 0x7B, 0x52, 0x4A, 0x81, 0x16, 0xA0, 0x10,
};

struct x_smb2_create_requ_app_instance_id_t
{
	uint16_t struct_size;
	uint16_t reserved0;
	x_smb2_uuid_bytes_t app_instance_id;
};

struct x_smb2_create_requ_app_instance_version_t
{
	uint16_t struct_size;
	uint16_t reserved0;
	uint32_t reserved1;
	uint64_t app_instance_version_high;
	uint64_t app_instance_version_low;
};

static bool decode_smb2_lease(x_smb2_lease_t &lease,
		const uint8_t *data, uint32_t length)
{
	const x_smb2_lease_t *in_lease = (const x_smb2_lease_t *)data;
	if (length == 52) {
		lease.key = in_lease->key;
		lease.state = X_LE2H32(in_lease->state);
		lease.flags = X_LE2H32(in_lease->flags) & X_SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET;
		lease.duration = X_LE2H64(in_lease->duration);
		if (lease.flags & X_SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET) {
			lease.parent_key = in_lease->parent_key;
		}
		lease.epoch = X_LE2H16(in_lease->epoch);
		lease.version = 2;
	} else if (length == 32) {
		lease.key = in_lease->key;
		lease.state = X_LE2H32(in_lease->state);
		lease.flags = 0;
		lease.duration = X_LE2H64(in_lease->duration);
		lease.version = 1;
	} else {
		return false;
	}
	return true;
}

static uint32_t encode_smb2_lease(const x_smb2_lease_t &lease,
		uint8_t *data)
{
	x_smb2_lease_t *out_lease = (x_smb2_lease_t *)data;
	out_lease->key = lease.key;
	out_lease->state = X_H2LE32(lease.state);
	out_lease->flags = X_H2LE32(lease.flags);
	out_lease->duration = X_H2LE64(lease.duration);
	if (lease.version == 2) {
		out_lease->parent_key = lease.parent_key;
		out_lease->epoch = X_H2LE16(lease.epoch);
		out_lease->version = 0;
		out_lease->unused = 0;
		return 52;
	} else {
		return 32;
	}
}

bool x_smb2_create_requ_context_t::decode(uint16_t dialect, const uint8_t *data, uint32_t length)
{
	const x_smb2_create_dhnc_requ_t *dhnc = nullptr;
	const x_smb2_create_dh2q_requ_t *dh2q = nullptr;
	const x_smb2_create_dh2c_requ_t *dh2c = nullptr;
	uint32_t in_contexts = 0;

	while (length > 0) {
		if (length < sizeof(x_smb2_create_context_header_t)) {
			return false;
		}

		const x_smb2_create_context_header_t *ch = (const x_smb2_create_context_header_t *)data;
		uint32_t chain_off = X_LE2H32(ch->chain_offset);
		uint16_t tag_off = X_LE2H16(ch->tag_offset);
		uint16_t tag_len = X_LE2H16(ch->tag_length); // we assume tag_len is 2 bytes
		uint16_t data_off = X_LE2H16(ch->data_offset);
		uint32_t data_len = X_LE2H32(ch->data_length);

		uint32_t clen;
		if (chain_off != 0) {
			if (chain_off + 0x10 > length) {
				return false;
			}
			clen = chain_off;
		} else {
			clen = length;
		}

		if (!x_check_range<uint32_t>(tag_off, tag_len, 0, clen)) {
			return false;
		}

		if (!x_check_range<uint32_t>(data_off, data_len, 0, clen)) {
			return false;
		}

		if (tag_len == 4) {
			uint32_t tag = x_get_be32(data + tag_off);
			if (tag == X_SMB2_CREATE_TAG_RQLS) {
				if (decode_smb2_lease(lease,
							data + data_off,
							data_len)) {
					in_contexts |= X_SMB2_CONTEXT_FLAG_RQLS;
				}
			} else if (tag == X_SMB2_CREATE_TAG_QFID) {
				in_contexts |= X_SMB2_CONTEXT_FLAG_QFID;
			} else if (tag == X_SMB2_CREATE_TAG_ALSI) {
				if (data_len != sizeof(uint64_t)) {
					return false;
				}
				const uint64_t *pdata = (uint64_t *)(data + data_off);
				allocation_size = X_LE2H64(*pdata);
				in_contexts |= X_SMB2_CONTEXT_FLAG_ALSI;
			} else if (tag == X_SMB2_CREATE_TAG_TWRP) {
				if (data_len != sizeof(uint64_t)) {
					return false;
				}
				const uint64_t *pdata = (uint64_t *)(data + data_off);
				twrp = X_LE2H64(*pdata);
			} else if (tag == X_SMB2_CREATE_TAG_MXAC) {
				in_contexts |= X_SMB2_CONTEXT_FLAG_MXAC;
			} else if (tag == X_SMB2_CREATE_TAG_SECD) {
				auto sd = std::make_shared<idl::security_descriptor>();
				idl::x_ndr_off_t ret = idl::x_ndr_pull(*sd,
						data + data_off, data_len, 0);
				if (ret <= 0) {
					X_LOG(SMB, WARN, "failed parsing TAG_SECD, ndr %ld", ret);
					return false;
				}
				security_descriptor = sd;
			} else if (tag == X_SMB2_CREATE_TAG_EXTA) {
				// TODO;
			} else if (tag == X_SMB2_CREATE_TAG_DHNQ) {
				/* MS-SMB2 2.2.13.2.3 ignore data content */
				if (data_len != 16) {
					return false;
				}
				in_contexts |= X_SMB2_CONTEXT_FLAG_DHNQ;
			} else if (tag == X_SMB2_CREATE_TAG_DHNC) {
				if (data_len != sizeof(x_smb2_create_dhnc_requ_t)) {
					return false;
				}
				dhnc = (const x_smb2_create_dhnc_requ_t *)(data + data_off);
				in_contexts |= X_SMB2_CONTEXT_FLAG_DHNC;
			} else if (tag == X_SMB2_CREATE_TAG_DH2Q) {
				if (data_len != sizeof(x_smb2_create_dh2q_requ_t)) {
					return false;
				}
				dh2q = (const x_smb2_create_dh2q_requ_t *)(data + data_off);
				in_contexts |= X_SMB2_CONTEXT_FLAG_DH2Q;
			} else if (tag == X_SMB2_CREATE_TAG_DH2C) {
				if (data_len != sizeof(x_smb2_create_dh2c_requ_t)) {
					return false;
				}
				dh2c = (const x_smb2_create_dh2c_requ_t *)(data + data_off);
				in_contexts |= X_SMB2_CONTEXT_FLAG_DH2C;
			} else if (tag == X_SMB2_CREATE_TAG_AAPL) {
				// TODO
			} else {
				X_LOG(SMB, WARN, "unknown create context 0x%x", tag);
			}

		} else if (tag_len == 16) {
			if (memcmp(data + tag_off, X_SMB2_CREATE_TAG_APP_INSTANCE_ID, 16) == 0) {
				if (dialect >= X_SMB2_DIALECT_300) {
					if (data_len != sizeof(x_smb2_create_requ_app_instance_id_t)) {
						return false;
					}
					auto ctx = (const x_smb2_create_requ_app_instance_id_t *)(data + data_off);
					uint16_t struct_size = X_LE2H16(ctx->struct_size);
					if (struct_size != sizeof(x_smb2_create_requ_app_instance_id_t)) {
						return false;
					}
					in_contexts |= X_SMB2_CONTEXT_FLAG_APP_INSTANCE_ID;
					this->app_instance_id.from_bytes(ctx->app_instance_id);
				}
			} else if (memcmp(data + tag_off, X_SMB2_CREATE_TAG_APP_INSTANCE_VERSION, 16) == 0) {
				if (dialect >= X_SMB2_DIALECT_311) {
					if (data_len != sizeof(x_smb2_create_requ_app_instance_version_t)) {
						return false;
					}
					auto ctx = (const x_smb2_create_requ_app_instance_version_t *)(data + data_off);
					uint16_t struct_size = X_LE2H16(ctx->struct_size);
					if (struct_size != sizeof(x_smb2_create_requ_app_instance_version_t)) {
						return false;
					}
					in_contexts |= X_SMB2_CONTEXT_FLAG_APP_INSTANCE_VERSION;
					this->app_instance_version_high = ctx->app_instance_version_high;
					this->app_instance_version_low = ctx->app_instance_version_low;
				}
			} else {
				X_LOG(SMB, WARN, "unknown create context");
			}

		} else if (tag_len < 4) {
			/* return NT_STATUS_INVALID_PARAMETER if tag_len < 4 */
			X_LOG(SMB, WARN, "unknown create context tag_len=%d", tag_len);
			return false;
		} else {
			/* ignore */
			X_LOG(SMB, WARN, "unknown create context tag_len=%d", tag_len);
		}

		data += clen;
		length -= clen;
	}

	if ((x_bit_any<uint32_t>(in_contexts, X_SMB2_CONTEXT_FLAG_DHNQ |
				X_SMB2_CONTEXT_FLAG_DHNC) &&
			x_bit_any<uint32_t>(in_contexts, X_SMB2_CONTEXT_FLAG_DH2Q |
				X_SMB2_CONTEXT_FLAG_DH2C)) ||
			x_bit_all<uint32_t>(in_contexts, X_SMB2_CONTEXT_FLAG_DH2Q |
				X_SMB2_CONTEXT_FLAG_DH2C)) {
		X_LOG(SMB, ERR, "Invalid combination of durable contexts");
		return false;
	}

	if (in_contexts & X_SMB2_CONTEXT_FLAG_DH2Q) {
		this->dh_timeout = X_LE2H32(dh2q->timeout);
		this->dh_flags = X_LE2H32(dh2q->flags);
		this->create_guid = {dh2q->create_guid[0], dh2q->create_guid[1]};
	} else if (in_contexts & X_SMB2_CONTEXT_FLAG_DH2C) {
		this->dh_id_persistent = X_LE2H64(dh2c->file_id_persistent);
		this->dh_id_volatile = X_LE2H64(dh2c->file_id_volatile);
		this->create_guid = {dh2c->create_guid[0], dh2c->create_guid[1]};
		this->dh_flags = X_LE2H32(dh2c->flags);
		in_contexts &= ~(X_SMB2_CONTEXT_FLAG_APP_INSTANCE_ID | X_SMB2_CONTEXT_FLAG_APP_INSTANCE_VERSION);
		this->app_instance_id = {};
		this->app_instance_version_high = 0;
		this->app_instance_version_low = 0;
	} else if (in_contexts & X_SMB2_CONTEXT_FLAG_DHNC) {
		in_contexts &= ~X_SMB2_CONTEXT_FLAG_DHNQ;
		this->dh_id_persistent = X_LE2H64(dhnc->file_id_persistent);
		this->dh_id_volatile = X_LE2H64(dhnc->file_id_volatile);
	}

	this->bits = in_contexts;
	return true;
}

template <class Context>
static void encode_context_one(Context &&ctx,
		x_smb2_create_context_header_t *&ch,
		uint8_t *&curr, uint8_t *begin,
		uint32_t tag)
{
	if (ch) {
		uint8_t *ncurr = begin + x_pad_len(curr - begin, 8);
		while (curr != ncurr) {
			*curr++ = 0;
		}
		ch->chain_offset = X_H2LE32(x_convert_assert<uint32_t>(curr - (uint8_t *)ch));
	}

	ch = (x_smb2_create_context_header_t *)curr;
	ch->tag_offset = X_H2LE16(0x10);
	ch->tag_length = X_H2LE16(0x4);
	ch->unused0 = 0;
	ch->data_offset = X_H2LE16(0x18);

	curr = (uint8_t *)(ch + 1);
	*(uint32_t *)curr = X_H2BE32(tag);
	curr += 4;
	*(uint32_t *)curr = 0;
	curr += 4;

	uint32_t data_len = ctx(curr);
	ch->data_length = X_H2LE32(data_len);
	curr += data_len;
}

static void encode_durable_v2_context(uint32_t timeout, uint32_t flags,
		x_smb2_create_context_header_t *&ch,
		uint8_t *&p,
		uint8_t *&out_ptr)
{
	encode_context_one([timeout, flags] (uint8_t *ptr) {
			x_smb2_create_dh2q_resp_t *dn2q = (x_smb2_create_dh2q_resp_t *)ptr;
			dn2q->timeout = X_H2LE32(timeout);
			dn2q->flags = X_H2LE32(flags);
			return x_convert<uint32_t>(sizeof(x_smb2_create_dh2q_resp_t));
		}, ch, p, out_ptr, X_SMB2_CREATE_TAG_DH2Q);
}

uint32_t x_smb2_create_resp_context_encode(
		uint8_t *out_ptr,
		const x_smb2_lease_t *lease,
		const uint32_t *maximal_access,
		const uint8_t *qfid_info,
		uint32_t out_contexts,
		uint32_t durable_flags,
		uint32_t durable_timeout_msec)
{
	uint8_t *p = out_ptr;
	x_smb2_create_context_header_t *ch = nullptr;

	if (lease) {
		encode_context_one([lease] (uint8_t *ptr) {
				return encode_smb2_lease(*lease, ptr);
			}, ch, p, out_ptr, X_SMB2_CREATE_TAG_RQLS);
	}

	if (maximal_access) {
		encode_context_one([maximal_access] (uint8_t *ptr) {
				uint32_t *data = (uint32_t *)ptr;
				data[0] = 0; /* MxAc INFO, query status */
				data[1] = X_H2LE32(*maximal_access);
				return 8;
			}, ch, p, out_ptr, X_SMB2_CREATE_TAG_MXAC);
	}

	if (qfid_info) {
		encode_context_one([qfid_info] (uint8_t *ptr) {
				memcpy(ptr, qfid_info, 32);
				return 32;
			}, ch, p, out_ptr, X_SMB2_CREATE_TAG_QFID);
	}

	if ((out_contexts & X_SMB2_CONTEXT_FLAG_DH2Q) != 0) {
		encode_durable_v2_context(durable_timeout_msec, durable_flags, ch, p, out_ptr);
	} else if ((out_contexts & X_SMB2_CONTEXT_FLAG_DHNQ) != 0) {
		encode_context_one([] (uint8_t *ptr) {
				memset(ptr, 0, 8);
				return 8;
			}, ch, p, out_ptr, X_SMB2_CREATE_TAG_DHNQ);
	}

	if (ch) {
		ch->chain_offset = 0;
	}
	return x_convert_assert<uint32_t>(p - out_ptr);
}

uint32_t x_smb2_create_requ_context_t::encode(uint8_t *out_ptr, uint32_t length) const
{
	uint8_t *p = out_ptr;
	x_smb2_create_context_header_t *ch = nullptr;

	if (bits & X_SMB2_CONTEXT_FLAG_RQLS) {
		encode_context_one([this] (uint8_t *ptr) {
				return encode_smb2_lease(this->lease, ptr);
			}, ch, p, out_ptr, X_SMB2_CREATE_TAG_RQLS);
	}

	if (bits & X_SMB2_CREATE_TAG_QFID) {
		encode_context_one([] (uint8_t *ptr) {
				return 0;
			}, ch, p, out_ptr, X_SMB2_CREATE_TAG_QFID);
	}

	if (bits & X_SMB2_CREATE_TAG_TWRP) {
		encode_context_one([this] (uint8_t *ptr) {
				*(uint64_t *)ptr = X_H2LE64(this->allocation_size);
				return 8;
			}, ch, p, out_ptr, X_SMB2_CREATE_TAG_TWRP);
	}

	if (bits & X_SMB2_CREATE_TAG_ALSI) {
		encode_context_one([this] (uint8_t *ptr) {
				*(uint64_t *)ptr = X_H2LE64(this->twrp);
				return 8;
			}, ch, p, out_ptr, X_SMB2_CREATE_TAG_ALSI);
	}

	if (bits & X_SMB2_CREATE_TAG_MXAC) {
		encode_context_one([] (uint8_t *ptr) {
				return 0;
			}, ch, p, out_ptr, X_SMB2_CREATE_TAG_MXAC);
	}

	if (security_descriptor) {
		encode_context_one([this] (uint8_t *ptr) {
				std::vector<uint8_t> buf;
				idl::x_ndr_off_t ret = idl::x_ndr_push(
						*this->security_descriptor, buf, 0);
				X_ASSERT(ret > 0);
				memcpy(ptr, buf.data(), buf.size());
				return x_convert_assert<uint32_t>(buf.size());
			}, ch, p, out_ptr, X_SMB2_CREATE_TAG_SECD);
	}

	/* TODO X_SMB2_CREATE_TAG_EXTA */
	if (bits & X_SMB2_CONTEXT_FLAG_DHNQ) {
		encode_context_one([] (uint8_t *ptr) {
				memset(ptr, 0, 16);
				return 16;
			}, ch, p, out_ptr, X_SMB2_CREATE_TAG_DHNQ);
	}

	if (bits & X_SMB2_CREATE_TAG_DHNC) {
		encode_context_one([this] (uint8_t *ptr) {
				uint64_t *data = (uint64_t *)ptr;
				data[0] = X_H2LE64(this->dh_id_persistent);
				data[1] = X_H2LE64(this->dh_id_volatile);
				return 16;
			}, ch, p, out_ptr, X_SMB2_CREATE_TAG_DHNC);
	}

	if (bits & X_SMB2_CREATE_TAG_DH2Q) {
		encode_context_one([this] (uint8_t *ptr) {
				x_smb2_create_dh2q_requ_t *dh2q = (x_smb2_create_dh2q_requ_t *)ptr;
				dh2q->timeout = X_H2LE32(this->dh_timeout);
				dh2q->flags = X_H2LE32(this->dh_flags);
				dh2q->create_guid[0] = this->create_guid.data[0];
				dh2q->create_guid[1] = this->create_guid.data[1];
				return x_convert<uint32_t>(sizeof(x_smb2_create_dh2q_requ_t));
			}, ch, p, out_ptr, X_SMB2_CREATE_TAG_DH2Q);
	}

	if (bits & X_SMB2_CREATE_TAG_DH2C) {
		encode_context_one([this] (uint8_t *ptr) {
				x_smb2_create_dh2c_requ_t *dh2c = (x_smb2_create_dh2c_requ_t *)ptr;
				dh2c->file_id_persistent = X_H2LE64(this->dh_id_persistent);
				dh2c->file_id_volatile = X_H2LE64(this->dh_id_volatile);
				dh2c->create_guid[0] = this->create_guid.data[0];
				dh2c->create_guid[1] = this->create_guid.data[1];
				dh2c->flags = X_H2LE32(this->dh_flags);
				return x_convert<uint32_t>(sizeof(x_smb2_create_dh2c_requ_t));
			}, ch, p, out_ptr, X_SMB2_CREATE_TAG_DHNC);
	}
	/* TODO X_SMB2_CONTEXT_FLAG_APP_INSTANCE_ID, X_SMB2_CONTEXT_FLAG_APP_INSTANCE_VERSION */
	if (ch) {
		ch->chain_offset = 0;
	}
	return x_convert_assert<uint32_t>(p - out_ptr);
}

bool x_smb2_create_resp_context_t::decode(const uint8_t *data, uint32_t length)
{
	uint32_t in_contexts = 0;

	while (length > 0) {
		if (length < sizeof(x_smb2_create_context_header_t)) {
			return false;
		}

		const x_smb2_create_context_header_t *ch = (const x_smb2_create_context_header_t *)data;
		uint32_t chain_off = X_LE2H32(ch->chain_offset);
		uint16_t tag_off = X_LE2H16(ch->tag_offset);
		uint16_t tag_len = X_LE2H16(ch->tag_length); // we assume tag_len is 2 bytes
		uint16_t data_off = X_LE2H16(ch->data_offset);
		uint32_t data_len = X_LE2H32(ch->data_length);

		uint32_t clen;
		if (chain_off != 0) {
			if (chain_off + 0x10 > length) {
				return false;
			}
			clen = chain_off;
		} else {
			clen = length;
		}

		if (!x_check_range<uint32_t>(tag_off, tag_len, 0, clen)) {
			return false;
		}

		if (!x_check_range<uint32_t>(data_off, data_len, 0, clen)) {
			return false;
		}

		if (tag_len == 4) {
			uint32_t tag = x_get_be32(data + tag_off);
			if (tag == X_SMB2_CREATE_TAG_RQLS) {
				if (decode_smb2_lease(lease,
							data + data_off,
							data_len)) {
					in_contexts |= X_SMB2_CONTEXT_FLAG_RQLS;
				}
			} else if (tag == X_SMB2_CREATE_TAG_QFID) {
				if (data_len != 32) {
					return false;
				}
				memcpy(qfid_info, data + data_off, 32);
				in_contexts |= X_SMB2_CONTEXT_FLAG_QFID;
			} else if (tag == X_SMB2_CREATE_TAG_MXAC) {
				if (data_len != 8) {
					return false;
				}
				uint32_t *ptr = (uint32_t *)(data + data_off);
				maximal_access = X_LE2H32(ptr[1]);
				/* TODO ptr[0] is the status */
				in_contexts |= X_SMB2_CONTEXT_FLAG_MXAC;
			} else if (tag == X_SMB2_CREATE_TAG_DHNQ) {
				/* MS-SMB2 2.2.13.2.3 ignore data content */
				in_contexts |= X_SMB2_CONTEXT_FLAG_DHNQ;
			} else if (tag == X_SMB2_CREATE_TAG_DH2Q) {
				if (data_len != sizeof(x_smb2_create_dh2q_resp_t)) {
					return false;
				}
				const x_smb2_create_dh2q_resp_t *dn2q = (const x_smb2_create_dh2q_resp_t *)(data + data_off);
				durable_timeout_msec = X_LE2H32(dn2q->timeout);
				durable_flags = X_LE2H32(dn2q->flags);
				in_contexts |= X_SMB2_CONTEXT_FLAG_DH2Q;
			} else {
				X_LOG(SMB, WARN, "unknown create context 0x%x", tag);
			}

		} else {
			/* ignore */
			X_LOG(SMB, WARN, "unknown create context tag_len=%d", tag_len);
		}

		data += clen;
		length -= clen;
	}

	bits = in_contexts;
	return true;
};

uint32_t x_smb2_create_resp_context_t::encode(uint8_t *out_ptr, uint32_t length) const
{
	return x_smb2_create_resp_context_encode(out_ptr,
			(bits & X_SMB2_CONTEXT_FLAG_RQLS) ? &lease : nullptr,
			(bits & X_SMB2_CONTEXT_FLAG_MXAC) ? &maximal_access : nullptr,
			(bits & X_SMB2_CONTEXT_FLAG_QFID) ? qfid_info : nullptr,
			bits, durable_flags, durable_timeout_msec);
}
