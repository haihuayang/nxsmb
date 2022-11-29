
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


