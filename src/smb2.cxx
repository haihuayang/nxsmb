
#include "smb2.hxx"

bool x_smb2_basic_info_decode(x_smb2_basic_info_t &basic_info,
		const std::vector<uint8_t> &in_data)
{
	/* x_smb2_basic_info_t size is not 0x24 */
	if (in_data.size() < 0x24) {
		return false;
	}
	/* TODO bigendian */
	x_smb2_basic_info_t *in_info = (x_smb2_basic_info_t *)in_data.data();
	basic_info.creation = in_info->creation;
	basic_info.last_access = in_info->last_access;
	basic_info.last_write = in_info->last_write;
	basic_info.change = in_info->change;
	basic_info.file_attributes = in_info->file_attributes;
	return true;
}

bool x_smb2_rename_info_decode(bool &replace_if_exists,
		std::u16string &file_name,
		const std::vector<uint8_t> &in_data)
{
	if (in_data.size() < sizeof(x_smb2_rename_info_t)) {
		return false;
	}
	const x_smb2_rename_info_t *in_info = (x_smb2_rename_info_t *)in_data.data();
	uint32_t file_name_length = X_LE2H32(in_info->file_name_length);
	if ((file_name_length % 2) != 0 || file_name_length + sizeof(x_smb2_rename_info_t) > in_data.size()) {
		return false;
	}
	const char16_t *in_name = (const char16_t *)(in_info + 1);
	file_name.assign(in_name, in_name + file_name_length / 2);
	replace_if_exists = in_info->replace_if_exists;
	return true;
}

NTSTATUS x_smb2_notify_marshall(
		const std::vector<std::pair<uint32_t, std::u16string>> &notify_changes,
		uint32_t max_offset,
		std::vector<uint8_t> &output)
{
	output.resize(std::min(max_offset, 1024u));

	uint32_t offset = 0;
	uint32_t rec_size = 0;
	for (const auto &change: notify_changes) {
		uint32_t pad_len = x_convert_assert<uint32_t>(x_pad_len(rec_size, 4));
		rec_size = x_convert_assert<uint32_t>(12 + 2 * change.second.size());
		uint32_t new_size = offset + pad_len + rec_size;
		if (new_size > max_offset) {
			offset = rec_size = 0;
			break;
		}
		if (new_size > output.size()) {
			output.resize(new_size);
		}
		x_put_le32(output.data() + offset, pad_len); // last rec's next offset
		offset += pad_len;
		x_put_le32(output.data() + offset + 4, change.first);
		x_put_le32(output.data() + offset + 8, x_convert_assert<uint32_t>(change.second.size() * 2));
		memcpy(output.data () + offset + 12, change.second.data(), change.second.size() * 2);
	}
	output.resize(offset + rec_size);
	return output.empty() ?  NT_STATUS_NOTIFY_ENUM_DIR : NT_STATUS_OK;
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
	return SMB2_DIALECT_REVISION_000;
}

