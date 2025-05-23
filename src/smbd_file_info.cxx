
#include "smbd_open.hxx"

/* copy from samba/source3/include/ntioctl.h */
#define IO_REPARSE_TAG_DFS	     0x8000000A

void x_smbd_get_file_info(x_smb2_file_basic_info_t &info,
		const x_smbd_object_meta_t &object_meta)
{
	x_smbd_push_time_info(info, object_meta);
	info.file_attributes = X_H2LE32(object_meta.file_attributes);
	info.unused = 0;
}

void x_smbd_get_file_info(x_smb2_file_standard_info_t &info,
		const x_smbd_object_meta_t &object_meta,
		const x_smbd_stream_meta_t &stream_meta,
		uint32_t access_mask,
		uint32_t mode,
		uint64_t current_offset)
{
	info.allocation_size = X_H2LE64(stream_meta.allocation_size);
	info.end_of_file = X_H2LE64(stream_meta.end_of_file);

	uint8_t delete_pending = stream_meta.delete_on_close ? 1 : 0;
	/* not sure why samba for nlink to 1 for directory, just follow it */
	uint32_t nlink = x_convert<uint32_t>(object_meta.nlink);
	if (nlink && object_meta.isdir()) {
		nlink = 1;
	}
	if (nlink > 0) {
		nlink -= delete_pending;
	}

	info.nlinks = X_H2LE32(nlink);
	info.delete_pending = delete_pending;
	info.directory = object_meta.isdir() ? 1 : 0;
	info.unused = 0;
}

void x_smbd_get_file_info(x_smb2_file_all_info_t &info,
		const x_smbd_object_meta_t &object_meta,
		const x_smbd_stream_meta_t &stream_meta,
		uint32_t access_mask,
		uint32_t mode,
		uint64_t current_offset)
{
	x_smbd_push_time_info(info.basic_info, object_meta);
	info.basic_info.file_attributes = X_H2LE32(object_meta.file_attributes);
	info.basic_info.unused = 0;

	x_smbd_get_file_info(info.standard_info, object_meta, stream_meta,
			access_mask,
			mode, current_offset);

	info.file_id = X_H2LE64(object_meta.inode);
	info.ea_size = 0; // not supported
	info.access_flags = X_H2LE32(access_mask);
	info.current_offset = X_H2LE64(current_offset);
	info.mode = X_H2LE32(mode);
	info.alignment_requirement = 0;
	info.file_name_length = 0;
	info.unused = 0;
}

void x_smbd_get_file_info(x_smb2_file_network_open_info_t &info,
		const x_smbd_object_meta_t &object_meta,
		const x_smbd_stream_meta_t &stream_meta)
{
	x_smbd_push_time_info(info, object_meta);
	info.allocation_size = X_H2LE64(stream_meta.allocation_size);
	info.end_of_file = X_H2LE64(stream_meta.end_of_file);
	info.file_attributes = X_H2LE32(object_meta.file_attributes);
	info.unused = 0;
}

void x_smbd_get_file_info(x_smb2_file_compression_info_t &info,
		const x_smbd_stream_meta_t &stream_meta)
{
	info.file_size = X_H2LE64(stream_meta.end_of_file);
	info.format = 0;
	info.unit_shift = 0;
	info.chunk_shift = 0;
	info.cluster_shift = 0;
	info.unused0 = 0;
	info.unused1 = 0;
}

void x_smbd_get_file_info(x_smb2_file_attribute_tag_info_t &info,
		const x_smbd_object_meta_t &object_meta)
{
	info.file_attributes = X_H2LE32(object_meta.file_attributes);
	info.reparse_tag = 0; // TODO not support for now
}

bool x_smbd_marshall_dir_entry(x_smb2_chain_marshall_t &marshall,
		const x_smbd_object_meta_t &object_meta,
		const x_smbd_stream_meta_t &stream_meta,
		const std::u16string &name,
		x_smb2_info_level_t info_level)
{
	uint8_t *pbegin;
	uint32_t rec_size;

	switch (info_level) {
	case x_smb2_info_level_t::FILE_ID_BOTH_DIR_INFORMATION:
		rec_size = x_convert_assert<uint32_t>(sizeof(x_smb2_file_id_both_dir_info_t) + name.size() * 2);
		pbegin = marshall.get_begin(rec_size);
		if (!pbegin) {
			return false;
		}
		{
			x_smb2_file_id_both_dir_info_t *info = (x_smb2_file_id_both_dir_info_t *)pbegin;
			info->next_offset = 0;
			info->file_index = 0;
			x_smbd_push_time_info(*info, object_meta);
			info->end_of_file = X_H2LE64(stream_meta.end_of_file);
			info->allocation_size = X_H2LE64(stream_meta.allocation_size);
			info->file_attributes = X_H2LE32(object_meta.file_attributes);
			info->file_name_length = X_H2LE32(x_convert_assert<uint32_t>(name.size() * 2));
			if (object_meta.file_attributes & X_SMB2_FILE_ATTRIBUTE_REPARSE_POINT) {
				info->ea_size = X_H2LE32(IO_REPARSE_TAG_DFS);
			} else {
				/*
				 * OS X specific SMB2 extension negotiated via
				 * AAPL create context: return max_access in
				 * ea_size field.
				 */
				info->ea_size = 0;
			}
		
			// TODO get short name
			info->short_name_length = 0;
			memset(info->short_name, 0, sizeof info->short_name);
			info->unused0 = 0; // aapl mode

			uint64_t file_index = object_meta.inode; // TODO
			info->file_id = X_H2LE64(file_index);
			x_utf16le_encode(name, info->file_name);
		}
		break;

	case x_smb2_info_level_t::FILE_ID_FULL_DIR_INFORMATION:
		rec_size = x_convert_assert<uint32_t>(sizeof(x_smb2_file_id_full_dir_info_t) + name.size() * 2);
		pbegin = marshall.get_begin(rec_size);
		if (!pbegin) {
			return false;
		}
		{
			x_smb2_file_id_full_dir_info_t *info = (x_smb2_file_id_full_dir_info_t *)pbegin;
			info->next_offset = 0;
			info->file_index = 0;
			x_smbd_push_time_info(*info, object_meta);
			info->end_of_file = X_H2LE64(stream_meta.end_of_file);
			info->allocation_size = X_H2LE64(stream_meta.allocation_size);
			info->file_attributes = X_H2LE32(object_meta.file_attributes);
			info->file_name_length = X_H2LE32(x_convert_assert<uint32_t>(name.size() * 2));
			if (object_meta.file_attributes & X_SMB2_FILE_ATTRIBUTE_REPARSE_POINT) {
				info->ea_size = X_H2LE32(IO_REPARSE_TAG_DFS);
			} else {
				/*
				 * OS X specific SMB2 extension negotiated via
				 * AAPL create context: return max_access in
				 * ea_size field.
				 */
				info->ea_size = 0;
			}
		
			info->unused0 = 0; // aapl mode

			info->file_id = X_H2LE64(object_meta.inode);
			x_utf16le_encode(name, info->file_name);
		}
		break;

	case x_smb2_info_level_t::FILE_DIRECTORY_INFORMATION:
		rec_size = x_convert_assert<uint32_t>(sizeof(x_smb2_file_dir_info_t) + name.size() * 2);
		pbegin = marshall.get_begin(rec_size);
		if (!pbegin) {
			return false;
		}
		{
			x_smb2_file_dir_info_t *info = (x_smb2_file_dir_info_t *)pbegin;
			info->next_offset = 0;
			info->file_index = 0;
			x_smbd_push_time_info(*info, object_meta);
			info->end_of_file = X_H2LE64(stream_meta.end_of_file);
			info->allocation_size = X_H2LE64(stream_meta.allocation_size);
			info->file_attributes = X_H2LE32(object_meta.file_attributes);
			info->file_name_length = X_H2LE32(x_convert_assert<uint32_t>(name.size() * 2));
			x_utf16le_encode(name, info->file_name);
		}
		break;

	case x_smb2_info_level_t::FILE_BOTH_DIR_INFORMATION:
		rec_size = x_convert_assert<uint32_t>(sizeof(x_smb2_file_both_dir_info_t) + name.size() * 2);
		pbegin = marshall.get_begin(rec_size);
		if (!pbegin) {
			return false;
		}
		{
			x_smb2_file_both_dir_info_t *info = (x_smb2_file_both_dir_info_t *)pbegin;
			info->next_offset = 0;
			info->file_index = 0;
			x_smbd_push_time_info(*info, object_meta);
			info->end_of_file = X_H2LE64(stream_meta.end_of_file);
			info->allocation_size = X_H2LE64(stream_meta.allocation_size);
			info->file_attributes = X_H2LE32(object_meta.file_attributes);
			info->file_name_length = X_H2LE32(x_convert_assert<uint32_t>(name.size() * 2));
			if (object_meta.file_attributes & X_SMB2_FILE_ATTRIBUTE_REPARSE_POINT) {
				info->ea_size = X_H2LE32(IO_REPARSE_TAG_DFS);
			} else {
				/*
				 * OS X specific SMB2 extension negotiated via
				 * AAPL create context: return max_access in
				 * ea_size field.
				 */
				info->ea_size = 0;
			}
		
			// TODO get short name
			info->short_name_length = 0;
			memset(info->short_name, 0, sizeof info->short_name);
			x_utf16le_encode(name, info->file_name);
		}
		break;

	case x_smb2_info_level_t::FILE_FULL_DIRECTORY_INFORMATION:
		rec_size = x_convert_assert<uint32_t>(sizeof(x_smb2_file_full_dir_info_t) + name.size() * 2);
		pbegin = marshall.get_begin(rec_size);
		if (!pbegin) {
			return false;
		}
		{
			x_smb2_file_full_dir_info_t *info = (x_smb2_file_full_dir_info_t *)pbegin;
			info->next_offset = 0;
			info->file_index = 0;
			x_smbd_push_time_info(*info, object_meta);
			info->end_of_file = X_H2LE64(stream_meta.end_of_file);
			info->allocation_size = X_H2LE64(stream_meta.allocation_size);
			info->file_attributes = X_H2LE32(object_meta.file_attributes);
			info->file_name_length = X_H2LE32(x_convert_assert<uint32_t>(name.size() * 2));
			if (object_meta.file_attributes & X_SMB2_FILE_ATTRIBUTE_REPARSE_POINT) {
				info->ea_size = X_H2LE32(IO_REPARSE_TAG_DFS);
			} else {
				/*
				 * OS X specific SMB2 extension negotiated via
				 * AAPL create context: return max_access in
				 * ea_size field.
				 */
				info->ea_size = 0;
			}
		
			x_utf16le_encode(name, info->file_name);
		}
		break;

	case x_smb2_info_level_t::FILE_NAMES_INFORMATION:
		rec_size = x_convert_assert<uint32_t>(sizeof(x_smb2_file_names_info_t) + name.size() * 2);
		pbegin = marshall.get_begin(rec_size);
		if (!pbegin) {
			return false;
		}
		{
			x_smb2_file_names_info_t *info = (x_smb2_file_names_info_t *)pbegin;
			info->next_offset = 0;
			info->file_index = 0;
			info->file_name_length = X_H2LE32(x_convert_assert<uint32_t>(name.size() * 2));
			x_utf16le_encode(name, info->file_name);
		}
		break;

	default:
		X_ASSERT(0);
	}
	return true;
}

