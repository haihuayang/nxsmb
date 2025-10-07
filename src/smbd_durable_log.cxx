
#include "smbd_durable.hxx"
#include "include/iuflog.hxx"

static int smbd_durable_update_decode(x_smbd_durable_update_t &state,
		const void *buf, size_t size)
{
	auto *record = (x_smbd_durable_update_record_t *)buf;
	if (size < sizeof(record->type)) {
		return -EINVAL;
	}

	uint32_t type = X_LE2H32(record->type);
	if (type == x_smbd_durable_update_t::type_update_flags) {
		if (size != sizeof(x_smbd_durable_update_record_t::update_flags)) {
			X_LOG(SMB, ERR, "invalid type_update_flags record size %lu", size);
			return -EINVAL;
		}
		uint32_t flags = X_LE2H32(record->update_flags.flags);
		state.flags = flags;

	} else if (type == x_smbd_durable_update_t::type_update_locks) {
		if (size < sizeof(x_smbd_durable_update_record_t::update_locks)) {
			X_LOG(SMB, ERR, "invalid type_update_locks record size %lu", size);
			return -EINVAL;
		}
		uint32_t num_lock = X_LE2H32(record->update_locks.num_lock);
		if (size != sizeof(x_smbd_durable_update_record_t::update_locks)
				+ num_lock * sizeof(x_smb2_lock_element_t)) {
			X_LOG(SMB, ERR, "invalid type_update_locks record size %lu", size);
			return -EINVAL;
		}

		const auto *ptr = record->update_locks.locks;
		std::vector<x_smb2_lock_element_t> locks(num_lock);
		for (uint32_t i = 0; i < num_lock; ++i) {
			auto &lock = locks[i];
			lock.offset = X_LE2H64(ptr[i].offset);
			lock.length = X_LE2H64(ptr[i].length);
			lock.flags = X_LE2H32(ptr[i].flags);
		}

		std::swap(state.locks, locks);

	} else if (type == x_smbd_durable_update_t::type_disconnect) {
		if (size != sizeof(x_smbd_durable_update_record_t::disconnect)) {
			X_LOG(SMB, ERR, "invalid type_disconnect record size %lu", size);
			return -EINVAL;
		}

		uint64_t disconnect_msec = X_LE2H64(record->disconnect.disconnect_msec);
		state.disconnect_msec = disconnect_msec;

	} else if (type == x_smbd_durable_update_t::type_reconnect) {
		if (size != sizeof(x_smbd_durable_update_record_t::reconnect)) {
			X_LOG(SMB, ERR, "invalid type_reconnect record size %lu", size);
			return -EINVAL;
		}

	} else {
		X_LOG(SMB, ERR, "invalid record type %u", type);
		return -EINVAL;
	}
	state.type = type;
	return 0;
}

struct smbd_durable_record_part1_t
{
	uint64_t disconnect_msec;
	uint64_t id_volatile;
	uint32_t file_handle_bytes;
	uint32_t file_handle_type;
	uint8_t file_handle_data[];
};

struct smbd_durable_record_part2_t
{
	x_smb2_uuid_t lease_key;
	uint8_t lease_version;
	uint8_t lease_state;
	uint16_t lease_epoch;
	uint8_t lease_breaking;
	uint8_t lease_breaking_to_requested;
	uint8_t lease_breaking_to_required;
	uint8_t lease_reserved;
	uint32_t access_mask;
	uint32_t share_access;
	x_smb2_uuid_t client_guid;
	x_smb2_uuid_t create_guid;
	x_smb2_uuid_t app_instance_id;
	uint64_t app_instance_version_high;
	uint64_t app_instance_version_low;
	x_smb2_uuid_t parent_lease_key;
	uint32_t owner_sid_header[2]; // first 8 bytes in dom_sid
	uint32_t owner_auth_data[]; // followed by sub_auths (padded to 8 bytes)
};

struct smbd_durable_record_part3_t
{
	uint32_t flags;
	uint16_t channel_sequence;
	uint8_t create_action;
	uint8_t oplock_level;
	uint8_t dhmode;
	uint8_t reserved[3];
	uint32_t durable_timeout_msec;
	uint64_t current_offset;
	uint64_t channel_generation;
	uint32_t reserved2;
	uint32_t num_locks;
	x_smb2_lock_element_t locks[];
};

ssize_t x_smbd_durable_encode(void *p, size_t buf_size,
		uint64_t disconnect_msec,
		uint64_t id_volatile,
		const x_smbd_open_state_t &open_state,
		const x_smbd_lease_data_t &lease_data,
		const x_smbd_file_handle_t &file_handle)
{
	X_ASSERT(file_handle.base.handle_bytes <= MAX_HANDLE_SZ);
	X_ASSERT(open_state.owner.num_auths <= 15);

	if (buf_size < sizeof(smbd_durable_record_part1_t) +
			+ x_pad_len(file_handle.base.handle_bytes, 8)
			+ sizeof(smbd_durable_record_part2_t)
			+ ((open_state.owner.num_auths + 1) & ~1) * sizeof(uint32_t)
			+ sizeof(smbd_durable_record_part3_t)
			+ sizeof(x_smb2_lock_element_t) * open_state.locks.size()) {
		return -ENOSPC;
	}

	auto *ptr1 = (smbd_durable_record_part1_t *)p;
	ptr1->disconnect_msec = X_H2LE64(disconnect_msec);
	ptr1->id_volatile = X_H2LE64(id_volatile);
	ptr1->file_handle_bytes = X_H2LE32(file_handle.base.handle_bytes);
	ptr1->file_handle_type = X_H2LE32(file_handle.base.handle_type);

	memcpy(ptr1->file_handle_data, file_handle.base.f_handle,
			file_handle.base.handle_bytes);

	auto *ptr2 = (smbd_durable_record_part2_t *)(ptr1->file_handle_data
			+ x_pad_len(file_handle.base.handle_bytes, 8));

	ptr2->lease_key = lease_data.key;
	ptr2->lease_version = lease_data.version;
	ptr2->lease_state = lease_data.state;
	ptr2->lease_epoch = X_H2LE16(lease_data.epoch);
	ptr2->lease_breaking = lease_data.breaking;
	ptr2->lease_breaking_to_requested = lease_data.breaking_to_requested;
	ptr2->lease_breaking_to_required = lease_data.breaking_to_required;
	ptr2->lease_reserved = 0;
	ptr2->access_mask = X_H2LE32(open_state.access_mask);
	ptr2->share_access = X_H2LE32(open_state.share_access);
	ptr2->client_guid = open_state.client_guid;
	ptr2->create_guid = open_state.create_guid;
	ptr2->app_instance_id = open_state.app_instance_id;
	ptr2->app_instance_version_high = X_H2LE64(open_state.app_instance_version_high);
	ptr2->app_instance_version_low = X_H2LE64(open_state.app_instance_version_low);
	ptr2->parent_lease_key = open_state.parent_lease_key;
	ptr2->owner_sid_header[0] = ((uint32_t *)&open_state.owner)[0];
	ptr2->owner_sid_header[1] = ((uint32_t *)&open_state.owner)[1];

	uint32_t *ptr_auth = ptr2->owner_auth_data;
	for (uint8_t i = 0; i < open_state.owner.num_auths; ++i) {
		*ptr_auth++ = X_H2LE32(open_state.owner.sub_auths[i]);
	}
	if (open_state.owner.num_auths % 2) {
		*ptr_auth++ = 0;
	}

	auto *ptr3 = (smbd_durable_record_part3_t *)ptr_auth;
	ptr3->flags = X_H2LE32(open_state.flags);
	ptr3->channel_sequence = X_H2LE16(open_state.channel_sequence);
	ptr3->create_action = uint8_t(open_state.create_action);
	ptr3->oplock_level = open_state.oplock_level;
	ptr3->dhmode = uint8_t(open_state.dhmode);
	ptr3->reserved[0] = 0;
	ptr3->reserved[1] = 0;
	ptr3->reserved[2] = 0;
	ptr3->durable_timeout_msec = X_H2LE32(open_state.durable_timeout_msec);
	ptr3->current_offset = X_H2LE64(open_state.current_offset);
	ptr3->channel_generation = X_H2LE64(open_state.channel_generation);
	ptr3->reserved2 = 0;
	uint32_t num_locks = x_convert_assert<uint32_t>(open_state.locks.size());
	ptr3->num_locks = X_H2LE32(num_locks);

	x_smb2_lock_element_t *ptr_lock = ptr3->locks;
	for (auto &lock : open_state.locks) {
		ptr_lock->offset = X_H2LE64(lock.offset);
		ptr_lock->length = X_H2LE64(lock.length);
		ptr_lock->flags = X_H2LE32(lock.flags);
		ptr_lock->unused = 0;
		++ptr_lock;
	}
	return x_convert_assert<int>((uint8_t *)ptr_lock - (uint8_t *)p);
}

std::unique_ptr<x_smbd_durable_t> x_smbd_durable_parse(
		const void *data, size_t size)
{
	if (size < sizeof(smbd_durable_record_part1_t)) {
		X_LOG(SMB, ERR, "record size %lu too small", size);
		return nullptr;
	}

	const smbd_durable_record_part1_t *part1 = (const smbd_durable_record_part1_t *)data;
	uint64_t disconnect_msec = X_LE2H64(part1->disconnect_msec);
	uint64_t id_volatile = X_LE2H64(part1->id_volatile);
	x_smbd_file_handle_t file_handle;
	file_handle.base.handle_bytes = X_LE2H32(part1->file_handle_bytes);
	file_handle.base.handle_type = X_LE2H32(part1->file_handle_type);
	if (file_handle.base.handle_bytes > MAX_HANDLE_SZ) {
		X_LOG(SMB, ERR, "invalid handle_bytes %u", file_handle.base.handle_bytes);
		return nullptr;
	}
	size_t pad_len = x_pad_len(file_handle.base.handle_bytes, 8);
	if (sizeof(smbd_durable_record_part1_t) + pad_len > size) {
		X_LOG(SMB, ERR, "record size %lu too small for handle", size);
		return nullptr;
	}
	memcpy(file_handle.base.f_handle, part1->file_handle_data,
			file_handle.base.handle_bytes);

	size -= sizeof(smbd_durable_record_part1_t) + pad_len;
	if (size < sizeof(smbd_durable_record_part2_t)) {
		X_LOG(SMB, ERR, "record size %lu too small for part2", size);
		return nullptr;
	}
	const smbd_durable_record_part2_t *part2 =
		(const smbd_durable_record_part2_t *)(part1->file_handle_data + pad_len);

	x_smbd_lease_data_t lease_data{
		part2->lease_key,
		part2->lease_version,
		part2->lease_state,
		X_LE2H16(part2->lease_epoch),
		part2->lease_breaking != 0,
		part2->lease_breaking_to_requested,
		part2->lease_breaking_to_required};

	uint32_t access_mask = X_LE2H32(part2->access_mask);
	uint32_t share_access = X_LE2H32(part2->share_access);
	x_smb2_uuid_t client_guid = part2->client_guid;
	x_smb2_uuid_t create_guid = part2->create_guid;
	x_smb2_uuid_t app_instance_id = part2->app_instance_id;
	uint64_t app_instance_version_high = X_LE2H64(part2->app_instance_version_high);
	uint64_t app_instance_version_low = X_LE2H64(part2->app_instance_version_low);
	x_smb2_uuid_t parent_lease_key = part2->parent_lease_key;
	idl::dom_sid owner;
	*(uint64_t *)&owner = *(uint64_t *)part2->owner_sid_header;
	if (owner.num_auths > 15) {
		X_LOG(SMB, ERR, "invalid owner.num_auths %u", owner.num_auths);
		return nullptr;
	}
	pad_len = ((owner.num_auths + 1) & ~1) * sizeof(uint32_t);
	if (sizeof(smbd_durable_record_part2_t) + pad_len > size) {
		X_LOG(SMB, ERR, "record size %lu too small for owner", size);
		return nullptr;
	}
	for (uint8_t i = 0; i < owner.num_auths; ++i) {
		owner.sub_auths[i] = X_LE2H32(part2->owner_auth_data[i]);
	}

	size -= sizeof(smbd_durable_record_part1_t) + pad_len;
	if (size < sizeof(smbd_durable_record_part3_t)) {
		X_LOG(SMB, ERR, "record size %lu too small for part3", size);
		return nullptr;
	}

	const smbd_durable_record_part3_t *part3 =
		(const smbd_durable_record_part3_t *)((const uint8_t *)part2->owner_auth_data + pad_len);

	uint32_t flags = X_LE2H32(part3->flags);
	uint16_t channel_sequence = X_LE2H16(part3->channel_sequence);
	auto create_action = (x_smb2_create_action_t)part3->create_action;
	uint8_t oplock_level = part3->oplock_level;
	auto dhmode = (x_smbd_dhmode_t)part3->dhmode;
	uint32_t durable_timeout_msec = X_LE2H32(part3->durable_timeout_msec);
	uint64_t current_offset = X_LE2H64(part3->current_offset);
	uint64_t channel_generation = X_LE2H64(part3->channel_generation);
	uint32_t num_locks = X_LE2H32(part3->num_locks);
	if (size < sizeof(smbd_durable_record_part3_t)
			+ num_locks * sizeof(x_smb2_lock_element_t)) {
		X_LOG(SMB, ERR, "record size %lu too small for locks", size);
		return nullptr;
	}
	std::vector<x_smb2_lock_element_t> locks(num_locks);
	for (uint32_t i = 0; i < num_locks; ++i) {
		locks[i].offset = X_LE2H64(part3->locks[i].offset);
		locks[i].length = X_LE2H64(part3->locks[i].length);
		locks[i].flags = X_LE2H32(part3->locks[i].flags);
	}
	return std::make_unique<x_smbd_durable_t>(
			disconnect_msec,
			id_volatile,
			lease_data,
			file_handle,
			x_smbd_open_state_t{
				access_mask,
				share_access,
				client_guid,
				create_guid,
				app_instance_id,
				app_instance_version_high,
				app_instance_version_low,
				parent_lease_key,
				owner,
				flags,
				channel_sequence,
				create_action,
				oplock_level,
				dhmode,
				durable_timeout_msec,
				current_offset,
				channel_generation,
				std::move(locks)
			}
	);
}

static int read_durable(x_smbd_durable_log_visitor_t &visitor,
		uint64_t id, x_iuflog_record_type_t type,
		const void *data, size_t size)
{
	if (type == x_iuflog_record_type_t::initiate) {
		std::unique_ptr<x_smbd_durable_t> durable =
			x_smbd_durable_parse(data, size);
		if (!durable) {
			return -EINVAL;
		}

		int ret = visitor.initiate(id, *durable);
		return ret;
	} else if (type == x_iuflog_record_type_t::update) {
		x_smbd_durable_update_t update;
		int ret = smbd_durable_update_decode(update, data, size);
		if (ret < 0) {
			return ret;
		}
		return visitor.update(id, update);
	} else if (type == x_iuflog_record_type_t::finalize) {
		return visitor.finalize(id);
	} else {
		X_ASSERT(false);
		return -EINVAL;
	}
}

ssize_t x_smbd_durable_log_read(int dirfd,
		x_smbd_durable_log_visitor_t &visitor)
{
	return x_iuflog_read(dirfd,
			X_SMBD_DURABLE_MAX_RECORD_SIZE,
		[&visitor](uint64_t id, x_iuflog_record_type_t type,
			const void *data, size_t size)
		{
			return read_durable(visitor, id, type, data, size);
		});
}

ssize_t x_smbd_durable_log_read_file(int dirfd, const char *name,
		bool is_merged,
		x_smbd_durable_log_visitor_t &visitor)
{
	return x_iuflog_read_file(dirfd, name,
			X_SMBD_DURABLE_MAX_RECORD_SIZE,
			is_merged,
		[&visitor](uint64_t id, x_iuflog_record_type_t type,
			const void *data, size_t size)
		{
			return read_durable(visitor, id, type, data, size);
		});
}


