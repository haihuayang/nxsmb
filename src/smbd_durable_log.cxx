
#include "smbd_durable.hxx"
#include <dirent.h>

static const char magic[8] = "DURABLE";
static constexpr size_t X_SMBD_DURABLE_LOG_LENGTH = strlen(X_SMBD_DURABLE_LOG);

struct x_smbd_durable_log_header_t
{
	uint8_t magic[8];
	uint32_t version;
	uint32_t flags;
	uint64_t next_file_no;
	uint64_t unused[5];
};

struct x_smbd_durable_record_t
{
	enum {
		type_invalid,
		type_durable,
		type_close,
		type_disconnect,
		type_update_flags,
		type_update_locks,
	};
	uint32_t cksum;
	uint32_t type_size;
	uint64_t id_persistent;
};

static_assert(offsetof(x_smbd_durable_t, open_state) % 8 == 0);
static_assert(offsetof(x_smbd_open_state_t, locks) % 8 == 0);

static inline size_t length_open_state(const x_smbd_open_state_t &open_state)
{
	return open_state.locks.size() * sizeof(x_smb2_lock_element_t) +
		8 + // open_state.locks.size()
		offsetof(x_smbd_open_state_t, locks);
}

#define PUSH_LE16(ptr, val) do { \
	*(uint16_t *)(ptr) = X_H2LE16(val); \
	(ptr) += sizeof(uint16_t); \
} while (0)

#define PULL_LE16(ptr) ({ \
	uint16_t __val = X_LE2H16(*(const uint16_t *)(ptr)); \
	(ptr) += sizeof(uint16_t); \
	__val; \
})

#define PUSH_LE32(ptr, val) do { \
	*(uint32_t *)(ptr) = X_H2LE32(val); \
	(ptr) += sizeof(uint32_t); \
} while (0)

#define PULL_LE32(ptr) ({ \
	uint32_t __val = X_LE2H32(*(const uint32_t *)(ptr)); \
	(ptr) += sizeof(uint32_t); \
	__val; \
})

#define PUSH_LE64(ptr, val) do { \
	*(uint64_t *)(ptr) = X_H2LE64(val); \
	(ptr) += sizeof(uint64_t); \
} while (0)

#define PULL_LE64(ptr) ({ \
	uint64_t __val = X_LE2H64(*(const uint64_t *)(ptr)); \
	(ptr) += sizeof(uint64_t); \
	__val; \
})

#define PUSH_UUID(ptr, val) do { \
	memcpy((ptr), &(val), sizeof(x_smb2_uuid_t)); \
	(ptr) += sizeof(x_smb2_uuid_t); \
} while (0)

#define PULL_UUID(ptr) ({ \
	x_smb2_uuid_t __val; \
	memcpy(&(__val), (ptr), sizeof(x_smb2_uuid_t)); \
	(ptr) += sizeof(x_smb2_uuid_t); \
	__val; \
})

#define PUSH_SID(ptr, val) do { \
	X_ASSERT((val).num_auths <= 15); \
	*(uint64_t *)(ptr) = *(uint64_t *)&(val); \
	(ptr) += sizeof(uint64_t); \
	for (uint8_t __i = 0; __i < (val).num_auths; ++__i) { \
		PUSH_LE32(ptr, (val).sub_auths[__i]); \
	} \
	if ((val).num_auths % 2) { \
		PUSH_LE32(ptr, 0); \
	} \
} while (0)

static uint8_t *encode_durable(void *p,
		uint64_t disconnect_msec,
		uint64_t id_volatile,
		const x_smbd_open_state_t &open_state,
		const x_smbd_lease_data_t &lease_data,
		const x_smbd_file_handle_t &file_handle)
{
	uint8_t *ptr = (uint8_t *)p;
	PUSH_LE64(ptr, disconnect_msec);
	PUSH_LE64(ptr, id_volatile);
	X_ASSERT(file_handle.base.handle_bytes <= MAX_HANDLE_SZ);
	PUSH_LE32(ptr, file_handle.base.handle_bytes);
	PUSH_LE32(ptr, file_handle.base.handle_type);
	memcpy(ptr, file_handle.base.f_handle, file_handle.base.handle_bytes);
	ptr += x_pad_len(file_handle.base.handle_bytes, 8);
	
	PUSH_UUID(ptr, lease_data.key);
	*ptr++ = lease_data.version;
	*ptr++ = lease_data.state;
	PUSH_LE16(ptr, lease_data.epoch);
	*ptr++ = lease_data.breaking;
	*ptr++ = lease_data.breaking_to_requested;
	*ptr++ = lease_data.breaking_to_required;
	*ptr++ = 0;

	PUSH_LE32(ptr, open_state.access_mask);
	PUSH_LE32(ptr, open_state.share_access);
	PUSH_UUID(ptr, open_state.client_guid);
	PUSH_UUID(ptr, open_state.create_guid);
	PUSH_UUID(ptr, open_state.app_instance_id);
	PUSH_LE64(ptr, open_state.app_instance_version_high);
	PUSH_LE64(ptr, open_state.app_instance_version_low);
	PUSH_UUID(ptr, open_state.parent_lease_key);

	PUSH_SID(ptr, open_state.owner);
	PUSH_LE32(ptr, open_state.flags);
	PUSH_LE16(ptr, open_state.channel_sequence);
	*ptr++ = uint8_t(open_state.create_action);
	*ptr++ = open_state.oplock_level;
	*ptr++ = uint8_t(open_state.dhmode);
	*ptr++ = 0;
	*ptr++ = 0;
	*ptr++ = 0;
	PUSH_LE32(ptr, open_state.durable_timeout_msec);
	PUSH_LE64(ptr, open_state.current_offset);
	PUSH_LE64(ptr, open_state.channel_generation);
	PUSH_LE32(ptr, 0);
	uint32_t num_locks = x_convert_assert<uint32_t>(open_state.locks.size());
	PUSH_LE32(ptr, num_locks);
	for (auto &lock : open_state.locks) {
		PUSH_LE64(ptr, lock.offset);
		PUSH_LE64(ptr, lock.length);
		PUSH_LE32(ptr, lock.flags);
		PUSH_LE32(ptr, 0);
	}
	return ptr;
}

static x_smbd_lease_data_t decode_lease_data(const uint8_t *ptr)
{
	x_smb2_uuid_t key = PULL_UUID(ptr);
	uint8_t version = *ptr++;
	uint8_t state = *ptr++;
	uint16_t epoch = PULL_LE16(ptr);
	bool breaking = *ptr++;
	uint8_t breaking_to_requested = *ptr++;
	uint8_t breaking_to_required = *ptr++;
	return x_smbd_lease_data_t{key, version, state, epoch, breaking,
		breaking_to_requested, breaking_to_required};
}

static std::unique_ptr<x_smbd_durable_t> decode_durable(const void *data, size_t size)
{
	const uint8_t *ptr = (const uint8_t *)data;
	const uint8_t *end = ptr + size;
	if (ptr + sizeof(uint64_t) * 3 >= end) {
		return nullptr;
	}

	uint64_t disconnect_msec = PULL_LE64(ptr);
	uint64_t id_volatile = PULL_LE64(ptr);

	x_smbd_file_handle_t file_handle;
	file_handle.base.handle_bytes = PULL_LE32(ptr);
	file_handle.base.handle_type = PULL_LE32(ptr);
	if (file_handle.base.handle_bytes > MAX_HANDLE_SZ) {
		return nullptr;
	}
	size_t pad_len = x_pad_len(file_handle.base.handle_bytes, 8);
	if (ptr + pad_len > end) {
		return nullptr;
	}
	memcpy(file_handle.base.f_handle, ptr, file_handle.base.handle_bytes);
	ptr += pad_len;

	if (ptr + sizeof(x_smbd_lease_data_t) > end) {
		return nullptr;
	}

	x_smbd_lease_data_t lease_data = decode_lease_data(ptr);
	ptr += sizeof(x_smbd_lease_data_t);

	if (ptr + 8 + sizeof(x_smb2_uuid_t) * 3 + 16 + sizeof(x_smb2_uuid_t) + 8 > end) {
		return nullptr;
	}

	uint32_t access_mask = PULL_LE32(ptr);
	uint32_t share_access = PULL_LE32(ptr);
	x_smb2_uuid_t client_guid = PULL_UUID(ptr);
	x_smb2_uuid_t create_guid = PULL_UUID(ptr);
	x_smb2_uuid_t app_instance_id = PULL_UUID(ptr);
	uint64_t app_instance_version_high = PULL_LE64(ptr);
	uint64_t app_instance_version_low = PULL_LE64(ptr);
	x_smb2_uuid_t parent_lease_key = PULL_UUID(ptr);

	idl::dom_sid owner;
	if (ptr + 8 > end) {
		return nullptr;
	}
	*(uint64_t *)&owner = *(uint64_t *)ptr;
	ptr += sizeof(uint64_t);
	if (owner.num_auths > 15) {
		return nullptr;
	}
	if (ptr + ((owner.num_auths + 1) & 0xfe) * sizeof(uint32_t) > end) {
		return nullptr;
	}
	for (uint8_t __i = 0; __i < owner.num_auths; ++__i) {
		owner.sub_auths[__i] = PULL_LE32(ptr);
	}
	if (owner.num_auths & 1) {
		ptr += sizeof(uint32_t);
	}

	if (ptr + 8 + 8 + 16 + 8 > end) {
		return nullptr;
	}
	uint32_t flags = PULL_LE32(ptr);
	uint16_t channel_sequence = PULL_LE16(ptr);
	auto create_action = (x_smb2_create_action_t)*ptr++;
	uint8_t oplock_level = *ptr++;
	auto dhmode = (x_smbd_dhmode_t)*ptr++;
	ptr += 3;
	uint32_t durable_timeout_msec = PULL_LE32(ptr);
	uint64_t current_offset = PULL_LE64(ptr);
	uint64_t channel_generation = PULL_LE64(ptr);
	ptr += 4;
	uint32_t num_locks = PULL_LE32(ptr);
	if (ptr + num_locks * sizeof(x_smb2_lock_element_t) > end) {
		return nullptr;
	}

	std::vector<x_smb2_lock_element_t> locks;
	locks.reserve(num_locks);
	for (uint32_t i = 0; i < num_locks; ++i) {
		uint64_t offset = PULL_LE64(ptr);
		uint64_t length = PULL_LE64(ptr);
		uint32_t flags = PULL_LE32(ptr);
		ptr += 4;
		locks.push_back({offset, length, flags});
	}

	return std::make_unique<x_smbd_durable_t>(x_smbd_durable_t{
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
		});
}

static ssize_t smbd_durable_read(int fd,
		bool is_merged, uint64_t &skip_no,
		std::map<uint64_t, std::unique_ptr<x_smbd_durable_t>> &durables)
{
	struct x_smbd_durable_log_header_t header;
	ssize_t err;
	off_t off = sizeof header;

#define REPORT_ERR(fmt, ...) X_LOG(SMB, ERR, "off=%ld " fmt, off, ##__VA_ARGS__)
	err = read(fd, &header, sizeof header);
	if (err != sizeof(header)) {
		REPORT_ERR("incomplete header size %ld", err);
		return -EINVAL;
	}

	if (!is_merged && header.next_file_no != 0) {
		REPORT_ERR("invalid next_file_no=0x%lu", header.next_file_no);
		return -EINVAL;
	}
	size_t count = 0;
	off += sizeof header;
	auto buf = std::make_unique<unsigned char[]>(X_SMBD_DURABLE_MAX_RECORD_SIZE);
	x_smbd_durable_record_t *record = (x_smbd_durable_record_t *)buf.get();
	for (;;) {
		err = read(fd, record, sizeof *record);
		if (err == 0) {
			break;
		} else if (err < 0) {
			if (errno != EINTR) {
				REPORT_ERR("read record errno=%d", errno);
				return -errno;
			}
		} else if (err != sizeof *record) {
			REPORT_ERR("incomplete record header size %ld", err);
			return -EINVAL;
		}
		if (record->id_persistent == 0) {
			return -EINVAL;
		}
		uint32_t type = record->type_size >> 24;
		uint32_t size = record->type_size & 0xffffff;
		if (size > X_SMBD_DURABLE_MAX_RECORD_SIZE || size < sizeof *record) {
			REPORT_ERR("invalid record size %u", size);
		}

		ssize_t toread = size - sizeof *record;
		err = read(fd, record + 1, toread);
		if (err != toread) {
			REPORT_ERR("fail to read record body err=%ld, errno=%d",
					err, errno);
			return -EINVAL;
		}

		if (type == x_smbd_durable_record_t::type_durable) {
			std::unique_ptr<x_smbd_durable_t> durable =
				decode_durable(record + 1, size -
						sizeof(x_smbd_durable_record_t));
			if (!durable) {
				REPORT_ERR("invalid type_durable record %u", size);
				return -EINVAL;
			}

			auto it = durables.lower_bound(record->id_persistent);
			if (it != durables.end() && it->first == record->id_persistent) {
				X_LOG(SMB, ERR, "delete existed id 0x%lx and reinsert",
						record->id_persistent);
				it = durables.erase(it);
			}
			durables.insert(it, std::make_pair(record->id_persistent,
						std::move(durable)));

		} else if (type == x_smbd_durable_record_t::type_close) {
			if (is_merged) {
				REPORT_ERR("unexpect type %u in merged log", type);
				return -EINVAL;
			}
			if (size != sizeof(x_smbd_durable_record_t)) {
				REPORT_ERR("invalid type_close record size %u", size);
				return -EINVAL;
			}
			auto it = durables.find(record->id_persistent);
			if (it == durables.end()) {
				X_LOG(SMB, ERR, "cannot remove, id 0x%lx not exist",
						record->id_persistent);
			} else {
				durables.erase(it);
			}

		} else if (type == x_smbd_durable_record_t::type_disconnect) {
			if (is_merged) {
				REPORT_ERR("unexpect type %u in merged log", type);
				return -EINVAL;
			}
			if (size != sizeof(x_smbd_durable_record_t) + sizeof(uint64_t)) {
				REPORT_ERR("invalid type_disconnect record size %u", size);
				return -EINVAL;
			}
			uint64_t disconnect_msec = X_LE2H64(*(uint64_t *)(record + 1));
			auto it = durables.find(record->id_persistent);
			if (it == durables.end()) {
				X_LOG(SMB, ERR, "cannot update, id 0x%lx not exist",
						record->id_persistent);
			} else {
				it->second->disconnect_msec = disconnect_msec;
			}
		} else if (type == x_smbd_durable_record_t::type_update_flags) {
			if (is_merged) {
				REPORT_ERR("unexpect type %u in merged log", type);
				return -EINVAL;
			}
			if (size != sizeof(x_smbd_durable_record_t) + sizeof(uint64_t)) {
				REPORT_ERR("invalid type_update_flags record size %u", size);
				return -EINVAL;
			}
			uint32_t flags = X_LE2H32(*(uint32_t *)(record + 1));
			auto it = durables.find(record->id_persistent);
			if (it == durables.end()) {
				X_LOG(SMB, ERR, "cannot update, id 0x%lx not exist",
						record->id_persistent);
			} else {
				it->second->open_state.flags = flags;
			}
		} else if (type == x_smbd_durable_record_t::type_update_locks) {
			if (is_merged) {
				REPORT_ERR("unexpect type %u in merged log", type);
				return -EINVAL;
			}
			if (size < sizeof(x_smbd_durable_record_t) + sizeof(uint64_t)) {
				REPORT_ERR("invalid type_update_locks record size %u", size);
				return -EINVAL;
			}
			const uint8_t *ptr = (const uint8_t *)(record + 1);
			uint32_t num_lock = PULL_LE32(ptr);
			if (size != sizeof(x_smbd_durable_record_t) + sizeof(uint64_t)
					+ num_lock * sizeof(x_smb2_lock_element_t)) {
				REPORT_ERR("invalid type_update_locks record size %u", size);
				return -EINVAL;
			}

			std::vector<x_smb2_lock_element_t> locks;
			locks.resize(num_lock);
			for (uint32_t i = 0; i < num_lock; ++i) {
				auto &lock = locks[i];
				lock.offset = PULL_LE64(ptr);
				lock.length = PULL_LE64(ptr);
				lock.flags = PULL_LE32(ptr);
				ptr += sizeof(uint32_t);
			}

			auto it = durables.find(record->id_persistent);
			if (it == durables.end()) {
				X_LOG(SMB, ERR, "cannot update, id 0x%lx not exist",
						record->id_persistent);
			} else {
				std::swap(it->second->open_state.locks, locks);
			}
		} else {
			REPORT_ERR("unexpect type %u", type);
			return -EINVAL;
		}
		++count;
		off += sizeof(x_smbd_durable_record_t) + size;
	}
	if (is_merged) {
		skip_no = header.next_file_no;
	}
	return count;
}

ssize_t x_smbd_durable_log_read_file(int dir_fd, const char *name,
		bool is_merged, uint64_t &skip_no,
		std::map<uint64_t, std::unique_ptr<x_smbd_durable_t>> &durables)
{
	int fd = openat(dir_fd, name, O_RDONLY);
	if (fd == -1) {
		X_LOG(SMB, ERR, "failed open durable log %s", name);
		return 0;
	}

	ssize_t ret = smbd_durable_read(fd, is_merged, skip_no, durables);
	close(fd);
	return ret;
}

static std::vector<std::string> smbd_durable_list_log_files(int dir_fd)
{
	int fd = dup(dir_fd);
	X_ASSERT(fd != -1);

	std::vector<std::string> list;
	DIR *dir = fdopendir(fd);
	rewinddir(dir);
	for (;;) {
		struct dirent *ent = readdir(dir);
		if (!ent) {
			break;
		}

		/* TODO what if type is not REG file */
		if (ent->d_type == DT_REG && strncmp(ent->d_name,
					X_SMBD_DURABLE_LOG "--",
					X_SMBD_DURABLE_LOG_LENGTH + 2) == 0) {
			list.push_back(ent->d_name);
		}
	}
	closedir(dir);
	std::sort(std::begin(list), std::end(list));
	return list;
}

ssize_t x_smbd_durable_log_read(int dir_fd, uint64_t max_file_no,
		uint64_t &next_file_no,
		std::map<uint64_t, std::unique_ptr<x_smbd_durable_t>> &durables,
		std::vector<std::string> &files)
{
	auto log_files = smbd_durable_list_log_files(dir_fd);
	uint64_t skip_no = 0, last_no = 0;
	size_t total = 0;
	ssize_t ret = x_smbd_durable_log_read_file(dir_fd,
			X_SMBD_DURABLE_LOG_MERGED,
			true,
			skip_no, durables);
	if (ret < 0) {
		X_LOG(SMB, ERR, "fail to read durable log %s", X_SMBD_DURABLE_LOG_MERGED);
	} else {
		total += ret;
	}

	size_t i = 0;
	for (auto &log_file: log_files) {
		++i;
		char *end;
		uint64_t no = strtoull(log_file.c_str() + X_SMBD_DURABLE_LOG_LENGTH + 2, &end, 16);
		if (*end != '\0') {
			X_LOG(SMB, ERR, "unrecognized durable log name '%s'",
					log_file.c_str());
			continue;
		}
		if (no < skip_no) {
			continue;
		}
		if (no >= max_file_no) {
			log_files.resize(i - 1);
			break;
		}
		uint64_t tmp;
		ret = x_smbd_durable_log_read_file(dir_fd,
				log_file.c_str(),
				false,
				tmp, durables);
		last_no = no;
		if (ret < 0) {
			X_LOG(SMB, ERR, "fail to read durable log %s",
					log_file.c_str());
		} else {
			total += ret;
		}
	}
	if (skip_no <= last_no) {
		next_file_no = last_no + 1;
	} else {
		next_file_no = skip_no;
	}
	std::swap(files, log_files);
	return total;
}

void x_smbd_durable_log_init_header(int fd, uint64_t next_file_no)
{
	x_smbd_durable_log_header_t header;
	memset(&header, 0, sizeof header);
	memcpy(header.magic, magic, 8);
	header.version = X_SMBD_DURABLE_DB_VERSION_1;
	header.next_file_no = next_file_no;

	ssize_t err = write(fd, &header, sizeof header);
	X_ASSERT(err == sizeof header);
}

static int smbd_durable_log_output(int fd, x_smbd_durable_record_t *rec,
		uint32_t type, uint32_t size,
		uint64_t id_persistent)
{
	rec->cksum = 0; // TODO
	rec->type_size = X_H2LE32((type << 24) | size);
	rec->id_persistent = X_H2LE64(id_persistent);

	ssize_t ret = write(fd, rec, size);
	if (ret < 0) {
		return -errno;
	} else if (ret != ssize_t(size)) {
		return -EIO;
	}
	return 0;
}

int x_smbd_durable_log_durable(int fd,
		uint64_t id_persistent,
		uint64_t disconnect_msec,
		uint64_t id_volatile,
		const x_smbd_open_state_t &open_state,
		const x_smbd_lease_data_t &lease_data,
		const x_smbd_file_handle_t &file_handle)
{
	X_LOG(SMB, DBG, "id_persistent=0x%lx", id_persistent);

	size_t size = sizeof(uint64_t) + sizeof(uint64_t);
	size += sizeof lease_data + sizeof file_handle;
	size += sizeof open_state;
	size += sizeof(uint64_t); // num of locks
	size += open_state.locks.size() * sizeof(x_smb2_lock_element_t);

	auto buf = std::make_unique<uint8_t[]>(sizeof(x_smbd_durable_record_t) + size);
	x_smbd_durable_record_t *rec = (x_smbd_durable_record_t *)buf.get();

	uint8_t *ptr = encode_durable(rec + 1, disconnect_msec,
			id_volatile, open_state, lease_data, file_handle);

	return smbd_durable_log_output(fd, rec,
			x_smbd_durable_record_t::type_durable,
			x_convert_assert<uint32_t>(ptr - (uint8_t *)rec),
			id_persistent);
}

int x_smbd_durable_log_close(int fd, uint64_t id_persistent)
{
	x_smbd_durable_record_t record;
	return smbd_durable_log_output(fd, &record,
			x_smbd_durable_record_t::type_close,
			sizeof record, id_persistent);
}

int x_smbd_durable_log_disconnect(int fd, uint64_t id_persistent, uint64_t disconnect_msec)
{
	struct {
		x_smbd_durable_record_t record;
		uint64_t disconnect_msec;
	} record;

	record.disconnect_msec = X_H2LE64(disconnect_msec);

	return smbd_durable_log_output(fd, &record.record,
			x_smbd_durable_record_t::type_disconnect,
			sizeof record, id_persistent);
}

int x_smbd_durable_log_flags(int fd, uint64_t id_persistent, uint32_t flags)
{
	struct {
		x_smbd_durable_record_t record;
		uint32_t flags;
		uint32_t unused0;
	} record;

	record.flags = X_H2LE32(flags);
	record.unused0 = 0;

	return smbd_durable_log_output(fd, &record.record,
			x_smbd_durable_record_t::type_update_flags,
			sizeof record, id_persistent);
}

int x_smbd_durable_log_locks(int fd, uint64_t id_persistent,
		const std::vector<x_smb2_lock_element_t> &locks)
{
	X_LOG(SMB, DBG, "id_persistent=0x%lx", id_persistent);

	X_ASSERT(locks.size() <= X_SMBD_MAX_LOCKS_PER_OPEN);

	size_t size = sizeof(x_smbd_durable_record_t);
	size += sizeof(uint64_t); // num of locks
	size += locks.size() * sizeof(x_smb2_lock_element_t);

	auto buf = std::make_unique<uint8_t[]>(size);
	x_smbd_durable_record_t *rec = (x_smbd_durable_record_t *)buf.get();

	uint8_t *ptr = (uint8_t *)(rec + 1);
	PUSH_LE32(ptr, 0);
	uint32_t num_locks = x_convert_assert<uint32_t>(locks.size());
	PUSH_LE32(ptr, num_locks);
	for (auto &lock : locks) {
		PUSH_LE64(ptr, lock.offset);
		PUSH_LE64(ptr, lock.length);
		PUSH_LE32(ptr, lock.flags);
		PUSH_LE32(ptr, 0);
	}

	return smbd_durable_log_output(fd, rec,
			x_smbd_durable_record_t::type_update_locks,
			x_convert<uint32_t>(size), id_persistent);
}

