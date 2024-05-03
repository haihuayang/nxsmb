
#include "smbd_durable.hxx"
#include <dirent.h>

static const char magic[8] = "DURABLE";
static constexpr size_t X_SMBD_DURABLE_LOG_LENGTH = strlen(X_SMBD_DURABLE_LOG);

static ssize_t smbd_durable_read(int fd,
		bool is_merged, uint64_t &skip_no,
		std::map<uint64_t, x_smbd_durable_t> &durables)
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

		if (type == x_smbd_durable_record_t::type_create) {
			if (size != sizeof(x_smbd_durable_record_t) +
					sizeof(x_smbd_durable_t)) {
				REPORT_ERR("invalid type_create record size %u", size);
				return -EINVAL;
			}

			x_smbd_durable_t *durable = (x_smbd_durable_t *)(record + 1);
			auto [it, success] = durables.insert(
					std::make_pair(record->id_persistent, *durable));
			if (!success) {
				X_LOG(SMB, ERR, "delete existed id 0x%lx and reinsert",
						record->id_persistent);
				auto it2 = durables.erase(it);
				durables.insert(it2,
					std::make_pair(record->id_persistent, *durable));
			}

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
			auto disconnect_msec = (uint64_t *)(record + 1);
			auto it = durables.find(record->id_persistent);
			if (it == durables.end()) {
				X_LOG(SMB, ERR, "cannot update, id 0x%lx not exist",
						record->id_persistent);
			} else {
				it->second.disconnect_msec = *disconnect_msec;
			}
		} else if (type == x_smbd_durable_record_t::type_update_replay) {
			if (is_merged) {
				REPORT_ERR("unexpect type %u in merged log", type);
				return -EINVAL;
			}
			if (size != sizeof(x_smbd_durable_record_t) + sizeof(uint64_t)) {
				REPORT_ERR("invalid type_update_replay record size %u", size);
				return -EINVAL;
			}
			auto replay_cached = (uint64_t *)(record + 1);
			auto it = durables.find(record->id_persistent);
			if (it == durables.end()) {
				X_LOG(SMB, ERR, "cannot update, id 0x%lx not exist",
						record->id_persistent);
			} else {
				it->second.open_state.replay_cached = *replay_cached;
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
		std::map<uint64_t, x_smbd_durable_t> &durables)
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
		std::map<uint64_t, x_smbd_durable_t> &durables,
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

bool x_smbd_durable_log_output(int fd, x_smbd_durable_record_t *rec,
		uint32_t type, uint32_t size,
		uint64_t id_persistent)
{
	rec->type_size = (type << 24) | size;
	rec->id_persistent = id_persistent;
	rec->cksum = 0; // TODO

	ssize_t ret = write(fd, rec, size);
	return ret == ssize_t(size);
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

