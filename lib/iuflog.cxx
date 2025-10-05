
#include "include/iuflog.hxx"
#include "include/bits.hxx"
#include <shared_mutex>
#include <mutex>
#include <map>
#include <memory>
#include <fcntl.h>
#include <dirent.h>
#include <zlib.h> // for crc32

enum {
	X_IUFLOG_VERSION_1 = 1,
};

static const char magic[8] = "IUFLOG";
#define IUFLOG_PREFIX "iuf-log"
static constexpr size_t IUFLOG_PREFIX_LEN = strlen(IUFLOG_PREFIX);
#define IUFLOG_MERGED IUFLOG_PREFIX "-merged"
#define IUFLOG_TMP IUFLOG_PREFIX "-tmp"


#define PADDING(s) (((s) + 7) & ~(7))

struct x_iuflog_header_t
{
	uint8_t magic[8];
	uint32_t version;
	uint32_t flags;
	uint64_t next_file_no;
	uint64_t unused[5];
};

struct iuflog_record_t
{
	uint32_t cksum;
	uint32_t type_size;
	uint64_t id;
};

static inline uint32_t x_crc32(const iuflog_record_t *rec, size_t size)
{
	uLong crc = crc32(0, Z_NULL, 0);
	crc = crc32(crc, (const uint8_t *)rec + sizeof(uint32_t),
			x_convert_assert<uint32_t>(size - sizeof(uint32_t)));
	return x_convert<uint32_t>(crc);
}


struct iuflog_fd_t
{
	iuflog_fd_t(int fd) : fd(fd) {
	}
	~iuflog_fd_t() {
		X_ASSERT(close(fd) == 0);
	}

	std::atomic<int> refcnt{1};
	const int fd;
	std::atomic<uint64_t> num_record{};
};

struct x_iuflog_t
{
	x_iuflog_t(x_threadpool_t *tpool,
			int fd,
			x_iuflog_parse_fn parse,
			uint32_t max_record_size,
			uint32_t max_record_per_file,
			uint32_t merge_threshold);

	~x_iuflog_t()
	{
		X_ASSERT(close(dir_fd) == 0);
	}

	x_job_t job;
	x_threadpool_t * const threadpool;
	x_iuflog_parse_fn const parse;

	std::atomic<int> refcnt{1};
	const int dir_fd;
	const uint32_t max_record_size;
	const uint32_t max_record_per_file;
	const uint32_t merge_threshold;
	std::shared_mutex mutex;
	x_ref_ptr_t<iuflog_fd_t> log_fd{nullptr};
	uint64_t next_file_no, last_merge_no = 0;
};

template <>
iuflog_fd_t *x_ref_inc(iuflog_fd_t *log_fd)
{
	log_fd->refcnt.fetch_add(1, std::memory_order_relaxed);
	return log_fd;
}

template <>
void x_ref_dec(iuflog_fd_t *log_fd)
{
	if (log_fd->refcnt.fetch_sub(1, std::memory_order_acq_rel) == 1) {
		delete log_fd;
	}
}

static inline iuflog_fd_t *get_log_fd(x_iuflog_t *log)
{
	std::shared_lock<std::shared_mutex> lock(log->mutex);
	log->log_fd->refcnt.fetch_add(1, std::memory_order_relaxed);
	return log->log_fd;
}

static inline void iuflog_state_release(x_iuflog_state_t *state)
{
	return state->ops->release(state);
}

static inline ssize_t iuflog_state_encode(const x_iuflog_state_t *state,
		void *data, size_t size)
{
	return state->ops->encode(state, data, size);
}

static inline int iuflog_state_update(x_iuflog_state_t *state,
		const void *data, size_t size)
{
	return state->ops->update(state, data, size);
}

static auto alloc_buffer(uint32_t max_record_size)
{
	return std::make_unique<unsigned char[]>(sizeof(iuflog_record_t) + max_record_size);
}

static ssize_t iuflog_read_file_intl(int fd, const char *name,
		uint32_t max_record_size,
		bool is_merged, uint64_t &skip_no,
		const std::function<int(uint64_t, x_iuflog_record_type_t type,
			const void *data, size_t size)> &visitor)
{
	struct x_iuflog_header_t header;
	ssize_t err;
	off_t off = sizeof header;

#define REPORT_ERR(fmt, ...) X_LOG(UTILS, ERR, "name=%s off=%ld " fmt, name, off, ##__VA_ARGS__)
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
	auto buf = alloc_buffer(max_record_size);
	iuflog_record_t *record = (iuflog_record_t *)buf.get();
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
		uint32_t type_size = X_LE2H32(record->type_size);
		uint32_t type = type_size >> 24;
		uint32_t size = type_size & 0xffffff;
		if (size > max_record_size) {
			REPORT_ERR("invalid record size %u", size);
			return -EINVAL;
		}

		if (is_merged) {
		       	if (type != uint32_t(x_iuflog_record_type_t::initiate)) {
				REPORT_ERR("unexpect type %u in merged log", type);
				return -EINVAL;
			}
		} else {
			if (type >= uint32_t(x_iuflog_record_type_t::max)) {
				REPORT_ERR("invalid record type %u", type);
				return -EINVAL;
			}
		}

		ssize_t toread = PADDING(size);
		err = read(fd, record + 1, toread);
		if (err != toread) {
			REPORT_ERR("fail to read record body err=%ld, errno=%d",
					err, errno);
			return -EINVAL;
		}

		uint32_t crc = x_crc32(record, size + sizeof(iuflog_record_t));
		if (crc != X_LE2H32(record->cksum)) {
			REPORT_ERR("invalid record cksum 0x%08x != 0x%08x",
					crc, X_LE2H32(record->cksum));
			break;
		}
		uint64_t id = X_LE2H64(record->id);
		visitor(id, x_iuflog_record_type_t(type), record + 1, size);
		++count;
		off += sizeof(iuflog_record_t) + toread;
	}
	if (is_merged) {
		skip_no = header.next_file_no;
	}
	return count;
}

static ssize_t iuflog_read_file(int dir_fd, const char *name,
		uint32_t max_record_size,
		bool is_merged, uint64_t &skip_no,
		const std::function<int(uint64_t, x_iuflog_record_type_t type,
			const void *data, size_t size)> &visitor)
{
	int fd = openat(dir_fd, name, O_RDONLY);
	if (fd == -1) {
		X_LOG(UTILS, ERR, "failed open durable log %s", name);
		return 0;
	}

	ssize_t ret = iuflog_read_file_intl(fd, name, max_record_size,
			is_merged, skip_no, visitor);
	close(fd);
	return ret;
}

static std::vector<std::string> iuflog_list_files(int dir_fd)
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
					IUFLOG_PREFIX "--",
					IUFLOG_PREFIX_LEN + 2) == 0) {
			list.push_back(ent->d_name);
		}
	}
	closedir(dir);
	std::sort(std::begin(list), std::end(list));
	return list;
}

static ssize_t iuflog_read(int dir_fd,
		uint32_t max_record_size, uint64_t max_file_no,
		uint64_t &next_file_no,
		std::vector<std::string> &files,
		const std::function<int(uint64_t, x_iuflog_record_type_t type,
			const void *data, size_t size)> &visitor)
{
	auto log_files = iuflog_list_files(dir_fd);
	uint64_t skip_no = 0, last_no = 0;
	size_t total = 0;
	ssize_t ret = iuflog_read_file(dir_fd,
			IUFLOG_MERGED,
			max_record_size,
			true, skip_no,
			visitor);
	if (ret < 0) {
		X_LOG(UTILS, ERR, "fail to read durable log %s", IUFLOG_MERGED);
	} else {
		total += ret;
	}

	size_t i = 0;
	for (auto &log_file: log_files) {
		++i;
		char *end;
		uint64_t no = strtoull(log_file.c_str() + IUFLOG_PREFIX_LEN + 2, &end, 16);
		if (*end != '\0') {
			X_LOG(UTILS, ERR, "unrecognized durable log name '%s'",
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
		ret = iuflog_read_file(dir_fd,
				log_file.c_str(),
				max_record_size,
				false, tmp,
				visitor);
		last_no = no;
		if (ret < 0) {
			X_LOG(UTILS, ERR, "fail to read durable log %s",
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

ssize_t x_iuflog_read_file(int dir_fd, const char *name,
		uint32_t max_record_size,
		bool is_merged,
		const std::function<int(uint64_t, x_iuflog_record_type_t type,
			const void *data, size_t size)> &visitor)
{
	uint64_t next_file_no;
	return iuflog_read_file(dir_fd, name,
			max_record_size,
			is_merged, next_file_no,
			visitor);
}

ssize_t x_iuflog_read(int dir_fd,
		uint32_t max_record_size,
		const std::function<int(uint64_t, x_iuflog_record_type_t type,
			const void *data, size_t size)> &visitor)
{
	uint64_t next_file_no;
	std::vector<std::string> files;
	return iuflog_read(dir_fd, max_record_size, uint64_t(-1),
			next_file_no, files, visitor);
}

static ssize_t iuflog_read_states(x_iuflog_t *log, uint64_t max_file_no,
		uint64_t &next_file_no,
		std::vector<std::string> &files,
		std::map<uint64_t, x_iuflog_state_t *> &states)
{
	return iuflog_read(log->dir_fd, log->max_record_size, max_file_no,
			next_file_no, files,
			[&](uint64_t id, x_iuflog_record_type_t type,
				const void *data, size_t size) {
		if (type == x_iuflog_record_type_t::initiate) {
			x_iuflog_state_t *state= log->parse(id, data, size);
			if (!state) {
				return -EINVAL;
			}

			auto it = states.lower_bound(id);
			if (it != states.end() && it->first == id) {
				X_LOG(UTILS, ERR, "delete existed id 0x%lx and reinsert",
						id);
				iuflog_state_release(it->second);
				it->second = state;
			} else {
				states.insert(it, std::make_pair(id, state));
			}

		} else if (type == x_iuflog_record_type_t::finalize) {
			if (size != 0) {
				return -EINVAL;
			}
			auto it = states.find(id);
			if (it == states.end()) {
				X_LOG(UTILS, ERR, "cannot remove, id 0x%lx not exist",
						id);
			} else {
				iuflog_state_release(it->second);
				states.erase(it);
			}

		} else if (type == x_iuflog_record_type_t::update) {
			auto it = states.find(id);
			if (it == states.end()) {
				X_LOG(UTILS, ERR, "cannot update, id 0x%lx not exist",
						id);
			} else {
				iuflog_state_update(it->second, data, size);
			}
		}
		return 0;
			});
}

static int iuflog_output(int fd, bool sync,
		x_iuflog_record_type_t type,
		uint64_t id,
		iuflog_record_t *rec,
		size_t body_size)
{
	rec->type_size = X_H2LE32((uint32_t(type) << 24) | uint32_t(body_size));
	rec->id = X_H2LE64(id);

	uint32_t crc = x_crc32(rec, body_size + sizeof(iuflog_record_t));
	rec->cksum = X_H2LE32(crc);

	size_t towrite = PADDING(body_size + sizeof(iuflog_record_t));
	ssize_t ret = write(fd, rec, towrite);
	if (ret < 0) {
		return -errno;
	} else if (size_t(ret) != towrite) {
		return -EIO;
	}
	if (sync) {
		fsync(fd);
	}
	return 0;
}

static int iuflog_output(x_iuflog_t *log, bool sync,
		x_iuflog_record_type_t type,
		uint64_t id,
		iuflog_record_t *rec,
		size_t body_size)
{
	auto log_fd = x_ref_ptr_t(get_log_fd(log));

	int err = iuflog_output(log_fd->fd, sync, type, id, rec, body_size);
	if (err < 0) {
		return err;
	}

	if (log_fd->num_record.fetch_add(1, std::memory_order_relaxed) ==
			log->max_record_per_file) {
		X_LOG(UTILS, NOTICE, "schedule create new durable log for dir_fd %d",
				log->dir_fd);
		log->refcnt.fetch_add(1, std::memory_order_relaxed);
		x_threadpool_schedule(log->threadpool, &log->job);
	}
	return 0;
}

int x_iuflog_initiate(x_iuflog_t *log,
		bool sync, uint64_t id,
		const x_iuflog_state_t *state)
{
	X_LOG(UTILS, DBG, "id=0x%lx", id);

	auto buf = alloc_buffer(log->max_record_size);
	iuflog_record_t *rec = (iuflog_record_t *)buf.get();
	ssize_t size = iuflog_state_encode(state, rec + 1, log->max_record_size);
	if (size < 0) {
		return x_convert_assert<int>(size);
	}
	return iuflog_output(log, sync,
			x_iuflog_record_type_t::initiate, id,
			rec, size);
}

int x_iuflog_update(x_iuflog_t *log,
		bool sync, uint64_t id,
		const x_iuflog_state_t *state)
{
	X_LOG(UTILS, DBG, "id=0x%lx", id);

	auto buf = alloc_buffer(log->max_record_size);
	iuflog_record_t *rec = (iuflog_record_t *)buf.get();
	ssize_t size = iuflog_state_encode(state, rec + 1, log->max_record_size);
	if (size < 0) {
		return x_convert_assert<int>(size);
	}
	return iuflog_output(log, sync,
			x_iuflog_record_type_t::update, id,
			rec, size);
}

int x_iuflog_finalize(x_iuflog_t *log, bool sync, uint64_t id)
{
	iuflog_record_t record;
	return iuflog_output(log, sync,
			x_iuflog_record_type_t::finalize, id,
			&record, 0);
}

static void iuflog_init_header(int fd, uint64_t next_file_no)
{
	x_iuflog_header_t header;
	memset(&header, 0, sizeof header);
	memcpy(header.magic, magic, 8);
	header.version = X_IUFLOG_VERSION_1;
	header.next_file_no = next_file_no;

	ssize_t err = write(fd, &header, sizeof header);
	X_ASSERT(err == sizeof header);
}

static int iuflog_open_log(x_iuflog_t *log, uint64_t next_file_no)
{
	char name[128];
	snprintf(name, sizeof name, IUFLOG_PREFIX "--%016lx", log->next_file_no);
	++log->next_file_no;
	int fd = openat(log->dir_fd, name,
			O_WRONLY | O_CREAT | O_EXCL | O_APPEND, 0644);
	X_ASSERT(fd != -1);

	iuflog_init_header(fd, next_file_no);
	return fd;
}

void x_iuflog_restore(x_iuflog_t *log,
		const std::function<int(uint64_t, x_iuflog_state_t *)> &restorer)
{
	uint64_t next_file_no;
	std::map<uint64_t, x_iuflog_state_t *> states;
	std::vector<std::string> log_files;
	ssize_t ret = iuflog_read_states(log, uint64_t(-1),
			next_file_no, log_files, states);
	X_LOG(UTILS, DBG, "x_smbd_durable_log_read ret %ld", ret);

	int fd = openat(log->dir_fd, IUFLOG_TMP,
			O_WRONLY | O_CREAT | O_TRUNC, 0644);
	iuflog_init_header(fd, next_file_no);

	auto buf = alloc_buffer(log->max_record_size);
	iuflog_record_t *rec = (iuflog_record_t *)buf.get();
	size_t count = 0;
	for (auto &[id, state]: states) {
		int ret = restorer(id, state);

		if (ret < 0) {
			X_LOG(UTILS, WARN, "failed to restore_state for id 0x%lx",
					id);
			iuflog_state_release(state);
			continue;
		}

		// log->num_durable.fetch_add(1, std::memory_order_relaxed);

		ssize_t size = iuflog_state_encode(state, rec + 1,
				log->max_record_size);
		X_ASSERT(size >= 0);
		int err = iuflog_output(fd, false,
				x_iuflog_record_type_t::initiate,
				id,
				rec, size);
		X_TODO_ASSERT(err == 0);
		iuflog_state_release(state);
		++count;
	}
	fsync(fd);
	close(fd);
	renameat(log->dir_fd, IUFLOG_TMP,
			log->dir_fd, IUFLOG_MERGED);

	for (auto &log_file: log_files) {
		unlinkat(log->dir_fd, log_file.c_str(), 0);
	}

	log->next_file_no = log->last_merge_no = next_file_no;
	fd = iuflog_open_log(log, 0);
	log->log_fd = x_ref_ptr_t(new iuflog_fd_t(fd));
	X_LOG(UTILS, NOTICE, "durable_restored %ld", count);
}

static void iuflog_merge_log(x_iuflog_t *log)
{
	uint64_t max_file_no = log->next_file_no;
	int fd = iuflog_open_log(log, 0);
	auto log_fd = x_ref_ptr_t(new iuflog_fd_t(fd));
	{
		auto lock = std::unique_lock(log->mutex);
		std::swap(log->log_fd, log_fd);
	}

	if (log_fd->refcnt.load(std::memory_order_relaxed) > 1) {
		--max_file_no;
		X_LOG(UTILS, DBG, "some thread still write into 0x%016lx, skip it",
				max_file_no);
	}

	if (max_file_no < log->last_merge_no + log->merge_threshold) {
		return;
	}

	uint64_t next_file_no;
	std::map<uint64_t, x_iuflog_state_t *> states;
	std::vector<std::string> log_files;

	ssize_t ret = iuflog_read_states(log, max_file_no,
			next_file_no, log_files, states);
	X_LOG(UTILS, DBG, "x_smbd_durable_log_read ret %ld", ret);

	fd = openat(log->dir_fd, IUFLOG_TMP,
			O_WRONLY | O_CREAT | O_TRUNC, 0644);
	iuflog_init_header(fd, next_file_no);

	size_t count = 0;
	auto buf = alloc_buffer(log->max_record_size);
	for (auto &[id, state]: states) {
		iuflog_record_t *rec = (iuflog_record_t *)buf.get();
		ssize_t err = iuflog_state_encode(state, rec + 1, log->max_record_size);
		if (err < 0) {
			X_LOG(UTILS, ERR, "fail to encode_state for id 0x%lx", id);
			continue;
		}
		err = iuflog_output(fd, false,
				x_iuflog_record_type_t::initiate,
				id,
				rec, err);
		X_TODO_ASSERT(err == 0);
		iuflog_state_release(state);
		++count;
	}
	fsync(fd);
	close(fd);
	renameat(log->dir_fd, IUFLOG_TMP,
			log->dir_fd, IUFLOG_MERGED);

	log->last_merge_no = max_file_no;
	for (auto &log_file: log_files) {
		X_LOG(UTILS, NOTICE, "remove iuflog %s",
				log_file.c_str());
		unlinkat(log->dir_fd, log_file.c_str(), 0);
	}
}

static x_job_t::retval_t iuflog_job_run(x_job_t *job, void *sche)
{
	x_iuflog_t *log = X_CONTAINER_OF(job, x_iuflog_t, job);
	iuflog_merge_log(log);
	x_iuflog_release(log);
	return x_job_t::JOB_BLOCKED;
}

x_iuflog_t::x_iuflog_t(x_threadpool_t *threadpool,
		int dir_fd,
		x_iuflog_parse_fn parse,
		uint32_t max_record_size,
		uint32_t max_record_per_file,
		uint32_t merge_threshold)
	: job(iuflog_job_run), threadpool(threadpool)
	, parse(parse), dir_fd(dup(dir_fd))
	, max_record_size(max_record_size)
	, max_record_per_file(max_record_per_file)
	, merge_threshold(merge_threshold)
{
	X_ASSERT(dir_fd >= 0);
}

void x_iuflog_release(x_iuflog_t *log)
{
	if (log->refcnt.fetch_sub(1, std::memory_order_acq_rel) == 1) {
		delete log;
	}
}

x_iuflog_t *x_iuflog_open(x_threadpool_t *threadpool,
		int dir_fd,
		x_iuflog_parse_fn parse,
		uint32_t max_record_size,
		uint32_t max_record_per_file,
		uint32_t merge_threshold)
{
	x_iuflog_t *log = new x_iuflog_t(threadpool, dir_fd,
			parse,
			max_record_size,
			max_record_per_file,
			merge_threshold);
	X_ASSERT(log);
	return log;
}

