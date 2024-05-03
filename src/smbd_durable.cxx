
#include "include/bits.hxx"
#include "smbd_durable.hxx"
#include <sys/mman.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <string.h>
#include <atomic>
#include <mutex>
#include <queue>
#include <stdlib.h>
#include <dirent.h>

#define ALIGN(s, a) (((s) + (a) - 1) & ~(a))

struct x_smbd_durable_slot_t
{
	std::atomic<uint64_t> id_volatile;
};

struct x_smbd_durable_fd_t
{
	x_smbd_durable_fd_t(int fd) : fd(fd) { }
	~x_smbd_durable_fd_t() { X_ASSERT(close(fd) == 0); }

	const int fd;
	std::atomic<uint64_t> num_record{};
};

struct x_smbd_durable_db_t
{
	x_smbd_durable_db_t(int fd, uint32_t capacity, uint32_t max_record_per_file);

	~x_smbd_durable_db_t()
	{
		X_ASSERT(close(dir_fd) == 0);
	}

	x_job_t job;

	std::atomic<int> refcnt{1};
	const int dir_fd;
	const uint32_t max_record_per_file;
	std::shared_ptr<x_smbd_durable_fd_t> log_fd;
	uint64_t next_file_no;

	std::atomic<int64_t> num_durable;
	std::vector<x_smbd_durable_slot_t> slots;
};

static inline uint64_t get_epoch_msec()
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
};

static inline uint32_t get_durable_slot(uint64_t id_persistent)
{
	return x_convert<uint32_t>(id_persistent);
}

int x_smbd_durable_db_allocate_id(x_smbd_durable_db_t *db,
		uint64_t *p_id_persistent, uint64_t id_volatile)
{
	X_ASSERT(id_volatile != 0);
	if (db->num_durable.load(std::memory_order_relaxed) >=
			int64_t(db->slots.size() / 2)) {
		return -ENOSPC;
	}
	uint64_t slot_id;
	uint64_t rval;
	std::uniform_int_distribution<uint64_t> distrib(0ul, (1ul << 48) - 1);

	for (uint32_t i = 0; ; ++i) {
		rval = distrib(rand_engine);
		slot_id = rval % db->slots.size();
		auto &slot = db->slots[slot_id];
		
		uint64_t old_val = 0ul;
		if (std::atomic_compare_exchange_weak_explicit(
					&slot.id_volatile,
					&old_val, id_volatile,
					std::memory_order_relaxed,
					std::memory_order_relaxed)) {
			break;
		}
	}
	X_ASSERT(db->num_durable.fetch_add(1, std::memory_order_relaxed) >= 0);
	uint64_t id = (rval & (0xffff00000000)) | slot_id;
	*p_id_persistent = id;
	return 0;
}

static void smbd_durable_output_log(x_smbd_durable_db_t *db,
		x_smbd_durable_record_t *rec,
		uint32_t type, uint32_t size,
		uint64_t id_persistent)
{
	auto log_fd = db->log_fd;
	bool ret = x_smbd_durable_log_output(log_fd->fd, rec, type, size, id_persistent);
	X_ASSERT(ret);
	/* shall it call fsync only for persistent handle? */
	fsync(log_fd->fd);
	if (log_fd->num_record.fetch_add(1, std::memory_order_relaxed) ==
			db->max_record_per_file) {
		X_LOG(SMB, NOTICE, "schedule create new durable log for dirfd %d",
				db->dir_fd);
		db->refcnt.fetch_add(1, std::memory_order_relaxed);
		x_smbd_schedule_async(&db->job);
	}
}

int x_smbd_durable_remove(x_smbd_durable_db_t *db, uint64_t id_persistent)
{
	X_LOG(SMB, DBG, "id_persistent=0x%lx", id_persistent);
	uint32_t slot_id = get_durable_slot(id_persistent);

	X_ASSERT(slot_id < db->slots.size());
	uint64_t id_volatile = db->slots[slot_id].id_volatile.exchange(0, std::memory_order_relaxed);
	X_ASSERT(id_volatile != 0);
	X_ASSERT(db->num_durable.fetch_sub(1, std::memory_order_relaxed) > 0);

	x_smbd_durable_record_t record;
	smbd_durable_output_log(db, &record,
			x_smbd_durable_record_t::type_close,
			sizeof record, id_persistent);
	return 0;
}

int x_smbd_durable_disconnect(x_smbd_durable_db_t *db, uint64_t id_persistent)
{
	X_LOG(SMB, DBG, "id_persistent=0x%lx", id_persistent);
	uint32_t slot_id = get_durable_slot(id_persistent);

	X_ASSERT(slot_id < db->slots.size());
	struct {
		x_smbd_durable_record_t record;
		uint64_t disconnect_msec;
	} record;
	record.disconnect_msec = get_epoch_msec();

	smbd_durable_output_log(db, &record.record,
			x_smbd_durable_record_t::type_disconnect,
			sizeof record, id_persistent);
	return 0;
}

int x_smbd_durable_save(x_smbd_durable_db_t *db,
		uint64_t id_persistent,
		uint64_t id_volatile,
		const x_smbd_open_state_t &open_state,
		const x_smbd_lease_data_t &lease_data,
		const x_smbd_file_handle_t &file_handle)
{
	X_LOG(SMB, DBG, "id_persistent=0x%lx", id_persistent);

	auto record = (x_smbd_durable_record_t *)malloc(sizeof(x_smbd_durable_record_t)
			+ sizeof(x_smbd_durable_t));
	/* TODO serialize */
	new (record + 1)x_smbd_durable_t{
		uint64_t(-1),
		id_volatile, open_state, lease_data, file_handle};
	smbd_durable_output_log(db, record, x_smbd_durable_record_t::type_create,
			sizeof(x_smbd_durable_record_t) + sizeof(x_smbd_durable_t),
			id_persistent);
	free(record);
	return 0;
}

int x_smbd_durable_update(x_smbd_durable_db_t *db,
		uint64_t id_persistent,
		const x_smbd_open_state_t &open_state)
{
	X_LOG(SMB, DBG, "id_persistent=0x%lx", id_persistent);

	/* only update replay_cached */
	struct {
		x_smbd_durable_record_t record;
		uint64_t replay_cached;
	} record;

	record.replay_cached = open_state.replay_cached ? 1 : 0;
	smbd_durable_output_log(db, &record.record,
			x_smbd_durable_record_t::type_update_replay,
			sizeof(record),
			id_persistent);
	return 0;
}

uint64_t x_smbd_durable_lookup(x_smbd_durable_db_t *db,
		uint64_t id_persistent)
{
	uint32_t slot_id = get_durable_slot(id_persistent);
	if (slot_id >= db->slots.size()) {
		return 0;
	}

	return db->slots[slot_id].id_volatile.load(std::memory_order_relaxed);
}

x_smbd_durable_db_t *x_smbd_durable_db_init(int dir_fd, uint32_t capacity,
		uint32_t max_record_per_file)
{
	x_smbd_durable_db_t *db = new x_smbd_durable_db_t(dir_fd, capacity,
			max_record_per_file);
	X_ASSERT(db);
	return db;
}

static int smbd_durable_open_log(x_smbd_durable_db_t *durable_db, uint64_t next_file_no)
{
	char name[128];
	snprintf(name, sizeof name, X_SMBD_DURABLE_LOG "--%016lx", durable_db->next_file_no);
	++durable_db->next_file_no;
	int fd = openat(durable_db->dir_fd, name,
			O_WRONLY | O_CREAT | O_EXCL | O_APPEND, 0644);
	X_ASSERT(fd != -1);

	x_smbd_durable_log_init_header(fd, next_file_no);
	return fd;
}

void x_smbd_durable_db_restore(std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		x_smbd_durable_db_t *durable_db,
		NTSTATUS (*restore_fn)(std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			x_smbd_durable_t &durable, uint64_t timeout_msec))
{
	uint64_t next_file_no;
	std::map<uint64_t, x_smbd_durable_t> durables;
	std::vector<std::string> log_files;
	ssize_t ret = x_smbd_durable_log_read(durable_db->dir_fd, uint64_t(-1),
			next_file_no, durables, log_files);
	X_LOG(SMB, DBG, "x_smbd_durable_log_read ret %ld", ret);

	int fd = openat(durable_db->dir_fd, X_SMBD_DURABLE_LOG_TMP,
			O_WRONLY | O_CREAT | O_TRUNC, 0644);
	x_smbd_durable_log_init_header(fd, next_file_no);

	uint64_t epoch = get_epoch_msec();
	size_t count = 0;
	for (auto &[id_persistent, durable]: durables) {
		uint64_t timeout_msec;
		if (durable.disconnect_msec == (uint64_t)-1) {
			durable.disconnect_msec = epoch;
			timeout_msec = durable.open_state.durable_timeout_msec;
		} else {
			uint64_t expired_msec = durable.disconnect_msec + durable.open_state.durable_timeout_msec;
		       	if (expired_msec < epoch) {
				continue;
			}
			timeout_msec = expired_msec - epoch;
		}
		uint64_t slot_id = get_durable_slot(id_persistent);
		if (slot_id >= durable_db->slots.size()) {
			X_LOG(SMB, ERR, "invalid id_persistent 0x%lx",
					id_persistent);
			continue;
		}
		NTSTATUS status = restore_fn(smbd_volume, durable, timeout_msec);
		if (!NT_STATUS_IS_OK(status)) {
			X_LOG(SMB, WARN, "failed to restore open %lx:%lx",
					id_persistent,
					durable.id_volatile);
			continue;
		}
		X_LOG(SMB, DBG, "restored open %lx:%lx",
				id_persistent,
				durable.id_volatile);

		durable_db->slots[slot_id].id_volatile.store(durable.id_volatile, std::memory_order_relaxed);
		durable_db->num_durable.fetch_add(1, std::memory_order_relaxed);
		struct {
			x_smbd_durable_record_t record;
			x_smbd_durable_t durable;
		} record = { {}, durable };
		x_smbd_durable_log_output(fd, &record.record,
				x_smbd_durable_record_t::type_create,
				sizeof record, id_persistent);
		++count;
	}
	fsync(fd);
	close(fd);
	renameat(durable_db->dir_fd, X_SMBD_DURABLE_LOG_TMP,
			durable_db->dir_fd, X_SMBD_DURABLE_LOG_MERGED);

	for (auto &log_file: log_files) {
		unlinkat(durable_db->dir_fd, log_file.c_str(), 0);
	}

	durable_db->next_file_no = next_file_no;
	fd = smbd_durable_open_log(durable_db, 0);
	durable_db->log_fd = std::make_shared<x_smbd_durable_fd_t>(fd);
	X_LOG(SMB, NOTICE, "durable_restored %ld", count);
}

void x_smbd_durable_db_release(x_smbd_durable_db_t *durable_db)
{
	if (durable_db->refcnt.fetch_sub(1, std::memory_order_acq_rel) == 1) {
		delete durable_db;
	}
}

static void smbd_durable_merge_log(x_smbd_durable_db_t *durable_db)
{
	uint64_t max_file_no = durable_db->next_file_no;
	int fd = smbd_durable_open_log(durable_db, 0);
	auto log_fd = std::make_shared<x_smbd_durable_fd_t>(fd);
	std::swap(durable_db->log_fd, log_fd);

	if ((max_file_no % 3) != 0) {
		return;
	}

	X_LOG(SMB, DBG, "merge durable log file for dirfd %d, next_file_no %lx",
			durable_db->dir_fd, max_file_no);

	if (log_fd.use_count() > 1) {
		--max_file_no;
		X_LOG(SMB, DBG, "some thread still write into 0x%016lx, skip it",
				max_file_no);
	}

	uint64_t next_file_no;
	std::map<uint64_t, x_smbd_durable_t> durables;
	std::vector<std::string> log_files;

	ssize_t ret = x_smbd_durable_log_read(durable_db->dir_fd, max_file_no,
			next_file_no, durables, log_files);
	X_LOG(SMB, DBG, "x_smbd_durable_log_read ret %ld", ret);

	fd = openat(durable_db->dir_fd, X_SMBD_DURABLE_LOG_TMP,
			O_WRONLY | O_CREAT | O_TRUNC, 0644);
	x_smbd_durable_log_init_header(fd, next_file_no);

	size_t count = 0;
	for (auto &[id_persistent, durable]: durables) {
		struct {
			x_smbd_durable_record_t record;
			x_smbd_durable_t durable;
		} record = { {}, durable };
		x_smbd_durable_log_output(fd, &record.record,
				x_smbd_durable_record_t::type_create,
				sizeof record, id_persistent);
		++count;
	}
	fsync(fd);
	close(fd);
	renameat(durable_db->dir_fd, X_SMBD_DURABLE_LOG_TMP,
			durable_db->dir_fd, X_SMBD_DURABLE_LOG_MERGED);

	for (auto &log_file: log_files) {
		X_LOG(SMB, NOTICE, "remove durable log %s",
				log_file.c_str());
		unlinkat(durable_db->dir_fd, log_file.c_str(), 0);
	}
}

static x_job_t::retval_t durable_job_run(x_job_t *job, void *sche)
{
	x_smbd_durable_db_t *durable_db = X_CONTAINER_OF(job, x_smbd_durable_db_t, job);
	smbd_durable_merge_log(durable_db);
	x_smbd_durable_db_release(durable_db);
	return x_job_t::JOB_BLOCKED;
}

x_smbd_durable_db_t::x_smbd_durable_db_t(int fd, uint32_t capacity,
		uint32_t max_record_per_file)
	: job(durable_job_run), dir_fd(dup(fd))
	, max_record_per_file(max_record_per_file), slots(capacity << 1)
{
	X_ASSERT(dir_fd >= 0);
}


