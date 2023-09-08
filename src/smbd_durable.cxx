
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

#define ALIGN(s, a) (((s) + (a) - 1) & ~(a))

enum {
	X_SMBD_DURABLE_DB_VERSION_1 = 1,
	X_SMBD_DURABLE_DB_RECORD_SIZE = 512,
	X_SMBD_DURABLE_TORELANT = 10,
};

static const char magic[8] = "DURABLE";

static_assert(X_SMBD_DURABLE_DB_RECORD_SIZE >= sizeof(x_smbd_durable_t));

/* reserve 4k for the header */
#define HEADER_SIZE 4096
struct x_smbd_durable_db_header_t
{
	uint8_t magic[8];
	uint32_t version;
	uint32_t record_size;
	uint32_t capacity;
	uint16_t generation;
	uint16_t unused1;
	uint64_t unused2;
};

struct x_smbd_durable_db_t
{
	x_smbd_durable_db_t(int fd, x_smbd_durable_db_header_t *header,
			uint64_t msize)
		: fd(fd), generation(header->generation), capacity(header->capacity)
		, header(header), map_size(msize)
	{
	}

	~x_smbd_durable_db_t()
	{
		X_ASSERT(munmap(header, map_size) == 0);
		X_ASSERT(close(fd) == 0);
	}

	const int fd;
	const uint16_t generation; /* increase every restart */
	const uint32_t capacity;

	std::mutex mutex;
	x_smbd_durable_db_header_t *const header;
	uint64_t const map_size;
	uint32_t free_region_index;
	std::priority_queue<uint32_t, std::vector<uint32_t>, std::greater<uint32_t>> free_slots;
};

static int64_t smbd_durable_db_size(uint32_t record_size, uint32_t capacity)
{
	return HEADER_SIZE + (record_size * capacity);
}

static x_smbd_durable_t *get_durable(x_smbd_durable_db_t *db, uint64_t slot)
{
	return (x_smbd_durable_t *)((uint8_t *)db->header + HEADER_SIZE + slot * X_SMBD_DURABLE_DB_RECORD_SIZE);
}

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
		uint64_t *p_id_persistent)
{
	auto lock = std::lock_guard(db->mutex);
	uint32_t slot;
	if (!db->free_slots.empty()) {
		slot = db->free_slots.top();
		db->free_slots.pop();
	} else if (db->free_region_index >= db->capacity) {
		return -ENOSPC;
	} else {
		slot = db->free_region_index++;
	}
	uint64_t id = db->generation;
	id = (id << 32) | slot;
	*p_id_persistent = id;
	return 0;
}

static void smbd_durable_db_free_slot(x_smbd_durable_db_t *db, uint32_t slot)
{
	auto lock = std::lock_guard(db->mutex);
	if (db->free_region_index == slot + 1) {
		db->free_region_index = slot;
	} else {
		db->free_slots.push(slot);
	}
}

int x_smbd_durable_remove(x_smbd_durable_db_t *db, uint64_t id_persistent)
{
	X_LOG_DBG("id_persistent=0x%lx", id_persistent);
	uint32_t slot = get_durable_slot(id_persistent);

	X_ASSERT(slot < db->capacity);
	x_smbd_durable_t *durable = get_durable(db, slot);
	/* mark it as freed */
	durable->open_state.id_persistent = 0;
	smbd_durable_db_free_slot(db, slot);
	msync(durable, sizeof *durable, MS_SYNC); // can we avoid msync ?
	return 0;
}

int x_smbd_durable_disconnect(x_smbd_durable_db_t *db, uint64_t id_persistent)
{
	X_LOG_DBG("id_persistent=0x%lx", id_persistent);
	uint32_t slot = get_durable_slot(id_persistent);

	X_ASSERT(slot < db->capacity);
	x_smbd_durable_t *durable = get_durable(db, slot);
	durable->expired_msec = get_epoch_msec() + durable->open_state.durable_timeout_msec;
	msync(durable, sizeof *durable, MS_SYNC); // can we avoid msync ?
	return 0;
}

int x_smbd_durable_save(x_smbd_durable_db_t *db,
		uint64_t id_volatile,
		const x_smbd_open_state_t &open_state,
		const x_smbd_file_handle_t &file_handle)
{
	X_LOG_DBG("id_persistent=0x%lx", open_state.id_persistent);
	uint32_t slot = get_durable_slot(open_state.id_persistent);

	X_ASSERT(slot < db->capacity);
	x_smbd_durable_t *db_rec = get_durable(db, slot);
	new (db_rec)x_smbd_durable_t{uint64_t(-1),
		id_volatile, open_state, file_handle};
	msync(db_rec, sizeof *db_rec, MS_SYNC);
	return 0;
}

x_smbd_durable_t *x_smbd_durable_lookup(x_smbd_durable_db_t *db,
		uint64_t id_persistent)
{
	uint32_t slot = get_durable_slot(id_persistent);
	if (slot >= db->capacity) {
		return nullptr;
	}

	x_smbd_durable_t *durable = get_durable(db, slot);
	if (durable->open_state.id_persistent != id_persistent ||
			durable->expired_msec < get_epoch_msec()) {
		return nullptr;
	}

	return durable;
}

static bool smbd_durable_db_check(const x_smbd_durable_db_header_t *db_header,
		int64_t db_size)
{
	if (memcmp(db_header->magic, magic, sizeof magic) != 0) {
		X_LOG_ERR("Invalid durable.db, wrong magic");
		return false;
	}

	if (db_header->version != X_SMBD_DURABLE_DB_VERSION_1) {
		X_LOG_ERR("Not support durable.db version %d", db_header->version);
		return false;
	}

	if (db_header->record_size != X_SMBD_DURABLE_DB_RECORD_SIZE) {
		X_LOG_ERR("Invalid durable.db, record_size = %u",
				db_header->record_size);
		return false;
	}

	if (db_size < (long)smbd_durable_db_size(db_header->record_size, db_header->capacity)) {
		X_LOG_ERR("Invalid durable.db, size not match");
		return false;
	}
	return true;
}

x_smbd_durable_db_t *x_smbd_durable_db_open(int fd)
{
	struct stat st;
	int err = fstat(fd, &st);
	X_ASSERT(err == 0);

	if (st.st_size < HEADER_SIZE) {
		X_LOG_ERR("Invalid durable.db");
		return nullptr;
	}

	void *ptr = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	X_ASSERT(ptr);
	x_smbd_durable_db_header_t *db_header = (x_smbd_durable_db_header_t *)ptr;

	if (!smbd_durable_db_check(db_header, st.st_size)) {
		munmap(ptr, st.st_size);
		return nullptr;
	}

	x_smbd_durable_db_t *db = new x_smbd_durable_db_t(fd,
			db_header, st.st_size);
	return db;
}

x_smbd_durable_db_t *x_smbd_durable_db_init(int fd, uint32_t capacity)
{
	struct stat st;
	int err = fstat(fd, &st);
	X_ASSERT(err == 0);
	x_smbd_durable_db_header_t *db_header = nullptr;
	uint16_t generation = 0;
	if (st.st_size == 0) {
		/* new file */
		X_LOG_NOTICE("new durable.db");
	} else if (st.st_size < HEADER_SIZE) {
		X_LOG_ERR("Invalid durable.db");
	} else {
		void *ptr = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		X_ASSERT(ptr);
		db_header = (x_smbd_durable_db_header_t *)ptr;
		generation = x_convert<uint16_t>(db_header->generation + 1);
		if (!smbd_durable_db_check(db_header, st.st_size)) {
			munmap(ptr, st.st_size);
			ptr = nullptr;
		} else {
			X_LOG_NOTICE("can reuse durable.db");
		}
	}

	size_t mmap_size;
	if (!db_header) {
		X_LOG_NOTICE("re-init durable.db");
		if (st.st_size != 0) {
			X_ASSERT(ftruncate(fd, 0) == 0);
		}
		mmap_size = smbd_durable_db_size(X_SMBD_DURABLE_DB_RECORD_SIZE,
				capacity);
		X_ASSERT(ftruncate(fd, mmap_size) == 0);
		void *ptr = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		X_ASSERT(ptr);
		db_header = (x_smbd_durable_db_header_t *)ptr;
		memcpy(db_header->magic, magic, 8);
		db_header->version = X_SMBD_DURABLE_DB_VERSION_1;
		db_header->record_size = X_SMBD_DURABLE_DB_RECORD_SIZE;
		db_header->capacity = capacity;
	} else {
		mmap_size = st.st_size;
		/* TODO restore durable opens */
	}
	db_header->generation = generation;
	msync(db_header, sizeof *db_header, MS_SYNC);

	x_smbd_durable_db_t *db = new x_smbd_durable_db_t(fd, db_header,
			mmap_size);
	return db;
}

void x_smbd_durable_db_traverse(x_smbd_durable_db_t *durable_db,
		x_smbd_durable_db_visitor_t &visitor)
{
	uint64_t epoch = get_epoch_msec();
	uint8_t *rec = (uint8_t *)durable_db->header + HEADER_SIZE;
	uint32_t i;
	for (i = 0; i < durable_db->capacity; ++i, rec += X_SMBD_DURABLE_DB_RECORD_SIZE) {
		x_smbd_durable_t *durable = (x_smbd_durable_t *)rec;
		if (durable->open_state.id_persistent == 0 && durable->id_volatile) {
			/* no valid record beyond this */
			break;
		}
		if (durable->open_state.id_persistent != 0 &&
				durable->expired_msec > epoch) {
			if (visitor(*durable)) {
				break;
			}
		}
	}
}

void x_smbd_durable_db_restore(std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		x_smbd_durable_db_t *durable_db,
		NTSTATUS (*restore_fn)(std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			x_smbd_durable_t &durable, uint64_t timeout_msec))
{
	uint64_t epoch = get_epoch_msec();
	uint8_t *rec = (uint8_t *)durable_db->header + HEADER_SIZE;
	std::array<uint32_t, 2> free_range{ 0, 0 };
	uint32_t i, count = 0;
	for (i = 0; i < durable_db->capacity; ++i, rec += X_SMBD_DURABLE_DB_RECORD_SIZE) {
		x_smbd_durable_t *durable = (x_smbd_durable_t *)rec;
		if (durable->open_state.id_persistent == 0 && durable->id_volatile == 0) {
			/* no valid record beyond this */
			break;
		}
		if (durable->open_state.id_persistent != 0 &&
				durable->expired_msec > epoch) {
			uint64_t timeout_msec;
			if (durable->expired_msec == (uint64_t)-1) {
				durable->expired_msec = epoch + durable->open_state.durable_timeout_msec;
				timeout_msec = durable->open_state.durable_timeout_msec;
			} else {
				timeout_msec = durable->expired_msec - epoch;
			}
			++count;

			NTSTATUS status = restore_fn(smbd_volume, *durable, timeout_msec);
			if (NT_STATUS_IS_OK(status)) {
				X_LOG_DBG("restored open %lx:%lx",
						durable->open_state.id_persistent,
						durable->id_volatile);
				continue;
			}
			X_LOG_WARN("failed to restore open %lx:%lx",
					durable->open_state.id_persistent,
					durable->id_volatile);
			durable->open_state.id_persistent = 0;
		}

		if (i == free_range[1]) {
			++free_range[1];
		} else {
			for (uint32_t f = free_range[0]; f < free_range[1]; ++f) {
				durable_db->free_slots.push(f);
			}
			free_range = { i, i + 1 };
		}
	}

	if (i != free_range[1]) {
		for (uint32_t f = free_range[0]; f < free_range[1]; ++f) {
			durable_db->free_slots.push(f);
		}
		durable_db->free_region_index = i;
	} else {
		durable_db->free_region_index = free_range[0];
	}
	X_LOG_NOTICE("durable_restored %d free_region_index=%u", count,
			durable_db->free_region_index);
	/* TODO
	 * msync the modified records, and
	 * should clean up all the region started from free_region_index,
	 * maybe do ftruncate
	 */
}

void x_smbd_durable_db_close(x_smbd_durable_db_t *durable_db)
{
	delete durable_db;
}


