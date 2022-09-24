
#include "include/xdefines.h"
#include "include/timerq.hxx"

static long timerq_timer_func(x_timer_t *timer)
{
	x_timerq_t *timerq = X_CONTAINER_OF(timer, x_timerq_t, timer);
	long wait_ns = timerq->timeout;
	uint64_t expire = tick_now - timerq->timeout;
	x_timerq_entry_t *entry;
	std::unique_lock<std::mutex> lock(timerq->mutex);
	while ((entry = timerq->entry_list.get_front()) != nullptr) {
		wait_ns = x_tick_cmp(entry->queue_time, expire);
		if (wait_ns > 0) {
			break;
		}
		X_LOG_DBG("entry %p at %f", entry, double(tick_now) / 1000000000.0);
		X_ASSERT(entry->state == x_timerq_entry_t::S_QUEUED);
		entry->state = x_timerq_entry_t::S_FIRED;
		timerq->entry_list.remove(entry);
		lock.unlock();
		entry->func(entry);
		lock.lock();
	}

	return std::max(wait_ns, 1l);
};

static void timerq_timer_done(x_timer_t *timer)
{
	x_timerq_t *timerq = X_CONTAINER_OF(timer, x_timerq_t, timer);
	X_LOG_DBG("timerq %p at %f", timerq, double(tick_now) / 1000000000.0);
	// what should we do to the remain entries?
}

static const x_timer_upcall_cbs_t timerq_timer_cbs = {
	timerq_timer_func,
	timerq_timer_done,
};

void x_timerq_init(x_timerq_t &timerq, x_evtmgmt_t *evtmgmt, uint64_t timeout_ns)
{
	timerq.timeout = timeout_ns;
	timerq.timer.cbs = &timerq_timer_cbs;
	x_evtmgmt_add_timer(evtmgmt, &timerq.timer, timeout_ns);
}

void x_timerq_add(x_timerq_t &timerq, x_timerq_entry_t *entry)
{
	entry->queue_time = tick_now;
	X_LOG_DBG("entry %p at %f", entry, double(tick_now) / 1000000000.0);
	std::lock_guard<std::mutex> lock(timerq.mutex);
	timerq.entry_list.push_back(entry);
	entry->state = x_timerq_entry_t::S_QUEUED;
}

bool x_timerq_cancel(x_timerq_t &timerq, x_timerq_entry_t *entry)
{
	X_LOG_DBG("entry %p at %f", entry, double(tick_now) / 1000000000.0);
	std::lock_guard<std::mutex> lock(timerq.mutex);
	if (entry->state != x_timerq_entry_t::S_QUEUED) {
		return false;
	}
	entry->state = x_timerq_entry_t::S_CANCELLED;
	timerq.entry_list.remove(entry);
	return true;
}

bool x_timerq_reset(x_timerq_t &timerq, x_timerq_entry_t *entry)
{
	std::lock_guard<std::mutex> lock(timerq.mutex);
	if (entry->state != x_timerq_entry_t::S_QUEUED) {
		return false;
	}
	timerq.entry_list.remove(entry);
	entry->queue_time = tick_now;
	timerq.entry_list.push_back(entry);
	return true;
}

