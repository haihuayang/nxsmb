
#include "nxfsd_sched.hxx"

struct x_nxfsd_defer_t
{
	uint32_t seqno = 0, last_seqno = 0;
	bool is_schedulable = false;
	x_tp_ddlist_t<fdevt_user_conn_traits> evt_list;
};

static thread_local x_nxfsd_defer_t g_nxfsd_defer;

static void nxfsd_set_schedulable(bool f)
{
	X_ASSERT(g_nxfsd_defer.is_schedulable != f);
	g_nxfsd_defer.is_schedulable = f;
}

x_nxfsd_scheduler_t::x_nxfsd_scheduler_t()
{
	nxfsd_set_schedulable(true);
}

static void nxfsd_defer_exec()
{
	x_tp_ddlist_t<fdevt_user_conn_traits> evt_list =
		std::move(g_nxfsd_defer.evt_list);
	
	for (x_fdevt_user_t *evt = evt_list.get_front();
			evt; evt = evt_list.get_front()) {
		evt_list.remove(evt);
		evt->func(nullptr, evt);
	}
}

void x_nxfsd_schedule(x_fdevt_user_t *evt)
{
	X_ASSERT(g_nxfsd_defer.is_schedulable);
	g_nxfsd_defer.evt_list.push_back(evt);
	++g_nxfsd_defer.seqno;
}

x_nxfsd_scheduler_t::~x_nxfsd_scheduler_t()
{
	nxfsd_set_schedulable(false);
	while (g_nxfsd_defer.seqno != g_nxfsd_defer.last_seqno) {
		g_nxfsd_defer.last_seqno = g_nxfsd_defer.seqno;
		nxfsd_defer_exec();
	}
}

