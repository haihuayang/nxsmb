
#include "smbd.hxx"
#include "smbd_ctrl.hxx"
#include "smbd_stats.hxx"
#include "smbd_open.hxx"
#include "include/idtable.hxx"

struct smbd_open_deleter
{
	void operator()(x_smbd_open_t *smbd_open) const {
		x_smbd_open_op_destroy(smbd_open);
	}
};

using smbd_open_table_t = x_idtable_t<x_smbd_open_t, x_idtable_64_traits_t, smbd_open_deleter>;
static smbd_open_table_t *g_smbd_open_table;

/* allocate extra count of open, so it unlikely exceed the hard limit when multiple thread
 * create the open in the same time, because each of them call x_smbd_open_has_space
 * before create it
 */
static constexpr uint32_t g_smbd_open_extra = 32;
bool x_smbd_open_has_space()
{
	return g_smbd_open_table->alloc_count + g_smbd_open_extra < g_smbd_open_table->count;
}

x_smbd_open_t::x_smbd_open_t(x_smbd_object_t *so,
		x_smbd_stream_t *strm,
		x_smbd_tcon_t *st,
		const x_smbd_open_state_t &open_state)
	: tick_create(tick_now), smbd_object(so), smbd_stream(strm)
	, smbd_tcon(x_smbd_ref_inc(st)), open_state(open_state)
{
	X_SMBD_COUNTER_INC(open_create, 1);
}

x_smbd_open_t::~x_smbd_open_t()
{
	x_smbd_ref_dec_if(smbd_tcon);
	x_smbd_object_release(smbd_object, nullptr);
	X_SMBD_COUNTER_INC(open_delete, 1);
}

template <>
x_smbd_open_t *x_smbd_ref_inc(x_smbd_open_t *smbd_open)
{
	g_smbd_open_table->incref(smbd_open->id_volatile);
	return smbd_open;
}

template <>
void x_smbd_ref_dec(x_smbd_open_t *smbd_open)
{
	g_smbd_open_table->decref(smbd_open->id_volatile);
}

int x_smbd_open_table_init(uint32_t count)
{
	g_smbd_open_table = new smbd_open_table_t(count + g_smbd_open_extra);
	return 0;
}

bool x_smbd_open_store(x_smbd_open_t *smbd_open)
{
	return g_smbd_open_table->store(smbd_open, smbd_open->id_volatile);
}

x_smbd_open_t *x_smbd_open_lookup(uint64_t id_presistent, uint64_t id_volatile,
		const x_smbd_tcon_t *smbd_tcon)
{
	auto [found, smbd_open] = g_smbd_open_table->lookup(id_volatile);
	if (found) {
		if (smbd_open->smbd_tcon == smbd_tcon || !smbd_tcon) {
			return smbd_open;
		}
		x_smbd_ref_dec(smbd_open);
	}
	return nullptr;
}

static void smbd_open_durable_timeout(x_timerq_entry_t *timerq_entry)
{
	x_smbd_open_t *smbd_open = X_CONTAINER_OF(timerq_entry,
			x_smbd_open_t, durable_timer);
	X_LOG_DBG("durable_timeout %lx,%lx", smbd_open->id_persistent,
			smbd_open->id_volatile);
	smbd_open->state = x_smbd_open_t::S_DONE;

	g_smbd_open_table->remove(smbd_open->id_volatile);
	x_smbd_ref_dec(smbd_open);

	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto smbd_volume = smbd_object->smbd_volume;
	std::vector<x_smb2_change_t> changes;
	std::unique_ptr<x_smb2_state_close_t> state;
	smbd_volume->ops->close(smbd_object, smbd_open,
			nullptr, state, changes);
	/* TODO changes */

	x_smbd_ref_dec(smbd_open); // ref by timer
}

static NTSTATUS smbd_open_set_durable(x_smbd_open_t *smbd_open)
{
	X_LOG_DBG("set_durable %lx,%lx", smbd_open->id_persistent,
			smbd_open->id_volatile);
	X_ASSERT(smbd_open->smbd_object);
	x_smbd_tcon_t *smbd_tcon;
	{
		/* TODO save durable info to volume so it can restore open
		 * when new smbd take over
		 */
		auto lock = std::lock_guard(smbd_open->smbd_object->mutex);
		X_ASSERT(smbd_open->state == x_smbd_open_t::S_ACTIVE);
		X_ASSERT(smbd_open->smbd_tcon);
		smbd_open->state = x_smbd_open_t::S_INACTIVE;
		smbd_tcon = smbd_open->smbd_tcon;
		smbd_open->smbd_tcon = nullptr;
		smbd_open->durable_timer.func = smbd_open_durable_timeout;
		smbd_open->durable_expire_tick = x_tick_add(tick_now,
				smbd_open->open_state.durable_timeout_msec * 1000000u);
		x_smbd_add_timer(x_smbd_timer_t::DURABLE, &smbd_open->durable_timer);
	}

	uint32_t durable_sec = (smbd_open->open_state.durable_timeout_msec + 999) / 1000;
	int ret = x_smbd_volume_set_durable_timeout(
			*smbd_open->smbd_object->smbd_volume,
			smbd_open->id_persistent,
			durable_sec);
	X_LOG_DBG("set_durable_expired for %p 0x%lx, ret = %d",
			smbd_open, smbd_open->id_persistent, ret);

	x_smbd_ref_dec(smbd_tcon);
	return NT_STATUS_OK;
}

NTSTATUS x_smbd_open_restore(
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		x_smbd_durable_t &smbd_durable)
{
	if (!x_smbd_open_has_space()) {
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	x_smbd_open_t *smbd_open{};
	NTSTATUS status = x_smbd_open_durable(smbd_open, smbd_volume,
			smbd_durable);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	{
		auto lock = std::lock_guard(smbd_open->smbd_object->mutex);
		X_ASSERT(smbd_open->state == x_smbd_open_t::S_ACTIVE);
		X_ASSERT(!smbd_open->smbd_tcon);
		smbd_open->state = x_smbd_open_t::S_INACTIVE;
		smbd_open->durable_timer.func = smbd_open_durable_timeout;
		smbd_open->durable_expire_tick = x_tick_add(tick_now,
				smbd_open->open_state.durable_timeout_msec * 1000000u);
		x_smbd_add_timer(x_smbd_timer_t::DURABLE, &smbd_open->durable_timer);
	}

	smbd_durable.id_volatile = smbd_open->id_volatile;
	return NT_STATUS_OK;
}

NTSTATUS x_smbd_open_close(x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state,
		std::vector<x_smb2_change_t> &changes,
		bool shutdown)
{
	/* TODO atomic change and set */
	if (smbd_open->state == x_smbd_open_t::S_DONE) {
		return NT_STATUS_FILE_CLOSED;
	}

	NTSTATUS status;
	if (shutdown && smbd_open->dh_mode != x_smbd_open_t::DH_NONE) {
		status = smbd_open_set_durable(smbd_open);
		if (NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	smbd_open->state = x_smbd_open_t::S_DONE;

	if (smbd_open->dh_mode != x_smbd_open_t::DH_NONE) {
		int ret = x_smbd_volume_set_durable_timeout(
				*smbd_open->smbd_object->smbd_volume,
				smbd_open->id_persistent,
				0); // 0 mean expired immediately
		X_LOG_DBG("remove_durable for %p 0x%lx, ret = %d",
				smbd_open, smbd_open->id_persistent, ret);
	}

	g_smbd_open_table->remove(smbd_open->id_volatile);
	x_smbd_ref_dec(smbd_open);

	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto smbd_volume = smbd_object->smbd_volume;
	status = smbd_volume->ops->close(smbd_object, smbd_open,
			smbd_requ, state, changes);

	x_smbd_ref_dec(smbd_open); // ref by smbd_tcon open_list
	return status;
}


NTSTATUS x_smbd_open_op_close(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state)
{
	if (!x_smbd_tcon_unlink_open(smbd_open->smbd_tcon, &smbd_open->tcon_link)) {
		return NT_STATUS_FILE_CLOSED;
	}

	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto smbd_volume = smbd_object->smbd_volume;
	std::vector<x_smb2_change_t> changes;
	auto status = x_smbd_open_close(smbd_open, smbd_requ, state, changes, false);
	x_smbd_notify_change(smbd_volume, changes);

	return status;
}

void x_smbd_open_unlinked(x_dlink_t *link, x_smbd_tcon_t *smbd_tcon,
		std::vector<x_smb2_change_t> &changes,
		bool shutdown)
{
	x_smbd_open_t *smbd_open = X_CONTAINER_OF(link, x_smbd_open_t, tcon_link);
	std::unique_ptr<x_smb2_state_close_t> state;
	x_smbd_open_close(smbd_open, nullptr, state, changes, shutdown);
}

struct x_smbd_open_list_t : x_smbd_ctrl_handler_t
{
	x_smbd_open_list_t() : iter(g_smbd_open_table->iter_start()) {
	}
	bool output(std::string &data) override;
	smbd_open_table_t::iter_t iter;
};

static const char dh_mode_name[] = "-DP";
bool x_smbd_open_list_t::output(std::string &data)
{
	std::ostringstream os;

	bool ret = g_smbd_open_table->iter_entry(iter, [&os](const x_smbd_open_t *smbd_open) {
			os << idl::x_hex_t<uint64_t>(smbd_open->id_persistent) << ','
			<< idl::x_hex_t<uint64_t>(smbd_open->id_volatile) << ' '
			<< idl::x_hex_t<uint32_t>(smbd_open->open_state.access_mask) << ' '
			<< idl::x_hex_t<uint32_t>(smbd_open->open_state.share_access) << ' '
			<< dh_mode_name[int(smbd_open->dh_mode)] << ' '
			<< idl::x_hex_t<uint32_t>(smbd_open->notify_filter) << ' '
			<< idl::x_hex_t<uint32_t>(x_smbd_tcon_get_id(smbd_open->smbd_tcon)) << " '"
			<< x_smbd_open_op_get_path(smbd_open) << "'" << std::endl;
			return true;
		});
	if (ret) {
		data = os.str(); // TODO avoid copying
		return true;
	} else {
		return false;
	}
}

x_smbd_ctrl_handler_t *x_smbd_open_list_create()
{
	return new x_smbd_open_list_t;
}
