
#include "smbd_stats.hxx"
#include "smbd_ctrl.hxx"

x_smbd_stats_t g_smbd_stats;

#undef X_SMBD_COUNTER_DECL
#define X_SMBD_COUNTER_DECL(x) # x,
static const char *smbd_counter_names[] = {
	X_SMBD_COUNTER_ENUM
};

int x_smbd_stats_init()
{
	return 0;
}

struct x_smbd_stats_report_t : x_smbd_ctrl_handler_t
{
	bool output(std::string &data) override;
	uint32_t counter_index = 0;
};

bool x_smbd_stats_report_t::output(std::string &data)
{
	std::ostringstream os;

	if (counter_index >= X_SMBD_COUNTER_ID_MAX) {
		return false;
	}

	os << smbd_counter_names[counter_index] << ": " << g_smbd_stats.counters[counter_index] << std::endl;
	++counter_index;
	data = os.str();
	return true;
}

x_smbd_ctrl_handler_t *x_smbd_stats_report_create()
{
	return new x_smbd_stats_report_t;
}

