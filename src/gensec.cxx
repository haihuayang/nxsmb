
#include "gensec.hxx"
#include <string.h>

struct x_gensec_context_t
{
	std::vector<const x_gensec_mech_t *> mechs;
	x_gensec_t *create_by_oid(const char *oid);
};

x_gensec_context_t *x_gensec_create_context()
{
	x_gensec_context_t *ret = new x_gensec_context_t();
	return ret;
}

int x_gensec_register(x_gensec_context_t *context, const x_gensec_mech_t *mech)
{
	for (auto &m : context->mechs) {
		if (strcmp(m->oid, mech->oid) == 0) {
			return EEXIST;
		}
	}
	context->mechs.push_back(mech);
	return 0;
}

static const x_gensec_mech_t *x_gensec_find_by_oid(x_gensec_context_t *gensec_context, const char *oid)
{
	for (auto mech : gensec_context->mechs) {
		if (strcmp(mech->oid, oid) == 0) {
			return mech;
		}
	}
	return NULL;
}

x_gensec_t *x_gensec_create_by_oid(x_gensec_context_t *context, const char *oid)
{
	const x_gensec_mech_t *mech = x_gensec_find_by_oid(context, oid);
	if (!mech) {
		return nullptr;
	}
	return mech->create(context);
}

