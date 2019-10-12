
#include "smbd.hxx"
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

static const x_gensec_mech_t *x_gensec_find_by_oid(x_gensec_context_t *gensec_context, gss_const_OID oid)
{
	for (auto mech : gensec_context->mechs) {
		if (gss_oid_equal(oid, mech->oid)) {
			return mech;
		}
	}
	return NULL;
}

int x_gensec_register(x_gensec_context_t *context, const x_gensec_mech_t *mech)
{
	auto old = x_gensec_find_by_oid(context, mech->oid);
	if (old) {
		return EEXIST;
	}
	context->mechs.push_back(mech);
	return 0;
}

x_gensec_t *x_gensec_create_by_oid(x_gensec_context_t *context, gss_const_OID oid)
{
	const x_gensec_mech_t *mech = x_gensec_find_by_oid(context, oid);
	if (!mech) {
		return nullptr;
	}
	return mech->create(context);
}

