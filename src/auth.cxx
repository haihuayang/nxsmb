
#include "smbd.hxx"
#include <string.h>

struct x_auth_context_t
{
	x_auth_context_t(x_smbd_t *smbd) : smbd(smbd) { }
	x_smbd_t * const smbd;
	std::vector<const x_auth_mech_t *> mechs;
	x_auth_t *create_by_oid(const char *oid);
	const std::shared_ptr<x_smbd_conf_t> get_smbd_conf() const {
		return smbd->smbd_conf;
	}
};

x_auth_context_t *x_auth_create_context(x_smbd_t *smbd)
{
	x_auth_context_t *ret = new x_auth_context_t(smbd);
	return ret;
}

static const x_auth_mech_t *x_auth_find_by_oid(x_auth_context_t *auth_context, gss_const_OID oid)
{
	for (auto mech : auth_context->mechs) {
		if (gss_oid_equal(oid, mech->oid)) {
			return mech;
		}
	}
	return NULL;
}

int x_auth_register(x_auth_context_t *context, const x_auth_mech_t *mech)
{
	auto old = x_auth_find_by_oid(context, mech->oid);
	if (old) {
		return EEXIST;
	}
	context->mechs.push_back(mech);
	return 0;
}

x_auth_t *x_auth_create_by_oid(x_auth_context_t *context, gss_const_OID oid)
{
	const x_auth_mech_t *mech = x_auth_find_by_oid(context, oid);
	if (!mech) {
		return nullptr;
	}
	return mech->create(context);
}

const std::shared_ptr<x_smbd_conf_t> x_auth_context_get_smbd_conf(const x_auth_context_t *context)
{
	return context->get_smbd_conf();
}
#if 0
bool x_auth_context_lpcfg_lanman_auth(const x_auth_context_t *context);
const std::string x_auth_context_lpcfg_netbios_name(const x_auth_context_t *context);
const std::string x_auth_context_lpcfg_workgroup(const x_auth_context_t *context);
const std::string x_auth_context_lpcfg_dns_domain(const x_auth_context_t *context);
const std::string x_auth_context_lpcfg_realm(const x_auth_context_t *context);

bool x_auth_context_lpcfg_lanman_auth(x_auth_context_t *context)
{
	return context->get_smbconf()->lanman_auth;
}

const std::string x_auth_context_lpcfg_netbios_name(x_auth_context_t *context)
{
	return context->get_smbconf()->netbios_name;
}

const std::string x_auth_context_lpcfg_workgroup(x_auth_context_t *context)
{
	return context->get_smbconf()->workgroup;
}

const std::string x_auth_context_lpcfg_realm(x_auth_context_t *context)
{
	return context->get_smbconf()->realm;
}

const std::string x_auth_context_lpcfg_dns_domain(x_auth_context_t *context)
{
	return context->get_smbconf()->dns_domain;
}
#endif

