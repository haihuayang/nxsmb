
#include "smbd_group_mapping.hxx"
#include <map>
#include <tdb.h>
#include <fcntl.h>

struct x_smbd_group_policy_t
{
	const char * const name;
	const idl::dom_sid * const sid;
	uint64_t privilege;
	std::vector<idl::dom_sid> members;
};

struct x_smbd_group_mapping_t
{
	x_smbd_group_policy_t policies[3] = {
		{ "Administrators", &global_sid_Builtin_Administrators, 0x1ffffff0, },
		{ "Users", &global_sid_Builtin_Users, 0, },
		{ "Backup", &global_sid_Builtin_Backup_Operators, 0x600, },
	};
};

x_smbd_group_mapping_t *x_smbd_group_mapping_create()
{
	return new x_smbd_group_mapping_t;
}

void x_smbd_group_mapping_delete(x_smbd_group_mapping_t *group_mapping)
{
	delete group_mapping;
}

struct dom_sid_comp_t
{
	bool operator() (const idl::dom_sid &lhs, const idl::dom_sid &rhs) const
	{
		if (lhs.num_auths != rhs.num_auths) {
			return lhs.num_auths < rhs.num_auths;
		}
		for (size_t i = lhs.num_auths; i-- != 0; ) {
			if (lhs.sub_auths[i] != rhs.sub_auths[i]) {
				return lhs.sub_auths[i] < rhs.sub_auths[i];
			}
		}
		if (lhs.sid_rev_num != rhs.sid_rev_num) {
			return lhs.sid_rev_num < rhs.sid_rev_num;
		}
		for (size_t i = 0; i < 6; ++i) {
			if (lhs.id_auth[i] != rhs.id_auth[i]) {
				return lhs.id_auth[i] < rhs.id_auth[i];
			}
		}
		return false;
	}
};

struct collect_aliases_state_t
{
	std::map<idl::dom_sid, std::vector<idl::dom_sid>, dom_sid_comp_t> mapping;
};

static const char MEMBEROF_PREFIX[] = "MEMBEROF/";
static int collect_aliases_read_func(struct tdb_context *tdb,
		TDB_DATA kbuf, TDB_DATA dbuf,
		void *private_data)
{
	collect_aliases_state_t *state = (collect_aliases_state_t *)private_data;
	if (kbuf.dsize < sizeof(MEMBEROF_PREFIX) || memcmp(kbuf.dptr,
				MEMBEROF_PREFIX, sizeof(MEMBEROF_PREFIX) - 1) != 0) {
		return 0;
	}

	const char *kstr = (const char *)kbuf.dptr;
	const char *dstr = (const char *)dbuf.dptr;
	if (kstr[kbuf.dsize - 1] != 0 || dstr[dbuf.dsize - 1] != 0) {
		X_LOG(CONF, ERR, "Invalid MEMBEROF");
		return 0;
	}
	idl::dom_sid sid, alias;
	if (!sid_from_string(sid, kstr + sizeof(MEMBEROF_PREFIX) - 1)) {
		X_LOG(CONF, ERR, "Invalid MEMBEROF %s", kstr);
	}
	if (!sid_from_string(alias, dstr)) {
		X_LOG(CONF, ERR, "Invalid alias %s", dstr);
	}

	auto &mapping = state->mapping;
	auto it = mapping.lower_bound(alias);
	if (it == mapping.end() || mapping.key_comp()(alias, it->first)) {
		mapping.insert(it, {alias, {sid}});
	} else {
		it->second.push_back(sid);
	}

	return 0;
}

static auto collect_aliases(struct tdb_context *gm_ctx)
{
	collect_aliases_state_t state;
	int ret = tdb_traverse_read(gm_ctx, collect_aliases_read_func, &state);
	if (ret < 0) {
		X_LOG(CONF, ERR, "ret = %d", ret);
	}
	return std::move(state.mapping);
}

static int get_priviledge_func(TDB_DATA key, TDB_DATA data,
		void *private_data)
{
	uint64_t *state = (uint64_t *)private_data;
	if (data.dsize != sizeof(uint64_t)) {
		/* TODO for old format with size 16, samba get_privileges */
		X_LOG(CONF, ERR, "invalid dsize = %lu", data.dsize);
		return -1;
	}

	uint64_t tmp;
	memcpy(&tmp, data.dptr, sizeof tmp);
	*state = X_LE2H64(tmp);
	return 0;
}

static uint64_t get_priviledge(struct tdb_context *ap_ctx, const idl::dom_sid &sid)
{
	std::ostringstream os;
	os << "PRIV_" << sid;
	const std::string &key = os.str();
	TDB_DATA tdb_key = { (uint8_t *)key.c_str(), key.size() + 1 };
	uint64_t ret = 0;
	int err = tdb_parse_record(ap_ctx, tdb_key, get_priviledge_func, &ret);
	if (err < 0) {
		X_LOG(CONF, ERR, "key = %s", key.c_str());
	}
	return ret;
}

int x_smbd_group_mapping_load(x_smbd_group_mapping_t *group_mapping,
		const std::string &lib_dir)
{
	std::string gm_path = lib_dir + "/group_mapping.tdb";
	struct tdb_context *gm_ctx = tdb_open(gm_path.c_str(), 0, TDB_DEFAULT, O_RDONLY, 0600);
	if (!gm_ctx) {
		X_LOG(CONF, ERR, "failed open tdb '%s'", gm_path.c_str());
		return -1;
	}
	std::string ap_path = lib_dir + "/account_policy.tdb";
	struct tdb_context *ap_ctx = tdb_open(ap_path.c_str(), 0, TDB_DEFAULT, O_RDONLY, 0600);
	if (!ap_ctx) {
		X_LOG(CONF, ERR, "failed open tdb '%s'", ap_path.c_str());
		tdb_close(gm_ctx);
		return -1;
	}

	auto mapping = collect_aliases(gm_ctx);

	for (auto &policy: group_mapping->policies) {
		auto it = mapping.find(*policy.sid);
		if (it == mapping.end()) {
			continue;
		}
		uint64_t privilege = get_priviledge(ap_ctx, *policy.sid);
		policy.privilege = privilege;
		policy.members = it->second;
	}

	tdb_close(ap_ctx);
	tdb_close(gm_ctx);
	return 0;
}

static bool auth_info_has_sid(const x_auth_info_t &auth_info,
		const idl::dom_sid &sid)
{
	if (idl::dom_sid_in_domain(auth_info.domain_sid, sid)) {
		uint32_t rid = sid.sub_auths[sid.num_auths - 1];
		if (rid == auth_info.rid || rid == auth_info.primary_gid) {
			return true;
		}
		for (auto &group: auth_info.group_rids) {
			if (rid == group.rid) {
				return true;
			}
		}
	}

	for (auto &other: auth_info.other_sids) {
		if (other.sid == sid) {
			return true;
		}
	}

	return false;
}

int x_smbd_group_mapping_get(const x_smbd_group_mapping_t *group_mapping,
		std::vector<idl::dom_sid> &aliases,
		uint64_t &privileges,
		const x_auth_info_t &auth_info)
{
	uint64_t ret_priv = 0;
	for (auto &policy: group_mapping->policies) {
		for (auto &msid: policy.members) {
			if (auth_info_has_sid(auth_info, msid)) {
				aliases.push_back(*policy.sid);
				ret_priv |= policy.privilege;
				break;
			}
		}
	}
	privileges = ret_priv;
	return 0;
}

