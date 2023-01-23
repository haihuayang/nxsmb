
#include "include/librpc/security.hxx"

namespace idl {

std::ostream &operator<<(std::ostream &os, const dom_sid &v)
{
	os << "S-" << (uint32_t)v.sid_rev_num << '-';

	uint64_t ia = ((uint64_t)v.id_auth[5]) +
		((uint64_t)v.id_auth[4] << 8 ) +
		((uint64_t)v.id_auth[3] << 16) +
		((uint64_t)v.id_auth[2] << 24) +
		((uint64_t)v.id_auth[1] << 32) +
		((uint64_t)v.id_auth[0] << 40);
	if (ia >= UINT32_MAX) {
		os << "0x" << std::hex << ia << std::dec;
	} else {
		os << ia;
	}
	for (int i = 0; i < v.num_auths; ++i) {
		os << '-' << v.sub_auths[i];
	}
	return os;
}

x_ndr_off_t dom_sid_ndr_scalars(const dom_sid &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level)
{
	X_NDR_HEADER_ALIGN(4, ndr, bpos, epos, flags);
	X_NDR_SCALARS_DEFAULT(val.sid_rev_num, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS_DEFAULT(val.num_auths, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_PUSH_BYTES(val.id_auth.data(), val.id_auth.size(), ndr, bpos, epos);
	for (uint32_t i = 0; i < val.num_auths; ++i) {
		X_NDR_SCALARS_DEFAULT(val.sub_auths[i], ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}
	X_NDR_TRAILER_ALIGN(4, ndr, bpos, epos, flags);
	return bpos;
}

x_ndr_off_t dom_sid_ndr_scalars(dom_sid &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level)
{
	X_NDR_HEADER_ALIGN(4, ndr, bpos, epos, flags);
	X_NDR_SCALARS_DEFAULT(val.sid_rev_num, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS_DEFAULT(val.num_auths, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (val.num_auths > 15) {
		return -NDR_ERR_RANGE;
	}
	X_NDR_PULL_BYTES(val.id_auth.data(), val.id_auth.size(), ndr, bpos, epos);
	for (uint32_t i = 0; i < val.num_auths; ++i) {
		X_NDR_SCALARS_DEFAULT(val.sub_auths[i], ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}
	X_NDR_TRAILER_ALIGN(4, ndr, bpos, epos, flags);
	return bpos;
}

x_ndr_off_t ndr_traits_t<dom_sid>::scalars(const dom_sid &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	return dom_sid_ndr_scalars(val, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
}
x_ndr_off_t ndr_traits_t<dom_sid>::scalars(dom_sid &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	return dom_sid_ndr_scalars(val, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
}

void ndr_traits_t<dom_sid>::ostr(const dom_sid &val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	ndr.os << val;
}

x_ndr_off_t ndr_traits_dom_sid2::scalars(const dom_sid &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	X_NDR_SCALARS_DEFAULT(uint3264{val.num_auths}, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	return dom_sid_ndr_scalars(val, ndr, bpos, epos, flags, level);
}

x_ndr_off_t ndr_traits_dom_sid2::scalars(dom_sid &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	uint3264 num_auths;
	X_NDR_SCALARS_DEFAULT(num_auths, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	bpos = dom_sid_ndr_scalars(val, ndr, bpos, epos, flags, level);
	if (num_auths.val != val.num_auths) {
		return -NDR_ERR_ARRAY_SIZE;
	}
	return bpos;
}


static long dom_sid_compare_id_auth(const dom_sid &sid1,
		const dom_sid &sid2)
{
	long cmp = long(sid1.sid_rev_num) - long(sid2.sid_rev_num);
	if (cmp) {
		return cmp;
	}

	for (int i = 0; i < 6; i++) {
		cmp = long(sid1.id_auth[i]) - long(sid2.id_auth[i]);
		if (cmp) {
			return cmp;
		}
	}
	return 0;
}

static long dom_sid_compare_subauth(const dom_sid &sid1,
		const dom_sid &sid2,
		int num_auth)
{
	long cmp;
	for (int i = num_auth - 1; i >= 0; --i) {
		cmp = long(sid1.sub_auths[i]) - long(sid2.sub_auths[i]);
		if (cmp) {
			return cmp;
		}
	}
	return 0;
}

/*
  See if 2 SIDs are in the same domain
  this just compares the leading sub-auths
*/
long dom_sid_compare_domain(const dom_sid &sid1,
		const dom_sid &sid2)
{
	int n = std::min(sid1.num_auths, sid2.num_auths);

	long cmp = dom_sid_compare_subauth(sid1, sid2, n);
	if (cmp) {
		return cmp;
	}

	return dom_sid_compare_id_auth(sid1, sid2);
}

/* equivilant to dom_sid_compare(sid, dom_sid_compose(domain, rid)) */
long dom_sid_compare_domain_and_rid(const dom_sid &sid,
		const dom_sid &domain, uint32_t rid)
{
	long cmp = long(sid.num_auths) - long(domain.num_auths + 1);
	if (cmp) {
		return cmp;
	}

	cmp = long(sid.sub_auths[domain.num_auths]) - long(rid);
	if (cmp) {
		return cmp;
	}

	cmp = dom_sid_compare_subauth(sid, domain, domain.num_auths);
	if (cmp) {
		return cmp;
	}

	return dom_sid_compare_id_auth(sid, domain);
}

long dom_sid_compare(const dom_sid &sid1, const dom_sid &sid2)
{
	long cmp = long(sid1.num_auths) - long(sid2.num_auths);

	if (cmp) {
		return cmp;
	}

	cmp = dom_sid_compare_subauth(sid1, sid2, sid1.num_auths);
	if (cmp) {
		return cmp;
	}
	return dom_sid_compare_id_auth(sid1, sid2);
}

bool dom_sid_in_domain(const dom_sid &domain, const dom_sid &sid)
{
	if (domain.num_auths + 1 != sid.num_auths) {
		return false;
	}
	if (dom_sid_compare_subauth(domain, sid, domain.num_auths) != 0) {
		return false;
	}
	return dom_sid_compare_id_auth(domain, sid) == 0;
}

static const struct {
	uint8_t flag;
	const char *name;
} ace_flag_names[] = {
	{ SEC_ACE_FLAG_OBJECT_INHERIT, "OI", },
	{ SEC_ACE_FLAG_CONTAINER_INHERIT, "CI" },
	{ SEC_ACE_FLAG_NO_PROPAGATE_INHERIT, "NP" },
	{ SEC_ACE_FLAG_INHERIT_ONLY, "IO" },
	{ SEC_ACE_FLAG_INHERITED_ACE, "I" },
};

static void print_ace_flags(std::ostream &os, uint8_t flags)
{
	char buf[16];
	snprintf(buf, sizeof buf, "x%x", flags);
	os << buf << '(';

	bool first = true;
	for (auto &fn: ace_flag_names) {
		if (!(flags & fn.flag)) {
			continue;
		}
		if (first) {
			first = false;
		} else {
			os << '|';
		}
		os << fn.name;
	}

	os << ')';
}

std::ostream &operator<<(std::ostream &os, const security_ace &v)
{
	/* TODO skip security_ace_object_ctr for now since it is unusual */
	os << v.trustee << "/(" << (uint32_t)v.type;
	if (v.type == SEC_ACE_TYPE_ACCESS_ALLOWED) {
		os << "A";
	} else if (v.type == SEC_ACE_TYPE_ACCESS_DENIED) {
		os << "D";
	} else {
		os << "X";
	}
	os << ")/";
	print_ace_flags(os, v.flags);
	os << "/";
	char buf[16];
	snprintf(buf, sizeof buf, "x%x", v.access_mask);
	os << buf;
	return os;
}

void ndr_traits_t<security_ace>::ostr(const security_ace &val,
		x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const
{
	ndr.os << val;
}

} /* namespace idl */

