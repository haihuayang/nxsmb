
#include "smbd.hxx"
#include "smbd_ntacl.hxx"
#include "util_sid.hxx"

NTSTATUS parse_acl_blob(const std::vector<uint8_t> &blob,
		std::shared_ptr<idl::security_descriptor> &psd,
		uint16_t *p_hash_type,
		uint16_t *p_version,
		std::array<uint8_t, idl::XATTR_SD_HASH_SIZE> &hash)
{
	idl::xattr_NTACL xacl;
	idl::x_ndr_off_t ret = idl::x_ndr_pull(xacl, blob.data(), blob.size(), 0);
	if (ret < 0) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	*p_version = xacl.version;

	switch (xacl.version) {
		case 1:
			psd = xacl.info.sd;
			/* No hash - null out. */
			*p_hash_type = idl::XATTR_SD_HASH_TYPE_NONE;
			memset(hash.data(), '\0', idl::XATTR_SD_HASH_SIZE);
			break;
		case 2:
			psd = xacl.info.sd_hs2->sd;
			/* No hash - null out. */
			*p_hash_type = idl::XATTR_SD_HASH_TYPE_NONE;
			memset(hash.data(), '\0', idl::XATTR_SD_HASH_SIZE);
			break;
		case 3:
			psd = xacl.info.sd_hs3->sd;
			*p_hash_type = xacl.info.sd_hs3->hash_type;
			/* Current version 3 (if no sys acl hash available). */
			hash = xacl.info.sd_hs3->hash;
			break;
		case 4:
			psd = xacl.info.sd_hs4->sd;
			*p_hash_type = xacl.info.sd_hs4->hash_type;
			/* Current version 4. */
			hash = xacl.info.sd_hs4->hash;
			break;
		default:
			return NT_STATUS_REVISION_MISMATCH;
	}

	return NT_STATUS_OK;
}

/*******************************************************************
 Create a DATA_BLOB from a hash of the security descriptor storead at
 the system layer and the NT ACL we wish to preserve
*******************************************************************/

NTSTATUS create_acl_blob(std::vector<uint8_t> &blob,
		const std::shared_ptr<idl::security_descriptor> &psd,
		uint16_t hash_type,
		const std::array<uint8_t, idl::XATTR_SD_HASH_SIZE> &hash)
{
	idl::xattr_NTACL xacl;
	auto sd_hs3 = std::make_shared<idl::security_descriptor_hash_v3>();
	sd_hs3->sd = psd;
	sd_hs3->hash_type = hash_type;
	sd_hs3->hash = hash;

	xacl.set_version(3);
	xacl.info.sd_hs3 = sd_hs3;

	idl::x_ndr_off_t ndr_ret = idl::x_ndr_push(xacl, blob, 0);
	if (ndr_ret < 0) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	return NT_STATUS_OK;
}

struct generic_mapping_t
{
	uint32_t generic_read;
	uint32_t generic_write;
	uint32_t generic_execute;
	uint32_t generic_all;
};

static const generic_mapping_t file_generic_mapping = {
	FILE_GENERIC_READ,
	FILE_GENERIC_WRITE,
	FILE_GENERIC_EXECUTE,
	FILE_GENERIC_ALL
};

static inline uint32_t se_map(uint32_t access_mask, uint32_t map_from, uint32_t map_to)
{
	if (access_mask & map_from) {
		access_mask &= ~map_from;
		access_mask |= map_to;
	}
	return access_mask;
}

static uint32_t se_map_generic(uint32_t access_mask, const generic_mapping_t &mapping)
{
	uint32_t old_mask = access_mask;

	access_mask = se_map(access_mask, idl::SEC_GENERIC_READ,
			mapping.generic_read);
	access_mask = se_map(access_mask, idl::SEC_GENERIC_WRITE,
			mapping.generic_write);
	access_mask = se_map(access_mask, idl::SEC_GENERIC_EXECUTE,
			mapping.generic_execute);
	access_mask = se_map(access_mask, idl::SEC_GENERIC_ALL,
			mapping.generic_all);

	if (old_mask != access_mask) {
		X_DBG("mapped mask 0x%08x to 0x%08x\n",
			   old_mask, access_mask);
	}
	return access_mask;
}

static void security_acl_map_generic(idl::security_acl &sa,
		const generic_mapping_t &mapping)
{
	for (auto &ace: sa.aces) {
		ace.access_mask = se_map_generic(ace.access_mask, mapping);
	}
}

/*******************************************************************
 Check for MS NFS ACEs in a sd
*******************************************************************/
static bool security_descriptor_with_ms_nfs(const idl::security_descriptor &sd)
{
	if (!sd.dacl) {
		return false;
	}

	for (auto &ace: sd.dacl->aces) {
		if (idl::dom_sid_compare_domain(
			    global_sid_Unix_NFS,
			    ace.trustee) == 0) {
			return true;
		}
	}

	return false;
}
/*********************************************************************
 Windows seems to do canonicalization of inheritance bits. Do the
 same.
*********************************************************************/

static void canonicalize_inheritance_bits(idl::security_descriptor &sd)
{
	bool set_auto_inherited = false;

	/*
	 * We need to filter out the
	 * SEC_DESC_DACL_AUTO_INHERITED|SEC_DESC_DACL_AUTO_INHERIT_REQ
	 * bits. If both are set we store SEC_DESC_DACL_AUTO_INHERITED
	 * as this alters whether SEC_ACE_FLAG_INHERITED_ACE is set
	 * when an ACE is inherited. Otherwise we zero these bits out.
	 * See:
	 *
	 * http://social.msdn.microsoft.com/Forums/eu/os_fileservices/thread/11f77b68-731e-407d-b1b3-064750716531
	 *
	 * for details.
	 */

	if ((sd.type & (idl::SEC_DESC_DACL_AUTO_INHERITED|idl::SEC_DESC_DACL_AUTO_INHERIT_REQ))
			== (idl::SEC_DESC_DACL_AUTO_INHERITED|idl::SEC_DESC_DACL_AUTO_INHERIT_REQ)) {
		set_auto_inherited = true;
	}

	sd.type = idl::security_descriptor_type(sd.type & ~(idl::SEC_DESC_DACL_AUTO_INHERITED|idl::SEC_DESC_DACL_AUTO_INHERIT_REQ));
	if (set_auto_inherited) {
		sd.type = idl::security_descriptor_type(sd.type | idl::SEC_DESC_DACL_AUTO_INHERITED);
	}
}

NTSTATUS parse_setinfo_sd_blob(idl::security_descriptor &sd,
		uint32_t &security_info_sent,
		uint32_t access_mask,
		const std::vector<uint8_t> &sd_blob)
{
	idl::x_ndr_off_t ndr_ret = idl::x_ndr_pull(sd, sd_blob.data(), sd_blob.size(), 0);
	if (ndr_ret < 0) {
		// TODO ndr_map_error2ntstatus
		return NT_STATUS_INVALID_PARAMETER;
	}
	security_info_sent &= idl::SMB_SUPPORTED_SECINFO_FLAGS;
	if (!sd.owner_sid) {
		security_info_sent &= ~idl::SECINFO_OWNER;
	} else if (!(access_mask & idl::SEC_STD_WRITE_OWNER)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!sd.group_sid) {
		security_info_sent &= ~idl::SECINFO_GROUP;
	} else if (!(access_mask & idl::SEC_STD_WRITE_OWNER)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if ((security_info_sent & idl::SECINFO_DACL) && !(access_mask & idl::SEC_STD_WRITE_DAC)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if ((security_info_sent & idl::SECINFO_SACL) && !(access_mask & idl::SEC_FLAG_SYSTEM_SECURITY)) {
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_OK;
}

NTSTATUS create_acl_blob_from_old(std::vector<uint8_t> &new_blob,
		const std::vector<uint8_t> &old_blob,
		idl::security_descriptor &sd,
		uint32_t security_info_sent)
{
	if (security_info_sent & idl::SECINFO_DACL && sd.dacl) {
		security_acl_map_generic(*sd.dacl, file_generic_mapping);
	}
	if (security_info_sent & idl::SECINFO_SACL && sd.sacl) {
		security_acl_map_generic(*sd.sacl, file_generic_mapping);
	}

	canonicalize_inheritance_bits(sd);
	
	std::shared_ptr<idl::security_descriptor> psd;
	uint16_t old_hash_type, old_version;
	std::array<uint8_t, idl::XATTR_SD_HASH_SIZE> old_hash;

	NTSTATUS status = parse_acl_blob(old_blob, 
		psd, &old_hash_type, &old_version,
		old_hash);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	psd->revision = sd.revision;
	if (security_info_sent & idl::SECINFO_DACL) {
		psd->type = sd.type;
		/* All our SD's are self relative. */
		psd->type = idl::security_descriptor_type(psd->type | idl::SEC_DESC_SELF_RELATIVE);
	}

	bool chown_needed = false;
	if (sd.owner_sid) {
		if (idl::dom_sid_compare(*psd->owner_sid, *sd.owner_sid) != 0) {
			chown_needed = true;
		}
		psd->owner_sid = sd.owner_sid;
	}

	if (sd.group_sid) {
		if (idl::dom_sid_compare(*psd->group_sid, *sd.group_sid) != 0) {
			chown_needed = true;
		}
		psd->group_sid = sd.group_sid;
	}

	if (security_info_sent & idl::SECINFO_DACL) {
		if (security_descriptor_with_ms_nfs(sd)) {
			/*
			 * If the sd contains a MS NFS SID, do
			 * nothing, it's a chmod() request from OS X
			 * with AAPL context.
			 */
			return NT_STATUS_OK;
		}
		psd->dacl = sd.dacl;
		psd->type = idl::security_descriptor_type(psd->type | idl::SEC_DESC_DACL_PRESENT);
	}

	if (security_info_sent & idl::SECINFO_SACL) {
		psd->sacl = sd.sacl;
		psd->type = idl::security_descriptor_type(psd->type | idl::SEC_DESC_SACL_PRESENT);
	}

	(void)chown_needed;
#if 0
	TODO
	fset_nt_acl_common chown_needed;
#endif
	return create_acl_blob(new_blob, psd, idl::XATTR_SD_HASH_TYPE_NONE, std::array<uint8_t, idl::XATTR_SD_HASH_SIZE>());
}

/*
 * Determine if an struct security_ace is inheritable
 */

static bool is_inheritable_ace(const idl::security_ace &ace,
				bool container)
{
	if (!container) {
		return ((ace.flags & idl::SEC_ACE_FLAG_OBJECT_INHERIT) != 0);
	}

	if (ace.flags & idl::SEC_ACE_FLAG_CONTAINER_INHERIT) {
		return true;
	}

	if ((ace.flags & idl::SEC_ACE_FLAG_OBJECT_INHERIT) &&
			!(ace.flags & idl::SEC_ACE_FLAG_NO_PROPAGATE_INHERIT)) {
		return true;
	}

	return false;
}

/*
 * Does a security descriptor have any inheritable components for
 * the newly created type ?
 */
static bool sd_has_inheritable_components(const idl::security_descriptor &sd, bool container)
{
	if (!sd.dacl) {
		return false;
	}

	for (auto &ace : sd.dacl->aces) {
		if (is_inheritable_ace(ace, container)) {
			return true;
		}
	}
	return false;
}

void append_ace(std::vector<idl::security_ace> &aces,
		idl::security_ace_type type,
		idl::security_ace_flags flags,
		uint32_t access_mask,
		const idl::dom_sid &trustee)
{
	aces.resize(aces.size() + 1);
	auto &new_ace = aces.back();
	new_ace.type = type;
	new_ace.flags = flags;
	new_ace.access_mask = access_mask;
	new_ace.trustee = trustee;
}

/* Create a child security descriptor using another security descriptor as
   the parent container.  This child object can either be a container or
   non-container object. */
static NTSTATUS se_create_child_secdesc(
		std::shared_ptr<idl::security_descriptor> &psd,
		const idl::security_descriptor &parent_sd,
		const idl::dom_sid *owner_sid,
		const idl::dom_sid *group_sid,
		bool container)
{
	bool set_inherited_flags = (parent_sd.type & idl::SEC_DESC_DACL_AUTO_INHERITED);
#if 0
	struct security_acl *new_dacl = NULL, *the_acl = NULL;
	struct security_ace *new_ace_list = NULL;
	unsigned int new_ace_list_ndx = 0, i;

	*psize = 0;

	/* Currently we only process the dacl when creating the child.  The
	   sacl should also be processed but this is left out as sacls are
	   not implemented in Samba at the moment.*/

	the_acl = parent_ctr->dacl;

	if (the_acl->num_aces) {
		if (2*the_acl->num_aces < the_acl->num_aces) {
			return NT_STATUS_NO_MEMORY;
		}

		if (!(new_ace_list = talloc_array(ctx, struct security_ace,
						  2*the_acl->num_aces))) {
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		new_ace_list = NULL;
	}

	auto new_ace_list = std::make_shared<std::vector<
	ppsd = NULL;
	frame = talloc_stackframe();
#endif
	auto new_dacl = std::make_shared<idl::security_acl>();
	for (auto &parent_ace: parent_sd.dacl->aces) {
		if (!is_inheritable_ace(parent_ace, container)) {
			continue;
		}
#if 0
		struct security_ace *new_ace = &new_ace_list[new_ace_list_ndx];
		uint8_t new_flags = ace->flags;
		struct dom_sid_buf sidbuf1, sidbuf2;
#endif
		uint8_t new_flags;
		/* see the RAW-ACLS inheritance test for details on these rules */
		if (!container) {
			new_flags = 0;
		} else {
			/*
			 * We need to remove SEC_ACE_FLAG_INHERITED_ACE here
			 * if present because it should only be set if the
			 * parent has the AUTO_INHERITED bit set in the
			 * type/control field. If we don't it will slip through
			 * and create DACLs with incorrectly ordered ACEs
			 * when there are CREATOR_OWNER or CREATOR_GROUP
			 * ACEs.
			 */
			new_flags = parent_ace.flags & ~(idl::SEC_ACE_FLAG_INHERIT_ONLY
					| idl::SEC_ACE_FLAG_INHERITED_ACE);

			if (!(new_flags & idl::SEC_ACE_FLAG_CONTAINER_INHERIT)) {
				new_flags |= idl::SEC_ACE_FLAG_INHERIT_ONLY;
			}
			if (new_flags & idl::SEC_ACE_FLAG_NO_PROPAGATE_INHERIT) {
				new_flags = 0;
			}
		}

		const idl::dom_sid *ptrustee = &parent_ace.trustee;
		const idl::dom_sid *creator = NULL;
		/* The CREATOR sids are special when inherited */
		if (*ptrustee == global_sid_Creator_Owner) {
			creator = &global_sid_Creator_Owner;
			ptrustee = owner_sid;
		} else if (*ptrustee == global_sid_Creator_Group) {
			creator = &global_sid_Creator_Group;
			ptrustee = group_sid;
		}

		if (creator && container &&
				(new_flags & idl::SEC_ACE_FLAG_CONTAINER_INHERIT)) {

			/* First add the regular ACE entry. */
			append_ace(new_dacl->aces,
					parent_ace.type,
					idl::security_ace_flags(set_inherited_flags ? idl::SEC_ACE_FLAG_INHERITED_ACE : 0),
					parent_ace.access_mask,
					*ptrustee);
#if 0
			DEBUG(5,("se_create_child_secdesc(): %s:%d/0x%02x/0x%08x"
				 " inherited as %s:%d/0x%02x/0x%08x\n",
				 dom_sid_str_buf(&ace->trustee, &sidbuf1),
				 ace->type, ace->flags, ace->access_mask,
				 dom_sid_str_buf(&new_ace->trustee, &sidbuf2),
				 new_ace->type, new_ace->flags,
				 new_ace->access_mask));

			new_ace_list_ndx++;

			/* Now add the extra creator ACE. */
			new_ace = &new_ace_list[new_ace_list_ndx];
#endif
			ptrustee = creator;
			new_flags |= idl::SEC_ACE_FLAG_INHERIT_ONLY;

		} else if (container &&
				!(parent_ace.flags & idl::SEC_ACE_FLAG_NO_PROPAGATE_INHERIT)) {
			ptrustee = &parent_ace.trustee;
		}

		append_ace(new_dacl->aces,
				parent_ace.type,
				idl::security_ace_flags(new_flags | (set_inherited_flags ? idl::SEC_ACE_FLAG_INHERITED_ACE : 0)),
				parent_ace.access_mask,
				*ptrustee);
#if 0
		DEBUG(5, ("se_create_child_secdesc(): %s:%d/0x%02x/0x%08x "
			  " inherited as %s:%d/0x%02x/0x%08x\n",
			  dom_sid_str_buf(&ace->trustee, &sidbuf1),
			  ace->type, ace->flags, ace->access_mask,
			  dom_sid_str_buf(&new_ace->trustee, &sidbuf2),
			  new_ace->type, new_ace->flags,
			  new_ace->access_mask));

		new_ace_list_ndx++;
#endif
	}

	if (new_dacl->aces.size() > 1) {
		/*
		 * remove duplicates
		 */
		size_t done = 1;
		for (size_t i = 1; i < new_dacl->aces.size(); ++i) {
			idl::security_ace &ai = new_dacl->aces[i];
			bool found = false;

			for (size_t j = 0; j < done; ++j) {
				idl::security_ace &aj = new_dacl->aces[j];
				if (ai == aj) {
					found = true;
					break;
				}
			}

			if (found) {
				continue;
			}
			if (i != done) {
				new_dacl->aces[done] = ai;
			}
			++done;
		}
	}

	/* Create child security descriptor to return */
	if (new_dacl->aces.size() > 0) {
		new_dacl->revision = idl::security_acl_revision(idl::NT4_ACL_REVISION);
	} else {
		new_dacl.reset();
	}

	auto new_psd = std::make_shared<idl::security_descriptor>();
	new_psd->revision = idl::SECURITY_DESCRIPTOR_REVISION_1;
	new_psd->type = idl::security_descriptor_type(idl::SEC_DESC_SELF_RELATIVE|idl::SEC_DESC_DACL_PRESENT|(set_inherited_flags ? idl::SEC_DESC_DACL_AUTO_INHERITED : 0));
	new_psd->owner_sid = std::make_shared<idl::dom_sid>(*owner_sid);
	new_psd->group_sid = std::make_shared<idl::dom_sid>(*group_sid);
	std::swap(new_psd->dacl, new_dacl);
	
	psd = new_psd;
	return NT_STATUS_OK;
}

static NTSTATUS make_dummy_sec_desc(
		std::shared_ptr<idl::security_descriptor> &psd,
		const idl::dom_sid *owner_sid,
		const idl::dom_sid *group_sid)
{
	/* Windows seems add SEC_DESC_DACL_AUTO_INHERITED */
	auto new_psd = std::make_shared<idl::security_descriptor>();
	new_psd->revision = idl::SECURITY_DESCRIPTOR_REVISION_1;
	new_psd->type = idl::security_descriptor_type(idl::SEC_DESC_SELF_RELATIVE|idl::SEC_DESC_DACL_PRESENT|idl::SEC_DESC_DACL_AUTO_INHERITED);
	new_psd->owner_sid = std::make_shared<idl::dom_sid>(*owner_sid);
	new_psd->group_sid = std::make_shared<idl::dom_sid>(*group_sid);
	auto new_dacl = std::make_shared<idl::security_acl>();
	new_dacl->revision = idl::security_acl_revision(idl::NT4_ACL_REVISION);
	append_ace(new_dacl->aces, 
			idl::SEC_ACE_TYPE_ACCESS_ALLOWED,
			idl::security_ace_flags(0),
			0x1f01ff, // TODO
			*owner_sid);

	if (!(*owner_sid == *group_sid)) {
		append_ace(new_dacl->aces, 
				idl::SEC_ACE_TYPE_ACCESS_ALLOWED,
				idl::security_ace_flags(0),
				0x1f01ff, // TODO
				*group_sid);
	}
	std::swap(new_psd->dacl, new_dacl);
	psd = new_psd;
	return NT_STATUS_OK;
}

NTSTATUS make_child_sec_desc(
		std::shared_ptr<idl::security_descriptor> &psd,
		const std::shared_ptr<idl::security_descriptor> &parent_psd,
		const idl::dom_sid *owner_sid,
		const idl::dom_sid *group_sid,
		bool container)
{
	if (parent_psd && sd_has_inheritable_components(*parent_psd, container)) {
		return se_create_child_secdesc(psd, *parent_psd, owner_sid, group_sid,
				container);
	} else {
		return make_dummy_sec_desc(psd, owner_sid, group_sid);
	}
}


static std::shared_ptr<idl::security_descriptor> get_share_security_default(uint32_t def_access)
{
	auto psd = std::make_shared<idl::security_descriptor>();

	psd->revision = idl::SECURITY_DESCRIPTOR_REVISION_1;
	psd->type = idl::security_descriptor_type(idl::SEC_DESC_SELF_RELATIVE|idl::SEC_DESC_DACL_PRESENT|idl::SEC_DESC_DACL_AUTO_INHERITED);
	auto dacl = std::make_shared<idl::security_acl>();
	dacl->revision = idl::security_acl_revision(idl::NT4_ACL_REVISION);
	uint32_t spec_access = se_map_generic(def_access, file_generic_mapping);
	spec_access |= def_access;
	append_ace(dacl->aces, 
			idl::SEC_ACE_TYPE_ACCESS_ALLOWED,
			idl::security_ace_flags(0),
			spec_access, // TODO
			global_sid_World);

	std::swap(psd->dacl, dacl);
	return psd;
}

std::shared_ptr<idl::security_descriptor> get_share_security(const std::string &sharename)
{
	/* TODO we do not set share_security for now, always use the default one */
	return get_share_security_default(idl::SEC_RIGHTS_DIR_ALL);
}
