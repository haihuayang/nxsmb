
#ifndef __smbd_ntacl__hxx__
#define __smbd_ntacl__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "defines.hxx"
#include "include/librpc/xattr.hxx"

struct x_smbd_user_t;

struct generic_mapping_t
{
	uint32_t generic_read;
	uint32_t generic_write;
	uint32_t generic_execute;
	uint32_t generic_all;
};

uint32_t se_map_generic(uint32_t access_mask, const generic_mapping_t &mapping);

NTSTATUS parse_acl_blob(const std::vector<uint8_t> &blob,
		std::shared_ptr<idl::security_descriptor> &psd,
		uint16_t *p_hash_type,
		uint16_t *p_version,
		std::array<uint8_t, idl::XATTR_SD_HASH_SIZE> &hash);

NTSTATUS create_acl_blob(std::vector<uint8_t> &blob,
		const std::shared_ptr<idl::security_descriptor> &psd,
		uint16_t hash_type,
		const std::array<uint8_t, idl::XATTR_SD_HASH_SIZE> &hash);

NTSTATUS parse_setinfo_sd_blob(idl::security_descriptor &sd,
		uint32_t &security_info_sent,
		uint32_t access_mask,
		const std::vector<uint8_t> &sd_blob);

NTSTATUS create_acl_blob_from_old(std::vector<uint8_t> &new_blob,
		std::shared_ptr<idl::security_descriptor> &curr_psd,
		idl::security_descriptor &sd,
		uint32_t security_info_sent);

void append_ace(std::vector<idl::security_ace> &aces,
		idl::security_ace_type type,
		idl::security_ace_flags flags,
		uint32_t access_mask,
		const idl::dom_sid &trustee);

NTSTATUS make_child_sec_desc(
		std::shared_ptr<idl::security_descriptor> &psd,
		const std::shared_ptr<idl::security_descriptor> &parent_psd,
		const x_smbd_user_t &smbd_user,
		bool container);

NTSTATUS normalize_sec_desc(
		idl::security_descriptor &sd,
		const x_smbd_user_t &smbd_user,
		uint32_t access_mask,
		bool container);

std::shared_ptr<idl::security_descriptor> get_share_security(const std::string &sharename);
std::shared_ptr<idl::security_descriptor> create_null_sec_desc();
std::shared_ptr<idl::security_descriptor> create_empty_sec_desc();

uint32_t se_calculate_maximal_access(const idl::security_descriptor &sd,
		const x_smbd_user_t &smbd_user);

uint32_t se_file_map_generic(uint32_t access_mask);

NTSTATUS se_file_access_check(const idl::security_descriptor &sd,
		const x_smbd_user_t &smbd_user,
		bool priv_open_requested,
		uint32_t access_desired,
		uint32_t *access_granted);

uint32_t se_rpc_map_maximal_access(const x_smbd_user_t &smbd_user,
		uint32_t acc_requested);

#endif /* __smbd_ntacl__hxx__ */

