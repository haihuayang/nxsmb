
#include "smbd_ntacl.hxx"
#include "smbd_posixfs_utils.hxx"
// #include "smbd_vfs.hxx"
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "util_sid.hxx"
#include "misc.hxx"
#include <iostream>

static void usage(const char *progname)
{
	fprintf(stderr, R"SSS(
Usage: %s command ...
available commands
	create-share
)SSS", progname);
	exit(1);
}

static std::shared_ptr<idl::security_descriptor> make_share_sec_desc()
{
	auto psd = std::make_shared<idl::security_descriptor>();
	psd->owner_sid = std::make_shared<idl::dom_sid>(global_sid_Builtin_Administrators);
	psd->group_sid = std::make_shared<idl::dom_sid>(global_sid_Builtin_Users);
	psd->dacl = std::make_shared<idl::security_acl>();
	psd->dacl->revision = idl::security_acl_revision(idl::NT4_ACL_REVISION);
	append_ace(psd->dacl->aces, 
			idl::SEC_ACE_TYPE_ACCESS_ALLOWED,
			idl::security_ace_flags(0xb),
			0x1f01ff, // TODO
			global_sid_Creator_Owner);
	append_ace(psd->dacl->aces, 
			idl::SEC_ACE_TYPE_ACCESS_ALLOWED,
			idl::security_ace_flags(0x3),
			0x1f01ff, // TODO
			global_sid_Builtin_Administrators);
	append_ace(psd->dacl->aces, 
			idl::SEC_ACE_TYPE_ACCESS_ALLOWED,
			idl::security_ace_flags(0x3),
			0x1f01ff, // TODO
			global_sid_Builtin_Users);
	psd->revision = idl::SECURITY_DESCRIPTOR_REVISION_1;
	psd->type = idl::security_descriptor_type(idl::SEC_DESC_SELF_RELATIVE|idl::SEC_DESC_DACL_PRESENT|idl::SEC_DESC_DACL_AUTO_INHERITED);
	return psd;
}

static int set_default_security_desc(char **argv)
{
	const char *path = argv[0];
	auto psd = make_share_sec_desc();
	std::vector<uint8_t> ntacl_blob;
	create_acl_blob(ntacl_blob, psd, idl::XATTR_SD_HASH_TYPE_NONE, std::array<uint8_t, idl::XATTR_SD_HASH_SIZE>());
	int fd = open(path, O_RDONLY);
	X_ASSERT(fd >= 0);
	posixfs_set_ntacl_blob(fd, ntacl_blob);
	close(fd);
	return 0;
}

static int show_security_desc(char **argv)
{
	const char *path = argv[0];
	int fd = open(path, O_RDONLY);
	X_ASSERT(fd >= 0);
	std::vector<uint8_t> blob;
	posixfs_get_ntacl_blob(fd, blob);
	close(fd);

	std::shared_ptr<idl::security_descriptor> psd;
	uint16_t hash_type;
	uint16_t version;
	std::array<uint8_t, idl::XATTR_SD_HASH_SIZE> hash;
	NTSTATUS status = parse_acl_blob(blob, psd, &hash_type, &version, hash);
	assert(NT_STATUS_IS_OK(status));
	std::cout << "SD " << idl_tostring(*psd) << std::endl;
	return 0;
}

int main(int argc, char **argv)
{
	const char *command = argv[1];
	if (strcmp(command, "set-default-security-desc") == 0) {
		return set_default_security_desc(argv + 2);
	} else if (strcmp(command, "show-security-desc") == 0) {
		return show_security_desc(argv + 2);
#if 0
	} else if (strcmp(command, "create-file") == 0) {
		return create_file(argv + 2);
#endif
	} else {
		usage(argv[0]);
	}
	return 0;
}

