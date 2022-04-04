
#include "samba/include/config.h"
#include "core.hxx"
extern "C" {
#include "samba/libcli/smb/smb_constants.h"
#include "samba/libcli/smb/smb2_constants.h"
#include "samba/libcli/util/ntstatus.h"
}

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

static int init_top_dir(char **argv)
{
	const char *path = argv[0];
	int fd = open(path, O_RDONLY);
	X_ASSERT(fd >= 0);
	posixfs_statex_t statex;
	auto psd = make_share_sec_desc();
	std::vector<uint8_t> ntacl_blob;
	create_acl_blob(ntacl_blob, psd, idl::XATTR_SD_HASH_TYPE_NONE, std::array<uint8_t, idl::XATTR_SD_HASH_SIZE>());

	posixfs_post_create(fd, FILE_ATTRIBUTE_DIRECTORY, &statex, ntacl_blob);
	close(fd);
	return 0;
}

static NTSTATUS get_sd(int fd,
		std::shared_ptr<idl::security_descriptor> &psd)
{
	std::vector<uint8_t> blob;
	int err = posixfs_get_ntacl_blob(fd, blob);
	if (err < 0) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	uint16_t hash_type;
	uint16_t version;
	std::array<uint8_t, idl::XATTR_SD_HASH_SIZE> hash;
	return parse_acl_blob(blob, psd, &hash_type, &version, hash);
}

static void output_timespec(const char *name, const struct timespec *ts)
{
	struct tm *lt = localtime(&ts->tv_sec);
	printf("%s: %d-%02d-%02d %02d:%02d:%02d %c%ld %ld.%09ld\n",
			name,
			lt->tm_year + 1900,
			lt->tm_mon + 1,
			lt->tm_mday,
			lt->tm_hour,
			lt->tm_min,
			lt->tm_sec,
			lt->tm_gmtoff > 0 ? '+' : '-',
			abs(lt->tm_gmtoff),
			ts->tv_sec, ts->tv_nsec);
}

static int show_attrex(char **argv)
{
	const char *path = argv[0];
	int fd = open(path, O_RDONLY);
	X_ASSERT(fd >= 0);
	posixfs_statex_t statex;

	int err = posixfs_statex_get(fd, &statex);
	X_ASSERT(err == 0);

	std::shared_ptr<idl::security_descriptor> psd;
	NTSTATUS status = get_sd(fd, psd);
	X_ASSERT(NT_STATUS_IS_OK(status));

	close(fd);

	printf("File: '%s'\n", path);
	printf("Size: %lu\n", statex.stat.st_size);
	printf("Blocks: %lu\n", statex.stat.st_blocks);
	printf("IOBlock: %lu\n", statex.stat.st_blksize);
	printf("Device: 0x%lx\n", statex.stat.st_dev);
	printf("Ino: %lu\n", statex.stat.st_ino);
	printf("Nlink: %lu\n", statex.stat.st_nlink);
	printf("Mode: 0%o\n", statex.stat.st_mode);
	printf("Uid: %d\n", statex.stat.st_uid);
	printf("Gid: %d\n", statex.stat.st_gid);
	output_timespec("Access", &statex.stat.st_atim);
	output_timespec("Modify", &statex.stat.st_mtim);
	output_timespec("Change", &statex.stat.st_ctim);
	output_timespec("Birth", &statex.birth_time);
	printf("DosAttr: 0x%x\n", statex.file_attributes);
	printf("NTACL: %s\n", idl_tostring(*psd).c_str());

	return 0;
}

int main(int argc, char **argv)
{
	const char *command = argv[1];
	if (strcmp(command, "init-top-dir") == 0) {
		return init_top_dir(argv + 2);
	} else if (strcmp(command, "attrex") == 0) {
		return show_attrex(argv + 2);
	} else if (strcmp(command, "set-default-security-desc") == 0) {
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

