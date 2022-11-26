
#include "include/bits.hxx"
#include "samba/include/config.h"
extern "C" {
#include "samba/libcli/smb/smb_constants.h"
#include "samba/libcli/smb/smb2_constants.h"
#include "samba/libcli/util/ntstatus.h"
}

#include "include/nttime.hxx"
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
	init-top-dir
	attrex
	set-default-security-desc
	show-security-desc
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

static int init_default_dir(int dirfd)
{
	x_smbd_object_meta_t object_meta;
	x_smbd_stream_meta_t stream_meta;
	auto psd = make_share_sec_desc();
	std::vector<uint8_t> ntacl_blob;
	create_acl_blob(ntacl_blob, psd, idl::XATTR_SD_HASH_TYPE_NONE, std::array<uint8_t, idl::XATTR_SD_HASH_SIZE>());

	posixfs_post_create(dirfd, 0u, &object_meta, &stream_meta, ntacl_blob);
	return 0;
}

static int init_top_dir(char **argv)
{
	const char *path = argv[0];
	int fd = open(path, O_RDONLY);
	X_ASSERT(fd >= 0);
	X_ASSERT(0 == init_default_dir(fd));
	close(fd);
	return 0;
}

static int make_default_dir(int dirfd, const char *name)
{
	int err = mkdirat(dirfd, name, 0777);
	X_ASSERT(err == 0);
	int fd = openat(dirfd, name, O_RDONLY);
	X_ASSERT(fd >= 0);
	X_ASSERT(0 == init_default_dir(fd));
	return fd;
}

static int init_volume(char **argv)
{
	bool root = false;
	while (*argv) {
		if (strcmp(*argv, "-r") == 0) {
			root = true;
		} else if ((*argv)[0] == '-') {
			X_ASSERT(false);
		} else {
			break;
		}
		++argv;
	}

	const char *path = argv[0];
	X_ASSERT(path);

	int vol_fd = open(path, O_RDONLY);
	X_ASSERT(vol_fd >= 0);

	int data_fd = make_default_dir(vol_fd, "data");
	X_ASSERT(data_fd >= 0);
	close(data_fd);

	if (root) {
		int root_fd = make_default_dir(vol_fd, "root");
		X_ASSERT(root_fd >= 0);
		int err = mkdirat(root_fd, ".tlds", 0777);
		X_ASSERT(err == 0);
		close(root_fd);
	}
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

static inline void output_timespec(const char *name, const struct timespec *ts)
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

static void output_nttime(const char *name, const idl::NTTIME nttime)
{
	struct timespec ts = x_nttime_to_timespec(nttime);
	struct tm *lt = localtime(&ts.tv_sec);
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
			ts.tv_sec, ts.tv_nsec);
}

static int show_attrex(char **argv)
{
	const char *path = argv[0];
	int fd = open(path, O_RDONLY);
	X_ASSERT(fd >= 0);
	x_smbd_object_meta_t object_meta;
	x_smbd_stream_meta_t stream_meta;

	int err = posixfs_statex_get(fd, &object_meta, &stream_meta);
	X_ASSERT(err == 0);

	std::shared_ptr<idl::security_descriptor> psd;
	NTSTATUS status = get_sd(fd, psd);
	X_ASSERT(NT_STATUS_IS_OK(status));

	close(fd);

	printf("File: '%s'\n", path);
	printf("Fsid: 0x%lx\n", object_meta.fsid);
	printf("Inode: %lu\n", object_meta.inode);
	printf("Nlink: %lu\n", object_meta.nlink);
	output_nttime("Birth", object_meta.creation);
	output_nttime("Access", object_meta.last_access);
	output_nttime("Modify", object_meta.last_write);
	output_nttime("Change", object_meta.change);
	printf("Size: %lu\n", stream_meta.end_of_file);
	printf("Allocation: %lu\n", stream_meta.allocation_size);
	printf("DosAttr: 0x%x\n", object_meta.file_attributes);
	printf("NTACL: %s\n", idl_tostring(*psd).c_str());

	return 0;
}

static int set_dos_attr(char **argv)
{
	const char *path = argv[0];
	char *end;
	unsigned long file_attrs = strtoul(argv[1], &end, 0);
	int fd = open(path, O_RDONLY);
	X_ASSERT(fd >= 0);
	dos_attr_t dos_attr;
	posixfs_dos_attr_get(fd, &dos_attr);

	printf("modify file_attrs 0x%x to 0x%lx\n", dos_attr.file_attrs,
			file_attrs);
	dos_attr.file_attrs = x_convert_assert<uint32_t>(file_attrs);
	dos_attr.attr_mask = DOS_SET_FILE_ATTR;
	posixfs_dos_attr_set(fd, &dos_attr);

	close(fd);

	return 0;
}

int main(int argc, char **argv)
{
	const char *command = argv[1];
	x_smbd_posixfs_init_dev();
	if (strcmp(command, "init-top-dir") == 0) {
		return init_top_dir(argv + 2);
	} else if (strcmp(command, "init-volume") == 0) {
		return init_volume(argv + 2);
	} else if (strcmp(command, "attrex") == 0) {
		return show_attrex(argv + 2);
	} else if (strcmp(command, "set-dos-attr") == 0) {
		return set_dos_attr(argv + 2);
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

