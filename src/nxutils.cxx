
#include "include/bits.hxx"
#include "include/ntstatus.hxx"

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
#include "smbd_volume.hxx"
#include "smbd_share.hxx"

static void usage(const char *progname)
{
	fprintf(stderr, R"SSS(
Usage: %s command ...
available commands
	init-top-dir
	attrex
	set-default-security-desc
	show-security-desc
	list-durable volumes ...
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
	NTSTATUS status = parse_acl_blob(blob.data(), blob.size(), psd, &hash_type, &version, hash);
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

static int make_volume(const char *path, uint16_t vol_id, bool dfs_root)
{
	int vol_fd = open(path, O_RDONLY);
	X_ASSERT(vol_fd >= 0);

	int rootdir_fd = make_default_dir(vol_fd, "root");
	X_ASSERT(rootdir_fd >= 0);
	if (dfs_root) {
		int tlds_fd = make_default_dir(rootdir_fd, ".tlds");
		close(tlds_fd);
	}
	close(rootdir_fd);

	int err = x_smbd_volume_set_id(vol_fd, vol_id);
	X_ASSERT(err == 0);

	close(vol_fd);
	return 0;
}

static int init_volume(int argc, char **argv)
{
	bool dfs_root = false;
	uint16_t vol_id = 0xffff;
	int opt;
	while ((opt = getopt(argc, argv, "ri:")) != -1) {
		switch (opt) {
			case 'r':
				dfs_root = true;
				break;
			case 'i': {
				char *end;
				unsigned long tmp = strtoul(optarg, &end, 0);
				if (*end || tmp >= 0xffff) {
					fprintf(stderr, "Invalid volume id %s\n",
							optarg);
					exit(EXIT_FAILURE);
				}
				vol_id = x_convert<uint16_t>(tmp);
				  }
				break;
			default: /* '?' */
				fprintf(stderr, "Usage: %s [-i volume_id] [-r] path\n",
						argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Usage: %s [-i volume_id] [-r] path\n",
				argv[0]);
		exit(EXIT_FAILURE);
	}

	const char *path = argv[optind];

	make_volume(path, vol_id, dfs_root);
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
	return parse_acl_blob(blob.data(), blob.size(), psd, &hash_type, &version, hash);
}

static void output_timespec(const char *name, const struct timespec &ts)
{
	struct tm *lt = localtime(&ts.tv_sec);
	printf("%s: %d-%02d-%02d %02d:%02d:%02d %c%ld %ld.%09ld",
			name,
			lt->tm_year + 1900,
			lt->tm_mon + 1,
			lt->tm_mday,
			lt->tm_hour,
			lt->tm_min,
			lt->tm_sec,
			lt->tm_gmtoff > 0 ? '+' : '-',
			std::abs(lt->tm_gmtoff),
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
	output_timespec("Birth", object_meta.creation);
	output_timespec("\nAccess", object_meta.last_access);
	output_timespec("\nModify", object_meta.last_write);
	output_timespec("\nChange", object_meta.change);
	printf("\nSize: %lu\n", stream_meta.end_of_file);
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

struct durable_printer_t : x_smbd_durable_log_visitor_t
{
	bool initiate(uint64_t id, x_smbd_durable_t &durable) override;
	bool update(uint64_t id, x_smbd_durable_update_t &update) override;
	bool finalize(uint64_t id) override;
	size_t num_initiate = 0;
	size_t num_update = 0;
	size_t num_finalize = 0;
};

bool durable_printer_t::initiate(uint64_t id, x_smbd_durable_t &durable)
{
	auto &lease_data = durable.lease_data;
	printf("I 0x%lx 0x%lx %c%c 0x%x %s %u %d-%d-%x%c-%x-%x ",
			id,
			durable.id_volatile,
			x_smbd_dhmode_to_name(durable.open_state.dhmode),
			(durable.open_state.flags & x_smbd_open_state_t::F_REPLAY_CACHED) ? 'R' : '-',
			durable.open_state.access_mask,
			x_tostr(durable.open_state.owner).c_str(),
			durable.open_state.durable_timeout_msec,
			lease_data.version,
			lease_data.epoch,
			lease_data.state,
			lease_data.breaking,
			lease_data.breaking_to_requested,
			lease_data.breaking_to_required);
	if (durable.disconnect_msec == (uint64_t)-1) {
		printf("active");
	} else {
		struct timespec ts;
		ts.tv_sec = durable.disconnect_msec / 1000;
		ts.tv_nsec = (durable.disconnect_msec % 1000) * 1000000;
		output_timespec("disconnect", ts);
	}
	printf(" locks %zu", durable.open_state.locks.size());
	for (auto &lock: durable.open_state.locks) {
		printf("\n\t[%lu,%lu,%x]", lock.offset, lock.length,
				lock.flags);
	}
	printf("\n");
	++num_initiate;
	return true;
}

bool durable_printer_t::update(uint64_t id, x_smbd_durable_update_t &update)
{
	printf("U 0x%lx ", id);
	if (update.type == x_smbd_durable_update_t::type_disconnect) {
		printf("D %ld", update.disconnect_msec);
	} else if (update.type == x_smbd_durable_update_t::type_reconnect) {
		printf("R");
	} else if (update.type == x_smbd_durable_update_t::type_update_flags) {
		printf("F 0x%x", update.flags);
	} else if (update.type == x_smbd_durable_update_t::type_update_locks) {
		printf("L %zu", update.locks.size());
		for (auto &lock: update.locks) {
			printf("\n\t[%lu,%lu,%x]", lock.offset, lock.length,
					lock.flags);
		}
	} else {
		printf("?");
	}
	printf("\n");
	++num_update;
	return true;
}

bool durable_printer_t::finalize(uint64_t id)
{
	printf("F 0x%lx\n", id);
	++num_finalize;
	return true;
}

static int list_volume_durable(const char *volume, const char *log_file)
{
	int dirfd = open(volume, O_RDONLY);
	if (dirfd < 0) {
		fprintf(stderr, "cannot open volume %s\n", volume);
		return 1;
	}

	int dfd = openat(dirfd, X_SMBD_DURABLE_DIR, O_RDONLY);
	close(dirfd);

	if (dfd < 0) {
		fprintf(stderr, "cannot open durable dir %s/%s\n",
				volume, X_SMBD_DURABLE_DIR);
		return 1;
	}

	durable_printer_t printer;
	std::vector<std::string> log_files;
	ssize_t ret;
	if (log_file) {
		ret = x_smbd_durable_log_read_file(dfd, log_file,
				false, printer);
	} else {
		ret = x_smbd_durable_log_read(dfd, printer);
	}

	close(dfd);

	if (ret < 0) {
		fprintf(stderr, "Error in read durable log, %ld\n", ret);
		return int(ret);
	}
	printf("total %zu initiate, %zu update, %zu finalize\n",
			printer.num_initiate,
			printer.num_update,
			printer.num_finalize);

	return 0;
}

static void list_durable_usage(const char *cmd)
{
	fprintf(stderr, "Usage: %s [-f log_file] volume\n", cmd);
	exit(EXIT_FAILURE);
}

static int list_durable(int argc, char **argv)
{
	const char *log_file = nullptr;
	int opt;
	while ((opt = getopt(argc, argv, "f:")) != -1) {
		switch (opt) {
			case 'f':
				log_file = optarg;
				break;
			default: /* '?' */
				list_durable_usage(argv[0]);
		}
	}
	if (optind + 1 !=  argc) {
		list_durable_usage(argv[0]);
	}
	return list_volume_durable(argv[optind], log_file);
}

int main(int argc, char **argv)
{
	const char *command = argv[1];
	x_smbd_posixfs_init_dev();
	if (strcmp(command, "init-top-dir") == 0) {
		return init_top_dir(argv + 2);
	} else if (strcmp(command, "init-volume") == 0) {
		return init_volume(argc - 1, argv + 1);
	} else if (strcmp(command, "attrex") == 0) {
		return show_attrex(argv + 2);
	} else if (strcmp(command, "set-dos-attr") == 0) {
		return set_dos_attr(argv + 2);
	} else if (strcmp(command, "set-default-security-desc") == 0) {
		return set_default_security_desc(argv + 2);
	} else if (strcmp(command, "show-security-desc") == 0) {
		return show_security_desc(argv + 2);
	} else if (strcmp(command, "list-durable") == 0) {
		return list_durable(argc - 1, argv + 1);
#if 0
	} else if (strcmp(command, "create-file") == 0) {
		return create_file(argv + 2);
#endif
	} else {
		usage(argv[0]);
	}
	return 0;
}

