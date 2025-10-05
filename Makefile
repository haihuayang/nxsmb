
MAKEFLAGS += --no-builtin-rules
.SUFFIXES:

PROJECT := nxsmb
VERSION := 0.1
GIT_COMMIT := $(shell git describe --always --abbrev=12 --dirty)
BUILD_DATE := $(shell date '+%Y%m%d-%H%M%S')
BRANCH := $(shell git rev-parse --abbrev-ref HEAD)

include config.mk
include functions.mk

TARGET_BUILD_CFLAGS_dbg := -g3
TARGET_BUILD_LDFLAGS_dbg := -g3
TARGET_BUILD_CFLAGS_opt := -O2 -g3
TARGET_BUILD_LDFLAGS_opt := -O2 -g3
TARGET_BUILD_CFLAGS_dev := -g3 -fsanitize=address -D__X_DEVELOPER__=1
TARGET_BUILD_LDFLAGS_dev := -g3 -fsanitize=address

BUILD ?= dbg

TARGET_BUILD_CFLAGS := $(TARGET_BUILD_CFLAGS_$(BUILD))
TARGET_BUILD_LDFLAGS := $(TARGET_BUILD_LDFLAGS_$(BUILD))

TARGET_PROJECT_CFLAGS := -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -DPROJECT=$(PROJECT) $(TARGET_BUILD_CFLAGS)
TARGET_CFLAGS = $(TARGET_PROJECT_CFLAGS) -Wstrict-prototypes -MT $@ -MMD -MP -MF $@.d
TARGET_CXXFLAGS = $(TARGET_PROJECT_CFLAGS) -std=c++2a -Werror -Wunused -Wconversion -Wmissing-declarations -Wno-invalid-offsetof -Wno-multichar -MT $@ -MMD -MP -MF $@.d
TARGET_LDFLAGS := $(TARGET_LDFLAGS) $(TARGET_BUILD_LDFLAGS)

TARGET_DIR_out := $(BUILD).$(PLATFORM).x86_64

TARGET_SET_dir := bin lib lib/librpc librpc/idl lib/asn1 src tests

.PHONY: all target_mkdir target_gen tags
TARGET_SET_tests := \
	test-list \
	test-dcerpc \
	test-timer \
	test-wbcli \
	test-wbpool \
	test-security \
	test-krb5pac \
	test-ntlmssp \
	test-iface \
	test-idtable \
	test-sid \
	test-signing \
	test-compression \
	test-timeout \
	test-charset \

TARGET_SET_lib := nxsmb nxversion

TARGET_CFLAGS_EXTRA :=

TARGET_CFLAGS_dependent = \
	$(TARGET_CFLAGS_platform) \
	$(TARGET_CFLAGS_heimdal) \
	-I$(TARGET_DIR_out) \
	-I. \

TARGET_LDFLAGS_dependent = \
	$(TARGET_LDFLAGS_heimdal) \
	$(TARGET_LDFLAGS_platform) \

all: $(TARGET_SET_tests:%=$(TARGET_DIR_out)/tests/%) \
	$(TARGET_DIR_out)/bin/smbd_nx \
	$(TARGET_DIR_out)/bin/nxutils

SET_src_smbd_nx := \
	main \
	smbd \
	smbd_registry \
	smbd_replay \
	smbd_volume \
	smbd_durable \
	smbd_durable_log \
	smbd_file_info \
	smbd_access \
	smbd_posixfs \
	smbd_simplefs \
	smbd_share \
	smbd_conf \
	smbd_secrets \
	smbd_group_mapping \
	smbd_ipc \
	smbd_requ \
	smbd_conn \
	smbd_sess \
	smbd_chan \
	smbd_tcon \
	smbd_open \
	smbd_object \
	smbd_posixfs_utils \
	smbd_lease \
	util_sid \
	smbd_ctrl \
	smbd_dcerpc \
	smbd_dcerpc_wkssvc \
	smbd_dcerpc_srvsvc \
	smbd_dcerpc_dssetup \
	smbd_dcerpc_lsarpc \
	smbd_dcerpc_winreg \
	smb2_negprot \
	smb2_sesssetup \
	smb2_logoff \
	smb2_tcon \
	smb2_tdis \
	smb2_create \
	smb2_close \
	smb2_flush \
	smb2_read \
	smb2_write \
	smb2_lock \
	smb2_ioctl \
	smb2_keepalive \
	smb2_query_directory \
	smb2_notify \
	smb2_getinfo \
	smb2_setinfo \
	smb2_break \
	smb2_copychunk \
	smb2_signing smb2_preauth \
	smb2_compression \
	smb2 \
	auth_ntlmssp auth_krb5 auth_spnego auth \
	network misc fnmatch \
	nxfsd_conn \
	nxfsd_requ \
	nxfsd_sched \
	nxfsd_stats \
	ctrld \
	smbd_ntacl \
	smbd_string \
	util_io \
	nxdr \
	noded \
	noded_requ \

SET_src_nxutils := \
	nxutils \
	smbd_posixfs_utils \
	smbd_ntacl \
	smbd_volume \
	smbd_durable_log \
	smbd_string \
	util_sid \
	misc \

COMMON_LIBS := -lpthread -lresolv -ldl

$(TARGET_DIR_out)/bin/smbd_nx: $(SET_src_smbd_nx:%=$(TARGET_DIR_out)/src/%.o) $(TARGET_SET_lib:%=$(TARGET_DIR_out)/lib%.a)
	$(CXX) -g $(TARGET_LDFLAGS) -o $@ $^ $(TARGET_LDFLAGS_dependent) -ltdb -lcrypto -lz -lcom_err -luuid $(COMMON_LIBS) -ljemalloc

$(TARGET_DIR_out)/bin/nxutils: $(SET_src_nxutils:%=$(TARGET_DIR_out)/src/%.o) $(TARGET_SET_lib:%=$(TARGET_DIR_out)/lib%.a)
	$(CXX) -g $(TARGET_LDFLAGS) -o $@ $^ $(COMMON_LIBS) -lz -ljemalloc

$(TARGET_DIR_out)/src/%.o: src/%.cxx | target_mkdir target_gen
	$(CXX) -c $(TARGET_CXXFLAGS) $(TARGET_CFLAGS_EXTRA) $(TARGET_CFLAGS_dependent) -o $@ $<

$(TARGET_SET_tests:%=$(TARGET_DIR_out)/tests/%) : %: %.o
	$(CXX) -g $(TARGET_LDFLAGS) -o $@ $^ $(TESTS_LDFLAGS_$(basename $(notdir $@)))

$(TARGET_DIR_out)/tests/test-signing : $(TARGET_DIR_out)/src/smb2_signing.o
TESTS_LDFLAGS_test-signing := -lcrypto

$(TARGET_DIR_out)/tests/test-compression : $(TARGET_DIR_out)/src/smb2_compression.o

$(TARGET_SET_tests:%=$(TARGET_DIR_out)/tests/%) : $(TARGET_DIR_out)/libnxsmb.a $(COMMON_LIBS)

TARGET_SET_asn1 := spnego gssapi

ASN1_OPT_spnego := --sequence=MechTypeList

$(foreach i,$(TARGET_SET_asn1),$(eval $(call asn1_compile_wrap,$(TARGET_DIR_out),lib/asn1,$(i))))


TARGET_SET_idl := \
	misc \
	security \
	lsa \
	samr \
	netlogon \
	krb5pac \
	ntlmssp \
	dcerpc \
	svcctl \
	srvsvc \
	wkssvc \
	dssetup \
	xattr \
	dfs \
	winreg \

TARGET_GEN_nxsmb := \
	$(TARGET_SET_asn1:%=$(TARGET_DIR_out)/lib/asn1/%_asn1.h) \
	$(TARGET_SET_asn1:%=$(TARGET_DIR_out)/lib/asn1/%_asn1-priv.h) \
	$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.hxx) \


$(TARGET_SET_tests:%=$(TARGET_DIR_out)/tests/%.o) : $(TARGET_DIR_out)/tests/%.o: tests/%.cxx | target_mkdir target_gen
	$(CXX) -c $(TARGET_CXXFLAGS) $(TARGET_CFLAGS_EXTRA) $(TARGET_CFLAGS_dependent) -o $@ $<


TARGET_SRC_libnxversion := \
	lib/version

$(TARGET_DIR_out)/libnxversion.a: $(TARGET_SRC_libnxversion:%=$(TARGET_DIR_out)/%.o)
	ar rcs $@ $^

$(TARGET_DIR_out)/lib/version.o: lib/version.cxx | target_gen
	$(CXX) -c $(TARGET_CXXFLAGS) $(TARGET_CFLAGS_EXTRA) $(TARGET_CFLAGS_dependent) \
		-DBUILD_COMMIT=\"$(GIT_COMMIT)\" -DBUILD_DATE=\"$(BUILD_DATE)\" \
		-DBUILD_TYPE=\"$(BUILD)\" -DBUILD_BRANCH=\"$(BRANCH)\" \
		-DBUILD_VERSION=\"$(VERSION)\" -DBUILD_PROJECT=\"$(PROJECT)\" \
		-o $@ $<

$(TARGET_DIR_out)/lib/version.o: \
		$(shell find src include lib tests scripts -type f) \
		config.mk functions.mk Makefile

TARGET_SRC_libnxsmb := \
		lib/librpc/ndr \
		lib/librpc/ndr_smb \
		lib/librpc/ndr_utils \
		lib/librpc/ndr_string \
		lib/librpc/misc \
		lib/librpc/security \
		lib/librpc/lsa \
		lib/librpc/samr \
		lib/librpc/netlogon \
		lib/librpc/krb5pac \
		lib/librpc/dcerpc \
		lib/librpc/srvsvc \
		lib/librpc/winreg \
		lib/librpc/ntlmssp \
		lib/xutils \
		lib/eventfd \
		lib/trace \
		lib/threadpool \
		lib/evtmgmt \
		lib/timeout \
		lib/wbpool \
		lib/kerberos_pac \
		lib/charset \
		lib/networking \
		lib/hexdump \
		lib/rand \
		lib/crypto \
		lib/ntstatus \
		lib/werror \
		lib/SpookyV2 \
		lib/ntlmssp \
		lib/spnego \
		lib/stats \
		lib/iuflog \


$(TARGET_DIR_out)/libnxsmb.a: \
	$(TARGET_SRC_libnxsmb:%=$(TARGET_DIR_out)/%.o) \
	$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.ndr.o) \
	$(TARGET_SET_asn1:%=$(TARGET_DIR_out)/lib/asn1/%_asn1.o)
	ar rcs $@ $^

$(TARGET_SRC_libnxsmb:%=$(TARGET_DIR_out)/%.o): $(TARGET_DIR_out)/lib/%.o: lib/%.cxx | target_gen
	$(CXX) -c $(TARGET_CXXFLAGS) $(TARGET_CFLAGS_EXTRA) $(TARGET_CFLAGS_dependent) -o $@ $<



$(TARGET_SET_asn1:%=$(TARGET_DIR_out)/lib/asn1/%_asn1.o): $(TARGET_DIR_out)/lib/asn1/%.o: $(TARGET_DIR_out)/lib/asn1/%.c | target_mkdir
	$(CC) -c $(TARGET_CFLAGS) $(TARGET_CFLAGS_EXTRA) $(TARGET_CFLAGS_dependent) -Iinclude/dummy -o $@ $<


$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.json): $(TARGET_DIR_out)/librpc/idl/%.idl.json: lib/librpc/idl/%.idl | target_mkdir
	$(CC) -E -D__PIDL__ -xc $< | scripts/idl-parser.py -o $@

$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.json): scripts/idl-parser.py scripts/idl_json.py


$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.ndr.o) : $(TARGET_DIR_out)/librpc/idl/%.idl.ndr.o: $(TARGET_DIR_out)/librpc/idl/%.idl.ndr.cxx
	$(CXX) -c $(TARGET_CXXFLAGS) $(TARGET_CFLAGS_EXTRA) $(TARGET_CFLAGS_dependent) -o $@ $<

$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.ndr.o) : $(TARGET_DIR_out)/librpc/idl/%.idl.ndr.o: $(TARGET_DIR_out)/librpc/idl/%.idl.hxx

$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.hxx): %.idl.hxx: %.idl.json | $(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.json)
	scripts/gen-rpc --header --outputdir $(dir $@) $<

$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.ndr.cxx): %.idl.ndr.cxx: %.idl.json | $(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.json)
	scripts/gen-rpc --ndrcxx --outputdir $(dir $@) $<

$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.d) : %.idl.d: %.idl.json
	scripts/gen-rpc --depend --outputdir $(dir $@) $<

include $(wildcard $(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.d))

$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.ndr.cxx): scripts/gen-rpc scripts/idl_json.py
$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.hxx): scripts/gen-rpc scripts/idl_json.py


target_gen: $(TARGET_GEN_nxsmb)

TARGET_DEPFILES := \
	$(TARGET_SET_tests:%=$(TARGET_DIR_out)/tests/%.o.d) \
	$(TARGET_SRC_libnxsmb:%=$(TARGET_DIR_out)/%.o.d) \
	$(SET_src_smbd_nx:%=$(TARGET_DIR_out)/src/%.o.d) \
	$(SET_src_nxutils:%=$(TARGET_DIR_out)/src/%.o.d) \
	$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.ndr.o.d) \
	$(TARGET_SET_asn1:%=$(TARGET_DIR_out)/lib/asn1/%_asn1.o.d) \

include $(wildcard $(TARGET_DEPFILES))

target_mkdir: $(TARGET_SET_dir:%=$(TARGET_DIR_out)/%)

$(TARGET_SET_dir:%=$(TARGET_DIR_out)/%): %:
	mkdir -p $@

.PHONY:
clean_target:
	rm -rf $(TARGET_DIR_out)

clean:
	rm -rf $(TARGET_DIR_out)

tags:
	ctags -R include lib src $(TARGET_DIR_out)/librpc/idl

test: $(TARGET_SET_tests:%=$(TARGET_DIR_out)/tests/%)
	$(TARGET_DIR_out)/tests/test-list
	$(TARGET_DIR_out)/tests/test-dcerpc
	$(TARGET_DIR_out)/tests/test-krb5pac
	$(TARGET_DIR_out)/tests/test-security
	$(TARGET_DIR_out)/tests/test-ntlmssp
	$(TARGET_DIR_out)/tests/test-timeout
	
TESTS_LDFLAGS_test-ntlmssp := -lcrypto

