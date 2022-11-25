
MAKEFLAGS += --no-builtin-rules
.SUFFIXES:

PROJECT := nxsmb
VERSION := 0.1

include config.mk
include functions.mk
include files.mk

TARGET_PROJECT_CFLAGS := -g3 -Wall -DPROJECT=$(PROJECT) -fsanitize=address
TARGET_CFLAGS = $(TARGET_PROJECT_CFLAGS) -Wstrict-prototypes -MT $@ -MMD -MP -MF $@.d
TARGET_CXXFLAGS = $(TARGET_PROJECT_CFLAGS) -std=c++2a -Werror -Wunused -Wconversion -Wmissing-declarations -Wno-invalid-offsetof -Wno-multichar -MT $@ -MMD -MP -MF $@.d
TARGET_LDFLAGS := $(TARGET_LDFLAGS) -fsanitize=address -g3

TARGET_DIR_out := target.dbg.linux.x86_64

TARGET_SET_samba_dir := \
	samba/lib/replace \
	samba/lib/tdb/common \
	samba/lib/util \
	samba/lib/crypto \
	samba/libcli/util \
	samba/include

TARGET_SET_dir := bin lib lib/librpc librpc/idl lib/asn1 src tests \
	$(TARGET_SET_samba_dir)

.PHONY: all target_mkdir target_samba_gen tags
TARGET_SET_tests := \
	test-srvsvc \
	test-timer \
	test-wbcli \
	test-wbpool \
	test-security \
	test-krb5pac \
	test-ntlmssp \
	test-iface \
	test-idtable \

TARGET_SET_lib := nxsmb samba

TARGET_CFLAGS_EXTRA := \
	-D__X_DEVELOPER__=1

# heimdal-krb5-config --cflags
TARGET_CFLAGS_heimdal = -I/usr/include/heimdal
TARGET_LDFLAGS_heimdal = -Wl,--enable-new-dtags -Wl,-rpath -Wl,/usr/lib64/heimdal -L/usr/lib64/heimdal -lkrb5 -lgssapi -lasn1

TARGET_CFLAGS_samba = \
	-I$(TARGET_DIR_out)/samba \
	-I$(TARGET_DIR_out)/samba/include \
	-I$(TARGET_DIR_out) \
	-Isamba/source4 \
	-Isamba \
	-Isamba/lib/replace \
	-Isamba/lib/tdb/include \
	-I. \
	-Isamba/lib/talloc \
	-Isamba/source3 \

all: $(TARGET_SET_tests:%=$(TARGET_DIR_out)/tests/%) \
	$(TARGET_DIR_out)/bin/smbd_nx \
	$(TARGET_DIR_out)/bin/nxutils

SET_src_smbd_nx := \
	smbd_file_info \
	smbd_access \
	smbd_posixfs \
	smbd_notify \
	smbd_dfs \
	smbd_simplefs \
	smbd_share \
	smbd_ipc \
	smbd_conf smbd_share \
	smbd \
	smbd_stats \
	smbd_requ \
	smbd_conn \
	smbd_sess \
	smbd_chan \
	smbd_tcon \
	smbd_open \
	smbd_object \
	smbd_secrets \
	smbd_posixfs_utils \
	smbd_lease \
	util_sid \
	smbd_ctrl \
	smbd_dcerpc \
	smbd_dcerpc_wkssvc \
	smbd_dcerpc_srvsvc \
	smbd_dcerpc_dssetup \
	smbd_dcerpc_lsarpc \
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
	smb2_cancel \
	smb2_keepalive \
	smb2_query_directory \
	smb2_notify \
	smb2_getinfo \
	smb2_setinfo \
	smb2_break \
	smb2_copychunk \
	smb2_signing smb2_preauth \
	smb2 \
	auth_ntlmssp auth_krb5 auth_spnego auth \
	network misc fnmatch \
	smbd_ntacl \
	util_io \

SET_src_nxutils := \
	nxutils \
	smbd_posixfs_utils \
	smbd_ntacl \
	util_sid \
	misc \

$(TARGET_DIR_out)/bin/smbd_nx: $(SET_src_smbd_nx:%=$(TARGET_DIR_out)/src/%.o) $(TARGET_SET_lib:%=$(TARGET_DIR_out)/lib%.a)
	$(CXX) -g $(TARGET_LDFLAGS) -o $@ $^ $(TARGET_LDFLAGS_heimdal) -lcrypto -lz -lcom_err -lpthread -lresolv -ldl

$(TARGET_DIR_out)/bin/nxutils: $(SET_src_nxutils:%=$(TARGET_DIR_out)/src/%.o) $(TARGET_SET_lib:%=$(TARGET_DIR_out)/lib%.a)
	$(CXX) -g $(TARGET_LDFLAGS) -o $@ $^ -lpthread -lresolv -ldl

$(TARGET_DIR_out)/src/%.o: src/%.cxx | target_mkdir target_idl target_samba_gen
	$(CXX) -c $(TARGET_CXXFLAGS) $(TARGET_CFLAGS_EXTRA) $(TARGET_CFLAGS_samba) $(TARGET_CFLAGS_heimdal) -Izfs/include -o $@ $<

$(TARGET_SET_tests:%=$(TARGET_DIR_out)/tests/%) : %: %.o $(TARGET_SET_lib:%=$(TARGET_DIR_out)/lib%.a)
	$(CXX) -g $(TARGET_LDFLAGS) -o $@ $^ -lpthread -lresolv -ldl

TARGET_SET_asn1 := spnego gssapi

ASN1_OPT_spnego := --sequence=MechTypeList


$(foreach i,$(TARGET_SET_asn1),$(eval $(call asn1_compile_wrap,$(TARGET_DIR_out),lib/asn1,$(i))))

TARGET_SRC_libsamba := \
		lib/util/genrand \
		lib/util/time \
		lib/util/time_basic \
		lib/util/blocking \
		lib/util/sys_rw_data \
		lib/util/sys_rw \
		lib/util/iov_buf \
		lib/replace/replace \
		lib/tdb/common/tdb \
		lib/tdb/common/error \
		lib/tdb/common/hash \
		lib/tdb/common/open \
		lib/tdb/common/freelist \
		lib/tdb/common/io \
		lib/tdb/common/lock \
		lib/tdb/common/mutex \
		lib/tdb/common/traverse \
		lib/tdb/common/transaction \

TARGET_GEN_ntstatus := ntstatus_gen.h nterr_gen.c py_ntstatus.c
TARGET_GEN_werror := werror_gen.h werror_gen.c py_werror.c

TARGET_GEN_samba := \
	$(TARGET_SET_asn1:%=$(TARGET_DIR_out)/lib/asn1/%_asn1.h) \
	$(TARGET_SET_asn1:%=$(TARGET_DIR_out)/lib/asn1/%_asn1-priv.h) \
	$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.hxx) \
	$(TARGET_DIR_out)/samba/include/config.h \
	$(TARGET_GEN_ntstatus:%=$(TARGET_DIR_out)/samba/libcli/util/%) \
	$(TARGET_GEN_werror:%=$(TARGET_DIR_out)/samba/libcli/util/%)


$(TARGET_DIR_out)/libsamba.a: $(TARGET_SRC_libsamba:%=$(TARGET_DIR_out)/samba/%.o) $(TARGET_GEN_libsamba:%=$(TARGET_DIR_out)/samba/%.o)
	ar rcs $@ $^

$(TARGET_DIR_out)/samba/lib/%.o: samba/lib/%.c | target_samba_gen
	$(CC) -c $(TARGET_CFLAGS) $(TARGET_CFLAGS_EXTRA) $(TARGET_CFLAGS_samba) \
		-DBINDIR=\"/usr/bin\" -DSBINDIR=\"/usr/sbin\" \
		-DLIBDIR=\"/usr/lib\" -DLIBEXECDIR=\"/usr/libexec\" \
		-o $@ $<

$(TARGET_GEN_libsamba:%=$(TARGET_DIR_out)/samba/%.o): %.o: %.c | target_samba_gen
	$(CC) -c $(TARGET_CFLAGS) $(TARGET_CFLAGS_EXTRA) $(TARGET_CFLAGS_heimdal) $(TARGET_CFLAGS_samba)  -o $@ $<

$(TARGET_SET_tests:%=$(TARGET_DIR_out)/tests/%.o) : $(TARGET_DIR_out)/tests/%.o: tests/%.cxx | target_mkdir target_idl
	$(CXX) -c $(TARGET_CXXFLAGS) $(TARGET_CFLAGS_EXTRA) $(TARGET_CFLAGS_heimdal) $(TARGET_CFLAGS_samba) -o $@ $<


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
		lib/librpc/ntlmssp \
		lib/xutils \
		lib/threadpool \
		lib/evtmgmt \
		lib/timerq \
		lib/wbpool \
		lib/kerberos_pac \
		lib/charset \
		lib/networking \
		lib/hexdump \



TARGET_SET_m_idl :=
#misc security lsa samr netlogon krb5pac ntlmssp dcerpc srvsvc

$(TARGET_DIR_out)/libnxsmb.a: \
	$(TARGET_SRC_libnxsmb:%=$(TARGET_DIR_out)/%.o) \
	$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.ndr.o) \
	$(TARGET_SET_asn1:%=$(TARGET_DIR_out)/lib/asn1/%_asn1.o)
	ar rcs $@ $^

$(TARGET_SRC_libnxsmb:%=$(TARGET_DIR_out)/%.o): $(TARGET_DIR_out)/lib/%.o: lib/%.cxx | target_idl target_samba_gen
	$(CXX) -c $(TARGET_CXXFLAGS) $(TARGET_CFLAGS_EXTRA) $(TARGET_CFLAGS_heimdal) $(TARGET_CFLAGS_samba) -o $@ $<



$(TARGET_SET_asn1:%=$(TARGET_DIR_out)/lib/asn1/%_asn1.o): $(TARGET_DIR_out)/lib/asn1/%.o: $(TARGET_DIR_out)/lib/asn1/%.c
	$(CC) -c $(TARGET_CFLAGS) $(TARGET_CFLAGS_EXTRA) $(TARGET_CFLAGS_heimdal) $(TARGET_CFLAGS_samba) -Iinclude/dummy -o $@ $<


#$(TARGET_SET_m_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.ndr.o) : $(TARGET_DIR_out)/librpc/idl/%.idl.ndr.o: idl-gen/librpc/idl/%.idl.ndr.cxx
#	$(CXX) -c $(TARGET_CXXFLAGS) $(TARGET_CFLAGS_EXTRA) -o $@ $<

$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.ndr.o) : $(TARGET_DIR_out)/librpc/idl/%.idl.ndr.o: $(TARGET_DIR_out)/librpc/idl/%.idl.ndr.cxx
	$(CXX) -c $(TARGET_CXXFLAGS) $(TARGET_CFLAGS_EXTRA) $(TARGET_CFLAGS_samba) $(TARGET_CFLAGS_heimdal) -o $@ $<

$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.ndr.o) : $(TARGET_DIR_out)/librpc/idl/%.idl.ndr.o: $(TARGET_DIR_out)/librpc/idl/%.idl.hxx

$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.hxx): %.idl.hxx: %.json | $(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.json)
	scripts/gen-rpc --header --outputdir $(dir $@) $<

$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.ndr.cxx): %.idl.ndr.cxx: %.json | $(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.json)
	scripts/gen-rpc --ndrcxx --outputdir $(dir $@) $<

$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.d) : %.d: %.json
	scripts/gen-rpc --depend --outputdir $(dir $@) $<

include $(wildcard $(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.d))

$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.ndr.cxx): scripts/gen-rpc
$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.hxx): scripts/gen-rpc

$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.json): $(TARGET_DIR_out)/librpc/idl/%.json: samba/librpc/idl/%.idl | target_mkdir
	CPP=cpp CC=gcc /usr/bin/perl samba/pidl/pidl --quiet --dump-json $< > $@

target_samba_gen: $(TARGET_GEN_samba)

$(TARGET_DIR_out)/samba/include/config.h: scripts/generate-config
	scripts/generate-config > $@

$(TARGET_GEN_ntstatus:%=$(TARGET_DIR_out)/samba/libcli/util/%): samba/libcli/util/ntstatus_err_table.txt
	$(PYTHON) samba/source4/scripting/bin/gen_ntstatus.py $< $(TARGET_GEN_ntstatus:%=$(TARGET_DIR_out)/samba/libcli/util/%)

$(TARGET_GEN_werror:%=$(TARGET_DIR_out)/samba/libcli/util/%): samba/libcli/util/werror_err_table.txt
	$(PYTHON) samba/source4/scripting/bin/gen_werror.py $< $(TARGET_GEN_werror:%=$(TARGET_DIR_out)/samba/libcli/util/%)

target_idl: $(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.ndr.cxx) $(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.hxx)

TARGET_DEPFILES := $(TARGET_SET_tests:%=$(TARGET_DIR_out)/tests/%.o.d) $(TARGET_SRC_libnxsmb:%=$(TARGET_DIR_out)/%.o.d) $(SET_src_smbd_nx:%=$(TARGET_DIR_out)/src/%.o.d) $(TARGET_SRC_libsamba:%=$(TARGET_DIR_out)/samba/%.o.d) $(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.idl.ndr.o.d)

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
	$(TARGET_DIR_out)/tests/test-srvsvc
	$(TARGET_DIR_out)/tests/test-krb5pac
	$(TARGET_DIR_out)/tests/test-security
	$(TARGET_DIR_out)/tests/test-ntlmssp
	
