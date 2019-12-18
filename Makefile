
MAKEFLAGS += --no-builtin-rules
.SUFFIXES:

PROJECT := nxsmb
VERSION := 0.1

include config.mk
include functions.mk
include files.mk

TARGET_PROJECT_CFLAGS := -g -Wall -DPROJECT=$(PROJECT)
TARGET_CFLAGS = $(TARGET_PROJECT_CFLAGS) -Wstrict-prototypes -MT $@ -MMD -MP -MF $@.d
TARGET_CXXFLAGS = $(TARGET_PROJECT_CFLAGS) -std=c++14 -MT $@ -MMD -MP -MF $@.d

TARGET_DIR_out := target.dbg.linux.x86_64
HOST_DIR_out := host.dbg.linux.x86_64

TARGET_SET_heimdal := lib/gssapi/mech lib/gssapi/krb5 lib/gssapi/spnego lib/hcrypto lib/hcrypto/libtommath base lib/wind  lib/ntlm
TARGET_SET_gen_heimdal := lib/asn1

TARGET_SET_samba_dir := \
	$(TARGET_SET_heimdal:%=samba/source4/heimdal/%) \
	$(TARGET_SET_gen_heimdal:%=samba/source4/heimdal/%) \
	samba/source4/heimdal/lib/com_err \
	samba/source4/heimdal/lib/roken \
	samba/source4/heimdal/lib/krb5 \
	samba/source4/heimdal/lib/hx509 \
	samba/source4/heimdal_build \
	samba/lib/replace \
	samba/lib/util \
	samba/lib/crypto \
	samba/include

TARGET_SET_dir := bin lib lib/librpc librpc/idl src tests \
	$(TARGET_SET_samba_dir)

.PHONY: all target_mkdir host_mkdir target_samba_gen
TARGET_SET_tests := test-timer test-krb5pac test-ntlmssp test-security test-wbcli test-wbpool
TARGET_SET_lib := nxsmb samba

TARGET_CFLAGS_EXTRA := \
	-I$(TARGET_DIR_out)/samba/source4/heimdal/lib/gssapi/spnego \
	-I$(TARGET_DIR_out)/samba/source4/heimdal/lib/gssapi/mech \
	-I$(TARGET_DIR_out)/samba/source4/heimdal/lib/asn1 \
	-I$(TARGET_DIR_out)/samba/source4/heimdal/lib/krb5 \
	-I$(TARGET_DIR_out)/samba/source4/heimdal/lib/ntlm \
	-I$(TARGET_DIR_out)/samba/source4 \
	-I$(TARGET_DIR_out)/samba \
	-I$(TARGET_DIR_out) \
	-Isamba/source4 \
	-Isamba \
	-Isamba/source4/heimdal_build\
	-Isamba/lib/replace \
	-Isamba/source4/heimdal/lib/hcrypto \
	-Isamba/source4/heimdal/lib/hcrypto/libtommath \
	-Isamba/source4/heimdal/lib/roken \
	-Isamba/source4/heimdal/lib/asn1 \
	-Isamba/source4/heimdal/lib/gssapi/mech \
	-Isamba/source4/heimdal/lib/gssapi \
	-Isamba/source4/heimdal/lib/gssapi/gssapi \
	-I$(TARGET_DIR_out)/samba/source4/heimdal/lib/gssapi/krb5 \
	-Isamba/source4/heimdal/lib/krb5 \
	-Isamba/source4/heimdal/lib/ntlm \
	-Isamba/source4/heimdal/lib/com_err \
	-I$(TARGET_DIR_out)/samba/source4/heimdal/lib/wind \
	-I$(TARGET_DIR_out)/samba/source4/heimdal/lib/hx509 \
	-Isamba/source4/heimdal/lib/wind \
	-Isamba/source4/heimdal/lib/hx509 \
	-Isamba/source4/heimdal/lib \
	-Isamba/source4/heimdal/include \
	-Isamba/source4/heimdal/base \
	-I. \
	-Isamba/lib/talloc \
	-Isamba/source3 \
	-D__X_DEVELOPER__=1

all: $(TARGET_SET_tests:%=$(TARGET_DIR_out)/tests/%) $(TARGET_DIR_out)/bin/nxsmbd

SET_src_nxsmbd := auth_ntlmssp auth_krb5 auth_spnego auth \
	network  \
	smbd smbd_negprot smbd_sesssetup \

$(TARGET_DIR_out)/bin/nxsmbd: $(SET_src_nxsmbd:%=$(TARGET_DIR_out)/src/%.o) $(TARGET_SET_lib:%=$(TARGET_DIR_out)/lib%.a)
	$(CXX) -g $(TARGET_LDFLAGS) -o $@ $^ -lpthread -lresolv -ldl

$(SET_src_nxsmbd:%=$(TARGET_DIR_out)/src/%.o): $(TARGET_DIR_out)/%.o: %.cxx | target_mkdir target_idl
	$(CXX) -c $(TARGET_CXXFLAGS) $(TARGET_CFLAGS_EXTRA) -o $@ $<

$(TARGET_SET_tests:%=$(TARGET_DIR_out)/tests/%) : %: %.o $(TARGET_SET_lib:%=$(TARGET_DIR_out)/lib%.a)
	$(CXX) -g $(TARGET_LDFLAGS) -o $@ $^ -lpthread -lresolv -ldl

SET_SRC_heimdal := $(foreach d,$(TARGET_SET_heimdal),$(call cfiles,samba/source4/heimdal,$(d)))


TARGET_SET_et := lib/asn1/asn1_err \
	lib/krb5/krb5_err lib/krb5/k524_err lib/krb5/krb_err \
	lib/wind/wind_err lib/krb5/heim_err \
	lib/gssapi/krb5/gkrb5_err lib/hx509/hx509_err \
	lib/ntlm/ntlm_err

TARGET_SET_asn1 := lib/gssapi/spnego/spnego lib/gssapi/mech/gssapi \
	lib/asn1/krb5 lib/asn1/rfc2459 lib/asn1/pkinit lib/asn1/cms lib/asn1/pkcs8 lib/asn1/pkcs9 lib/asn1/pkcs12 \
	lib/hx509/ocsp lib/hx509/pkcs10

ASN1_OPT_spnego := --sequence=MechTypeList
ASN1_OPT_krb5 := --option-file=samba/source4/heimdal/lib/asn1/krb5.opt
ASN1_OPT_rfc2459 := --preserve-binary=TBSCertificate --preserve-binary=TBSCRLCertList --preserve-binary=Name --sequence=GeneralNames --sequence=Extensions --sequence=CRLDistributionPoints
ASN1_OPT_cms := --option-file=samba/source4/heimdal/lib/asn1/cms.opt
ASN1_OPT_ocsp := --preserve-binary=OCSPTBSRequest --preserve-binary=OCSPResponseData	
ASN1_OPT_pkcs10 := --preserve-binary=CertificationRequestInfo

TARGET_SET_proto := \
	lib/asn1/der \
	lib/gssapi/spnego/spnego \
	lib/gssapi/krb5/gsskrb5 \
	lib/krb5/krb5 \
	lib/hx509/hx509 \
	lib/ntlm/heimntlm \

PROTO_OPT_krb5 := -E KRB5_LIB

SET_PROTO_der := \
	lib/asn1/der_get \
	lib/asn1/der_put \
	lib/asn1/der_free \
	lib/asn1/der_format \
	lib/asn1/der_length \
	lib/asn1/der_copy \
	lib/asn1/der_cmp \

SET_PROTO_hx509 := \
	lib/hx509/ca \
	lib/hx509/cert \
	lib/hx509/cms \
	lib/hx509/collector \
	lib/hx509/crypto \
	lib/hx509/error \
	lib/hx509/env \
	lib/hx509/file \
	lib/hx509/keyset \
	lib/hx509/ks_dir \
	lib/hx509/ks_file \
	lib/hx509/ks_keychain \
	lib/hx509/ks_mem \
	lib/hx509/ks_null \
	lib/hx509/ks_p11 \
	lib/hx509/ks_p12 \
	lib/hx509/lock \
	lib/hx509/name \
	lib/hx509/peer \
	lib/hx509/print \
	lib/hx509/req \
	lib/hx509/revoke \
	lib/hx509/sel \

SET_PROTO_gsskrb5 := $(SET_SRC_gssapi_krb5:%=lib/gssapi/krb5/%)

SET_PROTO_krb5 := $(call cfiles,samba/source4/heimdal,lib/krb5)

SET_PROTO_heimntlm := $(call cfiles,samba/source4/heimdal,lib/ntlm)

SET_PROTO_spnego := \
        lib/gssapi/spnego/init_sec_context \
        lib/gssapi/spnego/external \
        lib/gssapi/spnego/compat \
        lib/gssapi/spnego/context_stubs \
        lib/gssapi/spnego/cred_stubs \
        lib/gssapi/spnego/accept_sec_context \

$(foreach i,$(TARGET_SET_et),$(eval $(call compile_et_wrap,$(TARGET_DIR_out)/samba/source4/heimdal,$(i))))
$(foreach i,$(TARGET_SET_asn1),$(eval $(call asn1_compile_wrap,$(TARGET_DIR_out)/samba/source4/heimdal,$(i))))
$(foreach i,$(TARGET_SET_proto),$(eval $(call make_proto_wrap,$(TARGET_DIR_out)/samba/source4/heimdal,$(i))))

SET_GEN_wind := bidi_table combining_table map_table errorlist_table normalize_table

TARGET_SRC_libsamba := \
		lib/util/genrand \
		lib/util/time \
		lib/util/time_basic \
		lib/util/blocking \
		lib/crypto/md4 \
		source4/heimdal/lib/roken/resolve \
		source4/heimdal/lib/asn1/timegm \
		source4/heimdal/lib/asn1/extra \
		lib/replace/replace \
		source4/heimdal_build/gssapi-glue \
		source4/heimdal_build/replace \
		$(SET_SRC_heimdal:%=source4/heimdal/%) \
		$(SET_SRC_krb5:%=source4/heimdal/lib/krb5/%) \
		$(SET_SRC_roken:%=source4/heimdal/lib/roken/%) \
		$(SET_SRC_hx509:%=source4/heimdal/lib/hx509/%) \
		$(SET_PROTO_der:%=source4/heimdal/%) \
		$(SET_SRC_com_err:%=source4/heimdal/lib/com_err/%) \

TARGET_GEN_libsamba := \
		$(TARGET_SET_asn1:%=source4/heimdal/%_asn1) \
		$(TARGET_SET_et:%=source4/heimdal/%) \
		$(SET_GEN_wind:%=source4/heimdal/lib/wind/%) \

a=\
		$(SET_SRC_com_err:%=$(TARGET_DIR_out)/samba/source4/heimdal/lib/com_err/%.o) \


TARGET_GEN_samba := \
	$(TARGET_SET_asn1:%=$(TARGET_DIR_out)/samba/source4/heimdal/%_asn1.h) \
	$(TARGET_SET_et:%=$(TARGET_DIR_out)/samba/source4/heimdal/%.h) \
	$(TARGET_SET_proto:%=$(TARGET_DIR_out)/samba/source4/heimdal/%-protos.h) \
	$(TARGET_SET_proto:%=$(TARGET_DIR_out)/samba/source4/heimdal/%-private.h) \
	$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.h) \
	$(TARGET_DIR_out)/samba/source4/heimdal/lib/wind/bidi_table.h \
	$(TARGET_DIR_out)/samba/source4/heimdal/lib/wind/map_table.h \
	$(TARGET_DIR_out)/samba/source4/heimdal/lib/wind/errorlist_table.h \
	$(TARGET_DIR_out)/samba/source4/heimdal/lib/wind/normalize_table.h \
	$(TARGET_DIR_out)/samba/source4/heimdal/lib/wind/combining_table.h \
	$(TARGET_DIR_out)/samba/include/config.h

$(TARGET_DIR_out)/libsamba.a: $(TARGET_SRC_libsamba:%=$(TARGET_DIR_out)/samba/%.o) $(TARGET_GEN_libsamba:%=$(TARGET_DIR_out)/samba/%.o)
	ar rcs $@ $^

$(TARGET_SRC_libsamba:%=$(TARGET_DIR_out)/samba/%.o): $(TARGET_DIR_out)/%.o: %.c | target_samba_gen
	$(CC) -c $(TARGET_CFLAGS) $(TARGET_CFLAGS_EXTRA) \
		-DBINDIR=\"/usr/bin\" -DSBINDIR=\"/usr/sbin\" \
		-DLIBDIR=\"/usr/lib\" -DLIBEXECDIR=\"/usr/libexec\" \
		-o $@ $<

$(TARGET_GEN_libsamba:%=$(TARGET_DIR_out)/samba/%.o): %.o: %.c | target_samba_gen
	$(CC) -c $(TARGET_CFLAGS) $(TARGET_CFLAGS_EXTRA) -o $@ $<

$(TARGET_SET_tests:%=$(TARGET_DIR_out)/tests/%.o) : $(TARGET_DIR_out)/tests/%.o: tests/%.cxx | target_mkdir target_idl
	$(CXX) -c $(TARGET_CXXFLAGS) $(TARGET_CFLAGS_EXTRA) -o $@ $<


TARGET_SRC_libnxsmb := \
		lib/librpc/ndr \
		lib/librpc/ndr_nxsmb \
		lib/librpc/ndr_utils \
		lib/librpc/ndr_string \
		lib/librpc/ndr_misc \
		lib/librpc/ndr_ntlmssp \
		lib/librpc/ndr_security \
		lib/librpc/ndr_krb5pac \
		lib/librpc/ndr_netlogon \
		lib/librpc/ndr_samr \
		lib/librpc/ndr_lsa \
		lib/xutils \
		lib/string \
		lib/threadpool \
		lib/evtmgmt \
		lib/wbpool \
		lib/kerberos_pac \


$(TARGET_DIR_out)/libnxsmb.a: $(TARGET_SRC_libnxsmb:%=$(TARGET_DIR_out)/%.o) $(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.ndr.o)
	ar rcs $@ $^

$(TARGET_SRC_libnxsmb:%=$(TARGET_DIR_out)/%.o): $(TARGET_DIR_out)/lib/%.o: lib/%.cxx | target_idl target_samba_gen
	$(CXX) -c $(TARGET_CXXFLAGS) $(TARGET_CFLAGS_EXTRA) -o $@ $<


$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.ndr.o) : $(TARGET_DIR_out)/librpc/idl/%.ndr.o: $(TARGET_DIR_out)/librpc/idl/%.ndr.cxx
	$(CXX) -c $(TARGET_CXXFLAGS) $(TARGET_CFLAGS_EXTRA) -o $@ $<

$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.h): %.h: %.json | $(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.json)
	scripts/gen-rpc --depend --header --ndrcxx --outputdir $(dir $@) $<

$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.ndr.cxx): %.ndr.cxx: %.json | $(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.json)
	scripts/gen-rpc --depend --header --ndrcxx --outputdir $(dir $@) $<

$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.d) : %.d: %.json
	scripts/gen-rpc --depend --outputdir $(dir $@) $<

include $(wildcard $(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.d))

$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.ndr.cxx): scripts/gen-rpc
$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.h): scripts/gen-rpc

$(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.json): $(TARGET_DIR_out)/librpc/idl/%.json: samba/librpc/idl/%.idl | target_mkdir
	CPP=/usr/bin/cpp CC=/usr/bin/gcc /usr/bin/perl samba/pidl/pidl --quiet --dump-json $< > $@

target_samba_gen: $(TARGET_GEN_samba)

$(patsubst %,$(TARGET_DIR_out)/samba/source4/heimdal/lib/wind/bidi_table.%,c h): samba/source4/heimdal/lib/wind/rfc3454.txt
	python samba/source4/heimdal/lib/wind/gen-bidi.py $< $(dir $@)

$(patsubst %,$(TARGET_DIR_out)/samba/source4/heimdal/lib/wind/map_table.%,c h): samba/source4/heimdal/lib/wind/rfc3454.txt
	python samba/source4/heimdal/lib/wind/gen-map.py $< $(dir $@)

$(patsubst %,$(TARGET_DIR_out)/samba/source4/heimdal/lib/wind/errorlist_table.%,c h): samba/source4/heimdal/lib/wind/rfc3454.txt
	python samba/source4/heimdal/lib/wind/gen-errorlist.py $< $(dir $@)

$(patsubst %,$(TARGET_DIR_out)/samba/source4/heimdal/lib/wind/normalize_table.%,c h): samba/source4/heimdal/lib/wind/UnicodeData.txt samba/source4/heimdal/lib/wind/CompositionExclusions-3.2.0.txt
	python samba/source4/heimdal/lib/wind/gen-normalize.py $^ $(dir $@)

$(patsubst %,$(TARGET_DIR_out)/samba/source4/heimdal/lib/wind/combining_table.%,c h): samba/source4/heimdal/lib/wind/UnicodeData.txt
	python samba/source4/heimdal/lib/wind/gen-combining.py $< $(dir $@)

$(TARGET_DIR_out)/samba/include/config.h: scripts/generate-config
	scripts/generate-config > $@

target_idl: $(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.ndr.cxx) $(TARGET_SET_idl:%=$(TARGET_DIR_out)/librpc/idl/%.h)

TARGET_DEPFILES := $(TARGET_SET_tests:%=$(TARGET_DIR_out)/tests/%.o.d) $(TARGET_SRC_libnxsmb:%=$(TARGET_DIR_out)/%.o.d) $(SET_src_nxsmbd:%=$(TARGET_DIR_out)/src/%.o.d) $(TARGET_SRC_libsamba:%=$(TARGET_DIR_out)/samba/%.o.d)

include $(wildcard $(TARGET_DEPFILES))

target_mkdir: $(TARGET_SET_dir:%=$(TARGET_DIR_out)/%)

$(TARGET_SET_dir:%=$(TARGET_DIR_out)/%): %:
	mkdir -p $@

SET_asn1_compile := \
	main \
	gen \
	gen_copy \
	gen_decode \
	gen_encode \
	gen_free \
	gen_glue \
	gen_length \
	gen_seq \
	gen_template \
	hash \
	symbol \
	lex \
	asn1parse \

SET_SRC_host_common := \
	samba/lib/replace/replace \
	samba/source4/heimdal/lib/vers/print_version \
	samba/source4/heimdal_build/replace \
	samba/source4/heimdal_build/version	

HOST_CFLAGS += -g -I$(HOST_DIR_out)/include \
	-Isamba/source4/heimdal_build \
	-Isamba/source4/heimdal/lib/com_err \
	-Isamba/source4/heimdal/lib/roken \
	-I$(HOST_DIR_out)/samba/source4/heimdal/lib/asn1 \
	-I$(HOST_DIR_out)/samba \
	-I$(HOST_DIR_out)/samba/include \
	-Isamba -Isamba/lib/replace -Isamba/source4 \
	-D__STDC_WANT_LIB_EXT1__=1

SET_DIR_compile_et := lib/com_err
SET_SRC_compile_et := $(foreach d,$(SET_DIR_compile_et),$(call cfiles,samba/source4/heimdal,$(d)))

SET_OBJ_SRC_compile_et := \
	$(SET_SRC_compile_et:%=$(HOST_DIR_out)/samba/source4/heimdal/%.o) \
	$(SET_SRC_roken:%=$(HOST_DIR_out)/samba/source4/heimdal/lib/roken/%.o) \
	$(SET_SRC_host_common:%=$(HOST_DIR_out)/%.o) \

$(HOST_DIR_out)/bin/compile_et: $(SET_OBJ_SRC_compile_et)
	$(HOSTCC) -g -o $@ $^

SET_OBJ_SRC_asn1_compile := \
	$(SET_asn1_compile:%=$(HOST_DIR_out)/samba/source4/heimdal/lib/asn1/%.o) \
	$(SET_SRC_roken:%=$(HOST_DIR_out)/samba/source4/heimdal/lib/roken/%.o) \
	$(SET_SRC_host_common:%=$(HOST_DIR_out)/%.o) \

$(HOST_DIR_out)/bin/asn1_compile: $(SET_OBJ_SRC_asn1_compile)
	$(HOSTCC) -g -o $@ $^

$(HOST_DIR_out)/%.o: %.c | host_mkdir
	$(HOSTCC) -g $(HOST_CFLAGS) -o $@ -c $<

HOST_SET_proto := \
	lib/asn1/der

$(SET_OBJ_SRC_asn1_compile): \
	$(HOST_SET_proto:%=$(HOST_DIR_out)/samba/source4/heimdal/%-protos.h) \
	$(HOST_SET_proto:%=$(HOST_DIR_out)/samba/source4/heimdal/%-private.h) \
	$(HOST_DIR_out)/samba/include/version.h \
	$(HOST_DIR_out)/samba/include/config.h

$(HOST_DIR_out)/samba/include/version.h: ./scripts/generate-version
	./scripts/generate-version > $@

$(HOST_DIR_out)/samba/include/config.h: ./scripts/generate-config
	./scripts/generate-config > $@

$(foreach i,$(HOST_SET_proto),$(eval $(call make_proto_wrap,$(HOST_DIR_out)/samba/source4/heimdal,$(i))))

HOST_SET_heimdal := lib/com_err lib/vers

HOST_SET_dir := bin samba/include samba/lib/replace samba/source4/heimdal_build \
	$(HOST_SET_heimdal:%=samba/source4/heimdal/%) \
	samba/source4/heimdal/lib/asn1 \
	samba/source4/heimdal/lib/roken

host_mkdir: $(HOST_SET_dir:%=$(HOST_DIR_out)/%)

$(HOST_SET_dir:%=$(HOST_DIR_out)/%): %:
	mkdir -p $@

.PHONY:
clean_target:
	rm -rf $(TARGET_DIR_out)

clean:
	rm -rf $(HOST_DIR_out) $(TARGET_DIR_out)

