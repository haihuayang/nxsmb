
MAKEFLAGS += --no-builtin-rules
.SUFFIXES:

PROJECT := nxsmb
VERSION := 0.1

include config.mk
include dirs.mk

TARGET_PROJECT_CFLAGS := -g -Wall -DPROJECT=$(PROJECT)
TARGET_CFLAGS += $(TARGET_PROJECT_CFLAGS)
TARGET_CXXFLAGS += $(TARGET_PROJECT_CFLAGS)

TARGET_DIR_out := target.dbg.linux.x86_64
HOST_DIR_out := host.dbg.linux.x86_64



define cfiles
$(patsubst $(1)/%.c,%,$(wildcard $(1)/$(2)/*.c))
endef

define compile_et_wrap
$(1)/$(2).c $(1)/$(2).h: samba/source4/heimdal/$(2).et
	$(HOST_DIR_out)/bin/compile_et $$< && mv $(notdir $(2)).c $(notdir $(2)).h $(1)/$(dir $(2))
$(1)/$(2).c $(1)/$(2).h: $(HOST_DIR_out)/bin/compile_et
endef

define asn1_compile_wrap
$(1)/$(2)_asn1.h $(1)/$(2)_asn1.c: $(1)/$(2)_asn1.files

$(1)/$(2)_asn1.files: samba/source4/heimdal/$(2).asn1
	$(HOST_DIR_out)/bin/asn1_compile --one-code-file $(ASN1_OPT_$(notdir $(2))) --output-dir=$(TARGET_DIR_out)/source4/heimdal/$(dir $(2)) $$< $(notdir $(2))

$(1)/$(2)_asn1.files: $(HOST_DIR_out)/bin/asn1_compile
endef

define make_proto_wrap
$(1)/$(2)-protos.h: $(SET_PROTO_$(notdir $(2)):%=samba/source4/heimdal/%.c)
	perl samba/source4/heimdal/cf/make-proto.pl $(PROTO_OPT_$(notdir $(2))) -q -P comment -o $$@ $$^
$(1)/$(2)-private.h: $(SET_PROTO_$(notdir $(2)):%=samba/source4/heimdal/%.c)
	perl samba/source4/heimdal/cf/make-proto.pl -q -P comment -p $$@ $$^
endef


TARGET_SET_heimdal := lib/gssapi/mech lib/gssapi/krb5 lib/gssapi/spnego lib/hcrypto lib/hcrypto/libtommath base lib/wind 
TARGET_SET_gen_heimdal := lib/asn1

TARGET_SET_other_dir := \
	source4/heimdal/lib/com_err \
	source4/heimdal/lib/roken \
	source4/heimdal/lib/krb5 \
	source4/heimdal/lib/hx509 \
	source4/heimdal_build \
	lib/replace \
	include

TARGET_SET_dir := src bin \
	$(TARGET_SET_heimdal:%=source4/heimdal/%) \
	$(TARGET_SET_gen_heimdal:%=source4/heimdal/%) \
	$(TARGET_SET_other_dir)

.PHONY: all target_mkdir host_mkdir
all: target_mkdir host_mkdir $(TARGET_DIR_out)/bin/nxsmbd 

SET_src := threadpool epollmgmt network xutils gensec gensec-spnego smbd 

SET_SRC_heimdal := $(foreach d,$(TARGET_SET_heimdal),$(call cfiles,samba/source4/heimdal,$(d)))

TARGET_CFLAGS_EXTRA := \
	-I$(TARGET_DIR_out)/source4/heimdal/lib/gssapi/spnego \
	-I$(TARGET_DIR_out)/source4/heimdal/lib/gssapi/mech \
	-I$(TARGET_DIR_out)/source4/heimdal/lib/asn1 \
	-I$(TARGET_DIR_out)/source4/heimdal/lib/krb5 \
	-I$(TARGET_DIR_out)/source4 \
	-I$(TARGET_DIR_out) \
	-Isamba/source4 \
	-Isamba/source4/heimdal_build\
	-Isamba/lib/replace \
	-Isamba/source4/heimdal/lib/hcrypto \
	-Isamba/source4/heimdal/lib/hcrypto/libtommath \
	-Isamba/source4/heimdal/lib/roken \
	-Isamba/source4/heimdal/lib/asn1 \
	-Isamba/source4/heimdal/lib/gssapi/mech \
	-Isamba/source4/heimdal/lib/gssapi \
	-Isamba/source4/heimdal/lib/gssapi/gssapi \
	-I$(TARGET_DIR_out)/source4/heimdal/lib/gssapi/krb5 \
	-Isamba/source4/heimdal/lib/krb5 \
	-Isamba/source4/heimdal/lib/com_err \
	-I$(TARGET_DIR_out)/source4/heimdal/lib/wind \
	-I$(TARGET_DIR_out)/source4/heimdal/lib/hx509 \
	-Isamba/source4/heimdal/lib/wind \
	-Isamba/source4/heimdal/lib/hx509 \
	-Isamba/source4/heimdal/lib \
	-Isamba/source4/heimdal/include \
	-Isamba/source4/heimdal/base \
	-I. 

TARGET_SET_et := lib/asn1/asn1_err \
	lib/krb5/krb5_err lib/krb5/k524_err lib/krb5/krb_err \
	lib/wind/wind_err lib/krb5/heim_err \
	lib/gssapi/krb5/gkrb5_err lib/hx509/hx509_err \

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
SET_OBJ_SRC_nxsmbd := \
	$(SET_src:%=$(TARGET_DIR_out)/src/%.o)

SET_GEN_wind := bidi_table combining_table map_table errorlist_table normalize_table

$(TARGET_DIR_out)/bin/nxsmbd: $(SET_OBJ_SRC_nxsmbd) \
		$(TARGET_SET_asn1:%=$(TARGET_DIR_out)/source4/heimdal/%_asn1.o) \
		$(SET_SRC_heimdal:%=$(TARGET_DIR_out)/source4/heimdal/%.o) \
		$(SET_SRC_com_err:%=$(TARGET_DIR_out)/source4/heimdal/lib/com_err/%.o) \
		$(SET_SRC_krb5:%=$(TARGET_DIR_out)/source4/heimdal/lib/krb5/%.o) \
		$(SET_SRC_roken:%=$(TARGET_DIR_out)/source4/heimdal/lib/roken/%.o) \
		$(SET_SRC_hx509:%=$(TARGET_DIR_out)/source4/heimdal/lib/hx509/%.o) \
		$(SET_PROTO_der:%=$(TARGET_DIR_out)/source4/heimdal/%.o) \
		$(TARGET_SET_et:%=$(TARGET_DIR_out)/source4/heimdal/%.o) \
		$(SET_GEN_wind:%=$(TARGET_DIR_out)/source4/heimdal/lib/wind/%.o) \
		$(TARGET_DIR_out)/source4/heimdal/lib/roken/resolve.o \
		$(TARGET_DIR_out)/source4/heimdal/lib/asn1/timegm.o \
		$(TARGET_DIR_out)/source4/heimdal/lib/asn1/extra.o \
		$(TARGET_DIR_out)/source4/heimdal/lib/gssapi/spnego/compat.o \
		$(TARGET_DIR_out)/lib/replace/replace.o \
		$(TARGET_DIR_out)/source4/heimdal_build/gssapi-glue.o \
		$(TARGET_DIR_out)/source4/heimdal_build/replace.o
	$(CXX) -g -o $@ $^ -lpthread -lresolv -ldl

$(TARGET_DIR_out)/src/%.o: src/%.cxx
	$(CXX) -c $(TARGET_CXXFLAGS) $(TARGET_CFLAGS_EXTRA) -o $@ $<

$(TARGET_DIR_out)/source4/%.o: $(TARGET_DIR_out)/source4/%.c
	$(CC) -c $(TARGET_CFLAGS) $(TARGET_CFLAGS_EXTRA) -o $@ $<

$(TARGET_DIR_out)/source4/%.o: samba/source4/%.c
	$(CC) -c $(TARGET_CFLAGS) $(TARGET_CFLAGS_EXTRA) \
		-DBINDIR=\"/usr/bin\" -DSBINDIR=\"/usr/sbin\" \
		-DLIBDIR=\"/usr/lib\" -DLIBEXECDIR=\"/usr/libexec\" \
		-o $@ $<

$(TARGET_DIR_out)/lib/%.o: samba/lib/%.c
	$(CC) -c $(TARGET_CFLAGS) $(TARGET_CFLAGS_EXTRA) -o $@ $<

SET_PROTO_spnego := \
        lib/gssapi/spnego/init_sec_context \
        lib/gssapi/spnego/external \
        lib/gssapi/spnego/compat \
        lib/gssapi/spnego/context_stubs \
        lib/gssapi/spnego/cred_stubs \
        lib/gssapi/spnego/accept_sec_context \

$(foreach i,$(TARGET_SET_et),$(eval $(call compile_et_wrap,$(TARGET_DIR_out)/source4/heimdal,$(i))))
$(foreach i,$(TARGET_SET_asn1),$(eval $(call asn1_compile_wrap,$(TARGET_DIR_out)/source4/heimdal,$(i))))
$(foreach i,$(TARGET_SET_proto),$(eval $(call make_proto_wrap,$(TARGET_DIR_out)/source4/heimdal,$(i))))

$(SET_OBJ_SRC_nxsmbd): \
	$(TARGET_SET_asn1:%=$(TARGET_DIR_out)/source4/heimdal/%_asn1.h) \
	$(TARGET_SET_et:%=$(TARGET_DIR_out)/source4/heimdal/%.h) \
	$(TARGET_SET_proto:%=$(TARGET_DIR_out)/source4/heimdal/%-protos.h) \
	$(TARGET_SET_proto:%=$(TARGET_DIR_out)/source4/heimdal/%-private.h) \
	$(TARGET_DIR_out)/source4/heimdal/lib/wind/bidi_table.h \
	$(TARGET_DIR_out)/source4/heimdal/lib/wind/map_table.h \
	$(TARGET_DIR_out)/source4/heimdal/lib/wind/errorlist_table.h \
	$(TARGET_DIR_out)/source4/heimdal/lib/wind/normalize_table.h \
	$(TARGET_DIR_out)/source4/heimdal/lib/wind/combining_table.h \
	$(TARGET_DIR_out)/include/config.h

$(TARGET_DIR_out)/source4/heimdal/lib/wind/bidi_table.h: samba/source4/heimdal/lib/wind/rfc3454.txt
	python samba/source4/heimdal/lib/wind/gen-bidi.py $< $(dir $@)

$(TARGET_DIR_out)/source4/heimdal/lib/wind/map_table.h: samba/source4/heimdal/lib/wind/rfc3454.txt
	python samba/source4/heimdal/lib/wind/gen-map.py $< $(dir $@)

$(TARGET_DIR_out)/source4/heimdal/lib/wind/errorlist_table.h: samba/source4/heimdal/lib/wind/rfc3454.txt
	python samba/source4/heimdal/lib/wind/gen-errorlist.py $< $(dir $@)

$(TARGET_DIR_out)/source4/heimdal/lib/wind/normalize_table.h: samba/source4/heimdal/lib/wind/UnicodeData.txt samba/source4/heimdal/lib/wind/CompositionExclusions-3.2.0.txt
	python samba/source4/heimdal/lib/wind/gen-normalize.py $^ $(dir $@)

$(TARGET_DIR_out)/source4/heimdal/lib/wind/combining_table.h: samba/source4/heimdal/lib/wind/UnicodeData.txt
	python samba/source4/heimdal/lib/wind/gen-combining.py $< $(dir $@)

$(TARGET_DIR_out)/include/config.h: scripts/generate-config
	scripts/generate-config > $@

target_mkdir: $(TARGET_SET_dir:%=$(TARGET_DIR_out)/%)

$(TARGET_SET_dir:%=$(TARGET_DIR_out)/%): %:
	mkdir -p $@


HOST_SET_heimdal := lib/com_err lib/vers

HOST_SET_dir := include bin lib/replace source4/heimdal_build $(HOST_SET_heimdal:%=source4/heimdal/%) \
	source4/heimdal/lib/asn1 \
	source4/heimdal/lib/roken

HOST_CFLAGS += -g -I$(HOST_DIR_out)/include \
	-Isamba/source4/heimdal_build \
	-Isamba/source4/heimdal/lib/com_err \
	-Isamba/source4/heimdal/lib/roken \
	-I$(HOST_DIR_out)/source4/heimdal/lib/asn1 \
	-I$(HOST_DIR_out) \
	-Isamba/include -Isamba -Isamba/lib/replace -Isamba/source4 \
	-D__STDC_WANT_LIB_EXT1__=1

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
	lib/replace/replace \
	source4/heimdal/lib/vers/print_version \
	source4/heimdal_build/replace \
	source4/heimdal_build/version	

SET_DIR_compile_et := lib/com_err
SET_SRC_compile_et := $(foreach d,$(SET_DIR_compile_et),$(call cfiles,samba/source4/heimdal,$(d)))

SET_OBJ_SRC_compile_et := \
	$(SET_SRC_compile_et:%=$(HOST_DIR_out)/source4/heimdal/%.o) \
	$(SET_SRC_roken:%=$(HOST_DIR_out)/source4/heimdal/lib/roken/%.o) \
	$(SET_SRC_host_common:%=$(HOST_DIR_out)/%.o) \

$(HOST_DIR_out)/bin/compile_et: $(SET_OBJ_SRC_compile_et)
	$(HOSTCC) -g -o $@ $^

SET_OBJ_SRC_asn1_compile := \
	$(SET_asn1_compile:%=$(HOST_DIR_out)/source4/heimdal/lib/asn1/%.o) \
	$(SET_SRC_roken:%=$(HOST_DIR_out)/source4/heimdal/lib/roken/%.o) \
	$(SET_SRC_host_common:%=$(HOST_DIR_out)/%.o) \

$(HOST_DIR_out)/bin/asn1_compile: $(SET_OBJ_SRC_asn1_compile)
	$(HOSTCC) -g -o $@ $^

$(HOST_DIR_out)/%.o: samba/%.c
	$(HOSTCC) -g $(HOST_CFLAGS) -o $@ -c $<

HOST_SET_proto := \
	lib/asn1/der

$(SET_OBJ_SRC_asn1_compile): \
	$(HOST_SET_proto:%=$(HOST_DIR_out)/source4/heimdal/%-protos.h) \
	$(HOST_SET_proto:%=$(HOST_DIR_out)/source4/heimdal/%-private.h) \
	$(HOST_DIR_out)/include/version.h \
	$(HOST_DIR_out)/include/config.h

$(HOST_DIR_out)/include/version.h: ./scripts/generate-version
	./scripts/generate-version > $@

$(HOST_DIR_out)/include/config.h: ./scripts/generate-config
	./scripts/generate-config > $@

$(foreach i,$(HOST_SET_proto),$(eval $(call make_proto_wrap,$(HOST_DIR_out)/source4/heimdal,$(i))))

host_mkdir: $(HOST_SET_dir:%=$(HOST_DIR_out)/%)

$(HOST_SET_dir:%=$(HOST_DIR_out)/%): %:
	mkdir -p $@

.PHONY:
clean:
	rm -rf $(HOST_DIR_out) $(TARGET_DIR_out)


