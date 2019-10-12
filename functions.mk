
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
	$(HOST_DIR_out)/bin/asn1_compile --one-code-file $(ASN1_OPT_$(notdir $(2))) --output-dir=$(TARGET_DIR_out)/samba/source4/heimdal/$(dir $(2)) $$< $(notdir $(2))

$(1)/$(2)_asn1.files: $(HOST_DIR_out)/bin/asn1_compile
endef

define make_proto_wrap
$(1)/$(2)-protos.h: $(SET_PROTO_$(notdir $(2)):%=samba/source4/heimdal/%.c)
	perl samba/source4/heimdal/cf/make-proto.pl $(PROTO_OPT_$(notdir $(2))) -q -P comment -o $$@ $$^
$(1)/$(2)-private.h: $(SET_PROTO_$(notdir $(2)):%=samba/source4/heimdal/%.c)
	perl samba/source4/heimdal/cf/make-proto.pl -q -P comment -p $$@ $$^
endef


