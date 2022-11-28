
define cfiles
$(patsubst $(1)/%.c,%,$(wildcard $(1)/$(2)/*.c))
endef

define h_and_c
$(1).c $(1).h
endef

define compile_et_wrap
$(1)/$(2).h: samba/source4/heimdal/$(2).et
	$(HOST_DIR_out)/bin/compile_et $$< && mv $(notdir $(2)).c $(notdir $(2)).h $(1)/$(dir $(2)) && touch $(1)/$(2).c
$(1)/$(2).c: $(1)/$(2).h
	#noop
$(1)/$(2).c $(1)/$(2).h: $(HOST_DIR_out)/bin/compile_et
endef

define asn1_compile_wrap
$(3)_path := $(shell realpath $(2)/$(3).asn1)

$(1)/$(2)/$(3)_asn1.h: $(1)/$(2)/$(3)_asn1_files
	cp $(1)/$(2)/$(3)_asn1.hx $(1)/$(2)/$(3)_asn1.h

$(1)/$(2)/$(3)_asn1-priv.h: $(1)/$(2)/$(3)_asn1_files
	cp $(1)/$(2)/$(3)_asn1-priv.hx $(1)/$(2)/$(3)_asn1-priv.h

$(1)/$(2)/$(3)_asn1.c: $(1)/$(2)/$(3)_asn1_files
	cp $(1)/$(2)/asn1_$(3)_asn1.x $(1)/$(2)/$(3)_asn1.c

$(1)/$(2)/$(3)_asn1_files: $(2)/$(3).asn1
	echo $$($(3)_path)
	cd $(1)/$(2); $(ASN1_COMPILE) --one-code-file $(ASN1_OPT_$(3)) $$($(3)_path) $(3)_asn1
endef

define make_proto_wrap
$(1)/$(2)-protos.h: $(SET_PROTO_$(notdir $(2)):%=samba/source4/heimdal/%.c)
	perl samba/source4/heimdal/cf/make-proto.pl $(PROTO_OPT_$(notdir $(2))) -q -P comment -o $$@ $$^
$(1)/$(2)-private.h: $(SET_PROTO_$(notdir $(2)):%=samba/source4/heimdal/%.c)
	perl samba/source4/heimdal/cf/make-proto.pl -q -P comment -p $$@ $$^
endef


