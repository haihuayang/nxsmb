
define cfiles
$(patsubst $(1)/%.c,%,$(wildcard $(1)/$(2)/*.c))
endef

define h_and_c
$(1).c $(1).h
endef


define asn1_compile_wrap
$(3)_path := $(shell realpath $(2)/$(3).asn1)

$(1)/$(2)/$(3)_asn1.h: $(1)/$(2)/$(3)_asn1_files
	cp $(1)/$(2)/$(3)_asn1.hx $(1)/$(2)/$(3)_asn1.h

$(1)/$(2)/$(3)_asn1-priv.h: $(1)/$(2)/$(3)_asn1_files
	cp $(1)/$(2)/$(3)_asn1-priv.hx $(1)/$(2)/$(3)_asn1-priv.h

$(1)/$(2)/$(3)_asn1.c: $(1)/$(2)/$(3)_asn1_files
	cp $(1)/$(2)/asn1_$(3)_asn1.x $(1)/$(2)/$(3)_asn1.c

$(1)/$(2)/$(3)_asn1_files: $(2)/$(3).asn1 | $(1)/$(2)
	cd $(1)/$(2) && $(ASN1_COMPILE) --one-code-file $(ASN1_OPT_$(3)) $$($(3)_path) $(3)_asn1
endef


