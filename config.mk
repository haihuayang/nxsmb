
CXX := g++
CC := gcc
HOSTCC := gcc
PYTHON := python3


ifneq (, $(shell which heimdal-krb5-config))
TARGET_CFLAGS_heimdal := $(shell heimdal-krb5-config --cflags)
TARGET_LDFLAGS_heimdal := $(shell heimdal-krb5-config --libs krb5) -lgssapi -lasn1
ASN1_COMPILE := /usr/libexec/heimdal/asn1_compile
else
ifneq (, $(shell which krb5-config.heimdal))
TARGET_CFLAGS_heimdal := $(shell krb5-config.heimdal --cflags)
TARGET_LDFLAGS_heimdal := $(shell krb5-config.heimdal --libs krb5) -lgssapi -lasn1
ASN1_COMPILE := asn1_compile
else
$(error "Not supported system or missing heimdal devel package")
endif
endif


