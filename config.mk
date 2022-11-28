
ifeq (USE_CLANG,yes)

GCC_TOOLCHAIN:=/opt/cross/el7.3-x86_64/gcc-4.9.4
GCC_TOOLCHAIN:=/opt/rh/devtoolset-8/root/usr

TOOLCHAIN := /home/haihua.yang/ws/toolchain-builds/e8e4c83308ffeb8b3624d7aa98930728ed9f8b1c.x86_64
TOOLCHAIN_CFLAGS := -isystem $(GCC_TOOLCHAIN)/include -gcc-toolchain $(GCC_TOOLCHAIN)

#TOOLCHAIN_CFLAGS := -gcc-toolchain $(GCC_TOOLCHAIN)
TARGET_CFLAGS := $(TOOLCHAIN_CFLAGS)
#TARGET_LDFLAGS := -L$(TOOLCHAIN)/lib
CXX := /opt/cross/clang-3.8.1/bin/clang++
CC := /opt/cross/clang-3.8.1/bin/clang
else
CC :=/opt/rh/devtoolset-8/root/usr/bin/gcc
CXX :=/opt/rh/devtoolset-8/root/usr/bin/g++
endif

#TARGET_CXXFLAGS := $(TARGET_CFLAGS) -std=c++14

#	-Wall -Wextra -Wno-sign-compare -Wno-unused-parameter -Wmissing-prototypes -Wpointer-arith -Wbad-function-cast -Wmissing-declarations -Wnested-externs -Wshadow
#
HOSTCC := /usr/bin/gcc
HOST_CFLAGS := 

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


