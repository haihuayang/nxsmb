
CXX := /opt/cross/clang-3.8.1/bin/clang++
CC := /opt/cross/clang-3.8.1/bin/clang
TOOLCHAIN := /home/haihua.yang/ws/toolchain-builds/e8e4c83308ffeb8b3624d7aa98930728ed9f8b1c.x86_64
TOOLCHAIN_CFLAGS := -isystem $(TOOLCHAIN)/include -gcc-toolchain /opt/cross/el7.3-x86_64/gcc-4.9.4
TARGET_CFLAGS := $(TOOLCHAIN_CFLAGS)
TARGET_CXXFLAGS := $(TARGET_CFLAGS) -std=c++14
	
#	-Wall -Wextra -Wno-sign-compare -Wno-unused-parameter -Wmissing-prototypes -Wpointer-arith -Wbad-function-cast -Wmissing-declarations -Wnested-externs -Wshadow
#
HOSTCC := /usr/bin/gcc
HOST_CFLAGS := 
