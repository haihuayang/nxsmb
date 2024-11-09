
#include "include/utils.hxx"
#include "include/bits.hxx"
#include <unistd.h>
#include <fcntl.h>

// copy from include/linux/eventfd.h
#define EFD_CLOEXEC O_CLOEXEC
#define EFD_NONBLOCK O_NONBLOCK

#ifndef SYS_eventfd2
#define SYS_eventfd2	290
#endif
#define eventfd(count, flags) syscall(SYS_eventfd2, (count), (flags))

int x_eventfd(unsigned int initval)
{
	return x_convert_assert<int>(eventfd(initval, EFD_CLOEXEC | EFD_NONBLOCK));
}

