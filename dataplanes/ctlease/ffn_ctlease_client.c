// SPDX-License-Identifier: GPL-2.0-or-later
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "ffn_ctlease.h"
_Static_assert(sizeof(struct ffn_ctlease_bind)==72,"bind ABI");
_Static_assert(sizeof(struct ffn_ctlease_update)==48,"update ABI");

int ffn_ctlease_open(const struct ffn_ctlease_bind *identity)
{
    int fd=open("/dev/ffn-ctlease",O_RDWR|O_CLOEXEC);
    if(fd<0)return -errno;
    if(ioctl(fd,FFN_CTLEASE_BIND,identity)<0) {
        int error=errno;close(fd);return -error;
    }
    return fd;
}
int ffn_ctlease_update(int fd,const struct ffn_ctlease_update *update)
{
    if(ioctl(fd,FFN_CTLEASE_UPDATE,update)<0)return -errno;
    return 0;
}
int ffn_ctlease_check(int fd)
{
    if(ioctl(fd,FFN_CTLEASE_CHECK,0)<0)return -errno;
    return 0;
}
void ffn_ctlease_close(int fd) {if(fd>=0)close(fd);}
