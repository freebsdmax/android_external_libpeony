/*
 * libpeony for Android
 *
 * Copyright (C) 2012-2013 InSignal Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "__libpeony_b2_fd__"
#include <utils/Log.h>
	#define uuprintf(fmt, args...) ALOGE("%s(%d): " fmt, __FUNCTION__, __LINE__, ##args)


#include <media/stagefright/DataSource.h>
#include <media/stagefright/MediaBufferGroup.h>
#include <media/stagefright/MediaDebug.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MediaErrors.h>
#include <media/stagefright/MediaSource.h>
#include <media/stagefright/MetaData.h>
#include <utils/String8.h>
#include <dlfcn.h>
#include "libpeony.h"
#include "libpeony_demuxer.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>

namespace android {

/* standard file protocol */

static int isfile_read(URLContext *h, unsigned char *buf, int size)
{
    int fd = (intptr_t) h->priv_data;
    int r = read(fd, buf, size);
printf("fkdsflkdslfkslfks\n");
    return (-1 == r)?AVERROR(errno):r;
}

static int isfile_write(URLContext *h, const unsigned char *buf, int size)
{
    int fd = (intptr_t) h->priv_data;
    int r = write(fd, buf, size);
    return (-1 == r)?AVERROR(errno):r;
}

static int isfile_get_handle(URLContext *h)
{
    return (intptr_t) h->priv_data;
}

static int isfile_check(URLContext *h, int mask)
{
    struct stat st;
    int ret = stat(h->filename, &st);
    if (ret < 0)
        return AVERROR(errno);

    ret |= st.st_mode&S_IRUSR ? mask&AVIO_FLAG_READ  : 0;
    ret |= st.st_mode&S_IWUSR ? mask&AVIO_FLAG_WRITE : 0;

    return ret;
}

int __av_strstart(const char *str, const char *pfx, const char **ptr)
{
     while (*pfx && *pfx == *str) {
         pfx++;
         str++;
     }
     if (!*pfx && ptr)
         *ptr = str;
     return !*pfx;
}

static int isfile_open(URLContext *h, const char *filename, int flags)
{
    int access;
    int fd;

printf("fkdsflkdslfkslfks\n");
    __av_strstart(filename, "isfd://", &filename);

    sscanf(filename, "%d", &fd);

    if (fd == -1)
        return AVERROR(errno);
    h->priv_data = (void *) (intptr_t) fd;
lseek(fd, 0, SEEK_SET);

    return 0;
}

/* XXX: use llseek */
static int64_t isfile_seek(URLContext *h, int64_t pos, int whence)
{
    int fd = (intptr_t) h->priv_data;
    if (whence == AVSEEK_SIZE) {
        struct stat st;
        int ret = fstat(fd, &st);
        return ret < 0 ? AVERROR(errno) : st.st_size;
    }
    return lseek(fd, pos, whence);
}

static int isfile_close(URLContext *h)
{
    int fd = (intptr_t) h->priv_data;
uuprintf("isfile_close");

    //return close(fd);
    return 0;
}

URLProtocol isfd_protocol = {
    "isfd",
    isfile_open,
    0,
    isfile_read,
    isfile_write,
    isfile_seek,
    isfile_close,
    0,
    0,
    0,
    isfile_get_handle,
    0,
    0,
    0,
    0,
    isfile_check
};

}  // namespace android
