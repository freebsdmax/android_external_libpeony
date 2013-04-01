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

#define LOG_TAG "__libpeony_a1_source__"
#include <utils/Log.h>
	#define uuprintf(fmt, args...) ALOGE("%s(%d): " fmt, __FUNCTION__, __LINE__, ##args)

#include <media/stagefright/FFmpegSource.h>
#include <media/stagefright/MediaDebug.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "libpeony.h"
#include "libpeony_demuxer.h"

namespace android {

FFmpegSource::FFmpegSource(const char *filename)
    : mFd(-1),
      mOffset(0),
      mLength(-1),
      mDecryptHandle(NULL),
      mDrmManagerClient(NULL),
      mDrmBufOffset(0),
      mDrmBufSize(0),
      mDrmBuf(NULL){

    CUUKUUK *ckkp;
    int ret_sz;
    char is_file[128];

    mFd = -1;
    //ff_ptr = 0; return;
    mFd = open(filename, O_LARGEFILE | O_RDONLY);

    if( mFd < 0 )
    {
		uuprintf("FFmpegSource %s open error", filename);
        return;
    }
	uuprintf("FFmpegSource %s openr", filename);

    ff_ptr = new CUUKUUK;
	uuprintf("FFmpegSource ff_ptr=%p", ff_ptr);
    ckkp = (CUUKUUK *)ff_ptr;

    __bb_dx_init_libavformat(&(ckkp->dx_fns), &ret_sz);
    ckkp->dx_dptr = new uint8_t[ret_sz];
    if( ckkp->dx_fns.fnp_dx_load(ckkp->dx_dptr, &(ckkp->nrm)) )
    {
		uuprintf("FFmpegSource  <<< libffmpeg.so >>>  load error");
		close(mFd);
		delete[] (uint8_t *)(ckkp->dx_dptr);
		delete (CUUKUUK *)(ff_ptr);
		mFd = -1;
		ff_ptr = 0;
		return;
    }

    sprintf(is_file, "isfd://%d", mFd);
uuprintf("FFmpegSource string=%s", is_file);

    if( ckkp->dx_fns.fnp_dx_file_read(ckkp->dx_dptr, is_file, &(ckkp->nrm)) )
    {
		delete (CUUKUUK *)ff_ptr;
		ff_ptr = 0;
    }
    else 
    {
	    int i;
        NR_TRACK *ntpt;

        ckkp->ntpv = 0;
        ckkp->ntpa = 0;
        ckkp->track_aa = -1;
        ckkp->track_vv = -1;

        for( i=0 ; i<(int)(ckkp->nrm.track_sz) ; i++ )
        {
                ntpt = (NR_TRACK *)((uint8_t*)(ckkp->nrm.track_ptr)+sizeof(NR_TRACK)*i);
                if( ntpt->fourcc == MK_FOURCC("nra0") ) { ckkp->ntpa = ntpt; ckkp->track_aa = i; }
                if( ntpt->fourcc == MK_FOURCC("nrv0") ) { ckkp->ntpv = ntpt; ckkp->track_vv = i; }
        }

		ff_ex1 = ckkp->nrm.fourcc_ex1;
		ff_ex2 = ckkp->nrm.fourcc_ex2;
		ff_ex3 = ckkp->nrm.fourcc_ex3;
		ff_ex4 = ckkp->nrm.fourcc_ex4;
uuprintf("FFmpegSource Class create %d ------", mFd);
    }
}

FFmpegSource::FFmpegSource(int fd, int64_t offset, int64_t length)
    : mFd(fd),
      mOffset(offset),
      mLength(length),
      mDecryptHandle(NULL),
      mDrmManagerClient(NULL),
      mDrmBufOffset(0),
      mDrmBufSize(0),
      mDrmBuf(NULL){
    CHECK(offset >= 0);
    CHECK(length >= 0);

    CUUKUUK *ckkp;
    int ret_sz;
    char is_file[128];

    mFd = -1;
    //ff_ptr = 0; return;
    mFd = dup(fd);
uuprintf("FFmpegSource create dup %d -> %d", fd, mFd);
    ff_ptr = new CUUKUUK;
uuprintf("FFmpegSource ff_ptr=%p", ff_ptr);
    ckkp = (CUUKUUK *)ff_ptr;

//uuprintf("FFmpegSource ckkp=%p", ckkp);
    __bb_dx_init_libavformat(&(ckkp->dx_fns), &ret_sz);
    ckkp->dx_dptr = new uint8_t[ret_sz];
    if( ckkp->dx_fns.fnp_dx_load(ckkp->dx_dptr, &(ckkp->nrm)) )
    {
		uuprintf("FFmpegSource  <<< libffmpeg.so >>>  load error");
		close(mFd);
		delete[] (uint8_t *)(ckkp->dx_dptr);
		delete (CUUKUUK *)ff_ptr;
		mFd = -1;
		ff_ptr = 0;
		return;
    }

    sprintf(is_file, "isfd://%d", mFd);
uuprintf("FFmpegSource string=%s", is_file);

    if( ckkp->dx_fns.fnp_dx_file_read(ckkp->dx_dptr, is_file, &(ckkp->nrm)) ) 
    {
		delete (CUUKUUK *)ff_ptr;
		ff_ptr = 0;
    }
    else
    {
	    int i;
        NR_TRACK *ntpt;

        ckkp->ntpv = 0;
        ckkp->ntpa = 0;
        ckkp->track_aa = -1;
        ckkp->track_vv = -1;

        for( i=0 ; i<(int)(ckkp->nrm.track_sz) ; i++ )
        {
                ntpt = (NR_TRACK *)((uint8_t*)(ckkp->nrm.track_ptr)+sizeof(NR_TRACK)*i);
                if( ntpt->fourcc == MK_FOURCC("nra0") ) { ckkp->ntpa = ntpt; ckkp->track_aa = i; }
                if( ntpt->fourcc == MK_FOURCC("nrv0") ) { ckkp->ntpv = ntpt; ckkp->track_vv = i; }
        }

		ff_ex1 = ckkp->nrm.fourcc_ex1;
		ff_ex2 = ckkp->nrm.fourcc_ex2;
		ff_ex3 = ckkp->nrm.fourcc_ex3;
		ff_ex4 = ckkp->nrm.fourcc_ex4;
uuprintf("FFmpegSource Class create %d ------", mFd);
    }
}

FFmpegSource::~FFmpegSource() {
    CUUKUUK *ckkp = (CUUKUUK *)ff_ptr;

	if( ff_ptr ) {
        ckkp->dx_fns.fnp_dx_file_close(ckkp->dx_dptr, &(ckkp->nrm));
		if( ckkp->dx_dptr ) delete [] (uint8_t *)ckkp->dx_dptr;
		delete (CUUKUUK *)ff_ptr;
	}
uuprintf("FFmpegSource Class del %d ------", mFd);

    if (mFd >= 0) {
        close(mFd);
        mFd = -1;
    }

    if (mDrmBuf != NULL) {
        delete[] mDrmBuf;
        mDrmBuf = NULL;
    }

    if (mDecryptHandle != NULL) {
        // To release mDecryptHandle
        CHECK(mDrmManagerClient);
        mDrmManagerClient->closeDecryptSession(mDecryptHandle);
        mDecryptHandle = NULL;
    }

    if (mDrmManagerClient != NULL) {
        delete mDrmManagerClient;
        mDrmManagerClient = NULL;
    }
}

status_t FFmpegSource::initCheck() const {
    return mFd >= 0 ? OK : NO_INIT;
}

ssize_t FFmpegSource::readAt(off64_t offset, void *data, size_t size) {
    if (mFd < 0) {
        return NO_INIT;
    }
    CUUKUUK *ckkp;

    ckkp = (CUUKUUK *)ff_ptr;
//uuprintf("-----_____ read fd:%d sz:%d", mFd, size);
    Mutex::Autolock autoLock(mLock);

	if( ckkp->dx_fns.fnp_dx_frame_read(ckkp->dx_dptr, &(ckkp->nrm), (NR_FRAME *)data) == 0 ) {
//uuprintf("FFmpegSource track_no %d\n", ((NR_FRAME *)data)->track_no);
//uuprintf("FFmpegSource data_size %d\n", ((NR_FRAME *)data)->data_size);
//uuprintf("FFmpegSource data_time %f\n", (float)(((NR_FRAME *)data)->t_us_pos)/1000000);
		return ((NR_FRAME *)data)->data_size;
	}

	return -1;

}

status_t FFmpegSource::getSize(off64_t *size) {
    Mutex::Autolock autoLock(mLock);

    if (mFd < 0)
        return NO_INIT;

    if (mLength >= 0) {
        *size = mLength;
        return OK;
    }

    *size = lseek64(mFd, 0, SEEK_END);

    return OK;
}

sp<DecryptHandle> FFmpegSource::DrmInitialization(const char *mime) {
    if (mDrmManagerClient == NULL)
        mDrmManagerClient = new DrmManagerClient();

    if (mDrmManagerClient == NULL)
        return NULL;

    if (mDecryptHandle == NULL) {
        mDecryptHandle = mDrmManagerClient->openDecryptSession(
                mFd, mOffset, mLength, mime);
    }

    if (mDecryptHandle == NULL) {
        delete mDrmManagerClient;
        mDrmManagerClient = NULL;
    }

    return mDecryptHandle;
}

void FFmpegSource::getDrmInfo(sp<DecryptHandle> &handle, DrmManagerClient **client) {
    handle = mDecryptHandle;

    *client = mDrmManagerClient;
}

ssize_t FFmpegSource::readAtDRM(off64_t offset, void *data, size_t size) {
    size_t DRM_CACHE_SIZE = 1024;
    if (mDrmBuf == NULL) {
        mDrmBuf = new unsigned char[DRM_CACHE_SIZE];
    }

    if (mDrmBuf != NULL && mDrmBufSize > 0 && (offset + mOffset) >= mDrmBufOffset
            && (offset + mOffset + size) <= (mDrmBufOffset + mDrmBufSize)) {
        /* Use buffered data */
        memcpy(data, (void*)(mDrmBuf+(offset+mOffset-mDrmBufOffset)), size);
        return size;
    } else if (size <= DRM_CACHE_SIZE) {
        /* Buffer new data */
        mDrmBufOffset =  offset + mOffset;
        mDrmBufSize = mDrmManagerClient->pread(mDecryptHandle, mDrmBuf,
                DRM_CACHE_SIZE, offset + mOffset);
        if (mDrmBufSize > 0) {
            int64_t dataRead = 0;
            dataRead = size > mDrmBufSize ? mDrmBufSize : size;
            memcpy(data, (void*)mDrmBuf, dataRead);
            return dataRead;
        } else {
            return mDrmBufSize;
        }
    } else {
        /* Too big chunk to cache. Call DRM directly */
        return mDrmManagerClient->pread(mDecryptHandle, data, size, offset + mOffset);
    }
}
}  // namespace android


android::DataSource *create_DataSource_url(const char *filename) 
{
    return new android::FFmpegSource(filename);
}

android::DataSource *create_DataSource_fd(int fd, int64_t offset, int64_t length)
{
    return new android::FFmpegSource(fd, offset, length);
}
