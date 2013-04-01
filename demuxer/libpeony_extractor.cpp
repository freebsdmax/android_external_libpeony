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

//#define LOG_NDEBUG 0
#define LOG_TAG "__libpeony_Extractor0__"
#include <utils/Log.h>
	#define uuprintf(fmt, args...) ALOGE("%s(%d): " fmt, __FUNCTION__, __LINE__, ##args)

#include "libpeony.h"
#include "libpeony_demuxer.h"
#include "libpeony_b2_queue.h"
#include "libpeony_extractor.h"
#include "libpeony_c3_extradata.h"

#include <binder/ProcessState.h>
#include <media/stagefright/foundation/hexdump.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/DataSource.h>
#include <media/stagefright/MediaBuffer.h>
#include <media/stagefright/MediaBufferGroup.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MediaErrors.h>
#include <media/stagefright/MetaData.h>
#include <media/stagefright/Utils.h>
#include <utils/String8.h>
#include <sys/prctl.h>

namespace android {

class FFSource : public MediaSource {
public:
    FFSource(const sp<FFExtractor> &extractor,
			const sp<DataSource> &dataSource,
			const sp<MetaData> &format,
			int32_t trackno);

    virtual status_t start(MetaData *params = NULL);
    virtual status_t stop();
    virtual sp<MetaData> getFormat();

    virtual status_t read(MediaBuffer **buffer, const ReadOptions *options = NULL);

protected:
    virtual ~FFSource();

private:
    Mutex mLock;

    sp<FFExtractor> mExtractor;
    sp<DataSource> mDataSource;
    sp<MetaData> mFormat;
    bool mStarted;
    MediaBufferGroup *mBufferGroup;
    MediaBuffer *mBuffer;
    size_t mMaxInputSize;
    int32_t mTrackno;
    int32_t a_blk_sz;

    //uint8_t *mSrcBuffer;
    FFSource(const FFSource &);
    FFSource &operator=(const FFSource &);
};

FFSource::FFSource(const sp<FFExtractor> &extractor,
			const sp<DataSource> &dataSource,
			const sp<MetaData> &format,
			int32_t trackno)
    : mExtractor(extractor),
      mDataSource(dataSource),
      mFormat(format),
      mStarted(false),
      mBufferGroup(NULL),
      mBuffer(NULL) {

      a_blk_sz=0;
      mTrackno=trackno;
    uuprintf("~~~~~~~!!!!~~~~FFSource::data source ff_ptr = %p", mDataSource->ff_ptr);
    uuprintf("~~~~~~~!!!!~~~~FFSource::create track = %d", mTrackno);
}

FFSource::~FFSource() {
    uuprintf("~~~~~~~!!!!~~~~FFSource::delete track = %d", mTrackno);
    if (mStarted) {
        stop();
    }
}

status_t FFSource::start(MetaData *params) {
    uuprintf("FFSource::start");
    Mutex::Autolock autoLock(mLock);

    int32_t max_size;

    CHECK(!mStarted);
    mBufferGroup = new MediaBufferGroup;
    CHECK(mFormat->findInt32(kKeyMaxInputSize, &max_size));
    mBufferGroup->add_buffer(new MediaBuffer(max_size));
    mMaxInputSize = max_size;
    //mSrcBuffer = new uint8_t[max_size];
    mStarted = true;

    return OK;
}

status_t FFSource::stop() {
    uuprintf("FFSource::stop");
    Mutex::Autolock autoLock(mLock);

    CHECK(mStarted);

    if (mBuffer != NULL) {
        mBuffer->release();
        mBuffer = NULL;
    }

    //delete[] mSrcBuffer;
    //mSrcBuffer = NULL;

    delete mBufferGroup;
    mBufferGroup = NULL;

    mStarted = false;

    return OK;
}

sp<MetaData> FFSource::getFormat() {
    Mutex::Autolock autoLock(mLock);

    return mFormat;
}

status_t FFSource::read(
        MediaBuffer **out, const ReadOptions *options) {
    Mutex::Autolock autoLock(mLock);

    CHECK(mStarted);

    CUUKUUK *ckkp;
    NR_TRACK *ntp;
    NR_FRAME nf;
    int aa_rq, vv_rq;
    ssize_t n;
    int seek_opt = 0;

    *out = NULL;
    ckkp = (CUUKUUK *)(mDataSource->ff_ptr);
    ntp = (NR_TRACK *)((uint8_t*)(ckkp->nrm.track_ptr)+sizeof(NR_TRACK)*ckkp->nrm.audio_track_no);

    int64_t seekTimeUs;
    ReadOptions::SeekMode mode;
    if(options != NULL && options->getSeekTo(&seekTimeUs, &mode))
    {
		if( mTrackno == ckkp->nrm.master_track_no )
		{
			mExtractor->aLock.lock();
			if( pkt_clst_clear(&(mExtractor->aa_q)) ) return 1;
			mExtractor->aLock.unlock();
			if( pkt_clst_clear(&(mExtractor->vv_q)) ) return 1;
			ckkp->dx_fns.fnp_dx_frame_seek(ckkp->dx_dptr, &(ckkp->nrm), ckkp->nrm.master_track_no, seekTimeUs/1000, 1);
			seek_opt = 1;
            //if (mBuffer != NULL) { mBuffer->release(); mBuffer = NULL; }
		}
    }

//uuprintf("mTrackno, ckkp->nrm.audio_track_no, ckkp->nrm.video_track_no = %d, %d, %d",mTrackno, ckkp->nrm.audio_track_no, ckkp->nrm.video_track_no);

    if( mExtractor->thread_mode == 0 )
    {
        if( mTrackno == ckkp->nrm.master_track_no )
        {
            while( 1 )
            {
                aa_rq = pkt_clst_probe(&(mExtractor->aa_q));
                vv_rq = pkt_clst_probe(&(mExtractor->vv_q));
//uuprintf("aa_rq %d, vv_rq %d, seek_opt %d", aa_rq, vv_rq, seek_opt);

		        if( mTrackno == ckkp->nrm.video_track_no ){
				    if( (vv_rq <= 0 ) ) break;
		        }
		        else{
				    if( (aa_rq <= 0 ) ) break;
		        }

                n = mDataSource->readAt(0, (void *)&nf, 262144);
				if (nf.data_size <= 0)
					mExtractor->interrupt = 1;

		        if( (nf.track_no != mExtractor->vv_no) && (nf.track_no != mExtractor->aa_no) ){
                    mExtractor->aLock.lock();
                    ckkp->dx_fns.fnp_dx_frame_release(ckkp->dx_dptr, &nf);
                    mExtractor->aLock.unlock();
uuprintf("FFsource illegal track == %d : %d : %d", mExtractor->vv_no, mExtractor->aa_no, nf.track_no);
                    continue;
				}

                if( nf.track_no == mExtractor->aa_no ){
                    if( seek_opt ){   }
                    mExtractor->aLock.lock();
                    if( mDataSource->ff_ex3 == CODEC_ID_AC3 )
                    {
                        if( a_blk_sz == 0 ) a_blk_sz = nf.data_size;
                        if( a_blk_sz == nf.data_size ) pkt_clst_add(&(mExtractor->aa_q), &nf);
                        else ckkp->dx_fns.fnp_dx_frame_release(ckkp->dx_dptr, &nf);
                    }
                    else pkt_clst_add(&(mExtractor->aa_q), &nf);
                    mExtractor->aLock.unlock();
				}
                //if( nf.track_no == ckkp->nrm.audio_track_no ) pkt_clst_add(&(mExtractor->aa_q), &nf);
                if( nf.track_no == mExtractor->vv_no ) pkt_clst_add(&(mExtractor->vv_q), &nf);
            }
        }
    }

    int ret_v = 1;

    if (mTrackno == mExtractor->aa_no) {
		mExtractor->aLock.lock();
		ret_v = pkt_clst_get(&(mExtractor->aa_q), &nf);
		mExtractor->aLock.unlock();
    }
    if (mTrackno == mExtractor->vv_no ) ret_v = pkt_clst_get(&(mExtractor->vv_q), &nf);

    if (ret_v) {
uuprintf("nf read error %d:%d:%d:%d:%d:%d:", mTrackno, mExtractor->aa_no, mExtractor->vv_no, mExtractor->interrupt, pkt_clst_probe(&(mExtractor->aa_q)), pkt_clst_probe(&(mExtractor->vv_q)));
		if( mExtractor->interrupt ) return ERROR_END_OF_STREAM;
		return ERROR_IO;
    }

    status_t err = mBufferGroup->acquire_buffer(&mBuffer);
    if (err != OK) {
        return err;
    }

//uuprintf("nf track_no %d\n", nf.track_no);
//uuprintf("nf data_size %d\n", nf.data_size);
//uuprintf("nf data_time %f\n", (float)(nf.t_us_pos)/1000000);

	if (nf.data_size <= 0) {
		mBuffer->release();
		mBuffer = NULL;
		//usleep(500*1000);
		return ERROR_END_OF_STREAM;
	}

    if (mTrackno == mExtractor->aa_no) {
        if( mDataSource->ff_ex3 == CODEC_ID_AAC )
        {
            if( (((uint8_t *)(nf.data_ptr))[0] == 0xff) && (((uint8_t *)(nf.data_ptr))[1] & 0xf0) ){
				memcpy(mBuffer->data(), (void *)&(((uint8_t *)(nf.data_ptr))[7]), nf.data_size-7);
				mBuffer->set_range(0, nf.data_size-7);
            }
            else
            {
				memcpy(mBuffer->data(), (void *)nf.data_ptr, nf.data_size);
				mBuffer->set_range(0, nf.data_size);
				//__hexdump__("aac", (const void *)mBuffer->data(), (size_t)nf.data_size);
            }
        }
        //if( mDataSource->ff_ex3 == CODEC_ID_MP3 )
        else
        {
			memcpy(mBuffer->data(), (void *)nf.data_ptr, nf.data_size);
			mBuffer->set_range(0, nf.data_size);
        }
    }

    if (mTrackno == mExtractor->vv_no) {
//uuprintf("_____________^^^^^^^^^^^^^^&&&&&&&&&&____________ %d, mDataSource->ff_ex2 = %x, %x, %x", ckkp->nrm.video_track_enable, mDataSource->ff_ex2, CODEC_ID_MPEG4, CODEC_ID_H264);

		if( (ckkp->nrm.video_track_enable == 0) )
		{
		    if( mDataSource->ff_ex2 == CODEC_ID_H264 )
		    {
                uint8_t *dstData = (uint8_t *)mBuffer->data();
                uint8_t *mSrcBuffer = (uint8_t *)nf.data_ptr;
                size_t srcOffset = 0;
                size_t dstOffset = 0;
                size_t mNALLengthSize = ckkp->nrm.h264_nall_length;

//__hexdump__("new", mSrcBuffer, 160);
                if( memcmp("\x00\x00\x00\x01\x09", mSrcBuffer, 5) == 0 )
                {
				    memcpy(dstData, &mSrcBuffer[6], nf.data_size-6);
				    mBuffer->set_range(0, nf.data_size-6);
                }
                else if( memcmp("\x00\x00\x00\x01", mSrcBuffer, 4) == 0 )
                {
			        memcpy(mBuffer->data(), (void *)nf.data_ptr, nf.data_size);
			        mBuffer->set_range(0, nf.data_size);
                }
                else
                {
                    //if( memcmp("\x00\x00\x00\x02\x09", mSrcBuffer, 5) == 0 ) srcOffset = 6;
                    while ((int32_t)srcOffset < nf.data_size) {
                        bool isMalFormed = ((int32_t)(srcOffset + mNALLengthSize) > nf.data_size);
                        size_t nalLength = 0;
                        if (!isMalFormed) {
                            nalLength = h264_parseNALSize(&mSrcBuffer[srcOffset], mNALLengthSize);
                            srcOffset += mNALLengthSize;
                            isMalFormed = ((int32_t)(srcOffset + nalLength) > nf.data_size);
                        }

                        if (isMalFormed) {
                            ALOGE("Video is malformed");
                            mBuffer->release();
                            mBuffer = NULL;
                            return ERROR_MALFORMED;
                        }

                        if (nalLength == 0) {
                            continue;
                        }

                        CHECK(dstOffset + 4 <= mBuffer->size());

                        dstData[dstOffset++] = 0;
                        dstData[dstOffset++] = 0;
                        dstData[dstOffset++] = 0;
                        dstData[dstOffset++] = 1;
                        memcpy(&dstData[dstOffset], &mSrcBuffer[srcOffset], nalLength);
                        srcOffset += nalLength;
                        dstOffset += nalLength;
                    }

                    CHECK_EQ(srcOffset, nf.data_size);
                    CHECK(mBuffer != NULL);
                    mBuffer->set_range(0, dstOffset);
				    //__hexdump__("h264", dstData, 160);
                }
            }

            if( mDataSource->ff_ex2 == CODEC_ID_MPEG4 )
            {
			    memcpy(mBuffer->data(), (void *)nf.data_ptr, nf.data_size);
			    mBuffer->set_range(0, nf.data_size);
			}

            if( mDataSource->ff_ex2 == CODEC_ID_MPEG2VIDEO )
            {
			    memcpy(mBuffer->data(), (void *)nf.data_ptr, nf.data_size);
			    mBuffer->set_range(0, nf.data_size);
			}

		}
		else
		{
			memcpy(mBuffer->data(), (void *)nf.data_ptr, nf.data_size);
			mBuffer->set_range(0, nf.data_size);
		}
    }

	mBuffer->meta_data()->clear();
    if( nf.t_us_pos < 0 ) mBuffer->meta_data()->setInt64(kKeyTime, 0);
    else mBuffer->meta_data()->setInt64(kKeyTime, nf.t_us_pos);

    if( nf.i_frame_and_flag ) {
		mBuffer->meta_data()->setInt32(kKeyIsSyncFrame, 1);
    }

    *out = mBuffer;
    ckkp->dx_fns.fnp_dx_frame_release(ckkp->dx_dptr, &nf);
    mBuffer = NULL;

    return OK;
}

/////////////////////////////////////////////////////////////////////

FFExtractor::FFExtractor(const sp<DataSource> &source)
    :
//      thread_mode(1),
      vv_no(-1),
      aa_no(-1),
      track_sz(0),
      mMainMetaData(new MetaData) {
    CUUKUUK *ckkp;
    NR_TRACK *ntp;
    AVCodecContext *pCodecCtx;
    AVCodec *pCodec;
    AVFormatContext *pFormatCtx = NULL;
    int32_t i, j;
    const char *mime = NULL;

    thread_mode=0;
    interrupt=0;
    mFirstTrack=NULL;
    mLastTrack=NULL;
	mDataSource=source;
    mInitCheck=NO_INIT;
    ckkp = (CUUKUUK *)(mDataSource->ff_ptr);
uuprintf("________FFExtractor::init________ %p %d", ckkp, ckkp->nrm.track_sz );

    track_check(ckkp->nrm.fourcc_ex1);
    mInitCheck = OK;

    for( i=0 ; i<(int32_t)(ckkp->nrm.track_sz) ; i++ )
    {
        ntp = (NR_TRACK *)((uint8_t*)(ckkp->nrm.track_ptr)+sizeof(NR_TRACK)*i);

        if( i == ckkp->nrm.video_track_no && ckkp->nrm.fourcc_ex2 )
        {
	        pCodecCtx = (AVCodecContext *)(ntp->ffmpeg_codeccontext_ptr);
	        Track *track = new Track;
	        track->next = NULL;
	        if (mLastTrack) mLastTrack->next = track;
            else mFirstTrack = track;
            mLastTrack = track;

	        track->ff_track = i;
            track->mMeta = new MetaData;

            if( ckkp->nrm.video_track_enable )
            {
                mime = GetMIMETypeForHandler(ntp->ffmpeg_codec_id);
uuprintf("___---___ video track enable : use custom mime : %s", mime);
	            if( mime == NULL ) {
	                mInitCheck = ERROR_UNSUPPORTED;
	                break;
	            }
	        }
	        else
	        {
			    mime = GetMIMETypeForHandler_o(ntp->ffmpeg_codec_id);
uuprintf("___---___ video track disable : use original mime : %s", mime);
	            if( mime == NULL ) {
	                mInitCheck = ERROR_UNSUPPORTED;
	                break;
	            }
	        }
			track->mMeta->setCString(kKeyMIMEType, mime);
			track->mMeta->setInt32(kKeyWidth, pCodecCtx->width);
			track->mMeta->setInt32(kKeyHeight, pCodecCtx->height);
			track->mMeta->setInt32(kKeyMaxInputSize, 65536 * 4);
			track->mMeta->setInt64(kKeyDuration, ntp->t_calc_duration);
			track->mMeta->setInt32('fv01', ntp->ffmpeg_codec_id);
			track->mMeta->setInt32('fv02', ntp->v_s_res_x);
			track->mMeta->setInt32('fv03', ntp->v_s_res_x);
			track->mMeta->setInt32('fv04', ntp->ffmpeg_codec_tag);
			track->mMeta->setInt32('fv05', ntp->ffmpeg_stream_codec_tag);
			track->mMeta->setInt32('fv06', ntp->ffmpeg_extra_size);
			track->mMeta->setInt32('fv07', ntp->ffmpeg_extra_data_ptr);

		    if( ckkp->nrm.fourcc_ex2 == CODEC_ID_MPEG4 ) {
				sp<ABuffer> csd = ffmpeg_extradata_xvid(pCodecCtx->extradata, pCodecCtx->extradata_size);
				track->mMeta->setData(kKeyESDS, kTypeESDS, csd->data(), csd->size());
			}
			if( ckkp->nrm.fourcc_ex2 == CODEC_ID_H264 ) {
				sp<ABuffer> csd = ffmpeg_extradata_h264(pCodecCtx->extradata, pCodecCtx->extradata_size, ckkp->nrm.fourcc_ex1);
				track->mMeta->setData(kKeyAVCC, kTypeAVCC, csd->data(), csd->size());
			}

			track_sz++;
			vv_no = i;
uuprintf("___----___---- extractor mine %d %s", i, mime);
        }

        if( i == ckkp->nrm.audio_track_no && ckkp->nrm.fourcc_ex3 )
        {
			pCodecCtx = (AVCodecContext *)(ntp->ffmpeg_codeccontext_ptr);
			Track *track = new Track;
			track->next = NULL;
			if (mLastTrack)
				mLastTrack->next = track;
			else
				mFirstTrack = track;
			mLastTrack = track;

			track->ff_track = i;
			track->mMeta = new MetaData;

            if( ckkp->nrm.audio_track_enable )
            {
                mime = GetMIMETypeForHandler(ntp->ffmpeg_codec_id);
uuprintf("___---___ audio track enable : use custom mime : %s", mime);
	            if( mime == NULL ) {
	                mInitCheck = ERROR_UNSUPPORTED;
	                break;
	            }
	        }
	        else
	        {
			    mime = GetMIMETypeForHandler_o(ntp->ffmpeg_codec_id);
uuprintf("___---___ audio track disable : use original mime : %s", mime);
	            if( mime == NULL ) {
	                mInitCheck = ERROR_UNSUPPORTED;
	                break;
	            }
	        }
			track->mMeta->setCString(kKeyMIMEType, mime);
			track->mMeta->setInt32(kKeyChannelCount, ntp->a_chs);
			track->mMeta->setInt32(kKeySampleRate, ntp->a_s_rate);
			track->mMeta->setInt32(kKeyMaxInputSize, 65536);
			track->mMeta->setInt32(kKeyBitRate, pCodecCtx->bit_rate);
			track->mMeta->setInt64(kKeyDuration, ntp->t_calc_duration);
			track->mMeta->setInt32('fa01', ntp->ffmpeg_codec_id);
			track->mMeta->setInt32('fa02', ntp->a_chs);
			track->mMeta->setInt32('fa03', ntp->a_req_chs);
			track->mMeta->setInt32('fa04', ntp->a_bit_fmt);
			track->mMeta->setInt32('fa05', ntp->a_bits);
			track->mMeta->setInt32('fa06', ntp->a_s_rate);
			track->mMeta->setInt32('fa07', ntp->a_frame_size);
			track->mMeta->setInt32('fa08', ntp->ffmpeg_codec_tag);
			track->mMeta->setInt32('fa09', ntp->ffmpeg_stream_codec_tag);
			track->mMeta->setInt32('fa10', ntp->ffmpeg_extra_size);
			track->mMeta->setInt32('fa11', ntp->ffmpeg_extra_data_ptr);

		    if( ckkp->nrm.fourcc_ex3 == CODEC_ID_AAC )
		    {
				uint8_t ex_buf[5];
				int ret_sz;
				sp<ABuffer> csd;
				if( pCodecCtx->extradata_size == 0 )
				{
					ffmpeg_extradata_aac(ex_buf, &ret_sz, ntp);
					csd = ffmpeg_esds_aac_low(ex_buf, ret_sz, pCodecCtx->bit_rate);
				}
				else
				{
					csd = ffmpeg_esds_aac_low(pCodecCtx->extradata, pCodecCtx->extradata_size, pCodecCtx->bit_rate);
				}
				track->mMeta->setData(kKeyESDS, kTypeESDS, csd->data(), csd->size());

			}

			track_sz++;
			aa_no = i;
uuprintf("___----___---- extractor mine %d %s", i, mime);
        }
    }

    if( mInitCheck == OK )
    {
        if( pkt_clst_init(&(aa_q), aa_sz) ) mInitCheck = NO_INIT;
        if( pkt_clst_init(&(vv_q), vv_sz) ) mInitCheck = NO_INIT;

        if( thread_mode )
        {
            pthread_attr_t attr;
            pthread_attr_init(&attr);
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

            pthread_create(&mThread, &attr, ThreadWrapper, this);
            pthread_attr_destroy(&attr);
        }
    }

uuprintf("___----___---- extractor this %p", this);
}

FFExtractor::~FFExtractor() {
    pkt_clst_clear(&(aa_q));
    pkt_clst_clear(&(vv_q));

    if( thread_mode )
    {
        void *dummy;
        pthread_join(mThread, &dummy);
        thread_mode = 0;
    }

    Track *track = mFirstTrack;
    while (track) {
        Track *next = track->next;

        delete track;
        track = next;
    }
    mFirstTrack = mLastTrack = NULL;
uuprintf("___----___---- extractor delete %p", this);
}

size_t FFExtractor::countTracks() {
    return track_sz;
}

sp<MediaSource> FFExtractor::getTrack(size_t index) {
    Track *track = mFirstTrack;
    while (index > 0) {
        if (track == NULL) {
            return NULL;
        }

        track = track->next;
        --index;
    }

    if (track == NULL) {
        return NULL;
    }

    return new FFSource(this, mDataSource, track->mMeta, track->ff_track);
}

sp<MetaData> FFExtractor::getTrackMetaData(
        size_t index, uint32_t flags) {
    Track *track = mFirstTrack;
    while (index > 0) {
        if (track == NULL) {
            return NULL;
        }

        track = track->next;
        --index;
    }

    if (track == NULL) {
        return NULL;
    }

    return track->mMeta;
}

void *FFExtractor::ThreadWrapper(void *me) {
    return (void *) static_cast<FFExtractor *>(me)->threadFunc();
}

status_t FFExtractor::threadFunc() {
    status_t err=OK;
    CUUKUUK *ckkp;
    NR_FRAME nf, nf1;
    int aa_rq, vv_rq, n, loop;
/*
uuprintf("________FFExtractor::threadFunc________");

    prctl(PR_SET_NAME, (unsigned long)"FFExtractorThread", 0, 0, 0);
    ckkp = (CUUKUUK *)(mDataSource->ff_ptr);
    interrupt = 0;

    loop = 1;
    while( 1 )
    {
		//pLock.lock();
        while( loop )
        {
			if( vv_no >= 0 && aa_no >= 0 ) {
				aa_rq = pkt_clst_probe(&(aa_q));
				vv_rq = pkt_clst_probe(&(vv_q));
//uuprintf("aa_rq %d, vv_rq %d", aa_rq, vv_rq);
				if( (vv_rq < 3 ) ) break;
				n = mDataSource->readAt(0, (void *)&nf1, 262144);
//uuprintf("ffread %d, no %d\n", n, nf1.track_no);
				if( nf1.track_no == ckkp->nrm.audio_track_no && n>=0 )
					pkt_clst_add(&(aa_q), &nf1);
				if( nf1.track_no == ckkp->nrm.video_track_no && n>=0 )
					pkt_clst_add(&(vv_q), &nf1);
				if( n<0 ) {
					nf1.track_no = 0;
					nf1.data_size = 0;;
					nf1.t_us_pos = 0;
					pkt_clst_add(&(vv_q), &nf1);
					loop = 0;
				}
				continue;
			}

            aa_rq = pkt_clst_probe(&(aa_q));
            vv_rq = pkt_clst_probe(&(vv_q));
//uuprintf("aa_rq %d, vv_rq %d", aa_rq, vv_rq);
            if( (aa_rq < 3 ) || (vv_rq < 3 ) ) break;
            n = mDataSource->readAt(0, (void *)&nf1, 262144);
//uuprintf("ffread %d, no %d\n", n, nf1.track_no);
            if( nf1.track_no == ckkp->nrm.audio_track_no && n>=0 ) pkt_clst_add(&(aa_q), &nf1);
            if( nf1.track_no == ckkp->nrm.video_track_no && n>=0 ) pkt_clst_add(&(vv_q), &nf1);
            if( n<0 )
            {
                nf1.track_no = 0;
                nf1.data_size = 0;;
                nf1.t_us_pos = 0;
				pkt_clst_add(&(vv_q), &nf1);
				loop = 0;
            }
        }
		//pLock.unlock();
		if( interrupt ) break;
		//usleep(1000);
    }
*/
    return err;
}


status_t FFExtractor::init() {

    return OK;
}

/////////////////////////////////////////////////////////////////////
void FFExtractor::track_check(int container) {
    switch( container )
    {
    case __ITY_WAV__:
    case __ITY_MP3__:
		vv_sz = 1; aa_sz = 1;
		break;
    case __ITY_AVI__:
		vv_sz = 20; aa_sz = 200;
		break;
    case __ITY_MOV__:
    case __ITY_MPEGPS__:
    case __ITY_MPEGTS__:
		vv_sz = 40; aa_sz = 200;
		break;
    default:
		vv_sz = 1; aa_sz = 1;
		break;
    }
}

const char * FFExtractor::GetMIMETypeForHandler(uint32_t handler) {
    switch (handler) {
        ///frameworks/base/media/libstagefright/MediaDefs.cpp
uuprintf("FFExtractor::GetMIMETypeForHandler %d\n", handler);
	case CODEC_ID_H264:
	case CODEC_ID_MPEG4:
            return "video/libpeony";
	case CODEC_ID_MP1:
	case CODEC_ID_MP2:
	case CODEC_ID_MP3:
	case CODEC_ID_AAC:
	case CODEC_ID_AC3:
            return "audio/libpeony";
	default:
            return NULL;
    }
}

const char * FFExtractor::GetMIMETypeForHandler_o(uint32_t handler) {
    switch (handler) {
        ///frameworks/base/media/libstagefright/MediaDefs.cpp
uuprintf("FFExtractor::GetMIMETypeForHandler %d\n", handler);

	case CODEC_ID_H264:
            return MEDIA_MIMETYPE_VIDEO_AVC;
	case CODEC_ID_MPEG4:
            return MEDIA_MIMETYPE_VIDEO_MPEG4;
	case CODEC_ID_MP1:
	    return MEDIA_MIMETYPE_AUDIO_MPEG_LAYER_I;
	case CODEC_ID_MP2:
	    return MEDIA_MIMETYPE_AUDIO_MPEG_LAYER_II;
	case CODEC_ID_MP3:
	    return MEDIA_MIMETYPE_AUDIO_MPEG;
	case CODEC_ID_AAC:
	    return MEDIA_MIMETYPE_AUDIO_AAC;
	default:
            return NULL;
    }
}

sp<MetaData> FFExtractor::getMetaData() {
    if (mInitCheck == OK) {
        //if( mDataSource->ff_ex1 == __ITY_WAV__ ) mMainMetaData->setCString(kKeyMIMEType, MEDIA_MIMETYPE_AUDIO_RAW);
        if( mDataSource->ff_ex1 == __ITY_MP3__ ) mMainMetaData->setCString(kKeyMIMEType, MEDIA_MIMETYPE_AUDIO_MPEG);
        if( mDataSource->ff_ex1 == __ITY_AVI__ ) mMainMetaData->setCString(kKeyMIMEType, MEDIA_MIMETYPE_CONTAINER_AVI);
        if( mDataSource->ff_ex1 == __ITY_MOV__ ) mMainMetaData->setCString(kKeyMIMEType, MEDIA_MIMETYPE_CONTAINER_MPEG4);
        if( mDataSource->ff_ex1 == __ITY_MPEGPS__ ) mMainMetaData->setCString(kKeyMIMEType, MEDIA_MIMETYPE_CONTAINER_MPEG2PS);
        if( mDataSource->ff_ex1 == __ITY_MPEGTS__ ) mMainMetaData->setCString(kKeyMIMEType, MEDIA_MIMETYPE_CONTAINER_MPEG2TS);
    }

    return mMainMetaData;
}
///////////////////////////////////////////////////////////////////////////////

bool SniffFFmpeg(
        const sp<DataSource> &source, String8 *mimeType, float *confidence,
        sp<AMessage> *) {
    char header[12];
uuprintf("_____--SniffFFmpeg-");

    if( source->ff_ptr )
    {
        CUUKUUK *ckkp;
        ckkp = (CUUKUUK *)(source->ff_ptr);
uuprintf("_____--SniffFFmpeg- %d", ckkp->nrm.fourcc_ex1);

        if( ckkp->nrm.fourcc_ex1 == __ITY_WAV__ ) {
			mimeType->setTo(MEDIA_MIMETYPE_CONTAINER_WAV);
			*confidence = 0.3f;
        }
/*
		if( ckkp->nrm.fourcc_ex1 == __ITY_OGG__ ) {
			mimeType->setTo(MEDIA_MIMETYPE_CONTAINER_OGG);
			*confidence = 0.2f;
		}
*/
        if( ckkp->nrm.fourcc_ex1 == __ITY_MP3__ ) {
			mimeType->setTo(MEDIA_MIMETYPE_AUDIO_MPEG);
			*confidence = 0.2f;
        }
        if( ckkp->nrm.fourcc_ex1 == __ITY_AVI__ ) {
			mimeType->setTo(MEDIA_MIMETYPE_CONTAINER_AVI);
			*confidence = 0.21f;
        }
        if( ckkp->nrm.fourcc_ex1 == __ITY_MOV__ ) {
			mimeType->setTo(MEDIA_MIMETYPE_CONTAINER_MPEG4);
			*confidence = 0.4f;
        }
        if( ckkp->nrm.fourcc_ex1 == __ITY_MPEGPS__ ) {
			mimeType->setTo(MEDIA_MIMETYPE_CONTAINER_MPEG2PS);
			*confidence = 0.25f;
        }
        if( ckkp->nrm.fourcc_ex1 == __ITY_MPEGTS__ ) {
			mimeType->setTo(MEDIA_MIMETYPE_CONTAINER_MPEG2TS);
			*confidence = 0.1f;
        }

        return true;
    }

	return false;
}

MediaExtractor *create_MediaExtractor(const sp<DataSource> &source)
{
    return new android::FFExtractor(source);
}

}  // namespace android
