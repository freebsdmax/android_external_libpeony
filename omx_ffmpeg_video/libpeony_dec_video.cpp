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
#define LOG_TAG "__libpeony_dec_video__"
#include <utils/Log.h>
	#define uuprintf(fmt, args...) ALOGE("%s(%d): " fmt, __FUNCTION__, __LINE__, ##args)

#include "libpeony_dec_video.h"

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MediaErrors.h>
#include <media/IOMX.h>
#include <dlfcn.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdint.h>


typedef struct
{
	void (*__xx_av_init_packet)(AVPacket *);
	int (*__xx_avcodec_decode_video2)(AVCodecContext *, AVFrame *, int *, AVPacket *);
#ifdef __DP_FFMPEG_NEW__
	AVCodecContext *(*__xx_avcodec_alloc_context3)(AVCodec *);
#endif
#ifdef __DP_FFMPEG_OLD__
	AVCodecContext *(*__xx_avcodec_alloc_context)(void);
#endif
	AVCodec *(*__xx_avcodec_find_decoder)(enum CodecID);
	int (*__xx_avcodec_open)(AVCodecContext *, AVCodec *);
	int (*__xx_avcodec_close)(AVCodecContext *avctx);
	AVFrame *(*__xx_avcodec_alloc_frame)(void);
    void (*__xx_av_register_all)(void);
    void (*__xx_av_free)(void *ptr);
    void (*__xx_av_freep)(void *ptr);
    void (*__xx_avcodec_flush_buffers)(AVCodecContext *);

	AVCodecContext *avctx;
	AVCodec	*pCodec;
	AVFrame	*pFrame;
	uint8_t *pYUV;

	void* extra_buf;
	int extra_sz;
} __BB_VC_LIBAVCODEC__;



namespace android {

void __libaccodec_video_uninit__(__BB_VC_LIBAVCODEC__ *bbp)
{
    free((void*)(bbp->pYUV));
    if( bbp->avctx ) free(bbp->avctx->extradata);
    (*(bbp->__xx_av_freep))(&(bbp->avctx));
}

int __libaccodec_video_init__(__BB_VC_LIBAVCODEC__ *bbp, void *ffoa)
{
    OMX_VIDEO_PARAM_PEONY *ntp = (OMX_VIDEO_PARAM_PEONY *)ffoa;
    AVCodecContext *pCodecCtx;
    AVCodec *pCodec;

    pCodec = (*(bbp->__xx_avcodec_find_decoder))((enum CodecID)(ntp->ffmpeg_codec_id));
    if(!pCodec)
    {
            __libaccodec_video_uninit__(bbp);
            return 1;
    }

    pCodecCtx = (*(bbp->__xx_avcodec_alloc_context3))(pCodec);
    pCodecCtx->codec_id = pCodec->id;
    pCodecCtx->flags|= 0;
    pCodecCtx->coded_width = ntp->v_s_res_x;
    pCodecCtx->coded_height= ntp->v_s_res_y;
    pCodecCtx->workaround_bugs= FF_BUG_AUTODETECT;
    pCodecCtx->err_recognition |= AV_EF_COMPLIANT;
    pCodecCtx->flags2 |= CODEC_FLAG2_SHOW_ALL;
    pCodecCtx->codec_tag= ntp->ffmpeg_codec_tag;
    pCodecCtx->stream_codec_tag= ntp->ffmpeg_stream_codec_tag;
    pCodecCtx->idct_algo= 0;
    pCodecCtx->error_concealment= 3;
    pCodecCtx->debug= 0;
    pCodecCtx->debug_mv= 0;
    pCodecCtx->skip_top   = 0;
    pCodecCtx->skip_bottom= 0;
    pCodecCtx->skip_loop_filter = AVDISCARD_DEFAULT;
    pCodecCtx->skip_idct        = AVDISCARD_DEFAULT;
    pCodecCtx->skip_frame       = AVDISCARD_DEFAULT;

    pCodecCtx->extradata_size = ntp->ffmpeg_extra_size;
    pCodecCtx->extradata = (uint8_t *)malloc(pCodecCtx->extradata_size + FF_INPUT_BUFFER_PADDING_SIZE);
    memset(pCodecCtx->extradata, 0, pCodecCtx->extradata_size + FF_INPUT_BUFFER_PADDING_SIZE);
    memcpy(pCodecCtx->extradata, (const void *)(ntp->ffmpeg_extra_data_ptr), pCodecCtx->extradata_size);

    pCodecCtx->thread_count = 1;
    pCodecCtx->thread_type = FF_THREAD_FRAME | FF_THREAD_SLICE;

    if( (*(bbp->__xx_avcodec_open))(pCodecCtx, pCodec) < 0 )
    {
            __libaccodec_video_uninit__(bbp);
            return 1;
    }

    bbp->avctx = pCodecCtx;
    bbp->pCodec = pCodec;
    bbp->pYUV = (uint8_t *)malloc(ntp->v_s_res_x * ntp->v_s_res_y * 3 / 2);

    return 0;
}

int __bb_vc_init_libavcodec(VIDEO_FUNCS *fnp, int *ret_malloc_sz)
{
    fnp->fnp_vv_load = __bb_vc_load_libavcodec;
    fnp->fnp_vv_unload = __bb_vc_unload_libavcodec;
    fnp->fnp_vv_flush = __bb_vc_flush_libavcodec;
    fnp->fnp_vv_decode = __bb_vc_decode_libavcodec;

    *ret_malloc_sz = sizeof(__BB_VC_LIBAVCODEC__);

    return 0;
}

#define __so_get_fn__(a,b)              dlsym((a),(b))

int __bb_vc_load_libavcodec(void *r_data, void *ffoa)
{
    __BB_VC_LIBAVCODEC__ *bbp = (__BB_VC_LIBAVCODEC__ *)r_data;
    OMX_VIDEO_PARAM_PEONY *ntp = (OMX_VIDEO_PARAM_PEONY *)ffoa;
    void *dllsop;

uuprintf("^^^^^_____^^^^^_____^^^^^^ __bb_vc_load_libavcodec");
uuprintf("^^^^^_____^^^^^_____^^^^^^ __bb_vc_load_libavcodec");
	dllsop = dlopen("libffmpeg.so", RTLD_NOW);

    if( dllsop == 0 ) return 1;
uuprintf("====vc====dllsop = %p\n", dllsop);

    bbp->__xx_av_init_packet = 0;
    bbp->__xx_av_init_packet = (void (*)(AVPacket *))dlsym(dllsop, "av_init_packet");
    if( bbp->__xx_av_init_packet == 0 ) return 1;
uuprintf("====vc====__xx_av_init_packet = %p\n", bbp->__xx_av_init_packet);
    bbp->__xx_avcodec_decode_video2 = 0;
    bbp->__xx_avcodec_decode_video2 = (int (*)(AVCodecContext *, AVFrame *, int *, AVPacket *))dlsym(dllsop, "avcodec_decode_video2");
    if( bbp->__xx_avcodec_decode_video2 == 0 ) return 1;
uuprintf("====vc====__xx_avcodec_decode_video2 = %p\n", bbp->__xx_avcodec_decode_video2);
#ifdef __DP_FFMPEG_NEW__
    bbp->__xx_avcodec_alloc_context3 = 0;
    bbp->__xx_avcodec_alloc_context3 = (AVCodecContext *(*)(AVCodec *))dlsym(dllsop, "avcodec_alloc_context3");
    if( bbp->__xx_avcodec_alloc_context3 == 0 ) return 1;
uuprintf("====vc====__xx_avcodec_alloc_context3 = %p\n", bbp->__xx_avcodec_alloc_context3);
#endif
#ifdef __DP_FFMPEG_OLD__
    bbp->__xx_avcodec_alloc_context = 0;
    bbp->__xx_avcodec_alloc_context = (AVCodecContext *(*)(void))dlsym(dllsop, "avcodec_alloc_context");
    if( bbp->__xx_avcodec_alloc_context == 0 ) return 1;
uuprintf("====vc====__xx_avcodec_alloc_context = %p\n", bbp->__xx_avcodec_alloc_context);
#endif
    bbp->__xx_avcodec_find_decoder = 0;
    bbp->__xx_avcodec_find_decoder = (AVCodec *(*)(enum CodecID))dlsym(dllsop, "avcodec_find_decoder");
    if( bbp->__xx_avcodec_find_decoder == 0 ) return 1;
uuprintf("====vc====__xx_avcodec_find_decoder = %p\n", bbp->__xx_avcodec_find_decoder);
    bbp->__xx_avcodec_open = 0;
    bbp->__xx_avcodec_open = (int (*)(AVCodecContext *, AVCodec *))dlsym(dllsop, "avcodec_open");
    if( bbp->__xx_avcodec_open == 0 ) return 1;
uuprintf("====vc====__xx_avcodec_open = %p\n", bbp->__xx_avcodec_open);
    bbp->__xx_avcodec_close = 0;
    bbp->__xx_avcodec_close = (int (*)(AVCodecContext *avctx))dlsym(dllsop, "avcodec_close");
    if( bbp->__xx_avcodec_close == 0 ) return 1;
uuprintf("====vc====__xx_avcodec_close = %p\n", bbp->__xx_avcodec_close);
    bbp->__xx_avcodec_alloc_frame = 0;
    bbp->__xx_avcodec_alloc_frame = (AVFrame *(*)(void))dlsym(dllsop, "avcodec_alloc_frame");
    if( bbp->__xx_avcodec_alloc_frame == 0 ) return 1;
uuprintf("====vc====__xx_avcodec_alloc_frame = %p\n", bbp->__xx_avcodec_alloc_frame);
    bbp->__xx_av_register_all = 0;
    bbp->__xx_av_register_all = (void (*)(void))dlsym(dllsop, "av_register_all");
    if( bbp->__xx_av_register_all == 0 ) return 1;
uuprintf("====vc====__xx_av_register_all = %p\n", bbp->__xx_av_register_all);
    bbp->__xx_av_free = 0;
    bbp->__xx_av_free = (void (*)(void *ptr))dlsym(dllsop, "av_free");
    if( bbp->__xx_av_free == 0 ) return 1;
uuprintf("====vc====__xx_av_free = %p\n", bbp->__xx_av_free);
    bbp->__xx_av_freep = 0;
    bbp->__xx_av_freep = (void (*)(void *ptr))dlsym(dllsop, "av_freep");
    if( bbp->__xx_av_freep == 0 ) return 1;
uuprintf("====vc====__xx_av_freep = %p\n", bbp->__xx_av_freep);
    bbp->__xx_avcodec_flush_buffers = 0;
    bbp->__xx_avcodec_flush_buffers = (void (*)(AVCodecContext *))dlsym(dllsop, "avcodec_flush_buffers");
    if( bbp->__xx_avcodec_flush_buffers == 0 ) return 1;
uuprintf("====vc====__xx_avcodec_flush_buffers = %p\n", bbp->__xx_avcodec_flush_buffers);

//================================================================================
    (*(bbp->__xx_av_register_all))();
	__libaccodec_video_init__(bbp, ntp);
//================================================================
	bbp->pFrame =  (*(bbp->__xx_avcodec_alloc_frame))();
	if( bbp->pFrame == 0 ) return 1;
//================================================================
    return 0;
}

int __bb_vc_unload_libavcodec(void *r_data)
{
    __BB_VC_LIBAVCODEC__ *bbp = (__BB_VC_LIBAVCODEC__ *)r_data;

    (*(bbp->__xx_av_free))(bbp->pFrame);
    (*(bbp->__xx_avcodec_close))(bbp->avctx);
    __libaccodec_video_uninit__(bbp);

    return 0;
}

int __bb_vc_flush_libavcodec(void *r_data)
{
    __BB_VC_LIBAVCODEC__ *bbp = (__BB_VC_LIBAVCODEC__ *)r_data;

uuprintf("^^^^^_____^^^^^_____^^^^^^ __bb_vc_flush_libavcodec");

	//(*(bbp->__xx_avcodec_flush_buffers))((AVCodecContext *)(ntp->ffmpeg_codeccontext_ptr));

    return 0;
}

int __bb_vc_decode_libavcodec(void *r_data, uint8_t *in_p, uint32_t in_size, int *frameFinished, AVFrame **ppFrame)
{
    __BB_VC_LIBAVCODEC__ *bbp = (__BB_VC_LIBAVCODEC__ *)r_data;
	struct AVPacket	avp;
	int bytesDecoded;
    //AVPicture *pict;

//uuprintf("^^^^^_____^^^^^_____^^^^^^ __bb_vc_decode_libavcodec-----0000");
	(*(bbp->__xx_av_init_packet))(&avp);
	avp.data = in_p;
	avp.size = in_size;

//uuprintf("^^^^^_____^^^^^_____^^^^^^ __bb_vc_decode_libavcodec-----1111");
	bytesDecoded = (*(bbp->__xx_avcodec_decode_video2))(bbp->avctx, bbp->pFrame, frameFinished, &avp);
//uuprintf("^^^^^_____^^^^^_____^^^^^^ __bb_vc_decode_libavcodec-----2222 bytesDecoded=%d, frameFinished=%d", bytesDecoded, *frameFinished);

    *ppFrame = bbp->pFrame;

    return bytesDecoded;
}

int64_t tv_vari(struct timeval *tvp, struct timeval *tvp1)
{
	int64_t a_tv;
	int64_t a_tv1;

	a_tv = tvp->tv_sec;
	a_tv *= 1000000;
	a_tv += tvp->tv_usec;

	a_tv1 = tvp1->tv_sec;
	a_tv1 *= 1000000;
	a_tv1 += tvp1->tv_usec;


	return a_tv - a_tv1;
}

static void __filedump(char *name, int tag, const void *_data, uint64_t size)
{
    FILE *out;
    char buf[512];

    sprintf(buf, "/data/dump/%s_%08d", name, tag);

    out = fopen(buf, "wb");

    if( out == NULL )
    {
            uuprintf("file dump error %s\n", buf);
    }

    fwrite(_data, size, 1, out);
    fclose(out);
    uuprintf("file dump ~~~~~~~~ %s\n", buf);

    return;
}

static void __hexdump__(char *name, const void *_data, size_t size)
{
    const uint8_t *data = (const uint8_t *)_data;

    uint32_t i, j, k, pos;
    uint8_t str[100];

    //if( size > 64 ) size = 64;
    uuprintf("____DUMP____DUMP____NAME : %s\n", name);
    memset(str, 0, 100);
    uuprintf("Dec sz =  %4d| 000 001 002 003 004 005 006 007 008 009 00a 00b 00c 00d 00e 00f\n", size);
    for( i=0, j=0, k=0, pos=0 ; i<size ; i++, j++ )
    {
		if( j == 16 ) { j = 0; k++; pos=0; }
        if( j == 0 ) { sprintf((char*)&(str[pos]), "[%04d]", i); pos+=6; }
        sprintf((char*)&(str[pos]), " %3d", data[i]); pos+=4;
        if( j == 15 ) uuprintf("Dec Dump %s\n", str);
    }
	if( j < 16 ) uuprintf("Dec Dump %s\n", str);

    memset(str, 0, 100);
    uuprintf("Hex sz =  %4x| 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f\n", size);
    for( i=0, j=0, k=0, pos=0 ; i<size ; i++, j++ )
    {
        if( j == 16 ) { j = 0; k++; pos=0; }
        if( j == 0 ) { sprintf((char*)&(str[pos]), "[%04x]", i); pos+=6; }
        sprintf((char*)&(str[pos]), " %02x", data[i]); pos+=3;
        if( j == 15 ) uuprintf("Hex Dump %s\n", str);
    }
	if( j < 16 ) uuprintf("Hex Dump %s\n", str);
}

static const CodecProfileLevel kProfileLevels[] = {
    { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel1  },
    { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel1b },
    { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel11 },
    { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel12 },
    { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel13 },
    { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel2  },
    { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel21 },
    { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel22 },
    { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel3  },
    { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel31 },
    { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel32 },
    { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel4  },
    { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel41 },
    { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel42 },
    { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel5  },
    { OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel51 },
};

template<class T>
static void InitOMXParams(T *params) {
    params->nSize = sizeof(T);
    params->nVersion.s.nVersionMajor = 1;
    params->nVersion.s.nVersionMinor = 0;
    params->nVersion.s.nRevision = 0;
    params->nVersion.s.nStep = 0;
}

libpeony_omx::libpeony_omx(
        const char *name,
        const OMX_CALLBACKTYPE *callbacks,
        OMX_PTR appData,
        OMX_COMPONENTTYPE **component)
    : SimpleSoftOMXComponent(name, callbacks, appData, component),
      mHandle(NULL),
      mInputBufferCount(0),
      mWidth(320),
      mHeight(240),
      mPictureSize(mWidth * mHeight * 3 / 2),
      mCropLeft(0),
      mCropTop(0),
      mCropWidth(mWidth),
      mCropHeight(mHeight),
      mFirstPicture(NULL),
      mFirstPictureId(-1),
      mPicId(0),
      mHeadersDecoded(false),
      mEOSStatus(INPUT_DATA_AVAILABLE),
      mOutputPortSettingsChange(NONE),
      mSignalledError(false) {
    initPorts();
    CHECK_EQ(initDecoder(), (status_t)OK);
uuprintf("_____=====_____=====_____===== libpeony_omx video %p create", this);
}

libpeony_omx::~libpeony_omx() {
    mHandle = NULL;

    if( vv_dptr )
    {
         if( vv_fns.fnp_vv_unload(vv_dptr) )
         delete[] (uint8_t *)vv_dptr;
    }

    while (mPicToHeaderMap.size() != 0) {
        OMX_BUFFERHEADERTYPE *header = mPicToHeaderMap.editValueAt(0);
        mPicToHeaderMap.removeItemsAt(0);
        delete header;
        header = NULL;
    }
    List<BufferInfo *> &outQueue = getPortQueue(kOutputPortIndex);
    List<BufferInfo *> &inQueue = getPortQueue(kInputPortIndex);
    CHECK(outQueue.empty());
    CHECK(inQueue.empty());

    delete[] mFirstPicture;
uuprintf("_____=====_____=====_____===== libpeony_omx video %p delete", this);
}

void libpeony_omx::initPorts() {
    OMX_PARAM_PORTDEFINITIONTYPE def;
    InitOMXParams(&def);

    def.nPortIndex = kInputPortIndex;
    def.eDir = OMX_DirInput;
    def.nBufferCountMin = kNumInputBuffers;
    def.nBufferCountActual = def.nBufferCountMin;
    def.nBufferSize = 8192;
    def.bEnabled = OMX_TRUE;
    def.bPopulated = OMX_FALSE;
    def.eDomain = OMX_PortDomainVideo;
    def.bBuffersContiguous = OMX_FALSE;
    def.nBufferAlignment = 1;

    def.format.video.cMIMEType = const_cast<char *>(MEDIA_MIMETYPE_VIDEO_AVC);
    def.format.video.pNativeRender = NULL;
    def.format.video.nFrameWidth = mWidth;
    def.format.video.nFrameHeight = mHeight;
    def.format.video.nStride = def.format.video.nFrameWidth;
    def.format.video.nSliceHeight = def.format.video.nFrameHeight;
    def.format.video.nBitrate = 0;
    def.format.video.xFramerate = 0;
    def.format.video.bFlagErrorConcealment = OMX_FALSE;
    //def.format.video.eCompressionFormat = OMX_VIDEO_CodingAVC;
    def.format.video.eCompressionFormat = OMX_VIDEO_CodingAutoDetect;
    def.format.video.eColorFormat = OMX_COLOR_FormatUnused;
    def.format.video.pNativeWindow = NULL;

    addPort(def);

    def.nPortIndex = kOutputPortIndex;
    def.eDir = OMX_DirOutput;
    def.nBufferCountMin = kNumOutputBuffers;
    def.nBufferCountActual = def.nBufferCountMin;
    def.bEnabled = OMX_TRUE;
    def.bPopulated = OMX_FALSE;
    def.eDomain = OMX_PortDomainVideo;
    def.bBuffersContiguous = OMX_FALSE;
    def.nBufferAlignment = 2;

    def.format.video.cMIMEType = const_cast<char *>(MEDIA_MIMETYPE_VIDEO_RAW);
    def.format.video.pNativeRender = NULL;
    def.format.video.nFrameWidth = mWidth;
    def.format.video.nFrameHeight = mHeight;
    def.format.video.nStride = def.format.video.nFrameWidth;
    def.format.video.nSliceHeight = def.format.video.nFrameHeight;
    def.format.video.nBitrate = 0;
    def.format.video.xFramerate = 0;
    def.format.video.bFlagErrorConcealment = OMX_FALSE;
    def.format.video.eCompressionFormat = OMX_VIDEO_CodingUnused;
    def.format.video.eColorFormat = OMX_COLOR_FormatYUV420Planar;
    def.format.video.pNativeWindow = NULL;

    def.nBufferSize =
        (def.format.video.nFrameWidth * def.format.video.nFrameHeight * 3) / 2;

    addPort(def);
}

status_t libpeony_omx::initDecoder() {
    return OK;
}

OMX_ERRORTYPE libpeony_omx::internalGetParameter(
        OMX_INDEXTYPE index, OMX_PTR params) {
    switch (index) {
        case OMX_IndexParamVideoPortFormat:
        {
            OMX_VIDEO_PARAM_PORTFORMATTYPE *formatParams =
                (OMX_VIDEO_PARAM_PORTFORMATTYPE *)params;

            if (formatParams->nPortIndex > kOutputPortIndex) {
                return OMX_ErrorUndefined;
            }

            if (formatParams->nIndex != 0) {
                return OMX_ErrorNoMore;
            }

            if (formatParams->nPortIndex == kInputPortIndex) {
                //formatParams->eCompressionFormat = OMX_VIDEO_CodingAVC;
                formatParams->eCompressionFormat = OMX_VIDEO_CodingAutoDetect;
                formatParams->eColorFormat = OMX_COLOR_FormatUnused;
                formatParams->xFramerate = 0;
            } else {
                CHECK(formatParams->nPortIndex == kOutputPortIndex);

                formatParams->eCompressionFormat = OMX_VIDEO_CodingUnused;
                formatParams->eColorFormat = OMX_COLOR_FormatYUV420Planar;
                formatParams->xFramerate = 0;
            }

            return OMX_ErrorNone;
        }

        case OMX_IndexParamVideoProfileLevelQuerySupported:
        {
            OMX_VIDEO_PARAM_PROFILELEVELTYPE *profileLevel =
                    (OMX_VIDEO_PARAM_PROFILELEVELTYPE *) params;

            if (profileLevel->nPortIndex != kInputPortIndex) {
                ALOGE("Invalid port index: %ld", profileLevel->nPortIndex);
                return OMX_ErrorUnsupportedIndex;
            }

            size_t index = profileLevel->nProfileIndex;
            size_t nProfileLevels = sizeof(kProfileLevels) / sizeof(kProfileLevels[0]);
            if (index >= nProfileLevels) {
                return OMX_ErrorNoMore;
            }

            profileLevel->eProfile = kProfileLevels[index].mProfile;
            profileLevel->eLevel = kProfileLevels[index].mLevel;
            return OMX_ErrorNone;
        }

        default:
            return SimpleSoftOMXComponent::internalGetParameter(index, params);
    }
}

OMX_ERRORTYPE libpeony_omx::internalSetParameter(
        OMX_INDEXTYPE index, const OMX_PTR params) {
    switch (index) {
        case OMX_IndexParamStandardComponentRole:
        {
            const OMX_PARAM_COMPONENTROLETYPE *roleParams =
                (const OMX_PARAM_COMPONENTROLETYPE *)params;
/*
            if (strncmp((const char *)roleParams->cRole,
                        "video_decoder.libpeony",
                        OMX_MAX_STRINGNAME_SIZE - 1)) {
                return OMX_ErrorUndefined;
            }
*/
            return OMX_ErrorNone;
        }

        case OMX_IndexParamVideoPortFormat:
        {
            OMX_VIDEO_PARAM_PORTFORMATTYPE *formatParams =
                (OMX_VIDEO_PARAM_PORTFORMATTYPE *)params;

            if (formatParams->nPortIndex > kOutputPortIndex) {
                return OMX_ErrorUndefined;
            }

            if (formatParams->nIndex != 0) {
                return OMX_ErrorNoMore;
            }

            return OMX_ErrorNone;
        }

        case OMX_IndexMax-1:
        {
            const OMX_VIDEO_PARAM_PEONY *mParams = (const OMX_VIDEO_PARAM_PEONY *)params;
            int ret_sz;

            memcpy(&ffoa_param, params, sizeof(OMX_VIDEO_PARAM_PEONY));
            fWidth = ffoa_param.v_s_res_x;
            fHeight = ffoa_param.v_s_res_y;

            __bb_vc_init_libavcodec(&vv_fns, &ret_sz);
            vv_dptr = new uint8_t[ret_sz];
            if( vv_fns.fnp_vv_load(vv_dptr,(void *)&ffoa_param) )
            {
		        uuprintf("FFmpegSource  <<< libffmpeg.so >>>  load error");
		        delete[] (uint8_t *)vv_dptr;
		        return OMX_ErrorUndefined;
            }

            return OMX_ErrorNone;
        }

        default:
            return SimpleSoftOMXComponent::internalSetParameter(index, params);
    }
}

OMX_ERRORTYPE libpeony_omx::getConfig(
        OMX_INDEXTYPE index, OMX_PTR params) {
    switch (index) {
        case OMX_IndexConfigCommonOutputCrop:
        {
            OMX_CONFIG_RECTTYPE *rectParams = (OMX_CONFIG_RECTTYPE *)params;

            if (rectParams->nPortIndex != 1) {
                return OMX_ErrorUndefined;
            }

            rectParams->nLeft = mCropLeft;
            rectParams->nTop = mCropTop;
            rectParams->nWidth = mCropWidth;
            rectParams->nHeight = mCropHeight;

            return OMX_ErrorNone;
        }

        default:
            return OMX_ErrorUnsupportedIndex;
    }
}

#define FFOA_V_ST_CHECK     0
#define FFOA_V_ST_INIT      1
#define FFOA_V_ST_PRE       2
#define FFOA_V_ST_DECODE    3
#define FFOA_V_ST_POST      4
#define FFOA_V_ST_END       5

void libpeony_omx::onQueueFilled(OMX_U32 portIndex) {

//uuprintf("_____=====_____=====_____=000= portIndex = %d", portIndex);

    if (mSignalledError || mOutputPortSettingsChange != NONE) {
        return;
    }

    if (mEOSStatus == OUTPUT_FRAMES_FLUSHED) {
        return;
    }

    List<BufferInfo *> &inQueue = getPortQueue(kInputPortIndex);
    List<BufferInfo *> &outQueue = getPortQueue(kOutputPortIndex);
    bool portSettingsChanged = false;

    BufferInfo *inInfo;
    OMX_BUFFERHEADERTYPE *inHeader;
    OMX_BUFFERHEADERTYPE *outHeader;
    FFoa_SwDecInput inPicture;
    uint8_t *outb;
    int ret_v;
    int32_t state, next_state;

    state = FFOA_V_ST_CHECK;

    while( 1 )
    {
//uuprintf("_____=====_____=====_____=000= state = %d", state);
        if( state == FFOA_V_ST_CHECK )
        {
            if( (mEOSStatus != INPUT_DATA_AVAILABLE || !inQueue.empty())
                    && outQueue.size() == kNumOutputBuffers )
                next_state = FFOA_V_ST_INIT;
            else next_state = FFOA_V_ST_END;
        }

        if( state == FFOA_V_ST_INIT )
        {
            if( mEOSStatus == INPUT_EOS_SEEN )
            {
                drainAllOutputBuffers();
                return;
            }

            inInfo = *inQueue.begin();
            inHeader = inInfo->mHeader;
            ++mPicId;
            if (inHeader->nFlags & OMX_BUFFERFLAG_EOS)
            {
                inQueue.erase(inQueue.begin());
                inInfo->mOwnedByUs = false;
                notifyEmptyBufferDone(inHeader);
                mEOSStatus = INPUT_EOS_SEEN;
                next_state = FFOA_V_ST_CHECK;
            }
            else next_state = FFOA_V_ST_PRE;
        }

        if( state == FFOA_V_ST_PRE )
        {
            FFoa_SwDecInfo decoderInfo;
            outHeader = new OMX_BUFFERHEADERTYPE;
            memset(outHeader, 0, sizeof(OMX_BUFFERHEADERTYPE));
            outHeader->nTimeStamp = inHeader->nTimeStamp;
            outHeader->nFlags = inHeader->nFlags;
            mPicToHeaderMap.add(mPicId, outHeader);
            inQueue.erase(inQueue.begin());

            memset(&inPicture, 0, sizeof(inPicture));
            inPicture.dataLen = inHeader->nFilledLen;
            inPicture.pStream = inHeader->pBuffer + inHeader->nOffset;
            inPicture.picId = mPicId;
            inPicture.intraConcealmentMethod = 1;

            AVCodecCheck(&decoderInfo);
            if( handlePortSettingChangeEvent(&decoderInfo) )
            {
                portSettingsChanged = true;
            }

            next_state = FFOA_V_ST_DECODE;
        }

        if( state == FFOA_V_ST_DECODE )
        {
            if( inPicture.dataLen > 0 )
            {
                AVFrame *pFrame_a;

                ret_v = AVCodecDecode(reinterpret_cast<int16_t *>(outHeader->pBuffer), inPicture.pStream, inPicture.dataLen, &pFrame_a);
//uuprintf("^^^^^_____^^^^^____ ret_v = %d", ret_v);
                inInfo->mOwnedByUs = false;
                notifyEmptyBufferDone(inHeader);

                inPicture.dataLen = 0;
                //ret_v = 1;
                if (ret_v < 0)
                {
                    ALOGE("Decoder failed: %d", ret_v);

                    notify(OMX_EventError, OMX_ErrorUndefined,
                           ERROR_MALFORMED, NULL);

                    mSignalledError = true;
                    return;
                }
                if( ret_v )
                {
                    copyFrames(pFrame_a, ((__BB_VC_LIBAVCODEC__ *)vv_dptr)->pYUV);

                    if (portSettingsChanged)
                    {
                        saveFirstOutputBuffer(mPicId, ((__BB_VC_LIBAVCODEC__ *)vv_dptr)->pYUV);
                        portSettingsChanged = false;
                        return;
                    }
                    next_state = FFOA_V_ST_POST;
                }
                else next_state = FFOA_V_ST_CHECK;
            }
            else next_state = FFOA_V_ST_END;
        }

        if( state == FFOA_V_ST_POST )
        {
            if( !outQueue.empty() )
            {
                if( mFirstPicture )
                {
                    drainOneOutputBuffer(mFirstPictureId, mFirstPicture);
                    delete[] mFirstPicture;
                    mFirstPicture = NULL;
                    mFirstPictureId = -1;
                }
                drainOneOutputBuffer(mPicId, ((__BB_VC_LIBAVCODEC__ *)vv_dptr)->pYUV);
            }
            next_state = FFOA_V_ST_CHECK;
        }

        if( state == FFOA_V_ST_END )
        {
            return;
        }

        state = next_state;
    }
}

bool libpeony_omx::handlePortSettingChangeEvent(const FFoa_SwDecInfo *info)
{
    if (mWidth != info->picWidth || mHeight != info->picHeight)
    {


        mWidth  = info->picWidth;
        mHeight = info->picHeight;
    Width_16 = (mWidth + 15) & (- 16);
    Height_16 = (mHeight + 15) & (- 16);
        mPictureSize = mWidth * mHeight * 3 / 2;
        mCropWidth = mWidth;
        mCropHeight = mHeight;
        updatePortDefinitions();
        notify(OMX_EventPortSettingsChanged, 1, 0, NULL);
        mOutputPortSettingsChange = AWAITING_DISABLED;
        return true;
    }

    return false;
}

bool libpeony_omx::handleCropRectEvent(const CropParams *crop)
{
    if (mCropLeft != crop->cropLeftOffset ||
        mCropTop != crop->cropTopOffset ||
        mCropWidth != crop->cropOutWidth ||
        mCropHeight != crop->cropOutHeight) {
        mCropLeft = crop->cropLeftOffset;
        mCropTop = crop->cropTopOffset;
        mCropWidth = crop->cropOutWidth;
        mCropHeight = crop->cropOutHeight;

        notify(OMX_EventPortSettingsChanged, 1,
                OMX_IndexConfigCommonOutputCrop, NULL);

        return true;
    }

    return false;
}

void libpeony_omx::saveFirstOutputBuffer(int32_t picId, uint8_t *data) {
    CHECK(mFirstPicture == NULL);
    mFirstPictureId = picId;

    mFirstPicture = new uint8_t[mPictureSize];
    memcpy(mFirstPicture, data, mPictureSize);
}

void libpeony_omx::drainOneOutputBuffer(int32_t picId, uint8_t* data) {
    List<BufferInfo *> &outQueue = getPortQueue(kOutputPortIndex);
    BufferInfo *outInfo = *outQueue.begin();
    outQueue.erase(outQueue.begin());
    OMX_BUFFERHEADERTYPE *outHeader = outInfo->mHeader;
    OMX_BUFFERHEADERTYPE *header = mPicToHeaderMap.valueFor(picId);
//uuprintf("_____=====_____=====_____===== Header %p, %d",header, picId);
    outHeader->nTimeStamp = header->nTimeStamp;
//uuprintf("_____=====_____=====_____===== inHeader->nTimeStamp = %lld, %f", outHeader->nTimeStamp, (float)(outHeader->nTimeStamp)/1000000);
    outHeader->nFlags = header->nFlags;
    outHeader->nFilledLen = mPictureSize;
    memcpy(outHeader->pBuffer + outHeader->nOffset, data, mPictureSize);
    mPicToHeaderMap.removeItem(picId);
    delete header;
    outInfo->mOwnedByUs = false;
    notifyFillBufferDone(outHeader);
}

bool libpeony_omx::drainAllOutputBuffers() {
    List<BufferInfo *> &outQueue = getPortQueue(kOutputPortIndex);

    while (!outQueue.empty()) {
        BufferInfo *outInfo = *outQueue.begin();
        outQueue.erase(outQueue.begin());
        OMX_BUFFERHEADERTYPE *outHeader = outInfo->mHeader;

        outHeader->nTimeStamp = 0;
        outHeader->nFilledLen = 0;
        outHeader->nFlags = OMX_BUFFERFLAG_EOS;
        mEOSStatus = OUTPUT_FRAMES_FLUSHED;

        outInfo->mOwnedByUs = false;
        notifyFillBufferDone(outHeader);
    }

    return true;
}

void libpeony_omx::onPortFlushCompleted(OMX_U32 portIndex) {
    if (portIndex == kInputPortIndex) {
        mEOSStatus = INPUT_DATA_AVAILABLE;
    }
}

void libpeony_omx::onPortEnableCompleted(OMX_U32 portIndex, bool enabled) {
    switch (mOutputPortSettingsChange) {
        case NONE:
            break;

        case AWAITING_DISABLED:
        {
            CHECK(!enabled);
            mOutputPortSettingsChange = AWAITING_ENABLED;
            break;
        }

        default:
        {
            CHECK_EQ((int)mOutputPortSettingsChange, (int)AWAITING_ENABLED);
            CHECK(enabled);
            mOutputPortSettingsChange = NONE;
            break;
        }
    }
}

void libpeony_omx::updatePortDefinitions() {
    OMX_PARAM_PORTDEFINITIONTYPE *def = &editPortInfo(0)->mDef;
    def->format.video.nFrameWidth = mWidth;
    def->format.video.nFrameHeight = mHeight;
    def->format.video.nStride = def->format.video.nFrameWidth;
    def->format.video.nSliceHeight = def->format.video.nFrameHeight;

    def = &editPortInfo(1)->mDef;
    def->format.video.nFrameWidth = mWidth;
    def->format.video.nFrameHeight = mHeight;
    def->format.video.nStride = def->format.video.nFrameWidth;
    def->format.video.nSliceHeight = def->format.video.nFrameHeight;

    def->nBufferSize =
        (def->format.video.nFrameWidth
            * def->format.video.nFrameHeight * 3) / 2;
}

int32_t libpeony_omx::AVCodecDecode(int16_t *outb, uint8_t *ibuf, uint32_t isize, AVFrame **ppFrame)
{
    int bytesDecoded;
    int frameFinished;

    bytesDecoded = vv_fns.fnp_vv_decode(vv_dptr, ibuf, isize, &frameFinished, ppFrame);

    if( frameFinished == 0 ) return 0;
    if( bytesDecoded > 0 ) return bytesDecoded;
    return -1;
}

int32_t libpeony_omx::AVCodecCheck(FFoa_SwDecInfo *decoderInfo)
{
    decoderInfo->picWidth = fWidth;
    decoderInfo->picHeight = fHeight;

    return 0;
}


void libpeony_omx::copyFrames(void *pFrame_t, uint8_t *out)
{
    AVFrame *pFrame = (AVFrame *)pFrame_t;
    uint32_t i;
    uint32_t Width_16_b2 = Width_16 /2;
    uint32_t Height_16_b2 = Height_16 /2;
    uint32_t Width_b2 = mWidth /2;
    uint32_t Height_b2 = mHeight /2;
    uint8_t *tmp_s = (uint8_t *)(pFrame->data[0]);
    uint8_t *tmp_d = (uint8_t *)(out);
    uint8_t *tmp_s_t, *tmp_d_t;
//uuprintf("________$$$$$$$_______ %d, %d, %d, %d, %d, %d", mWidth, mHeight, Width_16, Height_16,  Width_16_b2, Height_16_b2);
    tmp_s_t = tmp_s;
    tmp_d_t = tmp_d;
    for( i=0 ; i<mHeight ; i++ )
    {
        memcpy((void *)tmp_d_t, (void *)tmp_s_t, mWidth);
        tmp_s_t += pFrame->linesize[0];
        tmp_d_t += mWidth;
    }

    tmp_s_t = (uint8_t *)(pFrame->data[1]);
    tmp_d_t = tmp_d + mWidth * mHeight;
    for( i=0 ; i<Height_b2 ; i++ )
    {
        memcpy((void *)tmp_d_t, (void *)tmp_s_t, Width_b2);
        tmp_s_t += pFrame->linesize[1];
        tmp_d_t += Width_b2;
    }

    tmp_s_t = (uint8_t *)(pFrame->data[2]);
    tmp_d_t = tmp_d + mWidth * mHeight + Width_b2 * Height_b2;
    for( i=0 ; i<Height_b2 ; i++ )
    {
        memcpy((void *)tmp_d_t, (void *)tmp_s_t, Width_b2);
        tmp_s_t += pFrame->linesize[2];
        tmp_d_t += Width_b2;
    }
}

}  // namespace android

android::SoftOMXComponent *createSoftOMXComponent(
        const char *name, const OMX_CALLBACKTYPE *callbacks,
        OMX_PTR appData, OMX_COMPONENTTYPE **component) {
    return new android::libpeony_omx(name, callbacks, appData, component);
}
