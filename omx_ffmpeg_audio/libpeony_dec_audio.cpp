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
#define LOG_TAG "__libpeony_dec_audio__"
#include <utils/Log.h>

#include "libpeony_dec_audio.h"

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/DataSource.h>
#include <media/stagefright/MediaBufferGroup.h>
#include <media/stagefright/MediaDebug.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MediaErrors.h>
#include <media/stagefright/MediaSource.h>
#include <media/stagefright/MetaData.h>
#include <utils/String8.h>
#include <dlfcn.h>

#if 1
	#define uuprintf(fmt, args...) ALOGE("%s(%d): " fmt, __FUNCTION__, __LINE__, ##args)
#else
	#define uuprintf(fmt, args...)
#endif

typedef struct
{
	void (*__xx_av_init_packet)(AVPacket *);
    int (*__xx_avcodec_decode_audio3)(AVCodecContext *, int16_t *, int *, AVPacket *);
#ifdef __DP_FFMPEG_NEW__
	AVCodecContext *(*__xx_avcodec_alloc_context3)(AVCodec *);
#endif
#ifdef __DP_FFMPEG_OLD__
	AVCodecContext *(*__xx_avcodec_alloc_context)(void);
#endif
	AVCodec *(*__xx_avcodec_find_decoder)(enum CodecID);
	int (*__xx_avcodec_open)(AVCodecContext *, AVCodec *);
	int (*__xx_avcodec_close)(AVCodecContext *avctx);
    void (*__xx_av_register_all)(void);
    void (*__xx_av_freep)(void *ptr);
    void (*__xx_avcodec_flush_buffers)(AVCodecContext *);

	AVCodecContext *avctx;
	AVCodec	*pCodec;
} __BB_AC_LIBAVCODEC__;


int             aout_buf_size = (AVCODEC_MAX_AUDIO_FRAME_SIZE * 3) / 2;
static uint8_t  audio_buf[(AVCODEC_MAX_AUDIO_FRAME_SIZE * 3) / 2]; // audio_buf[28880]

namespace android {


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

int __bb_ac_init_libavcodec(AUDIO_FUNCS *fnp, int *ret_malloc_sz)
{
        fnp->fnp_aa_load = __bb_ac_load_libavcodec;
        fnp->fnp_aa_unload = __bb_ac_unload_libavcodec;
        fnp->fnp_aa_flush = __bb_ac_flush_libavcodec;
        fnp->fnp_aa_decode = __bb_ac_decode_libavcodec;

        *ret_malloc_sz = sizeof(__BB_AC_LIBAVCODEC__);

        return 0;
}

#define __so_get_fn__(a,b)              dlsym((a),(b))

int __bb_ac_load_libavcodec(void *r_data, void *ffoa)
{
	void* dllsop;

    __BB_AC_LIBAVCODEC__ *bbp = (__BB_AC_LIBAVCODEC__ *)r_data;
    OMX_AUDIO_PARAM_PEONY *ntp = (OMX_AUDIO_PARAM_PEONY *)ffoa;
    int tmp;

    dllsop = dlopen("libffmpeg.so", RTLD_NOW);
    if( dllsop == 0 ) return 1;
uuprintf("====ac====dllsop = %p\n", dllsop);

    bbp->__xx_av_init_packet = 0;
    bbp->__xx_av_init_packet = (void (*)(AVPacket*))__so_get_fn__(dllsop, "av_init_packet");
    if( bbp->__xx_av_init_packet == 0 ) return 1;

    bbp->__xx_avcodec_decode_audio3 = 0;
    bbp->__xx_avcodec_decode_audio3 = (int (*)(AVCodecContext *, int16_t *, int *, AVPacket *))__so_get_fn__(dllsop, "avcodec_decode_audio3");
    if( bbp->__xx_avcodec_decode_audio3 == 0 ) return 1;
#ifdef __DP_FFMPEG_NEW__
    bbp->__xx_avcodec_alloc_context3 = 0;
    bbp->__xx_avcodec_alloc_context3 = (AVCodecContext *(*)(AVCodec *))__so_get_fn__(dllsop, "avcodec_alloc_context3");
    if( bbp->__xx_avcodec_alloc_context3 == 0 ) return 1;
#endif
#ifdef __DP_FFMPEG_OLD__
    bbp->__xx_avcodec_alloc_context = 0;
    bbp->__xx_avcodec_alloc_context = __so_get_fn__(dllsop, "avcodec_alloc_context");
    if( bbp->__xx_avcodec_alloc_context == 0 ) return 1;
#endif
    bbp->__xx_avcodec_find_decoder = 0;
    bbp->__xx_avcodec_find_decoder = (AVCodec *(*)(enum CodecID))__so_get_fn__(dllsop, "avcodec_find_decoder");
    if( bbp->__xx_avcodec_find_decoder == 0 ) return 1;

    bbp->__xx_avcodec_open = 0;
    bbp->__xx_avcodec_open = (int (*)(AVCodecContext *, AVCodec *))__so_get_fn__(dllsop, "avcodec_open");
    if( bbp->__xx_avcodec_open == 0 ) return 1;

    bbp->__xx_avcodec_close = 0;
    bbp->__xx_avcodec_close = (int (*)(AVCodecContext *))__so_get_fn__(dllsop, "avcodec_close");
    if( bbp->__xx_avcodec_close == 0 ) return 1;

    bbp->__xx_av_register_all = 0;
    bbp->__xx_av_register_all = (void (*)(void))__so_get_fn__(dllsop, "av_register_all");
    if( bbp->__xx_av_register_all == 0 ) return 1;

    bbp->__xx_av_freep = 0;
    bbp->__xx_av_freep = (void (*)(void *))__so_get_fn__(dllsop, "av_freep");
    if( bbp->__xx_av_freep == 0 ) return 1;

    bbp->__xx_avcodec_flush_buffers = 0;
    bbp->__xx_avcodec_flush_buffers = (void (*)(AVCodecContext *))__so_get_fn__(dllsop, "avcodec_flush_buffers");
    if( bbp->__xx_avcodec_flush_buffers == 0 ) return 1;

    (*(bbp->__xx_av_register_all))();

    bbp->pCodec = 0;
    bbp->pCodec = (*(bbp->__xx_avcodec_find_decoder))((enum CodecID)(ntp->ffmpeg_codec_id));
    if( bbp->pCodec == 0 ) return 1;

    bbp->avctx = 0;
#ifdef __DP_FFMPEG_NEW__
    bbp->avctx = (*(bbp->__xx_avcodec_alloc_context3))(bbp->pCodec);
#endif
#ifdef __DP_FFMPEG_OLD__
    bbp->avctx = (*(bbp->__xx_avcodec_alloc_context))();
#endif
    if( bbp->avctx == 0 ) return 1;

    bbp->avctx->flags = 0;
    bbp->avctx->channels = ntp->a_chs;
    bbp->avctx->request_channels = ntp->a_req_chs;
    bbp->avctx->sample_fmt = (AVSampleFormat)ntp->a_bit_fmt;
    bbp->avctx->bits_per_coded_sample = ntp->a_bits;
    bbp->avctx->sample_rate = ntp->a_s_rate;
    bbp->avctx->frame_size = ntp->a_frame_size;
    bbp->avctx->codec_tag                   = ntp->ffmpeg_codec_tag;
    bbp->avctx->stream_codec_tag            = ntp->ffmpeg_stream_codec_tag;
    bbp->avctx->extradata_size              = ntp->ffmpeg_extra_size;
    bbp->avctx->extradata                   = (uint8_t *)malloc(bbp->avctx->extradata_size + FF_INPUT_BUFFER_PADDING_SIZE);
    memset(bbp->avctx->extradata, 0, bbp->avctx->extradata_size + FF_INPUT_BUFFER_PADDING_SIZE);
    memcpy(bbp->avctx->extradata, (const void *)(ntp->ffmpeg_extra_data_ptr), bbp->avctx->extradata_size);

	if( (*(bbp->__xx_avcodec_open))(bbp->avctx, bbp->pCodec) < 0 ) return 1;

//================================================================
        return 0;
}

int __bb_ac_unload_libavcodec(void *r_data)
{
    __BB_AC_LIBAVCODEC__ *bbp = (__BB_AC_LIBAVCODEC__ *)r_data;

        if( bbp->avctx->extradata ) free(bbp->avctx->extradata);
        (*(bbp->__xx_avcodec_close))(bbp->avctx);
        (*(bbp->__xx_av_freep))(&(bbp->avctx));

    return 0;
}

int __bb_ac_flush_libavcodec(void *r_data)
{
    __BB_AC_LIBAVCODEC__ *bbp = (__BB_AC_LIBAVCODEC__ *)r_data;

	//(*(bbp->__xx_avcodec_flush_buffers))((AVCodecContext *)(ntp->ffmpeg_codeccontext_ptr));

    return 0;
}

int __bb_ac_decode_libavcodec(void *r_data, uint8_t *in_p, uint32_t in_size, int16_t *buf, int32_t *out_size, int32_t *first_flag)
{
    __BB_AC_LIBAVCODEC__ *bbp = (__BB_AC_LIBAVCODEC__ *)r_data;
	struct AVPacket	avp;
	int bytesDecoded, flag_decode, flag_post, flag_send;

	(*(bbp->__xx_av_init_packet))(&avp);
	avp.data = in_p;
	avp.size = in_size;

    //if( ntp->a_block_size == 0 ) *first_flag = 1; else *first_flag = 0;

    *out_size = AVCODEC_MAX_AUDIO_FRAME_SIZE;
    bytesDecoded = (*(bbp->__xx_avcodec_decode_audio3))(bbp->avctx, buf, out_size, &avp);
//uuprintf("_______bb_ac_decode_libavcodec____ %d, %d", in_size, *out_size);

    return bytesDecoded;
}


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
      mInputBufferCount(0),
      mSignalledError(false),
      mAnchorTimeUs(0),
      mNumFramesOutput(0),
      mNumFramesLeftOnPage(-1),
      mOutputPortSettingsChange(NONE) {
    initPorts();
    aa_dptr = 0;//ckkp = 0;
    aac_info = 0;
    CHECK_EQ(initDecoder(), (status_t)OK);
uuprintf("_____=====_____=====_____===== libpeony_omx audio %p create", this);
}

libpeony_omx::~libpeony_omx() {
    if( aa_dptr )
    {
         if( aa_fns.fnp_aa_unload(aa_dptr) )
         delete[] (uint8_t *)aa_dptr;
    }

uuprintf("_____=====_____=====_____===== libpeony_omx audio %p delete", this);
}

void libpeony_omx::initPorts() {
	uuprintf("1\n");
    OMX_PARAM_PORTDEFINITIONTYPE def;
    InitOMXParams(&def);

    def.nPortIndex = 0;
    def.eDir = OMX_DirInput;
    def.nBufferCountMin = kNumBuffers;
    def.nBufferCountActual = def.nBufferCountMin;
    def.nBufferSize = 8192;
    def.bEnabled = OMX_TRUE;
    def.bPopulated = OMX_FALSE;
    def.eDomain = OMX_PortDomainAudio;
    def.bBuffersContiguous = OMX_FALSE;
    def.nBufferAlignment = 1;

    def.format.audio.cMIMEType = const_cast<char *>("audio/peony");

    def.format.audio.pNativeRender = NULL;
    def.format.audio.bFlagErrorConcealment = OMX_FALSE;
    def.format.audio.eEncoding = OMX_AUDIO_CodingAutoDetect;

    addPort(def);

    def.nPortIndex = 1;
    def.eDir = OMX_DirOutput;
    def.nBufferCountMin = kNumBuffers;
    def.nBufferCountActual = def.nBufferCountMin;
    def.nBufferSize = kMaxNumSamplesPerBuffer; // in bytes
    def.bEnabled = OMX_TRUE;
    def.bPopulated = OMX_FALSE;
    def.eDomain = OMX_PortDomainAudio;
    def.bBuffersContiguous = OMX_FALSE;
    def.nBufferAlignment = 2;

    def.format.audio.cMIMEType = const_cast<char *>("audio/raw");
    def.format.audio.pNativeRender = NULL;
    def.format.audio.bFlagErrorConcealment = OMX_FALSE;
    def.format.audio.eEncoding = OMX_AUDIO_CodingPCM;

    addPort(def);
}

status_t libpeony_omx::initDecoder() {
    return OK;
}

OMX_ERRORTYPE libpeony_omx::internalGetParameter(
        OMX_INDEXTYPE index, OMX_PTR params) {


    switch (index) {
        case OMX_IndexParamAudioPcm:
        {
			uuprintf("OMX_IndexParamAudioPcm\n");
            OMX_AUDIO_PARAM_PCMMODETYPE *pcmParams =
                (OMX_AUDIO_PARAM_PCMMODETYPE *)params;

            if (pcmParams->nPortIndex != 1) {
                return OMX_ErrorUndefined;
            }

            pcmParams->eNumData = OMX_NumericalDataSigned;
            pcmParams->eEndian = OMX_EndianBig;
            pcmParams->bInterleaved = OMX_TRUE;
            pcmParams->nBitPerSample = 16;
            pcmParams->ePCMMode = OMX_AUDIO_PCMModeLinear;
            pcmParams->eChannelMapping[0] = OMX_AUDIO_ChannelLF;
            pcmParams->eChannelMapping[1] = OMX_AUDIO_ChannelRF;

            pcmParams->nChannels     = ffoa_param.a_chs;
            pcmParams->nSamplingRate = ffoa_param.a_s_rate;

            return OMX_ErrorNone;
        }

        default:
            return SimpleSoftOMXComponent::internalGetParameter(index, params);
    }
}

OMX_ERRORTYPE libpeony_omx::internalSetParameter(
        OMX_INDEXTYPE index, const OMX_PTR params) {
uuprintf("_____-----_____----- internalSetParameter = %x\n", index);
    switch (index) {
        case OMX_IndexParamStandardComponentRole:
        {
            const OMX_PARAM_COMPONENTROLETYPE *roleParams =
                (const OMX_PARAM_COMPONENTROLETYPE *)params;

uuprintf("_____-----_____----- OMX_IndexParamStandardComponentRole = %s\n", roleParams->cRole);
            if( !strncmp((const char *)roleParams->cRole, "audio_decoder.libpeony", OMX_MAX_STRINGNAME_SIZE - 1) )
            {
				uuprintf("ffoa audio decoder ....detected\n");
			}
            else
            {
				uuprintf("codec role......failed\n");
                return OMX_ErrorUndefined;
            }

            return OMX_ErrorNone;
        }

        case OMX_IndexMax-2:
        {
            const OMX_AUDIO_PARAM_PEONY *mParams = (const OMX_AUDIO_PARAM_PEONY *)params;
            int ret_sz;

            memcpy(&ffoa_param, params, sizeof(OMX_AUDIO_PARAM_PEONY));

            __bb_ac_init_libavcodec(&aa_fns, &ret_sz);
            aa_dptr = new uint8_t[ret_sz];
            if( aa_fns.fnp_aa_load(aa_dptr,(void *)&ffoa_param) )
            {
		        uuprintf("FFmpegSource  <<< libffmpeg.so >>>  load error");
		        delete[] (uint8_t *)aa_dptr;
		        return OMX_ErrorUndefined;
            }

            return OMX_ErrorNone;
        }

        default:
            return SimpleSoftOMXComponent::internalSetParameter(index, params);
    }
}

void libpeony_omx::onQueueFilled(OMX_U32 portIndex) {
    uint8_t *inputptr;
    int32_t ret;

//uuprintf("_____=====_____=====_____=000= portIndex = %d", portIndex);

    if (mSignalledError || mOutputPortSettingsChange != NONE) {
        return;
    }

    List<BufferInfo *> &inQueue = getPortQueue(0);
    List<BufferInfo *> &outQueue = getPortQueue(1);


    //if( (enum CodecID)(ckkp->ntpa->ffmpeg_codec_id) == CODEC_ID_AAC && portIndex == 0 && aac_info == 0)
    if( (enum CodecID)(ffoa_param.ffmpeg_codec_id) == CODEC_ID_AAC && portIndex == 0 && aac_info == 0)
    {
        ++aac_info;

        BufferInfo *info = *inQueue.begin();
        OMX_BUFFERHEADERTYPE *header = info->mHeader;

uuprintf("_____=====_____=====_____=000= header->nOffset, lenth = %x, %x",
		(uint32_t)header->nOffset, (uint32_t)header->nFilledLen);

        inQueue.erase(inQueue.begin());
        //notifyEmptyBufferDone(header);
        info->mOwnedByUs = true;
        //info->mOwnedByUs = false;
        //notifyEmptyBufferDone(header);
        //notify(OMX_EventPortSettingsChanged, 1, 0, NULL);
        //mOutputPortSettingsChange = AWAITING_ENABLED;
        //return;
    }

    while (!inQueue.empty() && !outQueue.empty()) {
        BufferInfo *inInfo = *inQueue.begin();
        OMX_BUFFERHEADERTYPE *inHeader = inInfo->mHeader;

        BufferInfo *outInfo = *outQueue.begin();
        OMX_BUFFERHEADERTYPE *outHeader = outInfo->mHeader;

        if (inHeader->nFlags & OMX_BUFFERFLAG_EOS) {
            inQueue.erase(inQueue.begin());
            inInfo->mOwnedByUs = false;
            notifyEmptyBufferDone(inHeader);

            outHeader->nFilledLen = 0;
            outHeader->nFlags = OMX_BUFFERFLAG_EOS;

            outQueue.erase(outQueue.begin());
            outInfo->mOwnedByUs = false;
            notifyFillBufferDone(outHeader);
            return;
        }

        if (inHeader->nOffset == 0) {
            mAnchorTimeUs = inHeader->nTimeStamp;
            mNumFramesOutput = 0;
        }

//uuprintf("_____=====_____=====_____===== inHeader->nOffset, lenth, Time = %d, %d, %f",
//	inHeader->nOffset, inHeader->nFilledLen, (float)(mAnchorTimeUs)/1000000);
//__hexdump__("ffoa_inHeader", (const void *)inputptr, (size_t)inHeader->nFilledLen);

        inputptr = inHeader->pBuffer + inHeader->nOffset;

        ret = AVCodecDecode(reinterpret_cast<int16_t *>(outHeader->pBuffer), inputptr, inHeader->nFilledLen);

        if(ret < 0 ) ret = 0;

        //CHECK_GE(inHeader->nFilledLen, mConfig->inputBufferUsedLength);
        outHeader->nOffset = 0;
        //outHeader->nFilledLen = inHeader->nFilledLen * sizeof(int16_t);
        outHeader->nFilledLen = ret; // decoded data lengeh in bytes
        outHeader->nTimeStamp = mAnchorTimeUs + (mNumFramesOutput * 1000000ll) / ffoa_param.a_s_rate;
        outHeader->nFlags = 0;

        mNumFramesOutput += ( (ret/sizeof(int16_t))/ffoa_param.a_chs );
//uuprintf("_____=====_____=====_____===== outHeader->nOffset, lenth, Time, mNumFramesOutput = %d, %d, %f, %d",
//	outHeader->nOffset, outHeader->nFilledLen, (float)(outHeader->nTimeStamp)/1000000, mNumFramesOutput);

        inInfo->mOwnedByUs = false;
        inQueue.erase(inQueue.begin());
        inInfo = NULL;
        notifyEmptyBufferDone(inHeader);
        inHeader = NULL;

        outInfo->mOwnedByUs = false;
        outQueue.erase(outQueue.begin());
        outInfo = NULL;
        notifyFillBufferDone(outHeader);
        outHeader = NULL;
    }

}

void libpeony_omx::onPortFlushCompleted(OMX_U32 portIndex)
{
    if( portIndex == 0 )
    {
        // Make sure that the next buffer output does not still
        // depend on fragments from the last one decoded.
        //ckkp->aa_fns.fnp_aa_flush(ckkp->aa_dptr, ckkp->ntpa);
        aa_fns.fnp_aa_flush(aa_dptr);
        mNumFramesOutput = 0;
    }
}

void libpeony_omx::onPortEnableCompleted(OMX_U32 portIndex, bool enabled) {
    if (portIndex != 1) {
        return;
    }

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

int32_t libpeony_omx::AVCodecDecode(int16_t *outb, uint8_t *ibuf, uint32_t isize)
{
    int out_size, first_flag;
    int bytesDecoded;

    bytesDecoded = aa_fns.fnp_aa_decode(aa_dptr, ibuf, isize, outb, &out_size, &first_flag);

    //return bytesDecoded;
    if( bytesDecoded > 0 ) return out_size;
    return -1;
}


}  // namespace android

android::SoftOMXComponent *createSoftOMXComponent(
        const char *name, const OMX_CALLBACKTYPE *callbacks,
        OMX_PTR appData, OMX_COMPONENTTYPE **component) {
    return new android::libpeony_omx(name, callbacks, appData, component);
}
