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

#ifndef __LIBPEONY_DEC_AUDIO_H__
#define __LIBPEONY_DEC_AUDIO_H__

#include "SimpleSoftOMXComponent.h"
#include "libpeony.h"
#include "libpeony_omx.h"

namespace android {

int __bb_ac_init_libavcodec(AUDIO_FUNCS *fnp, int *ret_malloc_sz);
int __bb_ac_load_libavcodec(void *r_data, void *ffoa);
int __bb_ac_unload_libavcodec(void *r_data);
int __bb_ac_flush_libavcodec(void *r_data);
int __bb_ac_decode_libavcodec(void *r_data, uint8_t *in_p, uint32_t in_size, int16_t *buf, int32_t *out_size, int32_t *first_flag);


struct libpeony_omx : public SimpleSoftOMXComponent {
    libpeony_omx(const char *name,
            const OMX_CALLBACKTYPE *callbacks,
            OMX_PTR appData,
            OMX_COMPONENTTYPE **component);

protected:
    virtual ~libpeony_omx();

    virtual OMX_ERRORTYPE internalGetParameter(
            OMX_INDEXTYPE index, OMX_PTR params);

    virtual OMX_ERRORTYPE internalSetParameter(
            OMX_INDEXTYPE index, const OMX_PTR params);

    virtual void onQueueFilled(OMX_U32 portIndex);
    virtual void onPortFlushCompleted(OMX_U32 portIndex);
    virtual void onPortEnableCompleted(OMX_U32 portIndex, bool enabled);

private:
    enum {
        kNumBuffers = 4,
        kMaxNumSamplesPerBuffer = ((AVCODEC_MAX_AUDIO_FRAME_SIZE * 3) / 2)
    };

    size_t mInputBufferCount;

//    int samplerate;
//    int channels;

    bool mSignalledError;

    int64_t mAnchorTimeUs;
    int64_t mNumFramesOutput;
    int32_t mNumFramesLeftOnPage;

    enum {
        NONE,
        AWAITING_DISABLED,
        AWAITING_ENABLED
    } mOutputPortSettingsChange;

    void initPorts();
    status_t initDecoder();

    //CUUKUUK *ckkp;
    AUDIO_FUNCS aa_fns;
    void *aa_dptr;
    OMX_AUDIO_PARAM_PEONY ffoa_param;

    int32_t AVCodecDecode(int16_t *outb, uint8_t *ibuf, uint32_t isize);
    int aac_info;

    DISALLOW_EVIL_CONSTRUCTORS(libpeony_omx);
};

}  // namespace android

#endif
