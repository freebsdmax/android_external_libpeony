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

#ifndef __LIBPEONY_DEC_VIDEO_H__
#define __LIBPEONY_DEC_VIDEO_H__

#include "SimpleSoftOMXComponent.h"
#include "libpeony.h"
#include "libpeony_omx.h"
#include <utils/KeyedVector.h>


/* Input structure */
typedef struct
{
    uint8_t  *pStream;            /* Pointer to stream to be decoded          */
    uint32_t  dataLen;            /* Number of bytes to be decoded            */
    uint32_t  picId;              /* Identifier for the picture to be decoded */
    uint32_t intraConcealmentMethod; /* 0 = Gray concealment for intra
                                   1 = Reference concealment for intra */

} FFoa_SwDecInput;

typedef struct
{
    uint32_t cropLeftOffset;
    uint32_t cropOutWidth;
    uint32_t cropTopOffset;
    uint32_t cropOutHeight;
} CropParams;

typedef struct
{
    uint32_t profile;
    uint32_t picWidth;
    uint32_t picHeight;
    uint32_t videoRange;
    uint32_t matrixCoefficients;
    uint32_t parWidth;
    uint32_t parHeight;
    uint32_t croppingFlag;
    CropParams cropParams;
} FFoa_SwDecInfo;

namespace android {

int __bb_vc_init_libavcodec(VIDEO_FUNCS *fnp, int *ret_malloc_sz);
int __bb_vc_load_libavcodec(void *r_data, void *ffoa);
int __bb_vc_unload_libavcodec(void *r_data);
int __bb_vc_flush_libavcodec(void *r_data);
int __bb_vc_decode_libavcodec(void *r_data, uint8_t *in_p, uint32_t in_size, int *frameFinished, AVFrame **ppFrame);

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

    virtual OMX_ERRORTYPE getConfig(OMX_INDEXTYPE index, OMX_PTR params);

    virtual void onQueueFilled(OMX_U32 portIndex);
    virtual void onPortFlushCompleted(OMX_U32 portIndex);
    virtual void onPortEnableCompleted(OMX_U32 portIndex, bool enabled);

private:
    enum {
        kInputPortIndex   = 0,
        kOutputPortIndex  = 1,
        kNumInputBuffers  = 8,
        kNumOutputBuffers = 2,
    };

    enum EOSStatus {
        INPUT_DATA_AVAILABLE,
        INPUT_EOS_SEEN,
        OUTPUT_FRAMES_FLUSHED,
    };

    void *mHandle;

    size_t mInputBufferCount;

    uint32_t mWidth, mHeight, mPictureSize;
    uint32_t Width_16;
    uint32_t Height_16;
    uint32_t mCropLeft, mCropTop;
    uint32_t mCropWidth, mCropHeight;

    uint8_t *mFirstPicture;
    int32_t mFirstPictureId;

    int32_t mPicId;  // Which output picture is for which input buffer?

    // OMX_BUFFERHEADERTYPE may be overkill, but it is convenient
    // for tracking the following fields: nFlags, nTimeStamp, etc.
    KeyedVector<int32_t, OMX_BUFFERHEADERTYPE *> mPicToHeaderMap;
    bool mHeadersDecoded;

    EOSStatus mEOSStatus;

    enum OutputPortSettingChange {
        NONE,
        AWAITING_DISABLED,
        AWAITING_ENABLED
    };
    OutputPortSettingChange mOutputPortSettingsChange;

    bool mSignalledError;

    void initPorts();
    status_t initDecoder();
    void updatePortDefinitions();
    bool drainAllOutputBuffers();
    void drainOneOutputBuffer(int32_t picId, uint8_t *data);
    void saveFirstOutputBuffer(int32_t pidId, uint8_t *data);
    bool handleCropRectEvent(const CropParams* crop);
    bool handlePortSettingChangeEvent(const FFoa_SwDecInfo *info);

    uint32_t fWidth, fHeight;

    VIDEO_FUNCS vv_fns;
    void *vv_dptr;
    OMX_VIDEO_PARAM_PEONY ffoa_param;
    int32_t AVCodecDecode(int16_t *outb, uint8_t *ibuf, uint32_t isize, AVFrame **ppFrame);
    int32_t AVCodecCheck(FFoa_SwDecInfo *decoderInfo);
    void copyFrames(void *pFrame_t, uint8_t *out);

    DISALLOW_EVIL_CONSTRUCTORS(libpeony_omx);
};

}  // namespace android

#endif  // SOFT_AVC_H_
