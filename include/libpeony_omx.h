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

#ifndef __LIBPEONY_OMX_AUDIO_H__
#define __LIBPEONY_OMX_AUDIO_H__

#include "OMX_Types.h"


typedef struct OMX_AUDIO_PARAM_PEONY {
    OMX_U32 nSize;
    OMX_VERSIONTYPE nVersion;
    OMX_U32 nPortIndex;
    OMX_U32 ffmpeg_codec_id;
    OMX_U32 a_chs;
    OMX_U32 a_req_chs;
    OMX_U32 a_bit_fmt;
    OMX_U32 a_bits;
    OMX_U32 a_s_rate;
    OMX_U32 a_frame_size;
    OMX_U32 ffmpeg_codec_tag;
    OMX_U32 ffmpeg_stream_codec_tag;
    OMX_U32 ffmpeg_extra_size;
    OMX_U32 ffmpeg_extra_data_ptr;
} OMX_AUDIO_PARAM_PEONY;

typedef struct OMX_VIDEO_PARAM_PEONY {
    OMX_U32 nSize;
    OMX_VERSIONTYPE nVersion;
    OMX_U32 nPortIndex;
    OMX_U32 nIndex;
    OMX_U32 ffmpeg_codec_id;
    OMX_U32 v_s_res_x;
    OMX_U32 v_s_res_y;
    OMX_U32 ffmpeg_codec_tag;
    OMX_U32 ffmpeg_stream_codec_tag;
    OMX_U32 ffmpeg_extra_size;
    OMX_U32 ffmpeg_extra_data_ptr;
} OMX_VIDEO_PARAM_PEONY;

#endif
