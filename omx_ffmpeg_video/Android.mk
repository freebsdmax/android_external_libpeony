#
# libpeony for Android
#
# Copyright (C) 2012-2013 InSignal Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

ifeq ($(BOARD_USES_LIBPEONY),true)

LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
        libpeony_dec_video.cpp

LOCAL_C_INCLUDES := \
        $(TOP)/frameworks/av/media/libstagefright/include \
        $(TOP)/frameworks/native/include/media/openmax \
        $(LOCAL_PATH)/../ffmpeg_dev_0.11/include \
        $(LOCAL_PATH)/../include \

LOCAL_SHARED_LIBRARIES := \
        libstagefright \
        libstagefright_omx \
        libstagefright_foundation \
        libutils \
        libdl \


LOCAL_MODULE := libstagefright_soft_libpeony_ffmpeg_video
LOCAL_MODULE_TAGS := optional

LOCAL_CFLAGS += -DLIBPEONY_ENABLE

include $(BUILD_SHARED_LIBRARY)

endif
