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

LIBPEONY_PATH := $(call my-dir)
include $(CLEAR_VARS)

include $(LIBPEONY_PATH)/demuxer/Android.mk
include $(LIBPEONY_PATH)/omx_ffmpeg_audio/Android.mk
include $(LIBPEONY_PATH)/omx_ffmpeg_video/Android.mk
