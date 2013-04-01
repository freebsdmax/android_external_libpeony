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

#ifndef __LIBPEONY_DEMUXER_H__
#define __LIBPEONY_DEMUXER_H__

//=====================================================================================


namespace android {

int __bb_dx_init_libavformat(void *fnp, int *ret_malloc_sz);
int dx_libavformat_load(void *r_data, NR_MEDIA *nmp);
int dx_libavformat_unload(void *r_data, NR_MEDIA *nmp);
int dx_libavformat_file_read_open(void *r_data, char *filename, NR_MEDIA *nmp);
int dx_libavformat_file_read_close(void *r_data, NR_MEDIA *nmp);
int dx_libavformat_frame_read(void *r_data, NR_MEDIA *nmp, NR_FRAME *nfp);
int dx_libavformat_frame_seek(void *r_data, NR_MEDIA *nmp, int track_no, uint64_t msec, int hw_on);
int dx_libavformat_frame_alloc(void *r_data, NR_FRAME *nfp);
int dx_libavformat_frame_release(void *r_data, NR_FRAME *nfp);


}  // namespace android
#endif
