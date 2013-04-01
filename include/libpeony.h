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

#ifndef __LIBPEONY_H__
#define __LIBPEONY_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <utils/Vector.h>

/*
#define __DP_SYS_GB__
#define __DP_SYS_ICS__
#define __DP_LINK_STATIC__
#define __DP_LINK_DYNAMIC__
#define __DP_FFMPEG_OLD__
#define __DP_FFMPEG_NEW__
*/

#define __DP_SYS_ICS__

#if defined(__DP_SYS_GB__) || defined(__DP_SYS_ICS__)
#define __DP_LINK_DYNAMIC__
#define __DP_FFMPEG_NEW__
//#define __DP_SWS__
#endif

#ifdef __DP_FFMPEG_NEW__
#define UINT64_C(val) val##ULL
#endif

#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <libavformat/url.h>

#ifdef __DP_FFMPEG_NEW__
#include <libavutil/dict.h>
#include <libavutil/mem.h>
#include <libavformat/url.h>
#endif

//#define MK_FOURCC(a,b,c,d) (a | (b << 8) | (c << 16) | (d << 24))
#define MK_FOURCC(a)                    (*((uint32_t *)(a)))
#define MK_EIGHTCC(a)                   (*((uint64_t *)(a)))

#define	INT64_MAX   0x7fffffffffffffffLL
#define	INT64_MIN   (-INT64_MAX - 1LL)
#define _FILE_OFFSET_BITS               64
#define _64_fseek(a,b,c)                fseeko(a,b,c)
#define _64_ftell(a)                    ftello(a)
#define _64_lseek(a,b,c)                lseek(a,b,c)



#define NR_FRAME_TY_NONE		0
#define NR_FRAME_TY_AUDIO		10
//#define NR_FRAME_TY_AUDIO_SILENT	11
#define NR_FRAME_TY_VIDEO		20
#define NR_FRAME_TY_RGB32	    21
#define NR_FRAME_TY_HW	        22
//#define NR_FRAME_TY_VIDEO_FF1		30
//#define NR_FRAME_TY_VIDEO_FF2		31
//#define NR_FRAME_TY_VIDEO_FF3		32
//#define NR_FRAME_TY_VIDEO_FF4		33


typedef struct
{
	uint64_t        data_ptr;
	int32_t         data_size;
	int16_t         type;
	int16_t         track_no;
	uint16_t        i_frame_and_flag;
	uint16_t        decode_contiune;        // 0:decode start,, else : continue data
	int64_t         t_us_pos;
} NR_FRAME;

#define NR_MEDIA_TY_STREAM		0
#define NR_MEDIA_TY_FD			1
#define NR_MEDIA_TY_AVFORMAT	2

#define NR_C_TY_VIDEO			0
#define NR_C_TY_AUDIO			1

typedef struct {
	uint32_t	m_ty;
	uint32_t	c_ty;
	uint32_t	fourcc;
	uint8_t		codec_name[32];
	uint32_t	ffmpeg_codec_id;
	uint32_t	ffmpeg_codec_tag;
	uint32_t	ffmpeg_stream_codec_tag;
	uint64_t	ffmpeg_avformat_ptr;
	uint64_t	ffmpeg_codeccontext_ptr;
	uint64_t	ffmpeg_codec_ptr;
	uint32_t	ffmpeg_extra_size;	// extra_size = sizeof(extra_data) + FF_INPUT_BUFFER_PADDING_SIZE
	uint64_t	ffmpeg_extra_data_ptr;

	int64_t     ff_pts_start;
	int64_t     ff_pts_end;
	int64_t     t_calc_duration;
	int64_t     t_calc_count;
	int64_t     t_cur_us;
	int64_t     t_sync_us;

	int32_t     t_range_enable;
	int64_t     t_range_s_us;
	int64_t     t_range_e_us;

	int32_t		pix_fmt;
	float       v_f_rate_num;       // frame rate : 30000
	float       v_f_rate_den;       // frame rate : 1001
	int32_t		v_s_res_x;
	int32_t		v_s_res_y;
	float		v_s_ratio;	// s_res_x / s_res_y
	int32_t		v_d_res_x;
	int32_t		v_d_res_y;
	float		v_d_ratio;
	int32_t		v_p_res_x;
	int32_t		v_p_res_y;
	float		v_p_ratio;
	int32_t		v_p_gdi_x;
	int32_t		v_p_gdi_y;
	int32_t		v_start;
	int64_t     t_start_us;
	int64_t     t_frame_duration;

	int32_t     a_chs;				// channels
    int32_t     a_req_chs;			// channels
	int32_t     a_bit_fmt;
	int32_t     a_bits;				// bits_per_coded_sample
	int32_t     a_s_rate;			// sample rate
	int32_t     a_frame_size;		// sample count / packet
	int32_t     a_block_size;		// (a_bits/8)*a_chs*a_frame_size
	int64_t     a_delay_us;
	int32_t     a_start;
} NR_TRACK;

typedef union {
	uint64_t	ffmpeg_avformat_ptr;
	int64_t     fd;
	uint64_t    file_ptr;
} NR_MEDIA_TY;

typedef struct {
	uint32_t	m_ty;
	NR_MEDIA_TY	m_ptr;
	int64_t		f_pos;
	int32_t		frame_start;
	uint32_t	fourcc_ex1;
	uint32_t	fourcc_ex2;
	uint32_t	fourcc_ex3;
	uint32_t	fourcc_ex4;
	uint32_t	track_sz;
	uint64_t	track_ptr;
	int64_t		duration_ms;
	int32_t		video_track_no;
	int32_t		audio_track_no;
	int32_t		master_track_no;
	//uint32_t	is_playing;			// 0 : stop, 1 : play
	uint32_t	video_track_enable;	// 0 : stop, 1 : play
	uint32_t	audio_track_enable;	// 0 : stop, 1 : play
	uint32_t	reservd_ex1;
	uint32_t	reservd_ex2;
	uint32_t	reservd_ex3;
	uint32_t	reservd_ex4;
	//int32_t   is_playing;
	int32_t     start_demux;
	int32_t     start_decode;
	int32_t     speed_def;
	int32_t     speed_play;
	int32_t     speed_play_bb;
	int32_t     speed_play_ff;
	int32_t     play_mode;
	int32_t     ff_msec;
	int32_t     ff_state;
	int32_t     ff_next_need;
	int32_t     frame_skip_mode1;
	int32_t     frame_drops;
	int64_t		frame_skip_us;
	int32_t		h264_nall_length;
	int32_t		h264_profile;
	//int32_t   ffplay_mode;
	//int32_t   ffplay_speed;
} NR_MEDIA;

#define __PLAY_MODE_PAUSE__     0
#define __PLAY_MODE_NORMAL__    1
#define __PLAY_MODE_OVERHEAD__  2
#define __PLAY_MODE_FFZZ__      11

//=====================================================================================

typedef struct {
	int (*fnp_dx_load)(void *, NR_MEDIA *);
	int (*fnp_dx_unload)(void *, NR_MEDIA *);
	int (*fnp_dx_file_read)(void *, char *, NR_MEDIA *);
	int (*fnp_dx_file_close)(void *, NR_MEDIA *);
	int (*fnp_dx_frame_read)(void *, NR_MEDIA *, NR_FRAME *);
	int (*fnp_dx_frame_seek)(void *, NR_MEDIA *, int, uint64_t, int);
	int (*fnp_dx_frame_alloc)(void *, NR_FRAME *);
	int (*fnp_dx_frame_release)(void *, NR_FRAME *);
} DEMUX_FUNCS;

typedef struct
{
        int (*fnp_aa_load)(void *, void *);
        int (*fnp_aa_unload)(void *);
        int (*fnp_aa_flush)(void *);
        int (*fnp_aa_decode)(void *, uint8_t *, uint32_t, int16_t *, int32_t *, int32_t *);
} AUDIO_FUNCS;

typedef struct
{
        int (*fnp_vv_load)(void *, void *);
        int (*fnp_vv_unload)(void *);
        int (*fnp_vv_flush)(void *);
        int (*fnp_vv_decode)(void *, uint8_t *, uint32_t , int *, AVFrame **);
} VIDEO_FUNCS;


typedef struct {
	NR_MEDIA nrm;
	DEMUX_FUNCS dx_fns;
	//AUDIO_FUNCS aa_fns;
	//VIDEO_FUNCS vv_fns;
	void *dx_dptr;
	//void *aa_dptr;
	//void *vv_dptr;
	NR_TRACK *ntpv;
	NR_TRACK *ntpa;
	int track_vv;
	int track_aa;
} CUUKUUK;

#define __ITY_NONE__            0
#define __ITY_AVI__             1
#define __ITY_MOV__             2
#define __ITY_MPEGPS__          3
#define __ITY_MPEGTS__          4
#define __ITY_MKV__             5
#define __ITY_MP3__             6
#define __ITY_OGG__             7
#define __ITY_WAV__             8
#define __ITY_ASF__             9

#endif
