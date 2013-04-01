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


#define LOG_TAG "__ffmpeg_c3_extradata__"
#include <utils/Log.h>
	#define uuprintf(fmt, args...) ALOGE("%s(%d): " fmt, __FUNCTION__, __LINE__, ##args)


#include <media/stagefright/DataSource.h>
#include <media/stagefright/MediaBufferGroup.h>
#include <media/stagefright/MediaDebug.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MediaErrors.h>
#include <media/stagefright/MediaSource.h>
#include <media/stagefright/MetaData.h>
#include <utils/String8.h>
//#include <media/stagefright/foundation/hexdump.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/ABase.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/Utils.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>

#include "libpeony_c3_extradata.h"

namespace android {


void __hexdump__(char *name, const void *_data, size_t size)
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

static size_t __GetSizeWidth(size_t x) {
    size_t n = 1;
    while (x > 127) {
        ++n;
        x >>= 7;
    }
    return n;
}

static uint8_t *__EncodeSize(uint8_t *dst, size_t x) {
    while (x > 127) {
        *dst++ = (x & 0x7f) | 0x80;
        x >>= 7;
    }
    *dst++ = x;
    return dst;
}

sp<ABuffer> ffmpeg_extradata_xvid(uint8_t *extradata, int32_t extradata_size) {
    size_t len1 = extradata_size + __GetSizeWidth(extradata_size) + 1;
    size_t len2 = len1 + __GetSizeWidth(len1) + 1 + 13;
    size_t len3 = len2 + __GetSizeWidth(len2) + 1 + 3;

uuprintf("xvid extra :::: GetSizeWidth(config->size()) = %d", __GetSizeWidth(extradata_size));
uuprintf("xvid extra :::: GetSizeWidth(config->size()) = %d", __GetSizeWidth(len1));
uuprintf("xvid extra :::: len1 = %d", len1);
uuprintf("xvid extra :::: len2 = %d", len2);
uuprintf("xvid extra :::: len3 = %d", len3);


    sp<ABuffer> csd = new ABuffer(len3);
    uint8_t *dst = csd->data();
    memset((void*)dst, 0, len3);
uuprintf("xvid extra :::: ptr_s = %p", dst);
    *dst++ = 0x03;
    dst = __EncodeSize(dst, len2 + 3);
uuprintf("xvid extra :::: ptr_s = %p", dst);
    *dst++ = 0x00;  // ES_ID
    *dst++ = 0x00;
    *dst++ = 0x00;  // streamDependenceFlag, URL_Flag, OCRstreamFlag

    *dst++ = 0x04;
    dst = __EncodeSize(dst, len1 + 13);
    *dst++ = 0x01;  // Video ISO/IEC 14496-2 Simple Profile
    for (size_t i = 0; i < 12; ++i) {
        *dst++ = 0x00;
    }

    *dst++ = 0x05;
uuprintf("xvid extra :::: ptr_s = %p", dst);
    dst = __EncodeSize(dst, extradata_size);
uuprintf("xvid extra :::: ptr_s = %p", dst);
    memcpy(dst, extradata, extradata_size);
uuprintf("xvid extra :::: config->size() = %d", extradata_size);
    dst += extradata_size;

    //__hexdump__("xvid 1", csd->data(), csd->size());

    return csd;
}

sp<ABuffer> ffmpeg_extradata_h264(uint8_t *extradata, int32_t extradata_size, uint32_t fourcc_ex1) {
	if( memcmp("\x00\x00\x00\x01", extradata, 4) == 0 ){
		int i, j, mode;
		int pps_table_sz = 1;
		int ex_sz;
		sp<ABuffer> sps = new ABuffer(100);
		sp<ABuffer> pps = new ABuffer(100);
		uint8_t *sps_p = sps->data();
		uint8_t *pps_p = pps->data();
		uint8_t *dst;
		int sps_pos=0, pps_pos=0;

		for( i=0,  mode=-1 ; i<extradata_size ; i++ )
		{
			if( i <= extradata_size - 4 )
			{
				if( memcmp("\x00\x00\x00\x01", &extradata[i], 4) == 0 )
				{
					mode = 0;
					i += 4;
				}
			}

			if( mode == 0 )
		    {
				mode = -1;
				if( (extradata[i] & 0x1f) == 0x07 )
			    {
					mode = 1;//sps
					sps_pos = 0;
			    }
				if( (extradata[i] & 0x1f) == 0x08 )
				{
					mode = 2;//pps
					pps_pos = 0;
			    }
		    }

		    if( mode == 1 )
		    {
			    sps_p[sps_pos++] = extradata[i];
		    }
		    if( mode == 2 )
		    {
				pps_p[pps_pos++] = extradata[i];
		    }
		}

	    ex_sz = 1 + 3 + 2 + 2 + sps_pos + 1;

	    for( j=0 ; j<pps_table_sz ; j++ )
	    {
			ex_sz += 2 + pps_pos;
	    }

		uuprintf("avc extradata_sz %d", ex_sz);
		sp<ABuffer> ex_data = new ABuffer(ex_sz);

		dst = ex_data->data();
	    uint8_t tmp8[2];

	    *dst++ = 0x01;
	    *dst++ = sps_p[1];
	    *dst++ = sps_p[2];
	    *dst++ = sps_p[3];
	    *dst++ = 0xff;
	    *dst++ = 0xe1;
	    *(uint16_t *)tmp8 = sps_pos;
	    *dst++ = tmp8[1];
	    *dst++ = tmp8[0];
	    memcpy(dst, sps_p, sps_pos);
	    dst += sps_pos;
	    *dst++ = pps_table_sz;

	    for( j=0 ; j<pps_table_sz ; j++ )
	    {
			*(uint16_t *)tmp8 = pps_pos;
		    *dst++ = tmp8[1];
		    *dst++ = tmp8[0];
		    memcpy(dst, pps_p, pps_pos);
		    dst += sps_pos;
	    }

		return ex_data;
	}
/*
	if( fourcc_ex1 == __ITY_AVI__ ){
		sp<ABuffer> sps = new ABuffer(0x17);
		sp<ABuffer> pps = new ABuffer(0x04);
		int pps_table_sz = 1;
		int ex_sz;
		int j;
	    uint8_t *dst;
	    uint8_t *src;

	    dst = sps->data();
	    memcpy(&dst[00], "\x67\x4d\x40\x1f\x9a\x74\x02\x80\x2d\xd8\x08\x80\x00\x01\xf4\x80", 16);
	    memcpy(&dst[16], "\x00\x75\x30\x47\x8c\x19\x50", 7);

	    dst = pps->data();
	    memcpy(&dst[0], "\x68\xee\x32\xc8", 4);

	    ex_sz = 1 + 3 + 2 + 2 + sps->size() + 1;

	    for( j=0 ; j<pps_table_sz ; j++ )
	    {
			ex_sz += 2 + pps->size();
	    }

	    uuprintf("avc extradata_sz %d", ex_sz);
		sp<ABuffer> ex_data = new ABuffer(ex_sz);

	    dst = ex_data->data();
	    uint8_t tmp8[2];

	    *dst++ = 0x01;
	    src = sps->data();
	    *dst++ = src[1];
	    *dst++ = src[2];
	    *dst++ = src[3];
	    *dst++ = 0xff;
	    *dst++ = 0xe1;
	    *(uint16_t *)tmp8 = sps->size();
	    *dst++ = tmp8[1];
	    *dst++ = tmp8[0];
	    memcpy(dst, sps->data(), sps->size());
	    dst += sps->size();
	    *dst++ = pps_table_sz;

	    for( j=0 ; j<pps_table_sz ; j++ )
	    {
			*(uint16_t *)tmp8 = pps->size();
		    *dst++ = tmp8[1];
		    *dst++ = tmp8[0];
		    memcpy(dst, pps->data(), pps->size());
		    dst += pps->size();
	    }

		return ex_data;
	}
*/
    sp<ABuffer> ex_data = new ABuffer(extradata_size);
    memcpy(ex_data->data(), extradata, extradata_size);
	return ex_data;
}

static void __EncodeSize14(uint8_t **_ptr, size_t size) {
    CHECK_LE(size, 0x3fff);

    uint8_t *ptr = *_ptr;

    *ptr++ = 0x80 | (size >> 7);
    *ptr++ = size & 0x7f;

    *_ptr = ptr;
}

/* IN  /frameworks/base/media/libstagefright/Utils.cpp
uint16_t U16_AT(const uint8_t *ptr) {
    return ptr[0] << 8 | ptr[1];
}

uint32_t U32_AT(const uint8_t *ptr) {
    return ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
}
*/

size_t h264_parseNALSize(const uint8_t *data, int32_t mNALLengthSize){
	switch (mNALLengthSize) {
		case 1:
			return *data;
		case 2:
			return U16_AT(data);
		case 3:
			return ((size_t)data[0] << 16) | U16_AT(&data[1]);
		case 4:
			return U32_AT(data);
	}

	// This cannot happen, mNALLengthSize springs to life by adding 1 to
	// a 2-bit integer.
	CHECK(!"Should not be here.");

	return 0;
}

int __bit_add__(uint8_t *ptr, int bit_pos, int bit_sz, uint32_t bit_value)
{
    int i;
    int end, ptr_pp, tmp;
    uint8_t ch;

    tmp = bit_pos + bit_sz - 1;
    ptr_pp = tmp / 8;
    end = tmp % 8;

    for( i=0 ; i<bit_sz ; i++, end--, bit_value>>=1 )
    {
        if( end == 0 )
        {
            end = 8;
            ptr_pp--;
        }
        ch = bit_value & 0x01;
        ch <<= (8-end);
        *(ptr+ptr_pp) |= ch;
    }

    return 0;
}

sp<ABuffer> ffmpeg_extradata_aac(uint8_t *extradata, int32_t *ex_sz_p, NR_TRACK *ntp)
{
	int tmp;

	memset(extradata, 0, 5);

	__bit_add__(&extradata[0], 1, 5, 2); //AAC LC (Low Complexity)

	tmp = 15;
	if( ntp->a_s_rate == 96000 ) tmp = 0;
	if( ntp->a_s_rate == 88200 ) tmp = 1;
	if( ntp->a_s_rate == 64000 ) tmp = 2;
	if( ntp->a_s_rate == 48000 ) tmp = 3;
	if( ntp->a_s_rate == 44100 ) tmp = 4;
	if( ntp->a_s_rate == 32000 ) tmp = 5;
	if( ntp->a_s_rate == 24000 ) tmp = 6;
	if( ntp->a_s_rate == 22050 ) tmp = 7;
	if( ntp->a_s_rate == 16000 ) tmp = 8;
	if( ntp->a_s_rate == 12000 ) tmp = 9;
	if( ntp->a_s_rate == 11025 ) tmp = 10;
	if( ntp->a_s_rate == 8000  ) tmp = 11;
	if( ntp->a_s_rate == 7350  ) tmp = 12;
	__bit_add__(&extradata[0], 6, 4, tmp);

	__bit_add__(&extradata[1], 2, 4, ntp->a_chs);

	tmp = 1;
	if( ntp->a_frame_size == 1024  ) tmp = 0;//frame length - 1024 samples
	__bit_add__(&extradata[1], 6, 1, tmp);

	__bit_add__(&extradata[1], 7, 1, 0); //does not depend on core coder

	__bit_add__(&extradata[1], 8, 1, 0); //is not extension
	*ex_sz_p = 2;

	// if extended
    //Explicitly Mark SBR absent
	/*
	au.ex.b1_1_11 = 0x2b7; //sync extension
	au.ex.b1_2_5 = 5; //AOT_SBR
	au.ex.b1_3_1 = 0;
	au.ex.dummy = 0;
	*/

	//__hexdump__("aac_make_extra_data", extradata, *ex_sz_p);

	return 0;
}


sp<ABuffer> ffmpeg_esds_aac_low(uint8_t *extradata, int32_t extradata_size, int bit_rate) {
	CHECK(extradata_size + 23 < 128);

	int len = extradata_size + 25;
    sp<ABuffer> csd = new ABuffer(len);
    uint8_t *dst = csd->data();
    uint8_t buf[4];
    memset((void*)dst, 0, len);

//=================================
    *dst++ = 0x03;
    *dst++ = 23 + extradata_size;
    *dst++ = 0x00;  // ES_ID
    *dst++ = 0x00;
    *dst++ = 0x00;  // streamDependenceFlag, URL_Flag, OCRstreamFlag
//=================================
    *dst++ = 0x04;
    *dst++ = 15 + extradata_size;
    *dst++ = 0x67;
    *dst++ = 0x15;
    *dst++ = 0x00;
    *dst++ = 0x12;	//buf 0
    *dst++ = 0x34;	//buf 1
/*
    *dst++ = 0x00;
    *dst++ = 0x02;
    *dst++ = 0xfb;
    *dst++ = 0x78;
    *dst++ = 0x00;
    *dst++ = 0x02;
    *dst++ = 0xc7;
    *dst++ = 0xb0;
*/
    *(int *)buf = bit_rate;
    //*(int *)buf = 0x12345678;
    *dst++ = buf[0];
    *dst++ = buf[1];
    *dst++ = buf[2];
    *dst++ = buf[3];
    *(int *)buf = bit_rate * 2;
    *dst++ = buf[0];
    *dst++ = buf[1];
    *dst++ = buf[2];
    *dst++ = buf[3];
//=================================
    *dst++ = 0x05;
    dst = __EncodeSize(dst, extradata_size);
    memcpy(dst, extradata, extradata_size);
    dst += extradata_size;
//=================================
    *dst++ = 0x06;
    *dst++ = 0x01;
    *dst++ = 0x02;

    //__hexdump__("xvid 1", csd->data(), csd->size());

    return csd;
}

}  // namespace android
