#ifndef __RT_AVSPLIT_H__
#define __RT_AVSPLIT_H__

#define HEADER_AUDIO1_IMAGE	0x5353beef
#define HEADER_AUDIO2_IMAGE	0x4141beef
#define HEADER_VIDEO1_IMAGE	0x5656beef
#define HEADER_VIDEO2_IMAGE	0x7878beef

typedef struct _kernel_image_header {
   unsigned int magic;
   unsigned int offset;
   unsigned int size;
   unsigned int version;
   unsigned int reserved[4];
} kernel_image_header;

#endif // __RT_AVSPLIT_H__

