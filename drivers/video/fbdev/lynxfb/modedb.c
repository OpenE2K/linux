/*******************************************************************
*Copyright (c) 2012 by Silicon Motion, Inc. (SMI)
*Permission is hereby granted, free of charge, to any person obtaining a copy
*of this software and associated documentation files (the "Software"), to deal
*in the Software without restriction, including without limitation the rights to
*use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
*of the Software, and to permit persons to whom the Software is furnished to
*do so, subject to the following conditions:
*
*THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
*EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
*OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
*NONINFRINGEMENT.  IN NO EVENT SHALL Mill.Chen and Monk.Liu OR COPYRIGHT
*HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
*WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
*FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
*OTHER DEALINGS IN THE SOFTWARE.
*******************************************************************/
static const struct fb_videomode modedb2[] = {
	{
	 /* 640x400 @ 70 Hz, 31.5 kHz hsync */
	 NULL, 70, 640, 400, 39721, 40, 24, 39, 9, 96, 2,
	 0, FB_VMODE_NONINTERLACED}, {
				      /* 640x480 @ 60 Hz, 31.5 kHz hsync */
				      NULL, 60, 640, 480, 39721, 40, 24,
				      32, 11, 96, 2,
				      0, FB_VMODE_NONINTERLACED}, {
								   /* 800x600 @ 56 Hz, 35.15 kHz hsync */
								   NULL,
								   56, 800,
								   600,
								   27777,
								   128, 24,
								   22, 1,
								   72, 2,
								   0,
								   FB_VMODE_NONINTERLACED},
	{
	 /* 1024x768 @ 87 Hz interlaced, 35.5 kHz hsync */
	 NULL, 87, 1024, 768, 22271, 56, 24, 33, 8, 160, 8,
	 0, FB_VMODE_INTERLACED}, {
				   /* 640x400 @ 85 Hz, 37.86 kHz hsync */
				   NULL, 85, 640, 400, 31746, 96, 32, 41,
				   1, 64, 3,
				   FB_SYNC_VERT_HIGH_ACT,
				   FB_VMODE_NONINTERLACED}, {
							     /* 640x480 @ 72 Hz, 36.5 kHz hsync */
							     NULL, 72, 640,
							     480, 31746,
							     144, 40, 30,
							     8, 40, 3,
							     0,
							     FB_VMODE_NONINTERLACED},
	{
	 /* 640x480 @ 75 Hz, 37.50 kHz hsync */
	 NULL, 75, 640, 480, 31746, 120, 16, 16, 1, 64, 3,
	 0, FB_VMODE_NONINTERLACED}, {
				      /* 800x600 @ 60 Hz, 37.8 kHz hsync */
				      NULL, 60, 800, 600, 25000, 88, 40,
				      23, 1, 128, 4,
				      FB_SYNC_HOR_HIGH_ACT |
				      FB_SYNC_VERT_HIGH_ACT,
				      FB_VMODE_NONINTERLACED}, {
								/* 640x480 @ 85 Hz, 43.27 kHz hsync */
								NULL, 85,
								640, 480,
								27777, 80,
								56, 25, 1,
								56, 3,
								0,
								FB_VMODE_NONINTERLACED},
	{
	 /* 1152x864 @ 89 Hz interlaced, 44 kHz hsync */
	 NULL, 69, 1152, 864, 15384, 96, 16, 110, 1, 216, 10,
	 0, FB_VMODE_INTERLACED}, {
				   /* 800x600 @ 72 Hz, 48.0 kHz hsync */
				   NULL, 72, 800, 600, 20000, 64, 56, 23,
				   37, 120, 6,
				   FB_SYNC_HOR_HIGH_ACT |
				   FB_SYNC_VERT_HIGH_ACT,
				   FB_VMODE_NONINTERLACED}, {
							     /* 1024x768 @ 60 Hz, 48.4 kHz hsync */
							     NULL, 60,
							     1024, 768,
							     15384, 168, 8,
							     29, 3, 144, 6,
							     0,
							     FB_VMODE_NONINTERLACED},
	{
	 /* 640x480 @ 100 Hz, 53.01 kHz hsync */
	 NULL, 100, 640, 480, 21834, 96, 32, 36, 8, 96, 6,
	 0, FB_VMODE_NONINTERLACED}, {
				      /* 1152x864 @ 60 Hz, 53.5 kHz hsync */
				      NULL, 60, 1152, 864, 11123, 208, 64,
				      16, 4, 256, 8,
				      0, FB_VMODE_NONINTERLACED}, {
								   /* 800x600 @ 85 Hz, 55.84 kHz hsync */
								   NULL,
								   85, 800,
								   600,
								   16460,
								   160, 64,
								   36, 16,
								   64, 5,
								   0,
								   FB_VMODE_NONINTERLACED},
	{
	 /* 1024x768 @ 70 Hz, 56.5 kHz hsync */
	 NULL, 70, 1024, 768, 13333, 144, 24, 29, 3, 136, 6,
	 0, FB_VMODE_NONINTERLACED}, {
				      /*  1280x960-60 VESA */
				      NULL, 60, 1280, 960, 9259, 312, 96,
				      36, 1, 112, 3,
				      FB_SYNC_HOR_HIGH_ACT |
				      FB_SYNC_VERT_HIGH_ACT,
				      FB_VMODE_NONINTERLACED,
				      FB_MODE_IS_VESA}, {
							 /*  1280x1024-60 VESA */
							 NULL, 60, 1280,
							 1024, 9259, 248,
							 48, 38, 1, 112, 3,
							 FB_SYNC_HOR_HIGH_ACT
							 |
							 FB_SYNC_VERT_HIGH_ACT,
							 FB_VMODE_NONINTERLACED,
							 FB_MODE_IS_VESA},
	{
	 /* 1280x1024 @ 87 Hz interlaced, 51 kHz hsync */
	 NULL, 87, 1280, 1024, 12500, 56, 16, 128, 1, 216, 12,
	 0, FB_VMODE_INTERLACED}, {
				   /* 800x600 @ 100 Hz, 64.02 kHz hsync */
				   NULL, 100, 800, 600, 14357, 160, 64, 30,
				   4, 64, 6,
				   0, FB_VMODE_NONINTERLACED}, {
								/* 1024x768 @ 76 Hz, 62.5 kHz hsync */
								NULL, 76,
								1024, 768,
								11764, 208,
								8, 36, 16,
								120, 3,
								0,
								FB_VMODE_NONINTERLACED},
	{
	 /* 1152x864 @ 70 Hz, 62.4 kHz hsync */
	 NULL, 70, 1152, 864, 10869, 106, 56, 20, 1, 160, 10,
	 0, FB_VMODE_NONINTERLACED}, {
				      /* 1280x1024 @ 61 Hz, 64.2 kHz hsync */
				      NULL, 61, 1280, 1024, 9090, 200, 48,
				      26, 1, 184, 3,
				      0, FB_VMODE_NONINTERLACED}, {
								   /* 1400x1050 @ 60Hz, 63.9 kHz hsync */
								   NULL,
								   68,
								   1400,
								   1050,
								   9259,
								   136, 40,
								   13, 1,
								   112, 3,
								   0,
								   FB_VMODE_NONINTERLACED},
	{
	 /* 1400x1050 @ 75,107 Hz, 82,392 kHz +hsync +vsync */
	 NULL, 75, 1400, 1050, 9271, 120, 56, 13, 0, 112, 3,
	 FB_SYNC_HOR_HIGH_ACT | FB_SYNC_VERT_HIGH_ACT,
	 FB_VMODE_NONINTERLACED}, {
				   /* 1400x1050 @ 60 Hz, ? kHz +hsync +vsync */
				   NULL, 60, 1400, 1050, 9259, 128, 40, 12,
				   0, 112, 3,
				   FB_SYNC_HOR_HIGH_ACT |
				   FB_SYNC_VERT_HIGH_ACT,
				   FB_VMODE_NONINTERLACED}, {
							     /* 1024x768 @ 85 Hz, 70.24 kHz hsync */
							     NULL, 85,
							     1024, 768,
							     10111, 192,
							     32, 34, 14,
							     160, 6,
							     0,
							     FB_VMODE_NONINTERLACED},
	{
	 /* 1152x864 @ 78 Hz, 70.8 kHz hsync */
	 NULL, 78, 1152, 864, 9090, 228, 88, 32, 0, 84, 12,
	 0, FB_VMODE_NONINTERLACED}, {
				      /* 1280x1024 @ 70 Hz, 74.59 kHz hsync */
				      NULL, 70, 1280, 1024, 7905, 224, 32,
				      28, 8, 160, 8,
				      0, FB_VMODE_NONINTERLACED}, {
								   /* 1600x1200 @ 60Hz, 75.00 kHz hsync */
								   NULL,
								   60,
								   1600,
								   1200,
								   6172,
								   304, 64,
								   46, 1,
								   192, 3,
								   FB_SYNC_HOR_HIGH_ACT
								   |
								   FB_SYNC_VERT_HIGH_ACT,
								   FB_VMODE_NONINTERLACED},
	{
	 /* 1152x864 @ 84 Hz, 76.0 kHz hsync */
	 NULL, 84, 1152, 864, 7407, 184, 312, 32, 0, 128, 12,
	 0, FB_VMODE_NONINTERLACED}, {
				      /* 1280x1024 @ 74 Hz, 78.85 kHz hsync */
				      NULL, 74, 1280, 1024, 7407, 256, 32,
				      34, 3, 144, 3,
				      0, FB_VMODE_NONINTERLACED}, {
								   /* 1024x768 @ 100Hz, 80.21 kHz hsync */
								   NULL,
								   100,
								   1024,
								   768,
								   8658,
								   192, 32,
								   21, 3,
								   192, 10,
								   0,
								   FB_VMODE_NONINTERLACED},
	{
	 /* 1280x1024 @ 76 Hz, 81.13 kHz hsync */
	 NULL, 76, 1280, 1024, 7407, 248, 32, 34, 3, 104, 3,
	 0, FB_VMODE_NONINTERLACED}, {
				      /* 1600x1200 @ 70 Hz, 87.50 kHz hsync */
				      NULL, 70, 1600, 1200, 5291, 304, 64,
				      46, 1, 192, 3,
				      0, FB_VMODE_NONINTERLACED}, {
								   /* 1152x864 @ 100 Hz, 89.62 kHz hsync */
								   NULL,
								   100,
								   1152,
								   864,
								   7264,
								   224, 32,
								   17, 2,
								   128, 19,
								   0,
								   FB_VMODE_NONINTERLACED},
	{
	 /* 1280x1024 @ 85 Hz, 91.15 kHz hsync */
	 NULL, 85, 1280, 1024, 6349, 224, 64, 44, 1, 160, 3,
	 FB_SYNC_HOR_HIGH_ACT | FB_SYNC_VERT_HIGH_ACT,
	 FB_VMODE_NONINTERLACED}, {
				   /* 1600x1200 @ 75 Hz, 93.75 kHz hsync */
				   NULL, 75, 1600, 1200, 4938, 304, 64, 46,
				   1, 192, 3,
				   FB_SYNC_HOR_HIGH_ACT |
				   FB_SYNC_VERT_HIGH_ACT,
				   FB_VMODE_NONINTERLACED}, {
							     /* 1600x1200 @ 85 Hz, 105.77 kHz hsync */
							     NULL, 85,
							     1600, 1200,
							     4545, 272, 16,
							     37, 4, 192, 3,
							     FB_SYNC_HOR_HIGH_ACT
							     |
							     FB_SYNC_VERT_HIGH_ACT,
							     FB_VMODE_NONINTERLACED},
	{
	 /* 1280x1024 @ 100 Hz, 107.16 kHz hsync */
	 NULL, 100, 1280, 1024, 5502, 256, 32, 26, 7, 128, 15,
	 0, FB_VMODE_NONINTERLACED}, {
				      /* 1800x1440 @ 64Hz, 96.15 kHz hsync  */
				      NULL, 64, 1800, 1440, 4347, 304, 96,
				      46, 1, 192, 3,
				      FB_SYNC_HOR_HIGH_ACT |
				      FB_SYNC_VERT_HIGH_ACT,
				      FB_VMODE_NONINTERLACED}, {
								/* 1800x1440 @ 70Hz, 104.52 kHz hsync  */
								NULL, 70,
								1800, 1440,
								4000, 304,
								96, 46, 1,
								192, 3,
								FB_SYNC_HOR_HIGH_ACT
								|
								FB_SYNC_VERT_HIGH_ACT,
								FB_VMODE_NONINTERLACED},
	{
	 /* 512x384 @ 78 Hz, 31.50 kHz hsync */
	 NULL, 78, 512, 384, 49603, 48, 16, 16, 1, 64, 3,
	 0, FB_VMODE_NONINTERLACED}, {
				      /* 512x384 @ 85 Hz, 34.38 kHz hsync */
				      NULL, 85, 512, 384, 45454, 48, 16,
				      16, 1, 64, 3,
				      0, FB_VMODE_NONINTERLACED}, {
								   /* 320x200 @ 70 Hz, 31.5 kHz hsync, 8:5 aspect ratio */
								   NULL,
								   70, 320,
								   200,
								   79440,
								   16, 16,
								   20, 4,
								   48, 1,
								   0,
								   FB_VMODE_DOUBLE},
	{
	 /* 320x240 @ 60 Hz, 31.5 kHz hsync, 4:3 aspect ratio */
	 NULL, 60, 320, 240, 79440, 16, 16, 16, 5, 48, 1,
	 0, FB_VMODE_DOUBLE}, {
			       /* 320x240 @ 72 Hz, 36.5 kHz hsync */
			       NULL, 72, 320, 240, 63492, 16, 16, 16, 4,
			       48, 2,
			       0, FB_VMODE_DOUBLE}, {
						     /* 400x300 @ 56 Hz, 35.2 kHz hsync, 4:3 aspect ratio */
						     NULL, 56, 400, 300,
						     55555, 64, 16, 10, 1,
						     32, 1,
						     0, FB_VMODE_DOUBLE}, {
									   /* 400x300 @ 60 Hz, 37.8 kHz hsync */
									   NULL,
									   60,
									   400,
									   300,
									   50000,
									   48,
									   16,
									   11,
									   1,
									   64,
									   2,
									   0,
									   FB_VMODE_DOUBLE},
	{
	 /* 400x300 @ 72 Hz, 48.0 kHz hsync */
	 NULL, 72, 400, 300, 40000, 32, 24, 11, 19, 64, 3,
	 0, FB_VMODE_DOUBLE}, {
			       /* 480x300 @ 56 Hz, 35.2 kHz hsync, 8:5 aspect ratio */
			       NULL, 56, 480, 300, 46176, 80, 16, 10, 1,
			       40, 1,
			       0, FB_VMODE_DOUBLE}, {
						     /* 480x300 @ 60 Hz, 37.8 kHz hsync */
						     NULL, 60, 480, 300,
						     41858, 56, 16, 11, 1,
						     80, 2,
						     0, FB_VMODE_DOUBLE}, {
									   /* 480x300 @ 63 Hz, 39.6 kHz hsync */
									   NULL,
									   63,
									   480,
									   300,
									   40000,
									   56,
									   16,
									   11,
									   1,
									   80,
									   2,
									   0,
									   FB_VMODE_DOUBLE},
	{
	 /* 480x300 @ 72 Hz, 48.0 kHz hsync */
	 NULL, 72, 480, 300, 33386, 40, 24, 11, 19, 80, 3,
	 0, FB_VMODE_DOUBLE},
};
static const int nmodedb2 = sizeof(modedb2);
