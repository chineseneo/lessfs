/*
 *   Lessfs: A data deduplicating filesystem.
 *   Copyright (C) 2008 Mark Ruijter <mruijter@lessfs.com>
 *
 *   This program is free software.
 *   You can redistribute lessfs and/or modify it under the terms of either
 *   (1) the GNU General Public License; either version 3 of the License,
 *   or (at your option) any later version as published by
 *   the Free Software Foundation; or (2) obtain a commercial license
 *   by contacting the Author.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

 *   Tiger has no usage restrictions nor patents. 
 *   It can be used freely, with the reference implementation,
 *   with other implementations or with a modification to the 
 *   reference implementation
 */

typedef unsigned long long int word64;
typedef unsigned long word32;
typedef unsigned char byte;

/* Big endian:                                         */
#if !(defined(__alpha)||defined(__i386__)||defined(__vax__))
#define BIG_ENDIAN
#endif

/* The following macro denotes that an optimization    */
/* for Alpha is required. It is used only for          */
/* optimization of time. Otherwise it does nothing.    */
#ifdef __alpha
#define OPTIMIZE_FOR_ALPHA
#endif

/* NOTE that this code is NOT FULLY OPTIMIZED for any  */
/* machine. Assembly code might be much faster on some */
/* machines, especially if the code is compiled with   */
/* gcc.                                                */

/* The number of passes of the hash function.          */
/* Three passes are recommended.                       */
/* Use four passes when you need extra security.       */
/* Must be at least three.                             */
#define PASSES 3
#define CHAR_OFFSET 0

extern word64 table[4 * 256];

#define t1 (table)
#define t2 (table+256)
#define t3 (table+256*2)
#define t4 (table+256*3)

#define save_abc \
      aa = a; \
      bb = b; \
      cc = c;

#ifdef OPTIMIZE_FOR_ALPHA
/* This is the official definition of round */
#define round(a,b,c,x,mul) \
      c ^= x; \
      a -= t1[((c)>>(0*8))&0xFF] ^ t2[((c)>>(2*8))&0xFF] ^ \
	   t3[((c)>>(4*8))&0xFF] ^ t4[((c)>>(6*8))&0xFF] ; \
      b += t4[((c)>>(1*8))&0xFF] ^ t3[((c)>>(3*8))&0xFF] ^ \
	   t2[((c)>>(5*8))&0xFF] ^ t1[((c)>>(7*8))&0xFF] ; \
      b *= mul;
#else
/* This code works faster when compiled on 32-bit machines */
/* (but works slower on Alpha) */
#define round(a,b,c,x,mul) \
      c ^= x; \
      a -= t1[(byte)(c)] ^ \
           t2[(byte)(((word32)(c))>>(2*8))] ^ \
	   t3[(byte)((c)>>(4*8))] ^ \
           t4[(byte)(((word32)((c)>>(4*8)))>>(2*8))] ; \
      b += t4[(byte)(((word32)(c))>>(1*8))] ^ \
           t3[(byte)(((word32)(c))>>(3*8))] ^ \
	   t2[(byte)(((word32)((c)>>(4*8)))>>(1*8))] ^ \
           t1[(byte)(((word32)((c)>>(4*8)))>>(3*8))]; \
      b *= mul;
#endif

#define pass(a,b,c,mul) \
      round(a,b,c,x0,mul) \
      round(b,c,a,x1,mul) \
      round(c,a,b,x2,mul) \
      round(a,b,c,x3,mul) \
      round(b,c,a,x4,mul) \
      round(c,a,b,x5,mul) \
      round(a,b,c,x6,mul) \
      round(b,c,a,x7,mul)

#define key_schedule \
      x0 -= x7 ^ 0xA5A5A5A5A5A5A5A5LL; \
      x1 ^= x0; \
      x2 += x1; \
      x3 -= x2 ^ ((~x1)<<19); \
      x4 ^= x3; \
      x5 += x4; \
      x6 -= x5 ^ ((~x4)>>23); \
      x7 ^= x6; \
      x0 += x7; \
      x1 -= x0 ^ ((~x7)<<19); \
      x2 ^= x1; \
      x3 += x2; \
      x4 -= x3 ^ ((~x2)>>23); \
      x5 ^= x4; \
      x6 += x5; \
      x7 -= x6 ^ 0x0123456789ABCDEFLL;

#define feedforward \
      a ^= aa; \
      b -= bb; \
      c += cc;

#ifdef OPTIMIZE_FOR_ALPHA
/* The loop is unrolled: works better on Alpha */
#define compress \
      save_abc \
      pass(a,b,c,5) \
      key_schedule \
      pass(c,a,b,7) \
      key_schedule \
      pass(b,c,a,9) \
      for(pass_no=3; pass_no<PASSES; pass_no++) { \
        key_schedule \
	pass(a,b,c,9) \
	tmpa=a; a=c; c=b; b=tmpa;} \
      feedforward
#else
/* loop: works better on PC and Sun (smaller cache?) */
#define compress \
      save_abc \
      for(pass_no=0; pass_no<PASSES; pass_no++) { \
        if(pass_no != 0) {key_schedule} \
	pass(a,b,c,(pass_no==0?5:pass_no==1?7:9)); \
	tmpa=a; a=c; c=b; b=tmpa;} \
      feedforward
#endif

#define tiger_compress_macro(str, state) \
{ \
  register word64 a, b, c, tmpa; \
  word64 aa, bb, cc; \
  register word64 x0, x1, x2, x3, x4, x5, x6, x7; \
  int pass_no; \
\
  a = state[0]; \
  b = state[1]; \
  c = state[2]; \
\
  x0=str[0]; x1=str[1]; x2=str[2]; x3=str[3]; \
  x4=str[4]; x5=str[5]; x6=str[6]; x7=str[7]; \
\
  compress; \
\
  state[0] = a; \
  state[1] = b; \
  state[2] = c; \
}

/* The compress function is a function. Requires smaller cache?    */
void tiger_compress(word64 * str, word64 state[3])
{
    tiger_compress_macro(((word64 *) str), ((word64 *) state));
}

#ifdef OPTIMIZE_FOR_ALPHA
/* The compress function is inlined: works better on Alpha.        */
/* Still leaves the function above in the code, in case some other */
/* module calls it directly.                                       */
#define tiger_compress(str, state) \
  tiger_compress_macro(((word64*)str), ((word64*)state))
#endif

void tiger(word64 * str, word64 length, word64 res[3])
{
    register word64 i, j;
    unsigned char temp[64];

    res[0] = 0x0123456789ABCDEFLL;
    res[1] = 0xFEDCBA9876543210LL;
    res[2] = 0xF096A5B4C3B2E187LL;

    for (i = length; i >= 64; i -= 64) {
#ifdef BIG_ENDIAN
        for (j = 0; j < 64; j++)
            temp[j ^ 7] = ((byte *) str)[j];
        tiger_compress(((word64 *) temp), res);
#else
        tiger_compress(str, res);
#endif
        str += 8;
    }

#ifdef BIG_ENDIAN
    for (j = 0; j < i; j++)
        temp[j ^ 7] = ((byte *) str)[j];

    temp[j ^ 7] = 0x01;
    j++;
    for (; j & 7; j++)
        temp[j ^ 7] = 0;
#else
    for (j = 0; j < i; j++)
        temp[j] = ((byte *) str)[j];

    temp[j++] = 0x01;
    for (; j & 7; j++)
        temp[j] = 0;
#endif
    if (j > 56) {
        for (; j < 64; j++)
            temp[j] = 0;
        tiger_compress(((word64 *) temp), res);
        j = 0;
    }

    for (; j < 56; j++)
        temp[j] = 0;
    ((word64 *) (&(temp[56])))[0] = ((word64) length) << 3;
    tiger_compress(((word64 *) temp), res);
}

/*
 *   a simple 32 bit checksum that can be upadted from either end
 *   (inspired by Mark Adler's Adler-32 checksum)
 */
unsigned int adler32_checksum(char *buf, int len)
{
    int i;
    unsigned int s1, s2;

    s1 = s2 = 0;
    for (i = 0; i < (len - 4); i += 4) {
        s2 += 4 * (s1 + buf[i]) + 3 * buf[i+1] + 2 * buf[i+2] + buf[i+3] +
          10 * CHAR_OFFSET;
        s1 += (buf[i+0] + buf[i+1] + buf[i+2] + buf[i+3] + 4 * CHAR_OFFSET);
    }
    for (; i < len; i++) {
        s1 += (buf[i]+CHAR_OFFSET); 
	s2 += s1;
    }

    return (s1 & 0xffff) + (s2 << 16);
}

/*
 * adler32_checksum(X0, ..., Xn), X0, Xn+1 ----> adler32_checksum(X1, ..., Xn+1)
 * where csum is adler32_checksum(X0, ..., Xn), c1 is X0, c2 is Xn+1
 */
unsigned int adler32_rolling_checksum(unsigned int csum, int len, char c1, 
	char c2)
{
	unsigned int s1, s2, s11, s22;

	s1 = csum & 0xffff;
	s2 = csum >> 16;
	s1 -= (c1 - c2);
	s2 -= (len * c1 - s1);

	return (s1 & 0xffff) + (s2 << 16);
}

