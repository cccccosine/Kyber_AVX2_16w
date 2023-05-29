#ifndef SIXTEEN_WAY_CONSTS_H
#define SIXTEEN_WAY_CONSTS_H

#include "params.h"

#define _16XQ_16           0
#define _16XQINV_16        4080
#define _16XFLO_16         6144
#define _16XFHI_16         6160
#define _16XV_16           6176
#define _16XMONTSQLO_16    6192
#define _16XMONTSQHI_16    6208
// #define _16XMASK       112
 #define _ZETAS_EXP_16     16
//#define	_16XSHIFT      624


#define _ZETAS_BASEMUL 4096


/* The C ABI on MacOS exports all symbols with a leading
 * underscore. This means that any symbols we refer to from
 * C files (functions) can't be found, and all symbols we
 * refer to from ASM also can't be found.
 *
 * This define helps us get around this
 */
#ifdef __ASSEMBLER__
#if defined(__WIN32__) || defined(__APPLE__)
#define decorate(s) _##s
#define cdecl2(s) decorate(s)
#define cdecl(s) cdecl2(KYBER_NAMESPACE(##s))
#else
#define cdecl(s) KYBER_NAMESPACE(##s)
#endif
#endif

#ifndef __ASSEMBLER__
#include "align.h"
typedef ALIGNED_INT16(6224) qdata_t_16;     //6144是到basemul结束所需的qdata
#define qdata_16 KYBER_NAMESPACE(qdata_16)
extern const qdata_t_16 qdata_16;
#endif

#endif