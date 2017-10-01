#ifndef __FINDNONCE_H__
#define __FINDNONCE_H__
#include "miner.h"
#include "config.h"

#define MAXTHREADS (0xFFFFFFFEULL)
#define MAXBUFFERS (0x100)
#define BUFFERSIZE (sizeof(uint32_t) * MAXBUFFERS)
#define FOUND (0xFF)

#ifdef HAVE_OPENCL
#ifdef USE_SHA256D
extern void precalc_hash(dev_blk_ctx *blk, uint32_t *state, uint32_t *data);
#endif /* USE_SHA256D */
extern void postcalc_hash_async(struct thr_info *thr, struct work *work, uint32_t *res);
#endif /* HAVE_OPENCL */
#endif /*__FINDNONCE_H__*/
