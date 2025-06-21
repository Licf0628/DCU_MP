// m3_hcsAcce_api.h
#ifndef M3_HCS_ACCE_API_H
#define M3_HCS_ACCE_API_H

#include "m3_env.h"         // wasm3 环境定义
#include <hcsAcce/hcsAcce_c_api.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SM2_PUBKEY_SIZE 128
#define SM2_SIG_SIZE    128
#define SM2_MSG_SIZE    64
#define SM2_RES_SIZE    32

// SM2 验证操作
	int m3_sm2_verify(m3stack_t _sp, M3MemoryHeader* _mem,u32 pubkeyOffset, u32 sigOffset, 
					u32 msgOffset, u32 len, u32 size, u32 resultsOffset, C_DeviceType deviceType);
#ifdef __cplusplus
}
#endif

#endif // M3_HCS_ACCE_API_H