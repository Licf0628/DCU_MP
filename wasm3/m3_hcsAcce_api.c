// m3_hcsAcce_api.c
#include "m3_hcsAcce_api.h"
#include "m3_env.h"
#include "m3_exception.h"
#include "m3_info.h"
#include <stdio.h>
C_SM2_POINT mPubKey = {
    {
        0xF2, 0x94, 0xB7, 0x10, 0x60, 0x1D, 0xE1, 0xC5,
        0xD3, 0x44, 0x20, 0xC4, 0x90, 0x2D, 0x81, 0xC3,
        0xA3, 0x06, 0x44, 0x90, 0x3E, 0x57, 0x99, 0xBF,
        0xE4, 0x01, 0x3E, 0x56, 0xC5, 0x5C, 0x86, 0x4C
    },
    {
        0x5C, 0x00, 0x3E, 0xB1, 0xB5, 0x0B, 0x9B, 0xBB,
        0x2E, 0x88, 0x07, 0x78, 0x2A, 0xA3, 0xC3, 0x8E,
        0xA8, 0x00, 0xE2, 0x3B, 0x30, 0xB7, 0x77, 0xFA,
        0xAD, 0x8F, 0x0F, 0x71, 0x46, 0xD6, 0x6A, 0xC1
    }
};


// SM2 验证操作实现
int m3_sm2_verify(m3stack_t _sp, M3MemoryHeader* _mem,u32 pubkeyOffset, u32 sigOffset,
                       u32 msgOffset, u32 len, u32 size, u32 resultsOffset,C_DeviceType deviceType) {


    // 获取线性内存数据指针
    u8* memData = m3MemData(_mem);
    const void* pubkey = memData + pubkeyOffset;
    const void* sig = memData + sigOffset;
    const void* msg = memData + msgOffset;
    u32* results = (u32*)(memData + resultsOffset);

    // 调试输出
    printf("pubkey: 0x%x, sig: 0x%x, msg: 0x%x, len: %u, size: %u, results: 0x%x\n",
        *(u32*)pubkey, *(u32*)sig, *(u32*)msg, len, size, *results);

    // 获取 HcsManager 实例
    void* hcs_mgr = hcs_manager_instance();
    if (!hcs_mgr) {
        fprintf(stderr, "Failed to get HcsManager instance\n");
        return -1;
    }

    // 初始化设备（假设已在其他地方初始化，此处仅检查）
    if (hcs_init_device(hcs_mgr) != 0) {
        fprintf(stderr, "Failed to initialize HCS device\n");
        return -2;
    }

    // 创建输出缓冲区
    C_SIGN_BUFFER** c_sign = malloc(sizeof(C_SIGN_BUFFER*) * size);
    C_RESULT_BUFFER** c_result = malloc(sizeof(C_RESULT_BUFFER*) * size);

    for (int i = 0; i < size; i++) {
        c_sign[i] = hcs_create_sign_buffer();
        c_result[i] = hcs_create_result_buffer();

        memcpy(c_sign[i]->msg, msg+64*i, 64);
        c_sign[i]->msgLen = len;
        memcpy(c_sign[i]->sigR, (u8*)sig+128*i, 64);
        memcpy(c_sign[i]->sigS, (u8*)sig +128*i+64, 64);
        
        memcpy(c_sign[i]->pubKeyAx, (u8*)pubkey+128*i, 64);
        memcpy(c_sign[i]->pubKeyAy, (u8*)pubkey +128*i+ 64, 64);
        
        memcpy(c_sign[i]->base.IDA, "Alice", 5);
        c_sign[i]->base.IDALen = 5;
        
    }
    HcsStatus status = HCS_ERROR;
    //status= hcs_verify_sign(hcs_mgr, c_sign, c_result, &mPubKey, size, C_DEVICE_CPU);
     status = hcs_verify_sign(hcs_mgr, c_sign, c_result, &mPubKey, size, deviceType);

    // 写回结果到 WebAssembly 内存
    for (u32 i = 0; i < size; i++) {
        results[i] = c_result[i]->result;
    }

    // 释放资源
    for (int i = 0; i < size; i++) {
        hcs_free_sign_buffer(c_sign[i]);
        hcs_free_result_buffer(c_result[i]);

    }

    // 设置返回值并继续执行
    return  (int)status;
    
}