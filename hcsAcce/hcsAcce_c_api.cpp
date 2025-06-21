// hcsAcce_c_api.c
#include <hcsAcce/hcsAcce_c_api.h>
#include <hcsAcce/hcsManager.h> // HcsManager 的头文件
#include "dataType.h"  // 数据类型的头文件
#include <stdlib.h>     // 提供 malloc/free
#include <string.h>     // 提供 memcpy




// 对齐检查宏
#define CHECK_ALIGNMENT(C_TYPE, CPP_TYPE) \
    static_assert(sizeof(C_TYPE) == sizeof(CPP_TYPE), "Size mismatch between " #C_TYPE " and " #CPP_TYPE); \
    static_assert(_Alignof(C_TYPE) == _Alignof(CPP_TYPE), "Alignment mismatch between " #C_TYPE " and " #CPP_TYPE)

// C 到 C++ 的转换函数
static UA_BUFFER* c_to_cpp_ua_buffer(const C_UA_BUFFER* c_buf) {
    UA_BUFFER* cpp_buf = new UA_BUFFER();
    memcpy(cpp_buf->IDA, c_buf->base.IDA, MAX_ID_LEN_SIZE);
    cpp_buf->IDALen = c_buf->base.IDALen;
    cpp_buf->type = c_buf->base.type;
    cpp_buf->socketFd = c_buf->base.socketFd;
    memcpy(cpp_buf->UAx, c_buf->UAx, 64);
    memcpy(cpp_buf->UAy, c_buf->UAy, 64);
    return cpp_buf;
}

static WATA_BUFFER* c_to_cpp_wata_buffer(const C_WATA_BUFFER* c_buf) {
    WATA_BUFFER* cpp_buf = new WATA_BUFFER();
    memcpy(cpp_buf->IDA, c_buf->base.IDA, MAX_ID_LEN_SIZE);
    cpp_buf->IDALen = c_buf->base.IDALen;
    cpp_buf->type = c_buf->base.type;
    cpp_buf->socketFd = c_buf->base.socketFd;
    memcpy(cpp_buf->WAx, c_buf->WAx, 64);
    memcpy(cpp_buf->WAy, c_buf->WAy, 64);
    memcpy(cpp_buf->TA, c_buf->TA, 64);
    return cpp_buf;
}

static SIGN_BUFFER* c_to_cpp_sign_buffer(const C_SIGN_BUFFER* c_buf) {
    SIGN_BUFFER* cpp_buf = new SIGN_BUFFER();
    memcpy(cpp_buf->IDA, c_buf->base.IDA, MAX_ID_LEN_SIZE);
    cpp_buf->IDALen = c_buf->base.IDALen;
    cpp_buf->type = c_buf->base.type;
    cpp_buf->socketFd = c_buf->base.socketFd;
    memcpy(cpp_buf->msg, c_buf->msg, MAX_SIGN_MSG_SIZE);
    cpp_buf->msgLen = c_buf->msgLen;
    memcpy(cpp_buf->sigR, c_buf->sigR, 64);
    memcpy(cpp_buf->sigS, c_buf->sigS, 64);
    memcpy(cpp_buf->pubKeyAx, c_buf->pubKeyAx, 64);
    memcpy(cpp_buf->pubKeyAy, c_buf->pubKeyAy, 64);
    return cpp_buf;
}

static RESULT_BUFFER* c_to_cpp_result_buffer(const C_RESULT_BUFFER* c_buf) {
    RESULT_BUFFER* cpp_buf = new RESULT_BUFFER();
    memcpy(cpp_buf->IDA, c_buf->base.IDA, MAX_ID_LEN_SIZE);
    cpp_buf->IDALen = c_buf->base.IDALen;
    cpp_buf->type = c_buf->base.type;
    cpp_buf->socketFd = c_buf->base.socketFd;
    cpp_buf->result = c_buf->result;
    return cpp_buf;
}

// C++ 到 C 的转换函数（用于输出参数）
static void cpp_to_c_ua_buffer(UA_BUFFER* cpp_buf, C_UA_BUFFER* c_buf) {
    memcpy(c_buf->base.IDA, cpp_buf->IDA, MAX_ID_LEN_SIZE);
    c_buf->base.IDALen = cpp_buf->IDALen;
    c_buf->base.type = cpp_buf->type;
    c_buf->base.socketFd = cpp_buf->socketFd;
    memcpy(c_buf->UAx, cpp_buf->UAx, 64);
    memcpy(c_buf->UAy, cpp_buf->UAy, 64);
}

static void cpp_to_c_wata_buffer(WATA_BUFFER* cpp_buf, C_WATA_BUFFER* c_buf) {
    memcpy(c_buf->base.IDA, cpp_buf->IDA, MAX_ID_LEN_SIZE);
    c_buf->base.IDALen = cpp_buf->IDALen;
    c_buf->base.type = cpp_buf->type;
    c_buf->base.socketFd = cpp_buf->socketFd;
    memcpy(c_buf->WAx, cpp_buf->WAx, 64);
    memcpy(c_buf->WAy, cpp_buf->WAy, 64);
    memcpy(c_buf->TA, cpp_buf->TA, 64);
}

static void cpp_to_c_sign_buffer(SIGN_BUFFER* cpp_buf, C_SIGN_BUFFER* c_buf) {
    memcpy(c_buf->base.IDA, cpp_buf->IDA, MAX_ID_LEN_SIZE);
    c_buf->base.IDALen = cpp_buf->IDALen;
    c_buf->base.type = cpp_buf->type;
    c_buf->base.socketFd = cpp_buf->socketFd;
    memcpy(c_buf->msg, cpp_buf->msg, MAX_SIGN_MSG_SIZE);
    c_buf->msgLen = cpp_buf->msgLen;
    memcpy(c_buf->sigR, cpp_buf->sigR, 64);
    memcpy(c_buf->sigS, cpp_buf->sigS, 64);
    memcpy(c_buf->pubKeyAx, cpp_buf->pubKeyAx, 64);
    memcpy(c_buf->pubKeyAy, cpp_buf->pubKeyAy, 64);
}

static void cpp_to_c_result_buffer(RESULT_BUFFER* cpp_buf, C_RESULT_BUFFER* c_buf) {
    memcpy(c_buf->base.IDA, cpp_buf->IDA, MAX_ID_LEN_SIZE);
    c_buf->base.IDALen = cpp_buf->IDALen;
    c_buf->base.type = cpp_buf->type;
    c_buf->base.socketFd = cpp_buf->socketFd;
    c_buf->result = cpp_buf->result;
}

// 对齐检查（仅在 C++ 编译时有效）
#ifdef __cplusplus
//CHECK_ALIGNMENT(C_SM2_KEY, SM2_KEY);
//CHECK_ALIGNMENT(C_SM2_POINT, SM2_POINT);
#endif

// 获取 HcsManager 单例
void* hcs_manager_instance() {
    return (void*)HcsManager::Instance();
}

// 初始化设备
int hcs_init_device(void* manager) {
    if (!manager) return -1;
    return ((HcsManager*)manager)->initDevice() ? 0 : -1;
}

// 生成 WATA
HcsStatus hcs_gen_wata(void* manager, C_UA_BUFFER** uaBuffer, C_WATA_BUFFER** wataBuffer, const C_SM2_KEY* mKeyPair, uint32_t size, C_DeviceType devType) {
    if (!manager || !uaBuffer || !wataBuffer || !mKeyPair) return HCS_ERROR;

    UA_BUFFER* cpp_ua = NULL;
    WATA_BUFFER* cpp_wata = NULL;
    SM2_KEY* cpp_key = (SM2_KEY*)mKeyPair; // 直接强制转换
    HcsStatus status = (HcsStatus)((HcsManager*)manager)->genWATA(&cpp_ua, &cpp_wata, cpp_key, size,(DeviceType) devType);
    if (status == HCS_OK) {
        *uaBuffer = (C_UA_BUFFER*)malloc(sizeof(C_UA_BUFFER));
        *wataBuffer = (C_WATA_BUFFER*)malloc(sizeof(C_WATA_BUFFER));
        cpp_to_c_ua_buffer(cpp_ua, *uaBuffer);
        cpp_to_c_wata_buffer(cpp_wata, *wataBuffer);
        delete cpp_ua;
        delete cpp_wata;
    }
    return status;
}

// 生成签名
HcsStatus hcs_gen_sign(void* manager, C_SIGN_BUFFER* genSignBuffer, const C_SM2_POINT* mPubKey, 
                        const C_SM2_KEY* keyPair, uint32_t size, C_DeviceType devType) {
    if (!manager || !genSignBuffer || !mPubKey || !keyPair) return HCS_ERROR;

    SIGN_BUFFER* cpp_sign = c_to_cpp_sign_buffer(genSignBuffer);
    SM2_POINT* cpp_pub_key = (SM2_POINT*)mPubKey; // 直接强制转换
    SM2_KEY* cpp_key = (SM2_KEY*)keyPair;         // 直接强制转换
    HcsStatus status = (HcsStatus)((HcsManager*)manager)->genSign(cpp_sign, cpp_pub_key, cpp_key, size,(DeviceType) devType);
    if (status == HCS_OK) {
        cpp_to_c_sign_buffer(cpp_sign, genSignBuffer);
    }
    delete cpp_sign;
    return status;
}

// 验证签名
HcsStatus hcs_verify_sign(void* manager, C_SIGN_BUFFER** verifySignBuffer, C_RESULT_BUFFER** resultBuffer,
                        const C_SM2_POINT* mPubKey, uint32_t size, C_DeviceType devType) {
    if (!manager || !verifySignBuffer || !resultBuffer || !mPubKey || size == 0) return HCS_ERROR;

    // 转换输入的 C_SIGN_BUFFER 数组为 SIGN_BUFFER 数组
    SIGN_BUFFER** cpp_sign_array = new SIGN_BUFFER*[size];
    RESULT_BUFFER** cpp_result = new RESULT_BUFFER*[size];
    if (!cpp_sign_array) return HCS_ERROR;

    for (uint32_t i = 0; i < size; i++) {
        if (!verifySignBuffer[i]) { // 检查每个输入是否有效
            delete cpp_sign_array[i];
            return HCS_ERROR;
        }
        cpp_sign_array[i] = c_to_cpp_sign_buffer(verifySignBuffer[i]);
        cpp_result[i] = new RESULT_BUFFER;
    }

   
    SM2_POINT* cpp_pub_key = (SM2_POINT*)mPubKey; // 直接强制转换

    // 调用 HcsManager::verifySign，假设新签名只返回 RESULT_BUFFER*
    HcsStatus status = (HcsStatus)((HcsManager*)manager)->verifySign(cpp_sign_array, cpp_result, cpp_pub_key, size, (DeviceType)devType);

    if (status == HCS_OK) {
        // 转换输出为 C 结构体
        for (int i = 0; i < size; i++) {
            cpp_to_c_result_buffer(cpp_result[i], resultBuffer[i]);
        }
    }

    // 释放临时转换的 SIGN_BUFFER 数组
    for (uint32_t i = 0; i < size; i++) {
        delete cpp_sign_array[i];
        delete cpp_result[i];
    }
    free(cpp_sign_array);
    free(cpp_result);
    return status;
}

// 负载均衡计算
int hcs_balance_computing(void* manager, C_DeviceType devType, uint32_t size) {
    if (!manager) return -1;
    return ((HcsManager*)manager)->balanceComputing((DeviceType)devType, size);
}

// 获取设备列表信息
void hcs_get_dev_list_info(void* manager) {
    if (manager) {
        ((HcsManager*)manager)->getDevListInfo();
    }
}

// 获取设备类型数量
int hcs_get_type_size(void* manager) {
    if (!manager) return -1;
    return ((HcsManager*)manager)->getHcsTypeSize();
}

// 检查设备是否加载
int hcs_get_is_loaded(void* manager, C_DeviceType type) {
    if (!manager) return 0;
    return ((HcsManager*)manager)->getIsLoaded((DeviceType)type) ? 1 : 0;
}

// 检查设备是否忙碌
int hcs_get_is_busy(void* manager, C_DeviceType type) {
    if (!manager) return 1;
    return ((HcsManager*)manager)->getIsBusy((DeviceType)type) ? 1 : 0;
}

// 构造函数和析构函数
C_UA_BUFFER* hcs_create_ua_buffer() {
    C_UA_BUFFER* c_buf = (C_UA_BUFFER*)malloc(sizeof(C_UA_BUFFER));
    memset(c_buf, 0, sizeof(C_UA_BUFFER));
    return c_buf;
}

void hcs_free_ua_buffer(C_UA_BUFFER* ptr) {
    if (ptr) free(ptr);
}

C_WATA_BUFFER* hcs_create_wata_buffer() {
    C_WATA_BUFFER* c_buf = (C_WATA_BUFFER*)malloc(sizeof(C_WATA_BUFFER));
    memset(c_buf, 0, sizeof(C_WATA_BUFFER));
    return c_buf;
}

void hcs_free_wata_buffer(C_WATA_BUFFER* ptr) {
    if (ptr) free(ptr);
}

C_SIGN_BUFFER* hcs_create_sign_buffer() {
    C_SIGN_BUFFER* c_buf = (C_SIGN_BUFFER*)malloc(sizeof(C_SIGN_BUFFER));
    memset(c_buf, 0, sizeof(C_SIGN_BUFFER));
    return c_buf;
}

void hcs_free_sign_buffer(C_SIGN_BUFFER* ptr) {
    if (ptr) free(ptr);
}

C_RESULT_BUFFER* hcs_create_result_buffer() {
    C_RESULT_BUFFER* c_buf = (C_RESULT_BUFFER*)malloc(sizeof(C_RESULT_BUFFER));
    memset(c_buf, 0, sizeof(C_RESULT_BUFFER));
    return c_buf;
}

void hcs_free_result_buffer(C_RESULT_BUFFER* ptr) {
    if (ptr) free(ptr);
}

C_SM2_KEY* hcs_create_sm2_key() {
    C_SM2_KEY* c_key = (C_SM2_KEY*)malloc(sizeof(C_SM2_KEY));
    memset(c_key, 0, sizeof(C_SM2_KEY));
    return c_key;
}

void hcs_free_sm2_key(C_SM2_KEY* ptr) {
    if (ptr) free(ptr);
}

C_SM2_POINT* hcs_create_sm2_point() {
    C_SM2_POINT* c_point = (C_SM2_POINT*)malloc(sizeof(C_SM2_POINT));
    memset(c_point, 0, sizeof(C_SM2_POINT));
    return c_point;
}

void hcs_free_sm2_point(C_SM2_POINT* ptr) {
    if (ptr) free(ptr);
}