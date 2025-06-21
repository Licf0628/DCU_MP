// hcsAcce_c_api.h
#ifndef HCS_ACCE_C_API_H
#define HCS_ACCE_C_API_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h> // 提供 uint32_t 等类型

    // 定义 C 兼容的常量（假设值，需与 config.h 一致）
#ifndef MAX_ID_LEN_SIZE
#define MAX_ID_LEN_SIZE 32
#endif
#ifndef MAX_SIGN_MSG_SIZE
#define MAX_SIGN_MSG_SIZE 1024
#endif

// C 结构体定义，与 C++ 类对应
    typedef struct {
        uint8_t IDA[MAX_ID_LEN_SIZE];   // 用户ID
        uint16_t IDALen;                // 用户ID长度
        uint8_t type;
        uint32_t socketFd;              // 套接字端口
    } C_BASE_BUFFER;

    typedef struct {
        C_BASE_BUFFER base;             // 继承基础字段
        uint8_t UAx[64];
        uint8_t UAy[64];
    } C_UA_BUFFER;

    typedef struct {
        C_BASE_BUFFER base;             // 继承基础字段
        uint8_t WAx[64];
        uint8_t WAy[64];
        uint8_t TA[64];
    } C_WATA_BUFFER;

    typedef struct {
        C_BASE_BUFFER base;             // 继承基础字段
        uint8_t msg[MAX_SIGN_MSG_SIZE]; // 签名原始信息
        uint16_t msgLen;                // 信息长度
        uint8_t sigR[64];               // 待验证签名
        uint8_t sigS[64];
        uint8_t pubKeyAx[64];           // 待验证用户声明公钥
        uint8_t pubKeyAy[64];
    } C_SIGN_BUFFER;

    typedef struct {
        C_BASE_BUFFER base;             // 继承基础字段
        uint8_t result;                 // 验签结果
    } C_RESULT_BUFFER;

    // SM2_KEY 和 SM2_POINT 的 C 结构体（假设典型 SM2 结构）
    

    typedef struct {
        uint8_t x[32];                  // SM2 公钥的 x 坐标
        uint8_t y[32];                  // SM2 公钥的 y 坐标
    } C_SM2_POINT;

    typedef struct {
        C_SM2_POINT public_key;
        uint8_t private_key[32];
    } C_SM2_KEY;
    // 枚举类型（与 C++ 中的 DeviceType 一致）
    typedef enum {
        C_DEVICE_CPU = 0,
        C_DEVICE_CCP = 1,
        C_DEVICE_DCU = 2,
        C_DEVICE_HCS = 3
    } C_DeviceType;

    // 返回状态类型（与 AcceStatus 对应）
    typedef enum {
        HCS_OK = 0,
        HCS_ERROR = -1,
    } HcsStatus;

    // HcsManager 相关函数
    void* hcs_manager_instance();
    int hcs_init_device(void* manager);
    HcsStatus hcs_gen_wata(void* manager, C_UA_BUFFER** uaBuffer, C_WATA_BUFFER** wataBuffer, const C_SM2_KEY* mKeyPair, uint32_t size, C_DeviceType devType);
    HcsStatus hcs_gen_sign(void* manager, C_SIGN_BUFFER* genSignBuffer, const C_SM2_POINT* mPubKey, const C_SM2_KEY* keyPair, uint32_t size, C_DeviceType devType);
    HcsStatus hcs_verify_sign(void* manager, C_SIGN_BUFFER** verifySignBuffer, C_RESULT_BUFFER** resultBuffer, const C_SM2_POINT* mPubKey, uint32_t size, C_DeviceType devType);
    int hcs_balance_computing(void* manager, C_DeviceType devType, uint32_t size);
    void hcs_get_dev_list_info(void* manager);
    int hcs_get_type_size(void* manager);
    int hcs_get_is_loaded(void* manager, C_DeviceType type);
    int hcs_get_is_busy(void* manager, C_DeviceType type);

    // 构造函数和析构函数
    C_UA_BUFFER* hcs_create_ua_buffer();
    void hcs_free_ua_buffer(C_UA_BUFFER* ptr);

    C_WATA_BUFFER* hcs_create_wata_buffer();
    void hcs_free_wata_buffer(C_WATA_BUFFER* ptr);

    C_SIGN_BUFFER* hcs_create_sign_buffer();
    void hcs_free_sign_buffer(C_SIGN_BUFFER* ptr);

    C_RESULT_BUFFER* hcs_create_result_buffer();
    void hcs_free_result_buffer(C_RESULT_BUFFER* ptr);

    C_SM2_KEY* hcs_create_sm2_key();
    void hcs_free_sm2_key(C_SM2_KEY* ptr);

    C_SM2_POINT* hcs_create_sm2_point();
    void hcs_free_sm2_point(C_SM2_POINT* ptr);

#ifdef __cplusplus
}
#endif

#endif // HCS_ACCE_C_API_H