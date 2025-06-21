#include <clpkm/clpkm.h>
#include<hcsAcce/comDevice.h>
#include <thread>

#ifndef __CPU_DEVICE_H__
#define __CPU_DEVICE_H__
/**************************************************************************
 * 功能：CPU执行设备类,直接继承CLPKM_COM，为CPU设备类提供无证书验签加解密并行加速相关的方法
 *   3W：240527 交子 wwj
 *
***************************************************************************/
class CpuDevice :public ComDevice {
public:
    CLPKM_COM* clpkm;
    CpuDevice(std::string& devName) {
        name = devName;
        devType = CPU;
    }
    int genWATA(UA_BUFFER** uaBuffer, WATA_BUFFER** wataBuffer, const SM2_KEY* mKeyPair,uint32_t size)override {
        std::vector<std::thread> threadPool;
        const uint32_t hardwareConcurrency = std::thread::hardware_concurrency(); // 获取CPU核数，用于分配任务，平衡负载
        for (uint32_t i = 0; i < hardwareConcurrency; i++) {
            threadPool.emplace_back(genWATAFunc, uaBuffer,wataBuffer, mKeyPair, size, i, hardwareConcurrency);
        }
        for (auto& th : threadPool) {
            th.join();
        }

        return ACCE_SUCCESS;
    }

    int genSign(SIGN_BUFFER* genSignBuffer, const SM2_POINT* mPubKey, const SM2_KEY* keyPair, uint32_t size) override
    {
        std::vector<std::thread> threadPool;
        const uint32_t hardwareConcurrency = std::thread::hardware_concurrency(); // 获取CPU核数，用于分配任务，平衡负载
        for (uint32_t i = 0; i < hardwareConcurrency; i++) {
            threadPool.emplace_back(genSignFunc, genSignBuffer, mPubKey, keyPair, size, i, hardwareConcurrency);
        }
        for (auto& th : threadPool) {
            th.join();
        }

        return ACCE_SUCCESS;
    }
    int verifySign(SIGN_BUFFER** verifySignBuffer,RESULT_BUFFER **results, const SM2_POINT* mPubKey, uint32_t size) override
    {
        std::vector<std::thread> threadPool;
        const uint32_t hardwareConcurrency = std::thread::hardware_concurrency(); // 获取CPU核数，用于分配任务，平衡负载
        for (uint32_t i = 0; i < hardwareConcurrency; i++) {
            threadPool.emplace_back(verifySignFunc, verifySignBuffer,results, mPubKey, size, i, hardwareConcurrency);
        }
        for (auto& th : threadPool) {
            th.join();
        }
        return ACCE_SUCCESS;
    }


    int encrypt(uint8_t* IDAs[], int IDALens[], uint8_t* msgs[], int msgLens[], const SM2_POINT mPubKeys[],
        const SM2_POINT pubKeyAs[], SM2_CIPHERTEXT encMsgs[], int size) override {
        return ACCE_SUCCESS;
    }

    int decrypt(SM2_CIPHERTEXT encMsgs[], SM2_KEY keyPairs[], uint8_t decMsgs[], int decMsgLens[], int size) override {
        return ACCE_SUCCESS;
    }

private:
    
    static void genWATAFunc(UA_BUFFER** uaBuffer, WATA_BUFFER** wataBuffer, const SM2_KEY* mKeyPair, uint32_t totalSize, uint32_t thisThread, uint32_t concurrency) {
        const uint32_t div = totalSize / concurrency;
        for (uint32_t i = thisThread * div; i < (thisThread + 1) * div; ++i) {
            SM2_BN TA;
            SM2_POINT UA,WA;
            uint8_t UAxc[32], UAyc[32];
            
            hexArray2bytes(uaBuffer[i]->UAx, UAxc, POINT_SIZE);
            hexArray2bytes(uaBuffer[i]->UAy, UAyc, POINT_SIZE);
            sm2_point_from_xy(&UA,UAxc,UAyc);

            if (genWA_TA_C(uaBuffer[i]->IDA, uaBuffer[i]->IDALen, mKeyPair, &UA, &WA, TA)) {
                std::cout << "THE " << i << " times generate signature failed!" << std::endl;
            }
            wataBuffer[i]->socketFd = uaBuffer[i]->socketFd;
            memcpy(wataBuffer[i]->IDA, uaBuffer[i]->IDA, uaBuffer[i]->IDALen);
            wataBuffer[i]->IDALen = uaBuffer[i]->IDALen;
            wataBuffer[i]->type = WATA_TYPE;
            bytes2hexArray(WA.x, wataBuffer[i]->WAx, POINT_SIZE);
            bytes2hexArray(WA.y, wataBuffer[i]->WAy, POINT_SIZE);
            sm2_bn_to_hex(TA, (char *)wataBuffer[i]->TA);
        }
        if (thisThread == concurrency - 1) {
            for (uint32_t i = (thisThread + 1) * div; i < totalSize; ++i) {
                SM2_BN TA;
                SM2_POINT UA, WA;
                uint8_t UAxc[32], UAyc[32];

                hexArray2bytes(uaBuffer[i]->UAx, UAxc, POINT_SIZE);
                hexArray2bytes(uaBuffer[i]->UAy, UAyc, POINT_SIZE);
                sm2_point_from_xy(&UA, UAxc, UAyc);

                if (genWA_TA_C(uaBuffer[i]->IDA, uaBuffer[i]->IDALen, mKeyPair, &UA, &WA, TA)) {
                    std::cout << "THE " << i << " times generate signature failed!" << std::endl;
                }
                wataBuffer[i]->socketFd = uaBuffer[i]->socketFd;
                memcpy(wataBuffer[i]->IDA, uaBuffer[i]->IDA, uaBuffer[i]->IDALen);
                wataBuffer[i]->IDALen = uaBuffer[i]->IDALen;
                wataBuffer[i]->type = WATA_TYPE;
                bytes2hexArray(WA.x, wataBuffer[i]->WAx, POINT_SIZE);
                bytes2hexArray(WA.y, wataBuffer[i]->WAy, POINT_SIZE);
                sm2_bn_to_hex(TA, (char*)wataBuffer[i]->TA);
            }     

        }
    }
    static void genSignFunc(SIGN_BUFFER* signBuffer, const SM2_POINT* mPubKey, const SM2_KEY* keyPair, uint32_t totalSize, uint32_t thisThread, uint32_t concurrency) {
        const uint32_t div = totalSize / concurrency;
        for (uint32_t i = thisThread * div; i < (thisThread + 1) * div; ++i) {
            SM2_SIGNATURE sig;
            hexArray2bytes(signBuffer[i].sigR, sig.r, POINT_SIZE);
            hexArray2bytes(signBuffer[i].sigS, sig.r, POINT_SIZE);
            if (genSign_C(signBuffer[i].IDA, signBuffer[i].IDALen, signBuffer[i].msg, signBuffer[i].msgLen, mPubKey, keyPair, &sig)) {
                std::cout << "THE " << i << " times generate signature failed!" << std::endl;
            }
        }
        if (thisThread == concurrency - 1) {
            for (uint32_t i = (thisThread + 1) * div; i < totalSize; ++i) {
                SM2_SIGNATURE sig;
                hexArray2bytes(signBuffer[i].sigR, sig.r, POINT_SIZE);
                hexArray2bytes(signBuffer[i].sigS, sig.r, POINT_SIZE);
                genSign_C(signBuffer[i].IDA, signBuffer[i].IDALen, signBuffer[i].msg, signBuffer[i].msgLen, mPubKey, keyPair, &sig);
            }
        }
    }

    static void verifySignFunc(SIGN_BUFFER** signBuffer,RESULT_BUFFER **results, const SM2_POINT* mPubKey, uint32_t totalSize, uint32_t thisThread, uint32_t concurrency) {
        const uint32_t div = totalSize / concurrency;
        for (uint32_t i = thisThread * div; i < (thisThread + 1) * div; ++i) {
            SM2_SIGNATURE sig;
            SM2_POINT pubKeyA;
            memcpy(results[i]->IDA, signBuffer[i]->IDA, MAX_ID_LEN_SIZE);
            results[i]->IDALen = signBuffer[i]->IDALen;
            results[i]->socketFd = signBuffer[i]->socketFd;
            hexArray2bytes(signBuffer[i]->pubKeyAx, pubKeyA.x, POINT_SIZE);
            hexArray2bytes(signBuffer[i]->pubKeyAy, pubKeyA.y, POINT_SIZE);
            hexArray2bytes(signBuffer[i]->sigR, sig.r, POINT_SIZE);
            hexArray2bytes(signBuffer[i]->sigS, sig.s, POINT_SIZE);

            results[i]->type = RESULT_TYPE;
            if (verifySign_C(signBuffer[i]->IDA, signBuffer[i]->IDALen, signBuffer[i]->msg, signBuffer[i]->msgLen, mPubKey, &pubKeyA, &sig)) {
                results[i]->result = 0;
                std::cout << "THE " << i << " signature verify failed!" << std::endl;
            }
            else {
                results[i]->result = 1;
            }
        }
        if (thisThread == concurrency - 1) {
            for (uint32_t i = (thisThread + 1) * div; i < totalSize; ++i) {
                SM2_SIGNATURE sig;
                SM2_POINT pubKeyA;
                memcpy(results[i]->IDA, signBuffer[i]->IDA, MAX_ID_LEN_SIZE);
                results[i]->IDALen = signBuffer[i]->IDALen;
                results[i]->socketFd = signBuffer[i]->socketFd;
                hexArray2bytes(signBuffer[i]->pubKeyAx, pubKeyA.x, POINT_SIZE);
                hexArray2bytes(signBuffer[i]->pubKeyAy, pubKeyA.y, POINT_SIZE);
                hexArray2bytes(signBuffer[i]->sigR, sig.r, POINT_SIZE);
                hexArray2bytes(signBuffer[i]->sigS, sig.s, POINT_SIZE);

                results[i]->type = RESULT_TYPE;
                if (verifySign_C(signBuffer[i]->IDA, signBuffer[i]->IDALen, signBuffer[i]->msg, signBuffer[i]->msgLen, mPubKey, &pubKeyA, &sig)) {
                    results[i]->result = 0;
                    std::cout << "THE " << i << " signature verify failed!" << std::endl;
                }
                else {
                    results[i]->result = 1;
                }
            }
        }
    }

};



#endif