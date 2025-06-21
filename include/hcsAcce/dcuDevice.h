#ifndef __DCU_DEVICE_H__
#define __DCU_DEVICE_H__
#include <clpkm/clpkm.h>
#include<hcsAcce/comDevice.h>
#include <hip/hip_runtime.h>
/**************************************************************************
 * 功能：DCU执行设备类,继承于comDevice
 *   3W：240531 交子 wwj
 *
***************************************************************************/
//使用DCU时编译该项，反之则不编译
#ifdef USE_DCU_DEVICE_ACCE
//extern hipError_t genSignWarp(GenSignBuffer* signBuffers, const SM2_POINT* mPubKey, const SM2_KEY* keyPair, uint32_t size, uint32_t devId);
//extern hipError_t genSignWarpSet(GenSignBuffer* signBuffers, const SM2_POINT* mPubKey, const SM2_KEY* keyPairs, uint32_t size, uint32_t devId);
extern hipError_t verifySignWarp(SIGN_BUFFER** verifySignBuffer, RESULT_BUFFER** results, const SM2_POINT* mPubKey, uint32_t size , uint32_t devId);




class DcuDevice :public ComDevice {
public:
	DcuDevice(int32_t Id, hipDeviceProp_t prop)
	{
		devId = Id;
		devProp = prop;
		name = prop.name;
		devType = DCU;
	}

	hipDeviceProp_t getProp() const
	{
		return devProp;
	}

	int32_t getDevId() const
	{
		return devId;
	}
	/*
	//DCU 并行执行生成验证签名
	int genSign(GenSignBuffer* buffer, const SM2_POINT* mPubKey, const SM2_KEY* keyPair, uint32_t size) override {
		if (genSignWarp(buffer, mPubKey, keyPair, size, devId) == hipSuccess)
		{
			return ACCE_SUCCESS;
		}
		else
		{
			return ACCE_FAILED;
		}

	}
	//DCU并发生成测试签名集合
	int genSignSet(GenSignBuffer* buffer, const SM2_POINT* mPubKey, const SM2_KEY* keyPairs, uint32_t size) override {
		if (genSignWarpSet(buffer, mPubKey, keyPairs, size, devId) == hipSuccess)
		{
			return ACCE_SUCCESS;
		}
		else
		{
			return ACCE_FAILED;
		}
	}*/
	int verifySign(SIGN_BUFFER** verifySignBuffer, RESULT_BUFFER** results, const SM2_POINT* mPubKey, uint32_t size) override {
		if (verifySignWarp(verifySignBuffer, results,mPubKey, size, devId) == hipSuccess)
		{
			return ACCE_SUCCESS;
		}
		else
		{
			return ACCE_FAILED;
		}
	}
	//待实现
	int encrypt(uint8_t* IDAs[], int IDALens[], uint8_t* msgs[], int msgLens[], const SM2_POINT mPubKeys[],
		const SM2_POINT pubKeyAs[], SM2_CIPHERTEXT encMsgs[], int size)override {
		return ACCE_SUCCESS;

	}
	int decrypt(SM2_CIPHERTEXT encMsgs[], SM2_KEY keyPairs[], uint8_t decMsgs[], int decMsgLens[], int size)override {
		return ACCE_SUCCESS;
	}
private:
	hipDeviceProp_t devProp;
	uint32_t devId;
};


#endif
#endif