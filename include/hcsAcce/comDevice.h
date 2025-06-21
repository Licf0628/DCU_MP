#include <clpkm/clpkm.h>
#include <config.h>
#include <dataType.h>
#ifndef __COM_DEVICE_H__
#define __COM_DEVICE_H__
/**************************************************************************
 * 功能：通用执行设备类,描述了几个CLPKM的方法抽象接口
 *   3W：240523 交子 wwj
 *
***************************************************************************/
class ComDevice {
public:
	std::string name;				//执行设备标识名
	float computingFactor;			//执行设备的计算能力因数，用于并行执行多任务时，分配设备的计算量
	DeviceType devType;
	/*并行任务执行方法，由不同的并行执行器分别实例化*/
	virtual int genWATA(UA_BUFFER **uaBuffer,WATA_BUFFER **wataBuffer, const SM2_KEY* mKeyPair,uint32_t size)
	{
		throw std::logic_error("Not Implemented"); return -1;
	}
	virtual	int genSign(SIGN_BUFFER* genSignBuffer, const SM2_POINT* mPubKey, const SM2_KEY* keyPair, uint32_t size)
	{
		throw std::logic_error("Not Implemented"); return -1;
	}
	virtual	int genSignSet(SIGN_BUFFER* genSignBuffer, const SM2_POINT* mPubKey, const SM2_KEY* keyPairs, uint32_t size)
	{
		throw std::logic_error("Not Implemented"); return -1;
	}
	virtual int verifySign(SIGN_BUFFER** verifySignBuffer,RESULT_BUFFER **results, const SM2_POINT* mPubKey, uint32_t size)
	{
		throw std::logic_error("Not Implemented"); return -1;
	}


	virtual int encrypt(uint8_t* IDAs[], int IDALens[], uint8_t* msgs[], int msgLens[], const SM2_POINT mPubKeys[],
		const SM2_POINT pubKeyAs[], SM2_CIPHERTEXT encMsgs[], int size)
	{
		throw std::logic_error("Not Implemented"); return -1;
	}
	virtual int decrypt(SM2_CIPHERTEXT encMsgs[], SM2_KEY keyPairs[], uint8_t decMsgs[], int decMsgLens[], int size)
	{
		throw std::logic_error("Not Implemented"); return -1;

	}
};

#endif