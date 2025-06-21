#ifndef __HCS_MANEGER_H__
#define __HCS_MANEGER_H__
#include <hcsAcce/cpuAcceManager.h>
#include <hcsAcce/dcuAcceManager.h>

//#include<common/duration.h>

/**************************************************************************
 * 功能：HCS 异构加速计算设备管理类，负责管理CPU/DCU/HCT 等高性能执行器
 *   3W：240605 交子 wwj
 *
***************************************************************************/


class HcsManager {
public:
	static HcsManager* Instance();
	bool initDevice();
	AcceStatus  genWATA(UA_BUFFER** uaBuffer, WATA_BUFFER** wataBuffer, const SM2_KEY* mKeyPair, uint32_t size, DeviceType devType = CPU);
	AcceStatus  genSign(SIGN_BUFFER* genSignBuffer, const SM2_POINT* mPubKey, const SM2_KEY* keyPair, uint32_t size, DeviceType devType = CPU);
	AcceStatus   verifySign(SIGN_BUFFER** verifySignBuffer,RESULT_BUFFER **resultBuffer, const SM2_POINT* mPubKey, uint32_t size, DeviceType devType = CPU);
	int balanceComputing(DeviceType devType = CPU, uint32_t size = 1000000);
	void getDevListInfo();
	int getHcsTypeSize() { return devList.size(); }
	bool getIsLoaded(DeviceType type) { if (type > devList.size())return false; return isLoaded[type]; }
	bool getIsBusy(DeviceType type) { if (type > devList.size())return true; return isBusy[type]; }
private:
	static void hcsGenWATA(ComDevice* device, UA_BUFFER** uaBuffer,WATA_BUFFER **wataBuffer, const SM2_KEY* mKeyPair, uint32_t size);
	static void hcsGenSign(ComDevice* device, SIGN_BUFFER* genSignBuffer, const SM2_POINT* mPubKey, const SM2_KEY* keyPair, uint32_t size);
	static void hcsVerifySign(ComDevice* device, SIGN_BUFFER** verifySignBuffer, RESULT_BUFFER** resultBuffer, const SM2_POINT* mPubKey, uint32_t size);

private:
	HcsManager() = default;
	std::vector<std::vector<ComDevice*>> devList;
	static HcsManager* _instance;
	bool isInit = false;			
	std::vector<bool> isBusy;		//设备是否忙
	std::vector<bool> isLoaded;		//设备是否被装载
	bool isVerbose = true;
};



#endif