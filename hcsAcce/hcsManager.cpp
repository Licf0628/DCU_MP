#include <hcsAcce/hcsManager.h>

CpuAcceManager* CpuAcceManager::_instance = nullptr;
 #ifdef USE_DCU_DEVICE_ACCE
DcuAcceManager* DcuAcceManager::_instance = nullptr;
#endif
//HctAcceManager* HctAcceManager::_instance = nullptr;
HcsManager* HcsManager::_instance = nullptr;

HcsManager* HcsManager::Instance()
{

	if (HcsManager::_instance == nullptr) {
		static std::mutex mutex;
		mutex.lock();
		if (HcsManager::_instance == nullptr) {
			HcsManager::_instance = new HcsManager();
		}
		mutex.unlock();
	}

	return HcsManager::_instance;
}
bool HcsManager::initDevice() {
	if (isInit) {
		std::cout << "Hcs Manager have been init!" << std::endl;
		return 1;
	}
	CpuAcceManager* cpuManager = CpuAcceManager::Instance();

	//HctAcceManager* hctManager = HctAcceManager::Instance();

	if (cpuManager->initCpuDevice()) {
		devList.push_back(std::vector<ComDevice*>());
		devList[CPU].push_back(cpuManager->getCpuDevice());
		isBusy.push_back(false);
		isLoaded.push_back(true);
	}
	else {
		std::cout << "Cpu Manager init failed!" << std::endl;
	}
	{
		devList.push_back(std::vector<ComDevice*>());		//HCTdevice，之后初始化记得修改这边的配置
		isBusy.push_back(false);
		isLoaded.push_back(false);
	}
	/*
	if (hctManager->initHctDevice()) {
		devList.push_back(dcuManager->getDeviceList());
		std::cout << "HCT number:" << devList[HCT].size() << std::endl;
	}
	else {
		std::cout << "HCT Manager init failed!" << std::endl;
	}*/
#ifdef USE_DCU_DEVICE_ACCE
	DcuAcceManager* dcuManager = DcuAcceManager::Instance();

	
	if (dcuManager->initDcuDevice() == hipSuccess) {
		devList.push_back(dcuManager->getDeviceList());
		std::cout << "DCU number:" << devList[DCU].size() << std::endl;
		isBusy.push_back(false);
		isLoaded.push_back(true);
	}
	else {
		std::cout << "Dcu Manager init failed!" << std::endl;
		isBusy.push_back(false);
		isLoaded.push_back(false);
	}
#endif
	
	return 1;

}
void HcsManager::getDevListInfo() {
	

}
AcceStatus HcsManager::genWATA(UA_BUFFER** uaBuffer, WATA_BUFFER** wataBuffer,  const SM2_KEY* mKeyPair, uint32_t size, DeviceType devType)
{
	isBusy[devType] = true;
	float sum = 0;
	for (auto device : devList[devType])
	{
		device->computingFactor = 1;		//先暂时定义统一的计算因子
		sum += device->computingFactor;
	}

	uint32_t loc = 0;
	uint32_t deviceListSize = devList[devType].size();
	std::vector<std::thread> threadPool;
	for (uint32_t i = 0; i < deviceListSize; ++i)
	{
		uint32_t len = 0;
		if (i == deviceListSize - 1)
		{
			len = size - loc;
		}
		else
		{
			len = size * (devList[devType][i]->computingFactor / sum);
		}
		threadPool.emplace_back(HcsManager::hcsGenWATA, devList[devType][i], uaBuffer+loc, wataBuffer+loc, mKeyPair, len);
		loc += len;
	}
	for (auto& th : threadPool) {
		th.join();
	}
	isBusy[devType] = false;
	return ACCE_SUCCESS;
}
AcceStatus  HcsManager::verifySign(SIGN_BUFFER** verifySignBuffer,RESULT_BUFFER **resultBuffer, const SM2_POINT* mPubKey, uint32_t size, DeviceType devType) {
	isBusy[devType] = true;
	float sum = 0;
	for (auto device : devList[devType])
	{
		device->computingFactor = 1;		//先暂时定义统一的计算因子
		sum += device->computingFactor;
	}

	uint32_t loc = 0;
	uint32_t deviceListSize = devList[devType].size();
	std::vector<std::thread> threadPool;
	for (uint32_t i = 0; i < deviceListSize; ++i)
	{
		uint32_t len = 0;
		if (i == deviceListSize - 1)
		{
			len = size - loc;
		}
		else
		{
			len = size * (devList[devType][i]->computingFactor / sum);
		}
		threadPool.emplace_back(HcsManager::hcsVerifySign, devList[devType][i], verifySignBuffer+loc,resultBuffer+loc, mPubKey, len);
		loc += len;
	}
	for (auto& th : threadPool) {
		th.join();
	}
	isBusy[devType] = false;
	return ACCE_SUCCESS;
}

AcceStatus  HcsManager::genSign(SIGN_BUFFER* genSignBuffer, const SM2_POINT* mPubKey, const SM2_KEY* keyPair, uint32_t size, DeviceType devType) {
	isBusy[devType] = true;
	float sum = 0;
	for (auto device : devList[devType])
	{
		device->computingFactor = 1;		//先暂时定义统一的计算因子
		sum += device->computingFactor;
	}

	uint32_t loc = 0;
	uint32_t deviceListSize = devList[devType].size();
	std::vector<std::thread> threadPool;
	for (uint32_t i = 0; i < deviceListSize; ++i)
	{
		uint32_t len = 0;
		if (i == deviceListSize - 1)
		{
			len = size - loc;
		}
		else
		{
			len = size * (devList[devType][i]->computingFactor / sum);
		}
		threadPool.emplace_back(HcsManager::hcsGenSign, devList[devType][i], genSignBuffer+loc, mPubKey, keyPair, len);
		loc += len;
	}
	for (auto& i : threadPool)
	{
		i.join();
	}
	isBusy[devType] = false;
	return ACCE_SUCCESS;

}

void HcsManager::hcsGenWATA(ComDevice* device, UA_BUFFER** uaBuffer, WATA_BUFFER** wataBuffer,  const SM2_KEY* mKeyPair, uint32_t size)
{
	if (size == 0) {
		return;
	}
	if (device->genWATA(uaBuffer,wataBuffer, mKeyPair, size) != ACCE_SUCCESS)
	{
		throw std::exception();
	}
}
void HcsManager::hcsGenSign(ComDevice* device, SIGN_BUFFER* genSignBuffer, const SM2_POINT* mPubKey, const SM2_KEY* keyPair, uint32_t size)
{
	if (size == 0) {
		return;
	}
	if (device->genSign(genSignBuffer, mPubKey, keyPair, size) != ACCE_SUCCESS)
	{
		throw std::exception();
	}
	
}

void HcsManager::hcsVerifySign(ComDevice* device, SIGN_BUFFER** verifySignBuffer, RESULT_BUFFER** resultBuffer, const SM2_POINT* mPubKey, uint32_t size)
{
	if (size == 0) {
		return;
	}
	if (device->verifySign(verifySignBuffer,resultBuffer, mPubKey, size) != ACCE_SUCCESS)
	{
		throw std::exception();
	}
}





int HcsManager::balanceComputing(DeviceType devType, uint32_t size)
{/*
	VerifySignBuffer* verifyBuffers = new VerifySignBuffer[size];
	const char* ID = "Alice", * ID_hex = "416c696365";
	std::string baseMsg = "BalanceTest";

	SM2_POINT mPubKey;
	SM2_KEY keyPair;

	//if (genKeyInfo(ID_hex, strlen(ID_hex), &mPubKey, &keyPair)) {
	//	return -1;
	//}
	for (int i = 0; i < size; i++) {
		std::string str;
		str = baseMsg + std::to_string(i);

		verifyBuffers[i].IDALen = strlen(ID);
		verifyBuffers[i].msgLen = str.size();
		verifyBuffers[i].result = 0;
		verifyBuffers[i].pubKeyA = keyPair.public_key;
		memcpy(verifyBuffers[i].IDA, ID, strlen(ID));
		memcpy(verifyBuffers[i].msg, str.c_str(), str.size());

	}
	for (auto device : devList[devType]) {
		CDuration timer;
		timer.Start();
		if (device->verifySign(verifyBuffers, &mPubKey, size) != ACCE_SUCCESS)
		{
			throw std::exception();
		}
		timer.Stop();
		double time = timer.GetDuration();
		device->computingFactor = size / time;
		//device->computingFactor = 100;
	}
	delete[] verifyBuffers;
	return 0;*/
	return 0;
}
