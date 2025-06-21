#include "ACCETest.h"
#define CPU_TEST_NUMBER  100000
#define DCU_TEST_NUMBER  4000000

/*
int genKeyInfo(const char* ID, int IDLen, SM2_POINT* mPubKey, SM2_KEY* keyPair) {
	SM2_BN ms = {
	0xF19A9FF9, 0x2B3535C9, 0xD7E99C97, 0x08319FF7,
	0xC1C932C2, 0xFE0F6388, 0x10F79415, 0x6BDD93B2 };		//主私钥
	std::string devId ,kgcId = "426f62";
	devId.assign((ID), IDLen);
	CLPKM_COM* dev, * kgc;
	dev = new CLPKM_COM(devId);				//实例化为普通设备对象	
	kgc = new CLPKM_COM(kgcId, ms);			//实例化为KGC设备对象

	Epoint MpubKey, UA, WA;
	Big HA, TA, DA;
	//DEVs生成UA，并将UA安全发送到KGC 
	dev->genUA(UA);
	//KGC生成WA、TA并将{MpubKey、WA、TA}安全发送到DEV
	//KGC将TA返回DEV时可使用UA作为公钥使用加密方法ENC加密包括TA的数据后将密文传递到DEV。DEV使用DAi解密密文后还原包括TA的数据。
	kgc->genWA_TA(devId, UA, WA, TA);
	MpubKey = kgc->getMPubKey();

	//DEV 接受到MpubKey、WA、TA后，设置kgc主公钥和公钥,根据TA生成设备私钥DA
	dev->setKgcPubKey(MpubKey);
	if (dev->genDA(TA, DA) != 0) {
		printf("Private key generation failed, key generation process terminated!\n");
		return -3;
	}
	//DA为私钥，WA为公钥，将密钥对保存在对象中
	dev->setKeyPair(DA, WA);
	//DEV校验密钥的正确性
	if (dev->verifyKeyPair() != 0) {
		printf("Failed verify keyPair\n");
		return -2;
	}
	else {
		printf("Success verify keyPair\n");
	}
	*keyPair=dev->getKeyPair();
	*mPubKey = MpubKey.getPoint();
	delete kgc;
	delete dev;
	return 0;

}

int ACCE_CPUTest(void) {
	printf("**************************CPU ACCE TEST!****************************\n");
	CpuAcceManager* cpuManager = CpuAcceManager::Instance();
	cpuManager->initCpuDevice();
	int size = CPU_TEST_NUMBER;
	const char* ID = "Alice",*ID_hex= "416c696365";
	std::string baseMsg = "test";
	SM2_POINT mPubKey;
	SM2_KEY keyPair;
	SIGN_BUFFER* genBuffers = new SIGN_BUFFER[size];
	RESULT_BUFFER* resBuffers = new RESULT_BUFFER[size];
	
	//GenSignBuffer * genBuffers = new GenSignBuffer[size];
	//VerifySignBuffer * verifyBuffers = new VerifySignBuffer[size];
	
	if (genKeyInfo(ID_hex, strlen(ID_hex), &mPubKey, &keyPair)) {
		return -1;
	}

	for (int i = 0; i < size; i++) {
		std::string str;
		str = baseMsg + std::to_string(i);

		genBuffers[i].IDALen = strlen(ID);
		genBuffers[i].msgLen = str.size();
		memcpy(genBuffers[i].IDA,ID, strlen(ID));
		memcpy(genBuffers[i].msg, str.c_str(), str.size());
		
		
	}
	CDuration timer;
	timer.Start();
	cpuManager->getCpuDevice()->genSign(genBuffers, &mPubKey, &keyPair, size);
	timer.Stop();
	std::cout << "Generating " << size << " signatures takes time :" << timer.GetDuration() << " us\n" 
			  << "CPU can signature :" << size / (timer.GetDuration() / 1000000) << " times /s" << std::endl; 

	timer.Start();
	cpuManager->getCpuDevice()->verifySign(&genBuffers, &resBuffers,&mPubKey,size);
	timer.Stop();
	std::cout << "Verifying " << size << " signatures takes time :" << timer.GetDuration() << " us\n" 
			  << "CPU can verify signature : " << size / (timer.GetDuration() / 1000000) << " times /s" << std::endl;

	delete[] resBuffers;
	delete[] genBuffers;
	return 0;
}

int ACCE_DCUTest(void) {
	printf("**************************DCU ACCE TEST!****************************\n");
	DcuAcceManager* dcuManager = DcuAcceManager::Instance();
	dcuManager->initDcuDevice();
	int size = DCU_TEST_NUMBER;
	const char* ID = "Alice", * ID_hex = "416c696365";
	std::string baseMsg = "test";
	SM2_POINT mPubKey;
	SM2_KEY keyPair;
	SIGN_BUFFER* genBuffers = new SIGN_BUFFER[size];
	RESULT_BUFFER* resBuffers = new RESULT_BUFFER[size];
	
	if (genKeyInfo(ID_hex, strlen(ID_hex), &mPubKey, &keyPair)) {
		return -1;
	}
	
	for (int i = 0; i < size; i++) {
		std::string str;
		str = baseMsg + std::to_string(i);

		genBuffers[i].IDALen = strlen(ID);
		genBuffers[i].msgLen = str.size();
		memcpy(genBuffers[i].IDA, ID, strlen(ID));
		memcpy(genBuffers[i].msg, str.c_str(), str.size());


	}
	CDuration timer;
	timer.Start();
	dcuManager->getDeviceList()[0]->genSign(genBuffers, &mPubKey, &keyPair, size);
	timer.Stop();
	std::cout << "Generating " << size << " signatures takes time :" << timer.GetDuration() << " us.\n" 
			  << "Single DCU can generate signature: "<<size/(timer.GetDuration()/1000000)<<" times /s" << std::endl;

	timer.Start();
	dcuManager->getDeviceList()[0]->verifySign(&genBuffers, &resBuffers, &mPubKey, size);
	timer.Stop();
	std::cout << "Verifying " << size << " signatures takes time :" << timer.GetDuration() << " us.\n" 
			  << "Single DCU can verify signature :" << size / (timer.GetDuration() / 1000000) << " times/s" << std::endl;

	std::cout << "Rresult 1  : " << resBuffers[1].result <<"  "
			  << "Rresult 100: " << resBuffers[100].result << std::endl;
	delete[] resBuffers;
	delete[] genBuffers;
	return 0;
}
int ACCE_HCSTest(void) {
	printf("**************************HCS ACCE TEST!****************************\n");
	HcsManager* hcsManager = HcsManager::Instance();
	hcsManager->initDevice();
	int size = DCU_TEST_NUMBER;
	const char* ID = "Alice", * ID_hex = "416c696365";
	std::string baseMsg = "test";
	SM2_POINT mPubKey;
	SM2_KEY keyPair;
	SIGN_BUFFER* genBuffers = new SIGN_BUFFER[size];
	RESULT_BUFFER* resBuffers = new RESULT_BUFFER[size];

	if (genKeyInfo(ID_hex, strlen(ID_hex), &mPubKey, &keyPair)) {
		return -1;
	}

	for (int i = 0; i < size; i++) {
		std::string str;
		str = baseMsg + std::to_string(i);

		genBuffers[i].IDALen = strlen(ID);
		genBuffers[i].msgLen = str.size();
		memcpy(genBuffers[i].IDA, ID, strlen(ID));
		memcpy(genBuffers[i].msg, str.c_str(), str.size());


	}
	hcsManager->balanceComputing(DCU);
	CDuration timer;
	timer.Start();
	hcsManager->genSign(genBuffers, &mPubKey, &keyPair, size,DCU);
	timer.Stop();
	std::cout << "Generating " << size << " signatures takes time :" << timer.GetDuration() << " us.\n"
		<< "4 pieces DCU can generate signature: " << size / (timer.GetDuration() / 1000000) << " times /s" << std::endl;

	
	genBuffers[100].sigR[3] = 22;	//测试验签准确性
	timer.Start();
	hcsManager->verifySign(&genBuffers,&resBuffers, &mPubKey, size,DCU);
	timer.Stop();
	std::cout << "Verifying " << size << " signatures takes time :" << timer.GetDuration() << " us.\n"
		<< "4 pieces DCU can verify signature :" << size / (timer.GetDuration() / 1000000) << " times/s" << std::endl;

	std::cout << "Result 1  : " << resBuffers[1].result << "  "
		<< "Result 100: " << resBuffers[100].result << std::endl;
	delete[] resBuffers;
	delete[] genBuffers;
	return 0;
}
*/