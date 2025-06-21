#include <cstdio>
#include <cstdint>
#ifndef __HIP_ECDSA_CPP_
#define __HIP_ECDSA_CPP_
#include <stdio.h>
#include <hcsAcce/comDevice.h>

#include <hip/hip_runtime.h>
#include <hip/sm2_alg_hip.h>
#include <hip/sm3_alg_hip.h>
#define BLOCK_SIZE				128
#define ECC_DEBUG				1
#ifdef USE_DCU_DEVICE_ACCE
__device__ void hexCharBuf_print(const char* name, uint8_t* src, int size) {
	printf("\n%s", name);
	for (int i = 0; i < size; i++) {
		if (i % POINT_SIZE == 0) printf("\n");
		printf("%02X", src[i]);
	}
	printf("\n");
}

__device__ int  hexCharToValue(char hex) {
	if ('0' <= hex && hex <= '9') {
		return hex - '0';
	}
	else if ('a' <= hex && hex <= 'f') {
		return 10 + (hex - 'a');
	}
	else if ('A' <= hex && hex <= 'F') {
		return 10 + (hex - 'A');
	}
	else if (hex == 0)
		return '0';
	else {
		// 非法的十六进制字符
		return -1;
	}
}
__device__ void hexArray2bytes(const uint8_t* hexStr, uint8_t* byteArray, size_t byteArraySize) {		//默认hex为正确的十六进制数组不以‘\0’结尾
	size_t len = byteArraySize * 2;

	for (size_t i = 0; i < len; i += 2) {
		int highNibble = hexCharToValue(hexStr[i]);
		int lowNibble = hexCharToValue(hexStr[i + 1]);

		if (highNibble == -1 || lowNibble == -1) {
			printf("Error: Invalid hex character found.\n");
			return;
		}

		byteArray[i / 2] = (uint8_t)((highNibble << 4) | lowNibble);
	}
}
__device__ void bytes2hexArray(const uint8_t* input, uint8_t* output, size_t input_len) {
	static const char* hex_chars = "0123456789ABCDEF";

	for (size_t i = 0; i < input_len; ++i) {
		output[i * 2] = hex_chars[(input[i] >> 4) & 0xF];
		output[i * 2 + 1] = hex_chars[input[i] & 0xF];
	}
}
__device__ int genHA_hip(uint8_t* IDA, int len, const SM2_POINT* mPubKey, SM2_BN HA)
{
	//HA 关于用户A的标识、部分椭圆曲线系统参数和系统主公钥的杂凑值。
	uint8_t tmp[256], ha[32];
	int bitLen = len * 8;
	int size = 0;
	if (len > 64) { return -1; }
	unsigned char len_buf[] = {
		static_cast<unsigned char>((bitLen >> 8) & 0xFF),  // 高8位
		static_cast<unsigned char>(bitLen & 0xFF)          // 低8位
	};

	//HA=Hash_sm3_256(ENTLA||IDA||SM2_a||SM2_b||Gx||Gy||mPubKey_x||mPubKey_y)
	//ENTLA是由整数entlenA转换而成的两个字节，entlenA=IDA.size() * 8,为ID的位个数；IDA为bytes形式；hexIDA为ID的十六进制字节码形式
	memcpy(tmp, len_buf, 2);						size = size + 2;
	memcpy(tmp + size, IDA, len);					size += len;
	memcpy(tmp + size, SM2_a, POINT_SIZE);			size += POINT_SIZE;
	memcpy(tmp + size, SM2_b, POINT_SIZE);			size += POINT_SIZE;
	memcpy(tmp + size, SM2_xg, POINT_SIZE);			size += POINT_SIZE;
	memcpy(tmp + size, SM2_yg, POINT_SIZE);			size += POINT_SIZE;
	memcpy(tmp + size, mPubKey->x, POINT_SIZE);		size += POINT_SIZE;
	memcpy(tmp + size, mPubKey->y, POINT_SIZE);		size += POINT_SIZE;

	sm3_digest_hip(tmp, size, ha);
	sm2_bn_from_bytes_hip(HA, ha);

	return 0;
}
__device__ int genLambda_hip(const SM2_POINT* pubKey, const SM2_BN HA, SM2_BN lambda)
{
	//lambda= H256(WA_x‖WA_y‖HA) mod n，
	uint8_t buf[128], dgst[32], ha[32];
	int size = 0;
	sm2_bn_to_bytes_hip(HA, ha);
	memcpy(buf, pubKey->x, POINT_SIZE);			size += POINT_SIZE;
	memcpy(buf + size, pubKey->y, POINT_SIZE);	size += POINT_SIZE;
	memcpy(buf + size, ha, POINT_SIZE);		size += POINT_SIZE;

	sm3_digest_hip(buf, size, dgst);
	sm2_bn_from_bytes_hip(lambda, dgst);

	return 0;
}
__device__ int genE_hip(uint8_t* msg, int len, const SM2_POINT* pubKey, const SM2_BN HA, SM2_BN E)
{
	//msg为输入的byte型信息
	uint8_t ZA[256], e[32], ha[32];
	int size = 0;
	if (len > 160) { return -1; }
	sm2_bn_to_bytes_hip(HA, ha);

	memcpy(ZA, ha, POINT_SIZE);					size += POINT_SIZE;
	memcpy(ZA + size, pubKey->x, POINT_SIZE);		size += POINT_SIZE;
	memcpy(ZA + size, pubKey->y, POINT_SIZE);		size += POINT_SIZE;
	memcpy(ZA + size, msg, len);				size += len;

	sm3_digest_hip(ZA, size, e);         //e=Hash256(HA||Wx||Wy||M)
	sm2_bn_from_bytes_hip(E, e);

	return 0;
}
__global__ void clpkmKernelGenSign(SIGN_BUFFER* buffers, SM2_POINT* mPubKey, SM2_KEY* keyPair, uint32_t* size)
{
	const int index = threadIdx.x + blockIdx.x * blockDim.x;
	if (index < size[0])
	{
		uint8_t dgst[32];
		SM2_BN E, HA;
		genHA_hip(buffers[index].IDA, buffers[index].IDALen, mPubKey, HA);
		if (genE_hip(buffers[index].msg, buffers[index].msgLen, &(keyPair->public_key), HA, E))
			return;
		sm2_bn_to_bytes_hip(E, dgst);
		SM2_SIGNATURE sig;
		if (sm2_do_sign_hip(keyPair, dgst, &sig, index) != 1) {
			printf("Size:%d, Sign Index: %d failed!\n", size[0], index);
			return;
		}
		bytes2hexArray(sig.r, buffers[index].sigR, 32);
		bytes2hexArray(sig.s, buffers[index].sigS, 32);
	}

}
/*
__global__ void clpkmKernelGenSignSet(GenSignBuffer* buffers, SM2_POINT* mPubKey, SM2_KEY* keyPairs, uint32_t* size)
{
	const int index = threadIdx.x + blockIdx.x * blockDim.x;
	if (index < size[0])
	{
		uint8_t dgst[32];
		SM2_BN E, HA;
		genHA_hip(buffers[index].ID, buffers[index].IDLen, mPubKey, HA);
		if (genE_hip(buffers[index].msg, buffers[index].msgLen, &(keyPairs[index].public_key), HA, E))
			return;
		sm2_bn_to_bytes_hip(E, dgst);
		if (sm2_do_sign_hip(&keyPairs[index], dgst, &buffers[index].sig, index) != 1) {
			printf("Size:%d, Sign Index: %d failed!\n", size[0], index);
			return;
		}
	}

}*/
__global__ void clpkmKernelVerifySign(DcuSignBuffer* buffers,uint8_t*results, SM2_POINT* mPubKey, uint32_t* size)
{
	const int index = threadIdx.x + blockIdx.x * blockDim.x;
	if (index < size[0])
	{
		SM2_BN HA, E, lambda;
		SM2_POINT PA,pubKeyA;
		uint8_t dgst[32];
		SM2_SIGNATURE sig;
		results[index] = 10;
		hexArray2bytes(buffers[index].pubKeyAx, pubKeyA.x, POINT_SIZE);
		hexArray2bytes(buffers[index].pubKeyAy, pubKeyA.y, POINT_SIZE);
		hexArray2bytes(buffers[index].sigR, sig.r, POINT_SIZE);
		hexArray2bytes(buffers[index].sigS, sig.s, POINT_SIZE);

		genHA_hip(buffers[index].IDA, buffers[index].IDALen, mPubKey, HA);
		if (genE_hip(buffers[index].msg, buffers[index].msgLen, &pubKeyA, HA, E))return;
		genLambda_hip(&pubKeyA, HA, lambda);

		SM2_KEY keyPair;
		uint8_t blambda[32];
		sm2_bn_to_bytes_hip(lambda, blambda);
		SM2_POINT tmp;
		sm2_point_mul_hip(&tmp, blambda, mPubKey);
		sm2_point_add_hip(&PA, &tmp, &pubKeyA);	//PA=pubKey+[lambda]*MpubKey
		keyPair.public_key = PA;
		sm2_bn_to_bytes_hip(E, dgst);

		sm2_do_verify_hip(&keyPair, dgst, &sig,&results[index]);
		if (results[index] != 1) {
			printf("DCU Verify Sign Index: %d failed! ID=%s, return flag=%d\n",index,buffers[index].IDA,results[index]);
			return;
		}
	}

}
template <typename T>
void check(T result, char const* const func, const char* const file, int const line)
{
	if (result)
	{
		fprintf(stderr, "HIP error at %s:%d code=%d(%s) \"%s\" \n", file, line, static_cast<unsigned int>(result), hipGetErrorName(result), func);
		hipDeviceReset();
		exit(EXIT_FAILURE);
	}
}

#define checkHipErrors(val) check((val), #val, __FILE__, __LINE__)
extern hipError_t genSignWarp(SIGN_BUFFER** signBuffers, const SM2_POINT* mPubKey, const SM2_KEY* keyPair, uint32_t size, uint32_t devId) {
	SIGN_BUFFER* buffers_dev = nullptr;
	SM2_POINT* mPubKey_dev = nullptr;
	SM2_KEY* keyPair_dev = nullptr;
	uint32_t* size_dev = nullptr;
	checkHipErrors(hipSetDevice(devId));			//根据devId设置DCU设备

#if ECC_DEBUG
	printf("Enter CLPKM_SignWarp\n");
#endif
	checkHipErrors(hipMalloc((void**)&buffers_dev, size * sizeof(SIGN_BUFFER)));		//在DCU分配内存，和主机端的内存地址建立映射
	checkHipErrors(hipMalloc((void**)&keyPair_dev, sizeof(SM2_KEY)));
	checkHipErrors(hipMalloc((void**)&mPubKey_dev, sizeof(SM2_POINT)));
	checkHipErrors(hipMalloc((void**)&size_dev, sizeof(uint32_t)));

	checkHipErrors(hipMemcpy(keyPair_dev, keyPair, sizeof(SM2_KEY), hipMemcpyHostToDevice));			//将主机端的变量拷贝到DCU端
	for (int i = 0; i < size; i++) {
		checkHipErrors(hipMemcpy(buffers_dev+i, signBuffers[i], sizeof(SIGN_BUFFER), hipMemcpyHostToDevice));
	}
	checkHipErrors(hipMemcpy(mPubKey_dev, mPubKey, sizeof(SM2_POINT), hipMemcpyHostToDevice));
	checkHipErrors(hipMemcpy(size_dev, &size, sizeof(uint32_t), hipMemcpyHostToDevice));

	dim3 blockSize(BLOCK_SIZE);
	dim3 gridSize(size / BLOCK_SIZE + 1);
#if ECC_DEBUG
	printf("Grid Size: %d Block Size:%d\n", gridSize.x, blockSize.x);
#endif
	clpkmKernelGenSign <<<gridSize, blockSize >>> (buffers_dev, mPubKey_dev, keyPair_dev, size_dev);
	checkHipErrors(hipGetLastError());
	checkHipErrors(hipDeviceSynchronize());
	//从DCU内存中拷贝签名结果到主机中
	for (int i = 0; i < size; i++) {
		checkHipErrors(hipMemcpy(signBuffers[i], buffers_dev+i, sizeof(SIGN_BUFFER), hipMemcpyDeviceToHost));
	}
	hipFree(buffers_dev);
	hipFree(keyPair_dev);
	hipFree(mPubKey_dev);
	hipFree(size_dev);
#if ECC_DEBUG
	printf("Exit ClpkmGenSignWarp As Expected\n");
#endif
	return hipSuccess;;
}
/*
extern hipError_t genSignWarpSet(SIGN_BUFFER** signBuffers,RESULT_BUFFER ** results, const SM2_POINT* mPubKey, const SM2_KEY* keyPairs, uint32_t size, uint32_t devId) {
	SIGN_BUFFER* buffers_dev = nullptr;
	RESULT_BUFFER* results_dev = nullptr;
	SM2_POINT* mPubKey_dev = nullptr;
	SM2_KEY* keyPairs_dev = nullptr;
	uint32_t* size_dev = nullptr;
	checkHipErrors(hipSetDevice(devId));			//根据devId设置DCU设备

#if ECC_DEBUG
	printf("Enter CLPKM_SignWarp\n");
#endif

	checkHipErrors(hipMalloc((void**)&buffers_dev, size * sizeof(SIGN_BUFFER)));		//在DCU分配内存，和主机端的内存地址建立映射
	checkHipErrors(hipMalloc((void**)&results_dev, size * sizeof(RESULT_BUFFER)));		
	checkHipErrors(hipMalloc((void**)&keyPairs_dev, size * sizeof(SM2_KEY)));
	checkHipErrors(hipMalloc((void**)&mPubKey_dev, sizeof(SM2_POINT)));
	checkHipErrors(hipMalloc((void**)&size_dev, sizeof(uint32_t)));

	for (int i = 0; i < size; i++) {
		checkHipErrors(hipMemcpy(buffers_dev+i, signBuffers[i], sizeof(SIGN_BUFFER), hipMemcpyHostToDevice));
	}
	checkHipErrors(hipMemcpy(keyPairs_dev, keyPairs, size * sizeof(SM2_KEY), hipMemcpyHostToDevice));			//将主机端的变量拷贝到DCU端
	checkHipErrors(hipMemcpy(mPubKey_dev, mPubKey, sizeof(SM2_POINT), hipMemcpyHostToDevice));
	checkHipErrors(hipMemcpy(size_dev, &size, sizeof(uint32_t), hipMemcpyHostToDevice));

	dim3 blockSize(BLOCK_SIZE);
	dim3 gridSize(size / BLOCK_SIZE + 1);
#if ECC_DEBUG
	printf("Grid Size: %d Block Size:%d\n", gridSize.x, blockSize.x);
#endif
	clpkmKernelGenSignSet << <gridSize, blockSize >> > (buffers_dev,results_dev, mPubKey_dev, keyPairs_dev, size_dev);
	checkHipErrors(hipGetLastError());
	checkHipErrors(hipDeviceSynchronize());
	//从DCU内存中拷贝签名结果到主机中
	checkHipErrors(hipMemcpy(signBuffers, buffers_dev, size * sizeof(GenSignBuffer), hipMemcpyDeviceToHost));
	hipFree(buffers_dev);
	hipFree(keyPairs_dev);
	hipFree(mPubKey_dev);
	hipFree(size_dev);
#if ECC_DEBUG
	printf("Exit ClpkmgenSignWarp As Expected\n");
#endif
	return hipSuccess;
}
*/
extern hipError_t verifySignWarp(SIGN_BUFFER** signBuffers, RESULT_BUFFER** results ,const SM2_POINT* mPubKey, uint32_t size, uint32_t devId) {
	DcuSignBuffer* buffers_dev = nullptr;
	uint8_t* results_dev = nullptr;
	SM2_POINT* mPubKey_dev = nullptr;
	uint32_t* size_dev = nullptr;

	checkHipErrors(hipSetDevice(devId));
#if ECC_DEBUG
	printf("Enter ClpkmVerifySignWarp\n");
#endif
	checkHipErrors(hipMalloc((void**)&buffers_dev, size * sizeof(DcuSignBuffer)));		//在DCU分配内存，和主机端的内存地址建立映射
	checkHipErrors(hipMalloc((void**)&results_dev, size * sizeof(uint8_t)));
	checkHipErrors(hipMalloc((void**)&mPubKey_dev, sizeof(SM2_POINT)));
	checkHipErrors(hipMalloc((void**)&size_dev, sizeof(uint32_t)));

	for (int i = 0; i < size; i++) {
		checkHipErrors(hipMemcpy(buffers_dev[i].IDA, signBuffers[i]->IDA, MAX_ID_LEN_SIZE, hipMemcpyHostToDevice));
		checkHipErrors(hipMemcpy(buffers_dev[i].msg, signBuffers[i]->msg, MAX_SIGN_MSG_SIZE, hipMemcpyHostToDevice));

		checkHipErrors(hipMemcpy(buffers_dev[i].pubKeyAx, signBuffers[i]->pubKeyAx, POINT_SIZE*2, hipMemcpyHostToDevice));
		checkHipErrors(hipMemcpy(buffers_dev[i].pubKeyAy, signBuffers[i]->pubKeyAy, POINT_SIZE * 2, hipMemcpyHostToDevice));
		checkHipErrors(hipMemcpy(buffers_dev[i].sigR, signBuffers[i]->sigR, POINT_SIZE * 2, hipMemcpyHostToDevice));
		checkHipErrors(hipMemcpy(buffers_dev[i].sigS, signBuffers[i]->sigS, POINT_SIZE * 2, hipMemcpyHostToDevice));

		checkHipErrors(hipMemcpy(&buffers_dev[i].IDALen, &signBuffers[i]->IDALen, sizeof(uint16_t), hipMemcpyHostToDevice));
		checkHipErrors(hipMemcpy(&buffers_dev[i].msgLen, &signBuffers[i]->msgLen, sizeof(uint16_t), hipMemcpyHostToDevice));
	}
	checkHipErrors(hipMemcpy(mPubKey_dev, mPubKey, sizeof(SM2_POINT), hipMemcpyHostToDevice));
	checkHipErrors(hipMemcpy(size_dev, &size, sizeof(uint32_t), hipMemcpyHostToDevice));

	dim3 blockSize(BLOCK_SIZE);
	dim3 gridSize(size / BLOCK_SIZE + 1);
#if ECC_DEBUG
	printf("Grid Size: %d Block Size:%d\n", gridSize.x, blockSize.x);
#endif
	clpkmKernelVerifySign <<<gridSize, blockSize >>> (buffers_dev,results_dev, mPubKey_dev, size_dev);
	checkHipErrors(hipGetLastError());
	checkHipErrors(hipDeviceSynchronize());
	for (int i = 0; i < size; i++) {
		//获取验签结果
		checkHipErrors(hipMemcpy(&results[i]->result, results_dev+i, sizeof(uint8_t), hipMemcpyDeviceToHost));
	}
	hipFree(buffers_dev);
	hipFree(results_dev);
	hipFree(mPubKey_dev);
	hipFree(size_dev);
#if ECC_DEBUG
	printf("Exit ClpkmVerifySignWarp As Expected\n");
#endif
	return hipSuccess;;
}
#pragma endregion

#endif
#endif 

