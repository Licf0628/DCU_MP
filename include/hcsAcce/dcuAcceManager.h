#ifndef __DCU_ACCE_MANAGER_H__
#ifdef USE_DCU_DEVICE_ACCE
#define __DCU_ACCE_MANAGER_H__
#include <hcsAcce/dcuDevice.h>
#include <vector>
#include <mutex>
/**************************************************************************
 * 功能：DCU并行加速执行管理类
 *   3W：240603 交子 wwj
 *
***************************************************************************/
class DcuAcceManager {
public:
	static DcuAcceManager* Instance()		//单实例化对象
	{
		if (DcuAcceManager::_instance == nullptr)
		{
			static std::mutex mutex;	//加上互斥量，防止异步初始化
			mutex.lock();
			if (DcuAcceManager::_instance == nullptr)
			{
				DcuAcceManager::_instance = new DcuAcceManager();
			}
			mutex.unlock();
		}
		return DcuAcceManager::_instance;
	}

	hipError_t initDcuDevice(bool isForce = false)
	{
		if (_isInit && !isForce)
		{
			return hipSuccess;
		}

		if (this->verbose)
		{
			std::cout << "----------------------HIP Device Init Begin-----------------------" << std::endl;
		}
		_deviceList.clear();

		hipError_t hipStatus;
		int deviceCount;
		hipStatus = hipGetDeviceCount(&deviceCount);
		if (hipStatus != hipSuccess)
		{
			fprintf(stderr, "hipDeviceSynchronize returned error code %d after launching ecdsaKernel!\n", hipStatus);
			return hipStatus;
		}
		for (int32_t deviceNumber = 0; deviceNumber < deviceCount; ++deviceNumber)
		{
			hipDeviceProp_t devProp;
			hipStatus = hipGetDeviceProperties(&devProp, deviceNumber);
			if (hipStatus != hipSuccess)
			{
				std::cout << "DCU index: " << deviceNumber << "have error status:" << hipStatus << std::endl;
				continue;
			}
			else
			{
				_deviceList.push_back(new DcuDevice(deviceNumber, devProp));
				if (this->verbose)
				{
					std::cout << "DCU index: " << deviceNumber << std::endl;
					std::cout << "HIP Device Name: " << devProp.name << std::endl;
					std::cout << "Shared Memory Per Block: " << devProp.sharedMemPerBlock << " Byte" << std::endl;
					std::cout << "Max Thread Per Block: " << devProp.maxThreadsPerBlock << std::endl;
				}

			}
		}
		if (this->verbose)
		{
			std::cout << "---------------------HIP Device Init Finished---------------------" << std::endl;
		}
		_isInit = true;
		return hipSuccess;
	}

	std::vector<ComDevice*> getDeviceList()
	{
		std::cout << "DCU vector size:" << _deviceList.size() << std::endl;
		return _deviceList;
	}

	bool isInit()
	{
		return _isInit;
	}
	bool verbose = true;
private:
	std::vector<ComDevice*> _deviceList;
	DcuAcceManager() = default;
	static DcuAcceManager* _instance;
	bool _isInit = false;

};
#endif
#endif