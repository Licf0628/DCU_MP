#include <hcsAcce/comDevice.h>
#include <hcsAcce/cpuDevice.h>
#include <vector>
#include <mutex>
#ifndef __CPU_ACCE_MANAGER_H__
#define __CPU_ACCE_MANAGER_H__
/**************************************************************************
 * 功能：CPU并行加速执行管理类
 *   3W：240603 交子 wwj
 *
***************************************************************************/
class CpuAcceManager {
public:
	static CpuAcceManager* Instance()		// 单实例化对象
	{
		if (CpuAcceManager::_instance == nullptr)
		{
			static std::mutex mutex;	// 加上互斥量，防止异步初始化
			mutex.lock();
			if (CpuAcceManager::_instance == nullptr)
			{
				CpuAcceManager::_instance = new CpuAcceManager();
			}
			mutex.unlock();
		}
		return CpuAcceManager::_instance;
	}
	bool initCpuDevice() {
		if (_isInit == true) {
			std::cout << "CPU Manager have been init!" << std::endl;
		}
		cpuCoreNum = std::thread::hardware_concurrency();
		std::string name = "CPU";
		std::cout << "Successfully init cpuAcceManager, CPU core number: " << cpuCoreNum << std::endl;
		cpuDevice = new CpuDevice(name);
		_isInit = true;
		return true;
	}
	ComDevice* getCpuDevice() {
		if (_isInit) {
			return cpuDevice;
		}
		else {
			std::cout << "CPU Manager  not init!" << std::endl;
			return NULL;
		}

	}
	int getCpuCoreNum() { return cpuCoreNum; }
	bool _isVerbose = true;
private:
	CpuAcceManager() = default;
	static CpuAcceManager* _instance;
	ComDevice* cpuDevice;
	uint32_t cpuCoreNum = 0;
	bool _isInit = false;

};

#endif