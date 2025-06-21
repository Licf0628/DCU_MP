#ifndef __SCHEDULER_H__
#define __SCHEDULER_H__
/**************************************************************************
 * 功能：调取器，负责提取缓冲区的验签数据并管理异构计算管理器进行执行
 *   3W：240623 交子 wwj
 *
***************************************************************************/
#include <condition_variable>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>
#include <config.h>
#include "tcpServer/cache.h"
#include <hcsAcce/hcsManager.h>
#include <queue>
#include <tcpServer/cache.h>
#include <comUtil/duration.h>
#define GEN_WATA_SIZE_FOR_CPU      50000
#define GEN_WATA_SIZE_FOR_HCT      100000
#define GEN_WATA_SIZE_FOR_DCU      500000
#define VERIFY_SIGN_SIZE_FOR_CPU    50000
#define VERIFY_SIGN_SIZE_FOR_HCT    100000
#define VERIFY_SIGN_SIZE_FOR_DCU    500000
/**************************************************************************
 * 功能：任务调度器，实现任务调度线程任务以及异构执行设备的监督线程任务
 *   3W：240723 交子 wwj
 *
***************************************************************************/

class Scheduler {
public:
    Scheduler(HcsManager& manager, std::vector<Cache<BASE_BUFFER*>*>&caches,
        SM2_KEY& mKeyPair,SM2_KEY &keyPair, std::condition_variable& sendVar);
    ~Scheduler();


private:
    SM2_KEY keyPair;
    SM2_KEY mKeyPair;

    std::vector<Cache<BASE_BUFFER*>*>& caches;//消费缓冲区

    HcsManager& hcsManager;
    std::thread  schedulerThread;
    std::vector<std::thread> hcsSuperviseThreads;                    //异构设备的任务监督线程，每一种设备都由一条线程去监督其完成情况

    std::vector<std::mutex*> cacheMutexes;
    std::mutex rwMutex;
    std::vector < std::condition_variable*> condVars;
    std::vector<TaskType> taskTypeVec;

    std::condition_variable& sendCondVar;
    bool stopFlag;

    void superviseFunc(DeviceType devType);
    void schedulerFunc();
    void chooseExecuter(TaskType taskType);
    int getTaskNum(TaskType taskType, DeviceType excDevType);
    void executeTask(TaskType taskType, DeviceType excDevType);
};
#endif