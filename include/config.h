#ifndef __GLOBAL_H__
#define __GLOBAL_H__
/**************************************************************************
 *  宏定义以及枚举类型头文件
 *   3W：240622 UESTC wwj
 *
***************************************************************************/
#include <iostream>
#define  USE_DCU_DEVICE_ACCE
#define  MAX_EVENTS         1000
#define  SOCKET_READ_BUFFER_MAX_SIZE        1024*200
#define  THREAD_POOL_SIZE    16
#define  CLIENT_HANDLER_SIZE 16
#define  MAX_CACHE_SIZE     10000*200
#define  PRINT_DEBUG

enum AcceStatus {
	ACCE_SUCCESS = 0,
	ACCE_FAILED = 1,
	CPU_ACCE_SUCCESS = 2,
	CPU_ACCE_FAILED = 3,
	DCU_ACCE_SUCCESS = 4,
	DCU_ACCE_FAILED = 5,

};
#define MAX_SIGN_MSG_SIZE 64					//规定的最大签名信息长度
#define MAX_ID_LEN_SIZE	32		


enum DataType {UA_TYPE,WATA_TYPE,SIGN_TYPE,RESULT_TYPE,BASE_TYPE};		
enum TaskType {NO_THING,GEN_UA,GEN_WATA,SEND_WATA,GEN_PA,GEN_DGST,GEN_SIGN,VERIFY_SIGN};			//任务类型
enum DeviceType { CPU, HCT, DCU };
const std::string DataTypeName[] = {"UA","WATA","PA","DGST","SIGN","RESULT","BASE"};
const std::string DeviceTypeName[] = { "CPU", "HCT", "DCU" };
const std::string TaskTypeName[] = { "NO_THING","GEN_UA","GEN_WATA","SEND_WATA","GEN_PA","GEN_DGST","GEN_SIGN","VERIFY_SIGN"};

enum ClientStatus {
	CLIENT_STATUS_OFFLINE = 0,
	CLIENT_STATUS_CONNECTED,
	CLIENT_STATUS_AUTHED
};
#endif