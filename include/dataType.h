#include <config.h>
#include <json-c/json.h>
#include <string.h>
#include <cstring>

#ifndef __DATA_TYPE_H__
#define __DATA_TYPE_H__
/**************************************************************************
 *  基本数据类型头文件
 *   3W：240630 UESTC wwj
 *
***************************************************************************/
typedef class BASE_BUFFER {
public:
	uint8_t IDA[MAX_ID_LEN_SIZE];				//用户ID
	uint16_t IDALen;							//用户ID长度
	uint8_t type;
	uint32_t socketFd;							//套接字端口
	virtual ~BASE_BUFFER() = default;
	virtual bool packToJsonStr(char **objPtr) = 0;			//JSON字符串的序列化和反序列化
	virtual bool parse(const char *srcPtr) = 0;
}BASE_BUFFER;


typedef class UA_BUFFER :public BASE_BUFFER {
public:
	uint8_t UAx[64];
	uint8_t UAy[64];
	bool packToJsonStr(char** objPtr) override {
		// 创建 JSON 对象
		json_object* jobj = json_object_new_object();
		char UAxs[65], UAys[65], IDAs[MAX_ID_LEN_SIZE + 1];
		memcpy(UAxs, UAx, 64);
		memcpy(UAys, UAy, 64);
		memcpy(IDAs, IDA, MAX_ID_LEN_SIZE);
		UAxs[64] = '\0';
		UAys[64] = '\0';
		IDAs[MAX_ID_LEN_SIZE] = '\0';

		// 添加数据到 JSON 对象
		json_object_object_add(jobj, "IDA", json_object_new_string(reinterpret_cast<char*>(IDAs)));
		json_object_object_add(jobj, "IDALen", json_object_new_int(IDALen));
		json_object_object_add(jobj, "type", json_object_new_int(type));
		//json_object_object_add(jobj, "socketFd", json_object_new_int(socketFd));
		json_object_object_add(jobj, "UAx", json_object_new_string(reinterpret_cast<char*>(UAxs)));
		json_object_object_add(jobj, "UAy", json_object_new_string(reinterpret_cast<char*>(UAys)));

		// 转换为 JSON 字符串
		const char* jsonStr = json_object_to_json_string(jobj);
		*objPtr = new char[strlen(jsonStr) + 1];
		strcpy(*objPtr, jsonStr);

		// 释放 JSON 对象
		json_object_put(jobj);
		return true;
	}
	bool parse(const char* srcPtr) override {
		int len = strlen(srcPtr);
		struct json_tokener* tok = json_tokener_new();
		struct json_object* jsonObj = json_tokener_parse_ex(tok, srcPtr, len);

		if (jsonObj == nullptr) {
			fprintf(stderr, "Error parsing JSON: %s\n", json_tokener_error_desc(json_tokener_get_error(tok)));
			json_tokener_free(tok);
			return false;
		}

		struct json_object* id = nullptr;
		struct json_object* idLen = nullptr;
		struct json_object* uax = nullptr;
		struct json_object* uay = nullptr;

		json_object_object_get_ex(jsonObj, "IDA", &id);
		json_object_object_get_ex(jsonObj, "IDALen", &idLen);
		json_object_object_get_ex(jsonObj, "UAx", &uax);
		json_object_object_get_ex(jsonObj, "UAy", &uay);

		if (id && idLen && uax && uay &&
			json_object_is_type(id, json_type_string) &&
			json_object_is_type(idLen, json_type_int) &&
			json_object_is_type(uax, json_type_string) &&
			json_object_is_type(uay, json_type_string)) {

			std::strncpy(reinterpret_cast<char*>(IDA), json_object_get_string(id), sizeof(IDA) );
			std::strncpy(reinterpret_cast<char*>(UAx), json_object_get_string(uax), sizeof(UAx) );
			std::strncpy(reinterpret_cast<char*>(UAy), json_object_get_string(uay), sizeof(UAy) );
			IDALen = json_object_get_int(idLen);

			json_object_put(jsonObj);
			json_tokener_free(tok);
			return true;
		}
		else {
			json_object_put(jsonObj);
			json_tokener_free(tok);
			return false;
		}
	}
}UA_BUFFER;
typedef class WATA_BUFFER :public BASE_BUFFER {
public:
	uint8_t WAx[64];
	uint8_t WAy[64];
	uint8_t TA[64];
	bool packToJsonStr(char** objPtr) override {
		// 创建 JSON 对象
		json_object* jobj = json_object_new_object();
		char WAxs[65], WAys[65], TAs[65], IDAs[MAX_ID_LEN_SIZE + 1];
		memcpy(WAxs, WAx, 64);
		memcpy(WAys, WAy, 64);
		memcpy(TAs, TA, 64);
		memcpy(IDAs, IDA, MAX_ID_LEN_SIZE);
		WAxs[64] = '\0';
		WAys[64] = '\0';
		TAs[64] = '\0';
		IDAs[MAX_ID_LEN_SIZE] = '\0';

		// 添加数据到 JSON 对象
		json_object_object_add(jobj, "IDA", json_object_new_string(reinterpret_cast<char*>(IDAs)));
		json_object_object_add(jobj, "IDALen", json_object_new_int(IDALen));
		json_object_object_add(jobj, "type", json_object_new_int(type));
		//json_object_object_add(jobj, "socketFd", json_object_new_int(socketFd));
		json_object_object_add(jobj, "WAx", json_object_new_string(reinterpret_cast<char*>(WAxs)));
		json_object_object_add(jobj, "WAy", json_object_new_string(reinterpret_cast<char*>(WAys)));
		json_object_object_add(jobj, "TA", json_object_new_string(reinterpret_cast<char*>(TAs)));

		// 转换为 JSON 字符串
		const char* jsonStr = json_object_to_json_string(jobj);
		*objPtr = new char[strlen(jsonStr) + 1];
		(*objPtr)[strlen(jsonStr)] = '\0';
		strcpy(*objPtr, jsonStr);

		// 释放 JSON 对象
		json_object_put(jobj);
		return true;
	}
	bool parse(const char* srcPtr) override {
		int len = strlen(srcPtr);
		struct json_tokener* tok = json_tokener_new();
		struct json_object* jsonObj = json_tokener_parse_ex(tok, srcPtr, len);

		if (jsonObj == nullptr) {
			fprintf(stderr, "Error parsing JSON: %s\n", json_tokener_error_desc(json_tokener_get_error(tok)));
			json_tokener_free(tok);
			return false;
		}

		struct json_object* id = nullptr;
		struct json_object* idLen = nullptr;
		struct json_object* wax = nullptr;
		struct json_object* way = nullptr;
		struct json_object* ta = nullptr;

		json_object_object_get_ex(jsonObj, "IDA", &id);
		json_object_object_get_ex(jsonObj, "IDALen", &idLen);
		json_object_object_get_ex(jsonObj, "WAx", &wax);
		json_object_object_get_ex(jsonObj, "WAy", &way);
		json_object_object_get_ex(jsonObj, "TA", &ta);

		if (id && idLen && wax && way && ta &&
			json_object_is_type(id, json_type_string) &&
			json_object_is_type(idLen, json_type_int) &&
			json_object_is_type(wax, json_type_string) &&
			json_object_is_type(way, json_type_string) &&
			json_object_is_type(ta, json_type_string)) {

			std::strncpy(reinterpret_cast<char*>(IDA), json_object_get_string(id), sizeof(IDA) );
			std::strncpy(reinterpret_cast<char*>(WAx), json_object_get_string(wax), sizeof(WAx) );
			std::strncpy(reinterpret_cast<char*>(WAy), json_object_get_string(way), sizeof(WAy) );
			std::strncpy(reinterpret_cast<char*>(TA), json_object_get_string(ta), sizeof(TA));
			IDALen = json_object_get_int(idLen);

			json_object_put(jsonObj);
			json_tokener_free(tok);
			return true;
		}
		else {
			json_object_put(jsonObj);
			json_tokener_free(tok);
			return false;
		}
	}
}WATA_BUFFER;
typedef class SIGN_BUFFER :public BASE_BUFFER {
public:
	uint8_t msg[MAX_SIGN_MSG_SIZE];				//签名原始信息	
	uint16_t msgLen;							//信息长度
	uint8_t sigR[64];							//待验证签名
	uint8_t sigS[64];
	uint8_t pubKeyAx[64];						//待验证用户声明公钥，验证签名为他人验证，需要传送自身的公钥		
	uint8_t pubKeyAy[64];
	bool packToJsonStr(char** objPtr) override {
		json_object* jobj = json_object_new_object();
		char msgStr[MAX_SIGN_MSG_SIZE + 1], sigRStr[65], sigSStr[65], pubKeyAxStr[65], pubKeyAyStr[65], IDAStr[MAX_ID_LEN_SIZE + 1];
		memcpy(msgStr, msg, msgLen);
		memcpy(sigRStr, sigR, 64);
		memcpy(sigSStr, sigS, 64);
		memcpy(pubKeyAxStr, pubKeyAx, 64);
		memcpy(pubKeyAyStr, pubKeyAy, 64);
		memcpy(IDAStr, IDA, MAX_ID_LEN_SIZE);
		msgStr[msgLen] = '\0';
		sigRStr[64] = '\0';
		sigSStr[64] = '\0';
		pubKeyAxStr[64] = '\0';
		pubKeyAyStr[64] = '\0';
		IDAStr[MAX_ID_LEN_SIZE] = '\0';

		// 添加数据到 JSON 对象
		json_object_object_add(jobj, "IDA", json_object_new_string(reinterpret_cast<char*>(IDAStr)));
		json_object_object_add(jobj, "IDALen", json_object_new_int(IDALen));
		json_object_object_add(jobj, "type", json_object_new_int(type));
		//json_object_object_add(jobj, "socketFd", json_object_new_int(socketFd));
		json_object_object_add(jobj, "msg", json_object_new_string(reinterpret_cast<char*>(msgStr)));
		json_object_object_add(jobj, "msgLen", json_object_new_int(msgLen));
		json_object_object_add(jobj, "sigR", json_object_new_string(reinterpret_cast<char*>(sigRStr)));
		json_object_object_add(jobj, "sigS", json_object_new_string(reinterpret_cast<char*>(sigSStr)));
		json_object_object_add(jobj, "pubKeyAx", json_object_new_string(reinterpret_cast<char*>(pubKeyAxStr)));
		json_object_object_add(jobj, "pubKeyAy", json_object_new_string(reinterpret_cast<char*>(pubKeyAyStr)));

		// 转换为 JSON 字符串
		const char* jsonStr = json_object_to_json_string(jobj);
		*objPtr = new char[strlen(jsonStr) + 1];
		strcpy(*objPtr, jsonStr);

		// 释放 JSON 对象
		json_object_put(jobj);
		return true;
	}
	bool parse(const char* srcPtr) override {
		int len = strlen(srcPtr);
		struct json_tokener* tok = json_tokener_new();
		struct json_object* jsonObj = json_tokener_parse_ex(tok, srcPtr, len);

		if (jsonObj == nullptr) {
			fprintf(stderr, "Error parsing JSON: %s\n", json_tokener_error_desc(json_tokener_get_error(tok)));
			json_tokener_free(tok);
			return false;
		}

		struct json_object* id = nullptr;
		struct json_object* idLen = nullptr;
		struct json_object* msgObj = nullptr;
		struct json_object* msgLenObj = nullptr;
		struct json_object* sigRObj = nullptr;
		struct json_object* sigSObj = nullptr;
		struct json_object* pubKeyAxObj = nullptr;
		struct json_object* pubKeyAyObj = nullptr;


		json_object_object_get_ex(jsonObj, "IDA", &id);
		json_object_object_get_ex(jsonObj, "IDALen", &idLen);
		json_object_object_get_ex(jsonObj, "msg", &msgObj);
		json_object_object_get_ex(jsonObj, "msgLen", &msgLenObj);
		json_object_object_get_ex(jsonObj, "sigR", &sigRObj);
		json_object_object_get_ex(jsonObj, "sigS", &sigSObj);
		json_object_object_get_ex(jsonObj, "pubKeyAx", &pubKeyAxObj);
		json_object_object_get_ex(jsonObj, "pubKeyAy", &pubKeyAyObj);


		if (id && idLen && msgObj && msgLenObj && sigRObj && sigSObj && pubKeyAxObj && pubKeyAyObj &&
			json_object_is_type(id, json_type_string) &&
			json_object_is_type(idLen, json_type_int) &&
			json_object_is_type(msgObj, json_type_string) &&
			json_object_is_type(msgLenObj, json_type_int) &&
			json_object_is_type(sigRObj, json_type_string) &&
			json_object_is_type(sigSObj, json_type_string) &&
			json_object_is_type(pubKeyAxObj, json_type_string)&&
			json_object_is_type(pubKeyAyObj, json_type_string)) {

			std::strncpy(reinterpret_cast<char*>(IDA), json_object_get_string(id), sizeof(IDA) );
			std::strncpy(reinterpret_cast<char*>(msg), json_object_get_string(msgObj), sizeof(msg) );
			std::strncpy(reinterpret_cast<char*>(sigR), json_object_get_string(sigRObj), sizeof(sigR) );
			std::strncpy(reinterpret_cast<char*>(sigS), json_object_get_string(sigSObj), sizeof(sigS) );
			std::strncpy(reinterpret_cast<char*>(pubKeyAx), json_object_get_string(pubKeyAxObj), sizeof(pubKeyAx) );
			std::strncpy(reinterpret_cast<char*>(pubKeyAy), json_object_get_string(pubKeyAyObj), sizeof(pubKeyAy));

			IDALen = json_object_get_int(idLen);
			msgLen = json_object_get_int(msgLenObj);

			json_object_put(jsonObj);
			json_tokener_free(tok);
			return true;
		}
		else {
			json_object_put(jsonObj);
			json_tokener_free(tok);
			return false;
		}
	}
}SIGN_BUFFER;
typedef class RESULT_BUFFER :public BASE_BUFFER {
public:
	uint8_t result;				//验签结果，或者处理结果		
	bool packToJsonStr(char** objPtr) {
		return false;
	}		
	bool parse(const char* srcPtr) {
		return false;
	}
}RESULT_BUFFER;

typedef struct DcuSignBuffer {				//验证签名数据结构
	uint8_t msg[MAX_SIGN_MSG_SIZE];				//签名原始信息	
	uint16_t msgLen;									//信息长度
	uint16_t IDALen;
	uint8_t IDA[MAX_ID_LEN_SIZE];				//待验证用户ID
	uint8_t sigR[64];							//待验证签名
	uint8_t sigS[64];
	uint8_t pubKeyAx[64];						//待验证用户声明公钥，验证签名为他人验证，需要传送自身的公钥		
	uint8_t pubKeyAy[64];
}DcuSignBuffer;
#endif