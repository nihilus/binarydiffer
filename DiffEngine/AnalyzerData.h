#pragma once
#pragma pack(1)

enum {UNKNOWN_BLOCK,FUNCTION_BLOCK};
#include "IDAAnalysisCommon.h"
//OneLocationInfo
//Pushing Basic Information on Address

typedef struct _OneLocationInfo_ {
	DWORD start_addr; //ea_t
	DWORD end_addr;
	DWORD flag; //flag_t
	//func_t get_func(current_addr)
	DWORD function_addr;
	byte block_type; // FUNCTION, UNKNOWN 
} OneLocationInfo,*POneLocationInfo;

//MapInfo
//Pushing Map information
enum {CALL,CREF_FROM,CREF_TO,DREF_FROM,DREF_TO};

typedef struct _MapInfo_ {
	BYTE type;
	DWORD src_block;
	DWORD src;
	DWORD dst;
} MapInfo,*PMapInfo;

//FingerPrintInfo
//Pushing Fingerprint Information
typedef struct _FingerPrintInfo_ {
	DWORD addr;
} FingerPrintInfo,*PFingerPrintInfo;

typedef struct _FileInfo_ 
{
	TCHAR orignal_file_path[100];
	TCHAR ComputerName[100];
	TCHAR UserName[100];
	TCHAR company_name_str[100];
	TCHAR file_version_str[100];
	TCHAR file_description_str[100];
	TCHAR internal_name_str[100];
	TCHAR product_name_str[100];
	TCHAR modified_time_str[100];
	TCHAR md5_sum_str[100];
} FileInfo,*PFileInfo;

typedef struct _MatchInfo_ {
	DWORD addr;
	DWORD end_addr;
	DWORD block_type;
	int match_rate;
	char name[40];
	DWORD type;
	DWORD match_addr;
	char match_name[40];
	int first_found_match;
	int first_not_found_match;
	int second_found_match;
	int second_not_found_match;
} MatchInfo;


enum {SEND_ANALYSIS_DATA,ADD_UNINDENTIFIED_ADDR,ADD_MATCH_ADDR,SHOW_DATA,SHOW_MATCH_ADDR,JUMP_TO_ADDR,GET_DISASM};