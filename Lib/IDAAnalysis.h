#pragma warning (disable: 4819)
#pragma warning (disable: 4996)
#pragma warning (disable : 4786)

#pragma once
#include <windows.h>
#include "IdaIncludes.h"

/****************************************************************************************************************/
/* Location Info && AddrMapHash structures and routines*/

typedef struct _LocationInfo_{
	ea_t address;
#define UNKNOWN 0
#define CODE 1
#define FUNCTION 2
#define DATA 3
	int block_type;
	flags_t flag;
#ifdef SAVE_NAME
	char name[1024];
	char function_name[1024];
#else
	char name[1];
	char function_name[1];
#endif
	size_t block_size;
	int instruction_count;
	DWORD block_reference_count;
	func_t *p_func_t;

	int prev_drefs_size;
	ea_t *prev_drefs;

	int prev_crefs_size;
	ea_t *prev_crefs;

	int next_crefs_size;
	ea_t *next_crefs;

	int call_addrs_size;
	ea_t *call_addrs;

	int next_drefs_size;
	ea_t *next_drefs;

	ea_t checked_function_consistency;
	int function_addresses_size;
	ea_t *function_addresses;

	bool saved;
	struct _LocationInfo_ *linked_node; 
	struct _LocationInfo_ *next; 
} LocationInfo;

typedef struct _AddrMapHash_{
	ea_t address;
	LocationInfo *p_location_info;
	struct _AddrMapHash_ *branch;
} AddrMapHash;


bool StartProcess(LPTSTR szCmdline);
AddrMapHash *AddToAddrMap(AddrMapHash *addr_map_hash,LocationInfo *p_location_info);
LocationInfo *FindFromAddrMap(AddrMapHash *addr_map_hash,ea_t address);
void DumpAddressInfo(ea_t address);
void DumpLocationInfo(AddrMapHash *addr_map_base,ea_t address);
bool MakeMemberOfFunction(AddrMapHash *addr_map_base,ea_t function_start_address,LocationInfo *p_location_info);
void CheckLocationInfos(AddrMapHash *addr_map_base,LocationInfo *p_first_location_info);
bool AnalyzeRegion(AddrMapHash **p_addr_map_base,LocationInfo **p_p_first_location_info);

void AnalyzeIDAData(bool (*Callback)(PVOID context,BYTE type,PBYTE data,DWORD length),PVOID Context);
