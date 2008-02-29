#pragma once
#pragma warning(disable:4200) 
#include <windows.h>
#include <tchar.h>

#pragma pack(4)

#include "TLV.h"
#define NULL_DATA 0xff


typedef struct _MemoryHeader_ {
	DWORD ReadPoint;
	DWORD WritePoint;
	DWORD BufferSize;
	BYTE Data[];
}  MemoryHeader,*PMemoryHeader ;


typedef struct _DataSharer_ {
	CRITICAL_SECTION critical_section;
	HANDLE read_event;
	HANDLE write_event;
	HANDLE map_file;
	PMemoryHeader p_memory_header;
} DataSharer,*PDataSharer;

BOOL PutData(PDataSharer p_data_sharer,BYTE type,PBYTE data,DWORD length);
PBYTE GetData(PDataSharer p_data_sharer,BYTE *p_type,DWORD *p_length);
BOOL InitDataSharer(PDataSharer p_data_sharer,TCHAR *shared_memory_name,int shared_memory_size,BOOL is_server);
