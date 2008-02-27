#include <stdio.h>
#include <windows.h>
#include "SharedMemory.h"
#include "AnalyzerData.h"

int main()
{
	DataSharer data_sharer;
	InitDataSharer(&data_sharer,
		SHARED_MEMORY_NAME,
		SHARED_MEMORY_SIZE,
		FALSE);

	for(int i=0;i<100;i++)
	{
#define DATA_STR "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		PutData(&data_sharer,0,(PBYTE)DATA_STR,(DWORD)strlen(DATA_STR));
	}
	return(0);
}
