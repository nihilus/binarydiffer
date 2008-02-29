#include <windows.h>


HANDLE ServerHandle=NULL;

bool StartProcess(LPTSTR szCmdline)
{
	//msg("%s: Entry\n",__FUNCTION__);

	STARTUPINFO StartupInfo;
	PROCESS_INFORMATION ProcessInformation;

	//msg("%s: Executing [%s] \n",__FUNCTION__,szCmdline);
	if(CreateProcess(
		NULL,
		szCmdline,      // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&StartupInfo,            // Pointer to STARTUPINFO structure
		&ProcessInformation)           // Pointer to PROCESS_INFORMATION structure
	)
	{
		ServerHandle=ProcessInformation.hProcess;
		//msg("%s: ServerHandle=%x\n",__FUNCTION__,ServerHandle);
		return TRUE;
	}
	if(1) //if server process is already up
	{
		//OpenProcess
		ServerHandle=OpenProcess(
			PROCESS_ALL_ACCESS,
			FALSE,
			10656);
		//msg("%s: ServerHandle=%x\n",__FUNCTION__,ServerHandle);
	}
	return FALSE;
}

void *malloc_wrapper(size_t size)
{
	if(ServerHandle)
	{
		return VirtualAllocEx(
			ServerHandle,
			NULL,
			size,
			MEM_COMMIT,
			PAGE_READWRITE);
	}else{
		return malloc(size);
	}
}

void *realloc(void *memblock,size_t old_size,size_t size)
{
	if(ServerHandle)
	{
		LPVOID ret_mem=VirtualAllocEx(
			ServerHandle,
			NULL,
			size,
			MEM_COMMIT,
			PAGE_READWRITE);
		if(memblock && old_size>0)
		{
			memcpy(ret_mem,memblock,old_size);
			VirtualFree(memblock,
				0, 
				MEM_RELEASE);
		}
		return ret_mem;
	}else{
		return realloc(memblock,size);
	}
}