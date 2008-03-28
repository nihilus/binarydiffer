#pragma warning(disable:4189)
#pragma warning(disable:4127)

#include <stdio.h>
#include <windows.h>
#include <tchar.h>
#include "SharedMemory.h"

#define DEBUG_LEVEL 0

void printd(TCHAR *format, ...)
{
	va_list args;
	va_start(args,format);
	TCHAR buffer[1024*3]={0,};
	_vsntprintf(buffer,sizeof(buffer),format,args);
	va_end(args);
#if DEBUG_LEVEL > 0	
	printf(buffer);
	OutputDebugString(buffer);
#endif
}

BOOL PutData(
	PDataSharer p_data_sharer,
	BYTE type,
	PBYTE data,
	DWORD length)
{
	DWORD buffer_length;
	PTLV p_tlv=NULL;
	BOOL read_pending=FALSE;
	DWORD length_to_boundary=0;
	DWORD real_writer_point;
	DWORD real_writable_size;

	EnterCriticalSection(&p_data_sharer->critical_section); 
	if(!p_data_sharer || !p_data_sharer->p_memory_header)
	{
		return FALSE;
	}

	//needed bytes
	buffer_length=sizeof(TLV)+length;
	while(p_data_sharer->p_memory_header->BufferSize
		<=
		p_data_sharer->p_memory_header->WritePoint+buffer_length-p_data_sharer->p_memory_header->ReadPoint
	)
	{
		//lack buffer to write
		//Wait For Read Event
#if DEBUG_LEVEL > 1 
		//too small buffer
		printd(TEXT("%s: Wait For Read Event(1) BufferSize=%d WritePoint=%d buffer_length=%d ReadPoint=%d\n"),
			__FUNCTION__,
			p_data_sharer->p_memory_header->BufferSize,
			p_data_sharer->p_memory_header->WritePoint,
			buffer_length,
			p_data_sharer->p_memory_header->ReadPoint
			);
#endif		
		while(WaitForSingleObject(p_data_sharer->write_event,100)!=WAIT_OBJECT_0) ;
#if DEBUG_LEVEL > 1 
		//too small buffer
		printd(TEXT("%s: Got it\n"),
				__FUNCTION__);
#endif				
	}

	real_writer_point=p_data_sharer->p_memory_header->WritePoint%p_data_sharer->p_memory_header->BufferSize;
	real_writable_size=p_data_sharer->p_memory_header->BufferSize-real_writer_point;
	if(real_writable_size<buffer_length)
	{
#if DEBUG_LEVEL > 1 
		//too small buffer
		printd(TEXT("%s: WritePoint %d -> %d\n"),
				__FUNCTION__,
				p_data_sharer->p_memory_header->WritePoint,
				p_data_sharer->p_memory_header->WritePoint+real_writable_size);
#endif
		memset(p_data_sharer->p_memory_header->Data+real_writer_point,NULL_DATA,real_writable_size);
		//fill it with null and wait again
		p_data_sharer->p_memory_header->WritePoint+=real_writable_size;
		real_writer_point=0;
	}

	while(p_data_sharer->p_memory_header->BufferSize<=p_data_sharer->p_memory_header->WritePoint+buffer_length-p_data_sharer->p_memory_header->ReadPoint)
	{
		//lack buffer to write
		//Wait For Read Event
#if DEBUG_LEVEL > 1 
		printd(TEXT("%s: Wait For Read Event\n"),
				__FUNCTION__);
#endif		
		while(WaitForSingleObject(p_data_sharer->write_event,100)!=WAIT_OBJECT_0) ;
#if DEBUG_LEVEL > 1 
		printd(TEXT("%s: Got it\n"),
				__FUNCTION__);
#endif		
		
	}
#if DEBUG_LEVEL > 3
	printd(TEXT("%s: BufferSize:%d<WP:%d+buffer_length:%d-RP=%d"),
		__FUNCTION__,
		p_data_sharer->p_memory_header->BufferSize,p_data_sharer->p_memory_header->WritePoint,buffer_length,p_data_sharer->p_memory_header->ReadPoint);
	printd(TEXT("%s: real_writer_point=%d\n"),
		__FUNCTION__,
		real_writer_point);
#endif
	//just copy and increase WritePoint
	p_tlv=(PTLV)(p_data_sharer->p_memory_header->Data+real_writer_point);
	p_tlv->Type=type;
	p_tlv->Length=length;
	if(data && length>0)
		memcpy(p_tlv->Data,data,length);
#if DEBUG_LEVEL > 2
	printd(TEXT("%s: W=%d/R=%d type=%d length=%d(length=%d)\n"),
		__FUNCTION__,
		p_data_sharer->p_memory_header->WritePoint,
		p_data_sharer->p_memory_header->ReadPoint,
		p_tlv->Type,
		p_tlv->Length,
		length);
#endif
	p_data_sharer->p_memory_header->WritePoint+=buffer_length;
	//Set Read Event: For the case when the buffer is full
	SetEvent(p_data_sharer->read_event);
	LeaveCriticalSection(&p_data_sharer->critical_section);
	return TRUE;
}

PBYTE GetData(PDataSharer p_data_sharer,BYTE *p_type,DWORD *p_length)
{
	PTLV p_tlv;
	DWORD readable_buffer_size;
	DWORD real_readable_buffer_size;
	DWORD real_read_point;

	if(!p_data_sharer->p_memory_header)
	{
		if(p_type)
			*p_type=0;
		if(p_length)
			*p_length=0;
		return NULL;
	}

	EnterCriticalSection(&p_data_sharer->critical_section); 
#ifdef NON_BLOCKING_SHARED_MEMORY
	if(1)
#else
	while(1)
#endif
	{
		printd(TEXT("RP:%d WP: %d\n"),
			p_data_sharer->p_memory_header->ReadPoint,
			p_data_sharer->p_memory_header->WritePoint);
		if(p_data_sharer->p_memory_header->ReadPoint==p_data_sharer->p_memory_header->WritePoint)
		{
			//Wait For Read Event
			while(WaitForSingleObject(p_data_sharer->read_event,1)!=WAIT_OBJECT_0)
			{
#ifdef NON_BLOCKING_SHARED_MEMORY
				LeaveCriticalSection(&p_data_sharer->critical_section); 
				return NULL;
#endif
			}
		}

		real_read_point=p_data_sharer->p_memory_header->ReadPoint%p_data_sharer->p_memory_header->BufferSize;
		real_readable_buffer_size=p_data_sharer->p_memory_header->BufferSize-real_read_point;
		//Read
		readable_buffer_size=p_data_sharer->p_memory_header->WritePoint-p_data_sharer->p_memory_header->ReadPoint;
		if(readable_buffer_size>0 && real_readable_buffer_size>0)
		{
			if(p_data_sharer->p_memory_header->Data[real_read_point]==NULL_DATA)
			{
#if DEBUG_LEVEL > 2
				printd(TEXT("%s: got NULL moving ReadPoint %d -> %d\n"),
						__FUNCTION__,
						p_data_sharer->p_memory_header->ReadPoint,
						p_data_sharer->p_memory_header->ReadPoint+real_readable_buffer_size);
#endif
				//null data
				//put ReadPoint to the boundary start
				p_data_sharer->p_memory_header->ReadPoint+=real_readable_buffer_size;
				//make real_read_point 0
				real_read_point=0;

				//re-calculate
				real_readable_buffer_size=p_data_sharer->p_memory_header->BufferSize-real_read_point;
				readable_buffer_size=p_data_sharer->p_memory_header->WritePoint-p_data_sharer->p_memory_header->ReadPoint;
			}
		}
		if(readable_buffer_size>sizeof(TLV))
		{
			DWORD current_block_length;
			p_tlv=(PTLV)(p_data_sharer->p_memory_header->Data+p_data_sharer->p_memory_header->ReadPoint%p_data_sharer->p_memory_header->BufferSize);
			current_block_length=p_tlv->Length+sizeof(TLV);

#if DEBUG_LEVEL > 2
			printd(TEXT("%s: R=%d/W=%d p_tlv->Length=%d current_block_length=%d readable_buffer_size=%d\n"),
				__FUNCTION__,
				p_data_sharer->p_memory_header->ReadPoint,
				p_data_sharer->p_memory_header->WritePoint,
				p_tlv->Length,
				current_block_length,
				readable_buffer_size);
#endif

			if(current_block_length<=readable_buffer_size)
			{
#if DEBUG_LEVEL > 3
				printd(TEXT("%s: p_tlv->Length=%d\n"),
					__FUNCTION__,
					p_tlv->Length);
#endif
				if(p_tlv->Length>2000)
				{
#if DEBUG_LEVEL > 3
					printd(TEXT("%s: p_tlv->Length=%d\n"),
						__FUNCTION__,
						p_tlv->Length);
					printd(TEXT("%s: R=%d/W=%d p_tlv->Length=%d current_block_length=%d readable_buffer_size=%d\n"),
						__FUNCTION__,
						p_data_sharer->p_memory_header->ReadPoint,
						p_data_sharer->p_memory_header->WritePoint,
						p_tlv->Length,
						current_block_length,
						readable_buffer_size);
#endif
					LeaveCriticalSection(&p_data_sharer->critical_section);
					return NULL;
				}
				//p_tlv->Type,p_tlv->Length,p_tlv->Data
				PBYTE data_buffer=(PBYTE)malloc(p_tlv->Length);
				*p_type=p_tlv->Type;
				*p_length=p_tlv->Length;
				memcpy(data_buffer,p_tlv->Data,p_tlv->Length);
				//Increase ReadPoint
				p_data_sharer->p_memory_header->ReadPoint+=current_block_length;
				//Set Write Event: For the case when the buffer is full
				SetEvent(p_data_sharer->write_event);
				LeaveCriticalSection(&p_data_sharer->critical_section);
				return data_buffer;
			}
		}
	}
	LeaveCriticalSection(&p_data_sharer->critical_section);
	return NULL;
}

BOOL InitDataSharer(PDataSharer p_data_sharer,TCHAR *shared_memory_name,int shared_memory_size,BOOL is_server)
{
	HANDLE map_file=INVALID_HANDLE_VALUE;
	PBYTE shared_buffer;
#define READ_EVENT_POSTIFX TEXT("_read")
#define WRITE_EVENT_POSTIFX TEXT("_write")
	int event_name_len=_tcslen(shared_memory_name)+max(_tcslen(READ_EVENT_POSTIFX),_tcslen(WRITE_EVENT_POSTIFX))+10;
	char *event_name=(char *)malloc(event_name_len);

	memset(event_name,0,event_name_len);
	memcpy(event_name,shared_memory_name,_tcslen(shared_memory_name));
	memcpy(event_name+_tcslen(shared_memory_name),READ_EVENT_POSTIFX,_tcslen(READ_EVENT_POSTIFX));
	//Init R/W Event
	if(1 || is_server)
	{
		p_data_sharer->read_event=CreateEventA(NULL,FALSE,FALSE,(LPCSTR)event_name);
	}else
	{
		p_data_sharer->read_event=OpenEventA(EVENT_ALL_ACCESS ,FALSE,(LPCSTR)event_name);
	}

	if (!p_data_sharer->read_event) 
	{ 
		//error
		return FALSE;
	}
	memset(event_name,0,event_name_len);
	memcpy(event_name,shared_memory_name,_tcslen(shared_memory_name));
	memcpy(event_name+_tcslen(shared_memory_name),WRITE_EVENT_POSTIFX,_tcslen(WRITE_EVENT_POSTIFX));
	if(1 || is_server)
	{
		p_data_sharer->write_event= CreateEventA(NULL,FALSE,FALSE,(LPCSTR)event_name);
	}else
	{
		p_data_sharer->write_event=OpenEventA(EVENT_ALL_ACCESS ,FALSE,(LPCSTR)event_name);
	}

	free(event_name);
	if (!p_data_sharer->write_event) 
	{ 
		//error
		return FALSE;
	}

	if(!is_server)
	{
		//Creates Map
		map_file=OpenFileMappingA(
			FILE_MAP_ALL_ACCESS,	// read/write access
			FALSE,					// do not inherit the name
			(LPCSTR)shared_memory_name);	// name of mapping object
	}
	if(map_file==INVALID_HANDLE_VALUE || !map_file)
	{
		//Creates Map
		map_file=CreateFileMappingA(
			INVALID_HANDLE_VALUE,
			NULL,
			PAGE_READWRITE,
			0,
			shared_memory_size+sizeof(MemoryHeader),
			(LPCSTR)shared_memory_name);
	}

	if (map_file!=INVALID_HANDLE_VALUE && map_file)  
	{
		printd(TEXT("%s: shared_memory_name=%s map_file=%x\n"),
			__FUNCTION__,
			shared_memory_name,
			map_file);
	
		shared_buffer=(PBYTE)MapViewOfFile(
			map_file,
			FILE_MAP_ALL_ACCESS,	// read/write permission
			0,
			0,
			shared_memory_size+sizeof(MemoryHeader)); 

		if(shared_buffer)
		{
			printd(TEXT("%s: shared_buffer=%x\n"),
				__FUNCTION__,
				shared_buffer);
		
			//Init Shared Memory Header(R/W Pointer,Size)
			p_data_sharer->p_memory_header=(PMemoryHeader)shared_buffer;
			if(is_server && p_data_sharer->p_memory_header)
			{
				p_data_sharer->p_memory_header->BufferSize=shared_memory_size;
				p_data_sharer->p_memory_header->ReadPoint=p_data_sharer->p_memory_header->WritePoint=0;
			}
			printd(TEXT("%s: p_data_sharer->p_memory_header->Data=%x\n"),
				__FUNCTION__,
				p_data_sharer->p_memory_header->Data);
				
			InitializeCriticalSection(&p_data_sharer->critical_section);
			return TRUE;
		}
	}
	return FALSE;	
}
