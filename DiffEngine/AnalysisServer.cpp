#if defined(INTERNAL_SERVER) || defined(STANDALONE_SERVER)
// turn off warning about symbols too long for debugger
#pragma warning (disable : 4786)
#pragma warning (disable : 4996)
//#pragma warning (disable : 2220)

#include <stdio.h>
#include <windows.h>
#include <winsock.h>
#include <time.h>

#include <string>
#include <map>
#include <hash_map>
#include <iostream>
#include <list>
#include <hash_set>
#include "AnalysisServer.h"
#include "SocketOperation.h"

#ifndef INTERNAL_SERVER
#include "ProcessUtils.h"
#endif

#define DEBUG_LEVEL 0

#undef USE_MATCH_MAP
#define USE_MATCH_MAP

FILE *log_fd=NULL;
bool met_linefeed=TRUE;
void printd2(char *format, ...)
{
	if(!log_fd)
	{
		log_fd=fopen("log.txt","a+");
	}
	va_list args;
	va_start(args,format);
	char buffer[1024*3]={0,};
	_vsnprintf(buffer,sizeof(buffer),format,args);
	va_end(args);
	__time64_t ltime;
	_time64(&ltime);
	char *time_str=strdup(_ctime64( &ltime));
	time_str[strlen(time_str)-1]=NULL;
	if(met_linefeed)
		printf("%s: %s", time_str,buffer);
	else
		printf( "%s",buffer);
	if(log_fd)
	{
		if(met_linefeed)
			fprintf(log_fd,"%s: %s",time_str,buffer);
		else
			fprintf(log_fd,"%s",buffer);
		fflush(log_fd);
	}
	if(buffer[strlen(buffer)-1]=='\n')
		met_linefeed=TRUE;
	else
		met_linefeed=FALSE;
}

#ifdef INTERNAL_SERVER
#include "IdaIncludes.h"
#undef strncat
#define strncat qstrncat
#define printf printd2
#define msg printd2
#else //INTERNAL_SERVER
#define printf printd2
#define msg printd2
#endif 

#include "SharedMemory.h"
#include "SharedSocket.h"
#include "AnalyzerData.h"

#define SHOW_MATCHED_FUNCTION
#define SHOW_UNIDENTIFIED_ADDR
#define SHOW_MATCHED_ADDR

using namespace std;
using namespace stdext;

#define TREE_CHECKED 0x00000001

typedef struct _MappingData_{
	short Type;
	short SubType;
	DWORD Status;
	DWORD Address;
	int MatchRate;
	DWORD UnpatchedParentAddress;
	DWORD PatchedParentAddress;
} MappingData;

enum {NAME_MATCH,FINGER_PRINT_MATCH,TWO_LEVEL_FINGER_PRINT_MATCH,TREE_MATCH};
char *MappingDataTypeStr[]={"Name Match","Fingerprint Match","Two Level Fingerprint Match","Tree Match"};
int types[]={CREF_FROM,CREF_TO,CALL,DREF_FROM,DREF_TO};

char *MapInfoTypesStr[]={"Call","Cref From","Cref To","Dref From","Dref To"};
char *SubTypeStr[]={"Cref From","Cref To","Call","Dref From","Dref To"};

/*
typedef char *string;
struct equ_str {
	size_t operator()(const string & x) const {
		size_t key;
		for(size_t i=0;i<strlen(x);i++)
		{
			key+=x[i];
		}
		return key;
	}
	bool operator()(const string & x, const string & y) const {
		if(strcmp(x, y)!=0)
			return true;
		return false;
	}
};

*/
typedef pair <DWORD, POneLocationInfo> AddrPOneLocationInfo_Pair;
typedef pair <string, DWORD> FingerPrintAddress_Pair;
typedef pair <string, DWORD*> TwoLevelFingerPrintAddress_Pair;
typedef pair <DWORD, string> AddressFingerPrintAddress_Pair;
typedef pair <string, DWORD> NameAddress_Pair;
typedef pair <DWORD, string> AddressName_Pair;
typedef pair <DWORD, PMapInfo> AddrPMapInfo_Pair;
typedef pair <DWORD, MappingData> MatchMap_Pair;
typedef pair <string, string> String_Pair;

//,hash_compare<string,equ_str> 
typedef struct _AnalysisInfo_ {
	FileInfo file_info;
	multimap <DWORD, POneLocationInfo> address_hash_map;
	multimap <string, DWORD > fingerprint_hash_map;
	multimap <string, DWORD *> two_level_fingerprint_hash_map;
	multimap <DWORD ,string > address_fingerprint_hash_map;
	multimap <string, DWORD> name_hash_map;
	multimap <DWORD,string> address_name_hash_map;
	multimap <DWORD, PMapInfo> map_info_hash_map;
} AnalysisInfo,*PAnalysisInfo;

typedef struct _AnalysisInfoList_ {
	PAnalysisInfo p_analysis_info;
	SOCKET socket;
	DWORD address;
	struct _AnalysisInfoList_ *prev;
	struct _AnalysisInfoList_ *next;
} AnalysisInfoList;
AnalysisInfoList *pAnalysisInfoListRoot=NULL;


DWORD *GetMappedAddresses(PAnalysisInfo p_analysis_info,DWORD address,int type,int *p_length)
{
	multimap <DWORD, PMapInfo>::iterator map_info_hash_map_pIter;
	DWORD *addresses=NULL;
	int current_size=50;

	addresses=(DWORD *)malloc(sizeof(DWORD)*current_size);
	int addresses_i=0;
	for(map_info_hash_map_pIter=p_analysis_info->map_info_hash_map.find(address);
		map_info_hash_map_pIter!=p_analysis_info->map_info_hash_map.end();
		map_info_hash_map_pIter++
		)
	{
		if(map_info_hash_map_pIter->first!=address)
			break;
		if(map_info_hash_map_pIter->second->type==type)
		{
			//map_info_hash_map_pIter->second->dst
			//TODO: add
			if(current_size<addresses_i+2)
			{
				current_size+=50;
				addresses=(DWORD *)realloc(addresses,sizeof(DWORD)*(current_size));
			}
			addresses[addresses_i]=map_info_hash_map_pIter->second->dst;
			addresses_i++;
			addresses[addresses_i]=NULL;
		}
	}

	if(p_length)
		*p_length=addresses_i;
	if(addresses_i==0)
	{
		free(addresses);
		addresses=NULL;
	}
	return addresses;
}

void RemoveFromFingerprintHash(PAnalysisInfo p_analysis_info,DWORD address)
{
	multimap <DWORD ,string >::iterator address_fingerprint_hash_map_PIter=
		p_analysis_info->address_fingerprint_hash_map.find(address);
	if(address_fingerprint_hash_map_PIter!=p_analysis_info->address_fingerprint_hash_map.end())
	{
		multimap <string,DWORD>::iterator fingerprint_hash_map_PIter;
		for(fingerprint_hash_map_PIter=p_analysis_info->fingerprint_hash_map.find(address_fingerprint_hash_map_PIter->second);
			fingerprint_hash_map_PIter!=p_analysis_info->fingerprint_hash_map.end();
			fingerprint_hash_map_PIter++
		)
		{
			if(fingerprint_hash_map_PIter->first!=address_fingerprint_hash_map_PIter->second)
				break;
			if(fingerprint_hash_map_PIter->second==address)
			{
				p_analysis_info->fingerprint_hash_map.erase(fingerprint_hash_map_PIter);
				break;
			}
		}
	}
}

const char *GetFingerPrintFromFingerprintHash(PAnalysisInfo p_analysis_info,DWORD address)
{
	multimap <DWORD ,string >::iterator address_fingerprint_hash_map_PIter=
		p_analysis_info->address_fingerprint_hash_map.find(address);
	if(address_fingerprint_hash_map_PIter!=p_analysis_info->address_fingerprint_hash_map.end())
	{
		return address_fingerprint_hash_map_PIter->second.c_str();
	}
	return "None";
}

int GetFingerPrintMatchRate(string unpatched_finger_print,string patched_finger_print)
{
	if(unpatched_finger_print.length()==0)
		return 0;

	if(unpatched_finger_print==patched_finger_print)
	{
		return 100;
	}

	if(unpatched_finger_print.length()==patched_finger_print.length())
	{
		return 99;
	}

	//return TRUE;
	/*
	printf("%s: %x/%x=%s:%s\n",__FUNCTION__,
		unpatched_address,patched_address,
		unpatched_finger_print.c_str(),patched_finger_print.c_str());
	*/
	return 0;
}

int GetMatchRate(
	PAnalysisInfo p_analysis_info_unpatched,
	PAnalysisInfo p_analysis_info_patched,
	DWORD unpatched_address,
	DWORD patched_address
)
{
	multimap <DWORD, string>::iterator unpatched_address_fingerprint_hash_map_Iter;
	multimap <DWORD, string>::iterator patched_address_fingerprint_hash_map_Iter;
						
	unpatched_address_fingerprint_hash_map_Iter=p_analysis_info_unpatched->address_fingerprint_hash_map.find(unpatched_address);

	patched_address_fingerprint_hash_map_Iter=p_analysis_info_patched->address_fingerprint_hash_map.find(patched_address);

	if(
		unpatched_address_fingerprint_hash_map_Iter!=p_analysis_info_unpatched->address_fingerprint_hash_map.end() &&
		patched_address_fingerprint_hash_map_Iter!=p_analysis_info_patched->address_fingerprint_hash_map.end() 
	)
	{
		return GetFingerPrintMatchRate(
			unpatched_address_fingerprint_hash_map_Iter->second,
			patched_address_fingerprint_hash_map_Iter->second);
	}
	return 0;
}

typedef struct _AnalysisResult_ {
	multimap <DWORD,MappingData> match_map;
	multimap <DWORD,MappingData> reverse_match_map;	
} AnalysisResult;

void DoFingerPrintMatch(
	multimap <DWORD,MappingData> *p_match_map,
	PAnalysisInfo p_analysis_info_unpatched,
	PAnalysisInfo p_analysis_info_patched)
{
		int matched_number=0;
		////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		//////1. Fingerprint match
		multimap <string,string> recent_fingerprint_match_map;
		multimap <string,DWORD>::iterator fingerprint_hash_map_pIter;
		multimap <string, DWORD>::iterator patched_fingerprint_hash_map_pIter;
		multimap <string, string> to_remove_map;

		for(fingerprint_hash_map_pIter=p_analysis_info_unpatched->fingerprint_hash_map.begin();
			fingerprint_hash_map_pIter!=p_analysis_info_unpatched->fingerprint_hash_map.end();
			fingerprint_hash_map_pIter++)
		{
			if(p_analysis_info_unpatched->fingerprint_hash_map.count(fingerprint_hash_map_pIter->first)==1)
			{
				//unique key
				if(p_analysis_info_patched->fingerprint_hash_map.count(fingerprint_hash_map_pIter->first)==1)
				{
					patched_fingerprint_hash_map_pIter=p_analysis_info_patched->fingerprint_hash_map.find(fingerprint_hash_map_pIter->first);
					if(patched_fingerprint_hash_map_pIter!=p_analysis_info_patched->fingerprint_hash_map.end())
					{
						MappingData mapping_data;
						memset(&mapping_data,0,sizeof(MappingData));
						mapping_data.Type=FINGER_PRINT_MATCH;
						mapping_data.Address=patched_fingerprint_hash_map_pIter->second;
						mapping_data.MatchRate=GetMatchRate(
							p_analysis_info_unpatched,
							p_analysis_info_patched,
							fingerprint_hash_map_pIter->second,
							patched_fingerprint_hash_map_pIter->second
							);
						p_match_map->insert(MatchMap_Pair(
							fingerprint_hash_map_pIter->second,
							mapping_data
							));
						to_remove_map.insert(String_Pair(
							fingerprint_hash_map_pIter->first,
							patched_fingerprint_hash_map_pIter->first
							));
						matched_number++;
					}
				}
			}
		}
		multimap <string, string>::iterator to_remove_map_pIter;
		for(to_remove_map_pIter=to_remove_map.begin();
			to_remove_map_pIter!=to_remove_map.end();
			to_remove_map_pIter++)
		{
			p_analysis_info_unpatched->fingerprint_hash_map.erase(to_remove_map_pIter->first);
			p_analysis_info_patched->fingerprint_hash_map.erase(to_remove_map_pIter->second);			
		}
		to_remove_map.clear();
		printf("%s: fingerprint matched number=%d\n",__FUNCTION__,matched_number);
		////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
}
extern CRITICAL_SECTION CriticalSection;
AnalysisInfoList *GetAnalysisInfoList(int pos)
{
	EnterCriticalSection(&CriticalSection); 
	AnalysisInfoList *pAnalysisInfoListCur=pAnalysisInfoListRoot;
	int analysis_info_i=0;
	while(pAnalysisInfoListCur)
	{
		if(pAnalysisInfoListCur->p_analysis_info)
		{
			if(pos==analysis_info_i)
				break;
			analysis_info_i++;
		}
		pAnalysisInfoListCur=pAnalysisInfoListCur->next;
	}
	LeaveCriticalSection(&CriticalSection);
	return pAnalysisInfoListCur;
}

void DumpMatchMapIterInfo(multimap <DWORD, MappingData>::iterator match_map_iter)
{
	msg("match: %x - %x (%s/%s) from: %x %x (Match rate=%d/100) Status=%x\n",
		match_map_iter->first,
		match_map_iter->second.Address,
		MappingDataTypeStr[match_map_iter->second.Type],
		(match_map_iter->second.Type==TREE_MATCH && match_map_iter->second.SubType<sizeof(SubTypeStr)/sizeof(char *))?SubTypeStr[match_map_iter->second.SubType]:"None",
		match_map_iter->second.UnpatchedParentAddress,
		match_map_iter->second.PatchedParentAddress,
		match_map_iter->second.MatchRate,
		match_map_iter->second.Status);
}

void AnalyzeFunctionSanity(
	AnalysisResult *p_analysis_result,
	PAnalysisInfo p_analysis_info_unpatched,
	PAnalysisInfo p_analysis_info_patched
	)
{
	multimap <DWORD, MappingData>::iterator last_match_map_iter;
	multimap <DWORD, MappingData>::iterator match_map_iter;
	DWORD last_unpatched_addr=0;
	DWORD last_patched_addr=0;
	DWORD unpatched_addr=0;
	DWORD patched_addr=0;
	
	PAnalysisInfo p_unpatched_analysis_info=GetAnalysisInfoList(0)->p_analysis_info;
	PAnalysisInfo p_patched_analysis_info=GetAnalysisInfoList(1)->p_analysis_info;
	
	for(match_map_iter=p_analysis_result->match_map.begin();
		match_map_iter!=p_analysis_result->match_map.end();
		match_map_iter++)
	{
		multimap <DWORD, POneLocationInfo>::iterator address_hash_map_pIter;
		address_hash_map_pIter=p_analysis_info_unpatched->address_hash_map.find(match_map_iter->first);
		if(address_hash_map_pIter!=p_analysis_info_unpatched->address_hash_map.end())
		{
			unpatched_addr=match_map_iter->first;
			patched_addr=match_map_iter->second.Address;
			if(last_unpatched_addr!=unpatched_addr &&
				last_patched_addr!=patched_addr
			)
			{
				if(address_hash_map_pIter->second->block_type==FUNCTION_BLOCK)
				{
				}else
				{
				}
			}
			if(last_unpatched_addr==unpatched_addr &&
				last_patched_addr!=patched_addr
			)
			{
				printf("%s: **** Multiple Possibilities\n",__FUNCTION__);
				DumpMatchMapIterInfo(last_match_map_iter);
				DumpMatchMapIterInfo(match_map_iter);
			}

			last_match_map_iter=match_map_iter;
			last_unpatched_addr=unpatched_addr;
			last_patched_addr=patched_addr;
		}
	}

	for(match_map_iter=p_analysis_result->reverse_match_map.begin();
		match_map_iter!=p_analysis_result->reverse_match_map.end();
		match_map_iter++)
	{
		multimap <DWORD, POneLocationInfo>::iterator address_hash_map_pIter;
		address_hash_map_pIter=p_analysis_info_patched->address_hash_map.find(match_map_iter->first);

		if(address_hash_map_pIter!=p_analysis_info_patched->address_hash_map.end())
		{
			unpatched_addr=match_map_iter->first;
			patched_addr=match_map_iter->second.Address;
			
			if(last_unpatched_addr!=unpatched_addr &&
				last_patched_addr!=patched_addr)
			{
				if(address_hash_map_pIter->second->block_type==FUNCTION_BLOCK)
				{
				}else
				{
				}
			}
			if(last_unpatched_addr==unpatched_addr &&
				last_patched_addr!=patched_addr
			)
			{
				printf("%s: **** Multiple Possibilities\n",__FUNCTION__);
				DumpMatchMapIterInfo(last_match_map_iter);
				DumpMatchMapIterInfo(match_map_iter);
			}else
			{
			}
			last_match_map_iter=match_map_iter;
			last_unpatched_addr=unpatched_addr;
			last_patched_addr=patched_addr;
		}
	}
}
	
AnalysisResult *DiffAnalysisInfo(PAnalysisInfo p_analysis_info_unpatched,PAnalysisInfo p_analysis_info_patched)
{
	multimap <DWORD, POneLocationInfo>::iterator address_hash_map_pIter;
	multimap <string, DWORD>::iterator fingerprint_hash_map_pIter;
	multimap <string, DWORD>::iterator name_hash_map_pIter;
	multimap <DWORD, PMapInfo>::iterator map_info_hash_map_pIter;
	multimap <string, string> to_remove_map;

	AnalysisResult *p_analysis_result=new AnalysisResult;
	printf("%s: Diff %d-%d\n",__FUNCTION__,
		p_analysis_info_unpatched->fingerprint_hash_map.size(),
		p_analysis_info_patched->fingerprint_hash_map.size());

	int matched_number=0;
	bool done_name_match=FALSE;

	multimap <DWORD,MappingData> temporary_match_map;
	while(1)
	{	
		// Name Match
		if(!done_name_match)
		{
			done_name_match=TRUE;
			//name match
			multimap <string, DWORD>::iterator patched_name_hash_map_pIter;
			for(name_hash_map_pIter=p_analysis_info_unpatched->name_hash_map.begin();
				name_hash_map_pIter!=p_analysis_info_unpatched->name_hash_map.end();
				name_hash_map_pIter++)
			{
				if(p_analysis_info_unpatched->name_hash_map.count(name_hash_map_pIter->first)==1)
				{
					//unique key
					if(p_analysis_info_patched->name_hash_map.count(name_hash_map_pIter->first)==1)
					{
						patched_name_hash_map_pIter=p_analysis_info_patched->name_hash_map.find(name_hash_map_pIter->first);
						if(patched_name_hash_map_pIter!=p_analysis_info_patched->name_hash_map.end())
						{
							MappingData mapping_data;
							memset(&mapping_data,0,sizeof(MappingData));
							mapping_data.Type=NAME_MATCH;
							mapping_data.Address=patched_name_hash_map_pIter->second;
							mapping_data.MatchRate=GetMatchRate(
								p_analysis_info_unpatched,
								p_analysis_info_patched,
								name_hash_map_pIter->second,
								patched_name_hash_map_pIter->second
								);

							temporary_match_map.insert(MatchMap_Pair(
								name_hash_map_pIter->second,
								mapping_data
								));
							matched_number++;
#if DEBUG_LEVEL > 2
							printf("%s: matched [%s]%x-[%s]%x\n",__FUNCTION__,
								name_hash_map_pIter->first.c_str(),
								name_hash_map_pIter->second,
								patched_name_hash_map_pIter->first.c_str(),
								patched_name_hash_map_pIter->second);
#endif
						}
						//printf("%s: %s\n",__FUNCTION__,name_hash_map_pIter->first);
					}
				}
			}
			printf("%s: name matched number=%d\n",__FUNCTION__,matched_number);
		}

		// FingerPrint Match
		DoFingerPrintMatch(
			&temporary_match_map,
			p_analysis_info_unpatched,
			p_analysis_info_patched);

		// Tree match
		multimap <DWORD,MappingData> *p_analyze_for_tree_matching_target_match_map=&temporary_match_map;
		while(1)
		{
			int matched_count=0;
			int processed_count=0;
			multimap <DWORD, MappingData>::iterator match_map_iter;
			multimap <DWORD,MappingData> *p_analyze_for_tree_matching_result_match_map=new multimap <DWORD,MappingData>;

			printf("%s: Performing Tree Matching on %d Items\n",__FUNCTION__,p_analyze_for_tree_matching_target_match_map->size());
			for(match_map_iter=p_analyze_for_tree_matching_target_match_map->begin();
				match_map_iter!=p_analyze_for_tree_matching_target_match_map->end();
				match_map_iter++)
			{
				match_map_iter->second.Status|=TREE_CHECKED;
#ifdef USE_MATCH_MAP
				p_analysis_result->match_map.insert(MatchMap_Pair(match_map_iter->first,match_map_iter->second));

				DWORD src_address;
				src_address=match_map_iter->second.Address;
				match_map_iter->second.Address=match_map_iter->first;
				p_analysis_result->reverse_match_map.insert(MatchMap_Pair(src_address,match_map_iter->second));
#endif

				int unpatched_addresses_number;
				int patched_addresses_number;

				for(int type_pos=0;type_pos<sizeof(types)/sizeof(int);type_pos++)
				{
					DWORD *unpatched_addresses=GetMappedAddresses(p_analysis_info_unpatched,match_map_iter->first,types[type_pos],&unpatched_addresses_number);
					DWORD *patched_addresses=GetMappedAddresses(p_analysis_info_patched,match_map_iter->second.Address,types[type_pos],&patched_addresses_number);
					if(unpatched_addresses_number==patched_addresses_number)
					{
						multimap <DWORD, string>::iterator unpatched_address_fingerprint_hash_map_Iter;
						multimap <DWORD, string>::iterator patched_address_fingerprint_hash_map_Iter;
						
						for(int i=0;i<unpatched_addresses_number;i++)
						{
							unpatched_address_fingerprint_hash_map_Iter=p_analysis_info_unpatched->address_fingerprint_hash_map.find(unpatched_addresses[i]);
							patched_address_fingerprint_hash_map_Iter=p_analysis_info_patched->address_fingerprint_hash_map.find(patched_addresses[i]);
								
							int match_rate;
							if(
								(
									(
										unpatched_address_fingerprint_hash_map_Iter!=p_analysis_info_unpatched->address_fingerprint_hash_map.end() &&
										patched_address_fingerprint_hash_map_Iter!=p_analysis_info_patched->address_fingerprint_hash_map.end() 
									) &&
									(match_rate=GetFingerPrintMatchRate(
										unpatched_address_fingerprint_hash_map_Iter->second,
										patched_address_fingerprint_hash_map_Iter->second))
								) ||
								(
									unpatched_address_fingerprint_hash_map_Iter==p_analysis_info_unpatched->address_fingerprint_hash_map.end() &&
									patched_address_fingerprint_hash_map_Iter==p_analysis_info_patched->address_fingerprint_hash_map.end()
								)
							)
							{
								bool add=TRUE;
								multimap <DWORD,MappingData> *p_compared_match_map[]={&p_analysis_result->match_map,
									p_analyze_for_tree_matching_result_match_map,
									p_analyze_for_tree_matching_target_match_map};
								
								multimap <DWORD, MappingData>::iterator cur_match_map_iter;

								//If not found from "all" match map
								for(int compare_i=0;compare_i<sizeof(p_compared_match_map)/sizeof(multimap <DWORD,MappingData> *);compare_i++)
								{
									cur_match_map_iter=p_compared_match_map[compare_i]->find(unpatched_addresses[i]);

									while(cur_match_map_iter!=p_compared_match_map[compare_i]->end() &&
											cur_match_map_iter->first==unpatched_addresses[i]
									)
									{
										if(cur_match_map_iter->first==unpatched_addresses[i] &&
											cur_match_map_iter->second.Address==patched_addresses[i])
										{
											add=FALSE;
											break;
										}
										cur_match_map_iter++;
									}
									if(!add)
										break;
								}
								if(add)
								{
									MappingData mapping_data;
									memset(&mapping_data,0,sizeof(MappingData));
									mapping_data.Type=TREE_MATCH;
									mapping_data.SubType=type_pos;
									mapping_data.Address=patched_addresses[i];
									mapping_data.MatchRate=match_rate;
									mapping_data.UnpatchedParentAddress=match_map_iter->first;
									mapping_data.PatchedParentAddress=match_map_iter->second.Address;
									p_analyze_for_tree_matching_result_match_map->insert(MatchMap_Pair(
										unpatched_addresses[i],
										mapping_data
										));
								}
							}
						}
					}
					if(unpatched_addresses)
						free(unpatched_addresses);
					if(patched_addresses)
						free(patched_addresses);
				}
				processed_count++;
				if(processed_count%100==0 || processed_count==p_analyze_for_tree_matching_target_match_map->size())
				{
					printf("%s: %d/%d Items processed and produced %d match entries.\n",__FUNCTION__,
						processed_count,
						p_analyze_for_tree_matching_target_match_map->size(),
						p_analyze_for_tree_matching_result_match_map->size()
					);
				}
			}

			p_analyze_for_tree_matching_target_match_map->clear();
			if(p_analyze_for_tree_matching_target_match_map!=&temporary_match_map)
			{
				printf("%s: Cleaning p_analyze_for_tree_matching_target_match_map\n",__FUNCTION__);
				delete p_analyze_for_tree_matching_target_match_map;
			}
			p_analyze_for_tree_matching_target_match_map=p_analyze_for_tree_matching_result_match_map;
			printf("%s: map tree match=%d\n",__FUNCTION__,p_analyze_for_tree_matching_result_match_map->size());
			if(p_analyze_for_tree_matching_result_match_map->size()==0)
			{
				p_analyze_for_tree_matching_result_match_map->clear();
				if(p_analyze_for_tree_matching_result_match_map!=&temporary_match_map)
				{
					printf("%s: Cleaning p_analyze_for_tree_matching_result_match_map\n",__FUNCTION__);
					delete p_analyze_for_tree_matching_result_match_map;
				}
				break;
			}

			for(match_map_iter=p_analyze_for_tree_matching_result_match_map->begin();
				match_map_iter!=p_analyze_for_tree_matching_result_match_map->end();
				match_map_iter++)
			{
				RemoveFromFingerprintHash(p_analysis_info_unpatched,match_map_iter->first);
				RemoveFromFingerprintHash(p_analysis_info_patched,match_map_iter->second.Address);
			}
		}
		////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		// Two level fingerprint match
		matched_number=0;
		multimap <string, DWORD*>::iterator two_level_fingerprint_hash_map_pIter;
		for(two_level_fingerprint_hash_map_pIter=p_analysis_info_unpatched->two_level_fingerprint_hash_map.begin();
			two_level_fingerprint_hash_map_pIter!=p_analysis_info_unpatched->two_level_fingerprint_hash_map.end();
			two_level_fingerprint_hash_map_pIter++)
		{
			/*printf("%s: %s: %d\n",__FUNCTION__,two_level_fingerprint_hash_map_pIter->first.c_str(),
				p_analysis_info_unpatched->two_level_fingerprint_hash_map.count(two_level_fingerprint_hash_map_pIter->first));
			*/
			if(p_analysis_info_unpatched->two_level_fingerprint_hash_map.count(two_level_fingerprint_hash_map_pIter->first)==1)
			{
				//unique key
				if(p_analysis_info_patched->two_level_fingerprint_hash_map.count(two_level_fingerprint_hash_map_pIter->first)==1)
				{
					multimap <string, DWORD*>::iterator two_level_patched_fingerprint_hash_map_pIter=p_analysis_info_patched->two_level_fingerprint_hash_map.find(two_level_fingerprint_hash_map_pIter->first);
					for(int i=0;two_level_patched_fingerprint_hash_map_pIter->second[i];i++)
					{
						MappingData mapping_data;
						memset(&mapping_data,0,sizeof(MappingData));
						mapping_data.Type=TWO_LEVEL_FINGER_PRINT_MATCH;
						mapping_data.Address=two_level_patched_fingerprint_hash_map_pIter->second[i];
						mapping_data.MatchRate=GetMatchRate(
							p_analysis_info_unpatched,
							p_analysis_info_patched,
							two_level_fingerprint_hash_map_pIter->second[i],
							two_level_patched_fingerprint_hash_map_pIter->second[i]
							);
						temporary_match_map.insert(MatchMap_Pair(
							two_level_fingerprint_hash_map_pIter->second[i],
							mapping_data
							));
						matched_number++;
					}
					to_remove_map.insert(String_Pair(
						two_level_fingerprint_hash_map_pIter->first,
						two_level_patched_fingerprint_hash_map_pIter->first
						));
				}
			}
		}
		// Clean Up map
		multimap <string, string>::iterator to_remove_map_pIter;		
		for(to_remove_map_pIter=to_remove_map.begin();
			to_remove_map_pIter!=to_remove_map.end();
			to_remove_map_pIter++)
		{
			p_analysis_info_unpatched->two_level_fingerprint_hash_map.erase(to_remove_map_pIter->first);
			p_analysis_info_patched->two_level_fingerprint_hash_map.erase(to_remove_map_pIter->second);			
		}
		to_remove_map.clear();
		printf("%s: Two level fingerprint matched count=%d\n",__FUNCTION__,matched_number);

		///////////////// Done, Summary ////////////////////
		printf("%s: total=%d\n",__FUNCTION__,p_analysis_result->match_map.size());
		if(temporary_match_map.size()==0)
			break;
	}

	AnalyzeFunctionSanity(
		p_analysis_result,
		p_analysis_info_unpatched,
		p_analysis_info_patched
	);	
	return p_analysis_result;
}

void PrintMatchMapInfo(
	AnalysisResult *p_analysis_result,
	PAnalysisInfo p_analysis_info_unpatched,
	PAnalysisInfo p_analysis_info_patched)
{
	multimap <DWORD, MappingData>::iterator match_map_iter;
	int unique_match_count=0;
	for(match_map_iter=p_analysis_result->match_map.begin();
		match_map_iter!=p_analysis_result->match_map.end();
		match_map_iter++)
	{
		if(p_analysis_result->match_map.count(match_map_iter->first)==1)
			unique_match_count++;
	}
	printf("%s: unique_match_count=%d\n",__FUNCTION__,unique_match_count);


	//Print Summary
	//TODO: p_analysis_result->match_map -> save to database...
	for(match_map_iter=p_analysis_result->match_map.begin();
		match_map_iter!=p_analysis_result->match_map.end();
		match_map_iter++)
	{
		printf("%s: %x-%x (%s)\n",__FUNCTION__,
		match_map_iter->first,
		match_map_iter->second.Address,
		MappingDataTypeStr[match_map_iter->second.Type]);
	}

	printf("%s: ** unidentified(0)\n",__FUNCTION__);
	int unpatched_unidentified_number=0;
	multimap <DWORD, string>::iterator unpatched_address_fingerprint_hash_map_Iter;
	for(unpatched_address_fingerprint_hash_map_Iter=p_analysis_info_unpatched->address_fingerprint_hash_map.begin();
		unpatched_address_fingerprint_hash_map_Iter!=p_analysis_info_unpatched->address_fingerprint_hash_map.end();
		unpatched_address_fingerprint_hash_map_Iter++
	)
	{
		if(p_analysis_result->match_map.find(unpatched_address_fingerprint_hash_map_Iter->first)==p_analysis_result->match_map.end())
		{
			printf("%s: %x ",__FUNCTION__,unpatched_address_fingerprint_hash_map_Iter->first);
			if(unpatched_unidentified_number%8==7)
				printf("\n");
			unpatched_unidentified_number++;
		}
	}
	printf("%s: unpatched_unidentified_number=%d\n",__FUNCTION__,unpatched_unidentified_number);


	printf("%s: ** unidentified(1)\n",__FUNCTION__);
	int patched_unidentified_number=0;
	multimap <DWORD, string>::iterator patched_address_fingerprint_hash_map_Iter;
	for(patched_address_fingerprint_hash_map_Iter=p_analysis_info_patched->address_fingerprint_hash_map.begin();
		patched_address_fingerprint_hash_map_Iter!=p_analysis_info_patched->address_fingerprint_hash_map.end();
		patched_address_fingerprint_hash_map_Iter++
	)
	{
		if(p_analysis_result->reverse_match_map.find(patched_address_fingerprint_hash_map_Iter->first)==p_analysis_result->reverse_match_map.end())
		{
			printf("%s: %x ",__FUNCTION__,patched_address_fingerprint_hash_map_Iter->first);
			if(patched_unidentified_number%8==7)
				printf("\n");
			patched_unidentified_number++;
		}
	}
	printf("%s: patched_unidentified_number=%d\n",__FUNCTION__,patched_unidentified_number);
}

void GetName(PAnalysisInfo p_analysis_info,DWORD address,char *buffer,int len)
{
	multimap <DWORD, string>::iterator address_name_hash_map_iter;

	address_name_hash_map_iter=p_analysis_info->address_name_hash_map.find(address);
	if(len>0)
	{
		buffer[len-1]=NULL;
		if(address_name_hash_map_iter!=p_analysis_info->address_name_hash_map.end())
		{
			_snprintf(buffer,len-1,address_name_hash_map_iter->second.c_str());
			return;
		}
		_snprintf(buffer,len-1,"");
	}
}

void ShowDiffMap(
	AnalysisResult *p_analysis_result,
	AnalysisInfoList *pAnalysisInfoListRoot,
	DWORD unpatched_address,
	DWORD patched_address)
{
	AnalysisInfoList *p_cur_analysis_info_list=GetAnalysisInfoList(0);
	DWORD *p_addresses;

	list <DWORD> address_list;
	list <DWORD>::iterator address_list_iter;
	hash_set <DWORD> checked_addresses;
	address_list.push_back(unpatched_address);
	checked_addresses.insert(unpatched_address);

	for(address_list_iter=address_list.begin();
		address_list_iter!=address_list.end();
		address_list_iter++
	)
	{
		int addresses_number;
		printf("%s:  address=%x\n",__FUNCTION__,*address_list_iter);
		p_addresses=GetMappedAddresses(p_cur_analysis_info_list->p_analysis_info,
			*address_list_iter,CREF_FROM,&addresses_number);
		if(p_addresses && addresses_number>0)
		{
			printf("%s:  p_addresses=%x addresses_number=%d\n",__FUNCTION__,p_addresses,addresses_number);
			for(int i=0;i<addresses_number;i++)
			{
				if(p_addresses[i])
				{
					if(checked_addresses.find(p_addresses[i])==checked_addresses.end())
					{
						address_list.push_back(p_addresses[i]);
						checked_addresses.insert(p_addresses[i]);
					}
				}
			}
			free(p_addresses);
		}
	}
}

void GetMatchStatistics(
	DWORD address,
	PAnalysisInfo p_analysis_info,
	multimap <DWORD,MappingData> *p_match_map,
	int *p_found_match_number,
	int *p_not_found_match_number)
{
	DWORD *p_addresses;

	list <DWORD> address_list;
	list <DWORD>::iterator address_list_iter;
	hash_set <DWORD> checked_addresses;

	address_list.push_back(address);
	checked_addresses.insert(address);

	(*p_found_match_number)=0;
	(*p_not_found_match_number)=0;
	for(address_list_iter=address_list.begin();
		address_list_iter!=address_list.end();
		address_list_iter++
	)
	{
		int addresses_number;
#if DEBUG_LEVEL > 3
		printf("%s: address=%x\n",__FUNCTION__,*address_list_iter);
#endif
		p_addresses=GetMappedAddresses(p_analysis_info,
			*address_list_iter,CREF_FROM,&addresses_number);
		if(p_addresses && addresses_number>0)
		{
#if DEBUG_LEVEL > 5
			printf("%s: p_addresses=%x addresses_number=%d\n",__FUNCTION__,p_addresses,addresses_number);
#endif
			for(int i=0;i<addresses_number;i++)
			{
				if(p_addresses[i])
				{
					if(checked_addresses.find(p_addresses[i])==checked_addresses.end())
					{
						address_list.push_back(p_addresses[i]);
						checked_addresses.insert(p_addresses[i]);
					}
				}
			}
			free(p_addresses);
		}
		if(p_match_map->find(*address_list_iter)
			!= p_match_map->end())
		{
			//found match
			(*p_found_match_number)++;
		}else
		{
			//not found match
			(*p_not_found_match_number)++;
		}
	}
}

void ShowOnIDA(
	AnalysisResult *p_analysis_result,
	PAnalysisInfo p_analysis_info_unpatched,
	SOCKET unpatched_socket,
	PAnalysisInfo p_analysis_info_patched,
	SOCKET patched_socket)
{
	multimap <DWORD, MappingData>::iterator match_map_iter;
	DWORD last_unpatched_addr=0;
	DWORD last_patched_addr=0;
	MatchInfo match_info;
	
	if(!p_analysis_result ||! p_analysis_info_unpatched ||!p_analysis_info_patched)
		return;
	PAnalysisInfo p_unpatched_analysis_info=GetAnalysisInfoList(0)->p_analysis_info;
	PAnalysisInfo p_patched_analysis_info=GetAnalysisInfoList(1)->p_analysis_info;
	
	for(match_map_iter=p_analysis_result->match_map.begin();
		match_map_iter!=p_analysis_result->match_map.end();
		match_map_iter++)
	{
		multimap <DWORD, POneLocationInfo>::iterator address_hash_map_pIter;
		address_hash_map_pIter=p_analysis_info_unpatched->address_hash_map.find(match_map_iter->first);
		if(address_hash_map_pIter!=p_analysis_info_unpatched->address_hash_map.end())
		{
			match_info.addr=match_map_iter->first;
			match_info.block_type=address_hash_map_pIter->second->block_type;
			match_info.end_addr=address_hash_map_pIter->second->end_addr;
			match_info.type=match_map_iter->second.Type;
			match_info.match_addr=match_map_iter->second.Address;
			match_info.match_rate=match_map_iter->second.MatchRate;

			if(last_unpatched_addr!=match_info.addr &&
				last_patched_addr!=match_info.match_addr
			)
			{
				if(address_hash_map_pIter->second->block_type==FUNCTION_BLOCK)
				{
					GetName(p_analysis_info_unpatched,match_info.addr,match_info.name,sizeof(match_info.name));
					GetName(p_analysis_info_patched,match_info.match_addr,match_info.match_name,sizeof(match_info.match_name));
#ifdef SHOW_MATCHED_FUNCTION
					GetMatchStatistics(
						match_info.addr,
						p_unpatched_analysis_info,
						&p_analysis_result->match_map,
						&match_info.first_found_match,
						&match_info.first_not_found_match
					);

					GetMatchStatistics(
						match_info.match_addr,
						p_patched_analysis_info,
						&p_analysis_result->reverse_match_map,
						&match_info.second_found_match,
						&match_info.second_not_found_match
					);

					SendTLVData(
						unpatched_socket,
						ADD_MATCH_ADDR,
						(PBYTE)&match_info,
						sizeof(match_info));
#endif
				}else
				{
#ifdef SHOW_MATCHED_ADDR
					SendTLVData(
						unpatched_socket,
						ADD_MATCH_ADDR,
						(PBYTE)&match_info,
						sizeof(match_info));
				}
#endif
			}
			last_unpatched_addr=match_info.addr;
			last_patched_addr=match_info.match_addr;
		}
	}

	for(match_map_iter=p_analysis_result->reverse_match_map.begin();
		match_map_iter!=p_analysis_result->reverse_match_map.end();
		match_map_iter++)
	{
		multimap <DWORD, POneLocationInfo>::iterator address_hash_map_pIter;
		address_hash_map_pIter=p_analysis_info_patched->address_hash_map.find(match_map_iter->first);

		if(address_hash_map_pIter!=p_analysis_info_patched->address_hash_map.end())
		{
			match_info.addr=match_map_iter->first;
			match_info.end_addr=address_hash_map_pIter->second->end_addr;
			match_info.block_type=address_hash_map_pIter->second->block_type;
			match_info.type=match_map_iter->second.Type;
			match_info.match_addr=match_map_iter->second.Address;
			match_info.match_rate=match_map_iter->second.MatchRate;
			if(last_unpatched_addr!=match_info.addr &&
				last_patched_addr!=match_info.match_addr)
			{
				if(address_hash_map_pIter->second->block_type==FUNCTION_BLOCK)
				{
					GetName(p_analysis_info_patched,match_info.addr,match_info.name,sizeof(match_info.name));
					GetName(p_analysis_info_unpatched,match_info.match_addr,match_info.match_name,sizeof(match_info.match_name));
#ifdef SHOW_MATCHED_FUNCTION
					GetMatchStatistics(
						match_info.match_addr,
						p_unpatched_analysis_info,
						&p_analysis_result->match_map,
						&match_info.first_found_match,
						&match_info.first_not_found_match
					);

					GetMatchStatistics(
						match_info.addr,
						p_patched_analysis_info,
						&p_analysis_result->reverse_match_map,
						&match_info.second_found_match,
						&match_info.second_not_found_match
					);

					SendTLVData(
						patched_socket,
						ADD_MATCH_ADDR,
						(PBYTE)&match_info,
						sizeof(match_info));
#endif
				}else
				{
#ifdef SHOW_MATCHED_ADDR
					SendTLVData(
						patched_socket,
						ADD_MATCH_ADDR,
						(PBYTE)&match_info,
						sizeof(match_info));
#endif
				}
			}
			last_unpatched_addr=match_info.addr;
			last_patched_addr=match_info.match_addr;
		}
	}
	
	
	//////////// Unidentifed Locations

	multimap <DWORD, POneLocationInfo>::iterator address_hash_map_pIter;

	printf("%s: ** unidentified(0)\n",__FUNCTION__);
	int unpatched_unidentified_number=0;
	multimap <DWORD, string>::iterator unpatched_address_fingerprint_hash_map_Iter;
	for(unpatched_address_fingerprint_hash_map_Iter=p_analysis_info_unpatched->address_fingerprint_hash_map.begin();
		unpatched_address_fingerprint_hash_map_Iter!=p_analysis_info_unpatched->address_fingerprint_hash_map.end();
		unpatched_address_fingerprint_hash_map_Iter++
	)
	{
		if(p_analysis_result->match_map.find(unpatched_address_fingerprint_hash_map_Iter->first)==p_analysis_result->match_map.end())
		{
			printf("%s: %x ",__FUNCTION__,unpatched_address_fingerprint_hash_map_Iter->first);
			address_hash_map_pIter=p_analysis_info_unpatched->address_hash_map.find(unpatched_address_fingerprint_hash_map_Iter->first);
			if(address_hash_map_pIter!=p_analysis_info_unpatched->address_hash_map.end())
			{
				POneLocationInfo p_one_location_info=(POneLocationInfo)address_hash_map_pIter->second;

#ifdef SHOW_UNIDENTIFIED_ADDR
				if(p_one_location_info->block_type==FUNCTION_BLOCK)
				{
					DWORD start_end_addr[2];
					start_end_addr[0]=p_one_location_info->start_addr;
					start_end_addr[1]=p_one_location_info->end_addr;
					SendTLVData(
						unpatched_socket,
						ADD_UNINDENTIFIED_ADDR,
						(PBYTE)start_end_addr,
						sizeof(DWORD)*2);
				}
#endif
			}
			if(unpatched_unidentified_number%8==7)
				printf("\n");
			unpatched_unidentified_number++;
		}
	}
	printf("%s: unpatched_unidentified_number=%d\n",__FUNCTION__,unpatched_unidentified_number);


	printf("%s: ** unidentified(1)\n",__FUNCTION__);
	int patched_unidentified_number=0;
	multimap <DWORD, string>::iterator patched_address_fingerprint_hash_map_Iter;
	for(patched_address_fingerprint_hash_map_Iter=p_analysis_info_patched->address_fingerprint_hash_map.begin();
		patched_address_fingerprint_hash_map_Iter!=p_analysis_info_patched->address_fingerprint_hash_map.end();
		patched_address_fingerprint_hash_map_Iter++
	)
	{
		if(p_analysis_result->reverse_match_map.find(patched_address_fingerprint_hash_map_Iter->first)==p_analysis_result->reverse_match_map.end())
		{
			printf("%s: %x ",__FUNCTION__,patched_address_fingerprint_hash_map_Iter->first);

			address_hash_map_pIter=p_analysis_info_patched->address_hash_map.find(patched_address_fingerprint_hash_map_Iter->first);
			if(address_hash_map_pIter!=p_analysis_info_patched->address_hash_map.end())
			{
				POneLocationInfo p_one_location_info=(POneLocationInfo)address_hash_map_pIter->second;

#ifdef SHOW_UNIDENTIFIED_ADDR
				if(p_one_location_info->block_type==FUNCTION_BLOCK)
				{
					DWORD start_end_addr[2];
					start_end_addr[0]=p_one_location_info->start_addr;
					start_end_addr[1]=p_one_location_info->end_addr;
					SendTLVData(
						patched_socket,
						ADD_UNINDENTIFIED_ADDR,
						(PBYTE)start_end_addr,
						sizeof(DWORD)*2);
				}
#endif
			}
			if(patched_unidentified_number%8==7)
				printf("\n");
			patched_unidentified_number++;
		}
	}
	printf("%s: patched_unidentified_number=%d\n",__FUNCTION__,patched_unidentified_number);
	
	SendTLVData(
		unpatched_socket,
		SHOW_DATA,
		(PBYTE)"test",
		4);
	SendTLVData(
		patched_socket,
		SHOW_DATA,
		(PBYTE)"test",
		4);
}

AnalysisInfo *RetrieveAnalysisInfo(DataSharer *p_data_sharer)
{
	BYTE type;
	DWORD length;

	multimap <DWORD, POneLocationInfo>::iterator address_hash_map_pIter;
	multimap <string, DWORD>::iterator fingerprint_hash_map_pIter;
	multimap <string, DWORD>::iterator name_hash_map_pIter;
	multimap <DWORD, PMapInfo>::iterator map_info_hash_map_pIter;

	AnalysisInfo *p_analysis_info=new AnalysisInfo;
	DWORD current_addr=0L;

			
	POneLocationInfo p_last_one_location_info=NULL;
	while(1)
	{
		PBYTE data=GetData(p_data_sharer,&type,&length);

		/*
		printf("%s:  type=%d/length=%d/data=%x\n",__FUNCTION__,
			type,length,data);
		*/
		if(!data)
			break;
		if(type==FILE_INFO)
		{
			memcpy((PVOID)&p_analysis_info->file_info,(PVOID)data,sizeof(FileInfo));
			printf("%s: p_analysis_info=%x\n",__FUNCTION__,p_analysis_info);
		}else
		if(type==ONE_LOCATION_INFO && length==sizeof(OneLocationInfo))
		{
			POneLocationInfo p_one_location_info=(POneLocationInfo)data;
			current_addr=p_one_location_info->start_addr;
			if(p_last_one_location_info)
			{
				p_last_one_location_info->end_addr=p_one_location_info->start_addr;
			}
			p_last_one_location_info=p_one_location_info;
#if DEBUG_LEVEL > 2
			printf("%s: %x %d [%x] block_type=%d\n",__FUNCTION__,
				p_one_location_info->start_addr,//ea_t
				p_one_location_info->flag, //flag_t
				p_one_location_info->function_addr,
				p_one_location_info->block_type);
#endif
			p_analysis_info->address_hash_map.insert(AddrPOneLocationInfo_Pair(p_one_location_info->start_addr,p_one_location_info) );
		}else if(type==NAME_INFO)
		{
			if(strncmp("loc",(TCHAR *)data,3))
			{
				p_analysis_info->name_hash_map.insert(NameAddress_Pair((TCHAR *)data,current_addr));
			}
			p_analysis_info->address_name_hash_map.insert(AddressName_Pair(current_addr,(TCHAR *)data));
		}else if(type==MAP_INFO && length==sizeof(MapInfo))
		{
			PMapInfo p_map_info=(PMapInfo)data;
#if DEBUG_LEVEL > 2
			printf("%s: %s %x(%x)->%x\n",__FUNCTION__,
				MapInfoTypesStr[p_map_info->type],
				p_map_info->src_block,
				p_map_info->src,
				p_map_info->dst);
#endif
			p_analysis_info->map_info_hash_map.insert(AddrPMapInfo_Pair(p_map_info->src_block,p_map_info));
			if(p_map_info->type==CREF_FROM)
			{
				PMapInfo p_new_map_info=(PMapInfo)malloc(sizeof(MapInfo));
				p_new_map_info->src_block=p_map_info->dst;
				p_new_map_info->src=p_map_info->dst;
				p_new_map_info->dst=p_map_info->src_block;
				p_new_map_info->type=CREF_TO;
				p_analysis_info->map_info_hash_map.insert(AddrPMapInfo_Pair(p_new_map_info->src_block,p_new_map_info));
			}
		}else if(type==FINGERPRINT_INFO && 4<length)
		{
			DWORD block_addr=0;
			memcpy(&block_addr,data,4);
#if DEBUG_LEVEL > 2
			printf("%s: FingerPrint: %x(%d bytes)\n",__FUNCTION__,block_addr,length-4);
#endif
			TCHAR *string_buffer=(TCHAR *)malloc(length*2+10);
			memset(string_buffer,0,length*2+10);
			char tmp_buffer[10];
			for(DWORD i=0;i<length-4;i++)
			{
				_snprintf(tmp_buffer,sizeof(tmp_buffer),"%.2x",data[i+4]&0xff);
				strncat(string_buffer,tmp_buffer,sizeof(tmp_buffer));
			}
			p_analysis_info->fingerprint_hash_map.insert(FingerPrintAddress_Pair(string_buffer,block_addr));
			p_analysis_info->address_fingerprint_hash_map.insert(AddressFingerPrintAddress_Pair(block_addr,string_buffer));
			free(data);
		}else if(type==END_OF_DATA)
		{
			printf("%s: End of Analysis\n",__FUNCTION__);
			printf("%s: address_hash_map %d entries\nfingerprint_hash_map %d entries\nname_hash_map %d entries\nmap_info_hash_map %d entries\n",__FUNCTION__,
				p_analysis_info->address_hash_map.size(),
				p_analysis_info->fingerprint_hash_map.size(),
				p_analysis_info->name_hash_map.size(),
				p_analysis_info->map_info_hash_map.size()
				);
#if DEBUG_LEVEL > 1000
			fingerprint_hash_map_pIter=p_analysis_info->fingerprint_hash_map.find("1b04020502");
			if(fingerprint_hash_map_pIter!=p_analysis_info->fingerprint_hash_map.end())
			{
				printf("%s: %s-%x (%d)\n",__FUNCTION__,
					fingerprint_hash_map_pIter->first.c_str(),
					fingerprint_hash_map_pIter->second,
					p_analysis_info->fingerprint_hash_map.count("1b04020502"));
			}

			for(fingerprint_hash_map_pIter=p_analysis_info->fingerprint_hash_map.begin();
				fingerprint_hash_map_pIter!=p_analysis_info->fingerprint_hash_map.end();
				fingerprint_hash_map_pIter++)
			
			{	
				printf("%s: %x-%x\n",__FUNCTION__,
					fingerprint_hash_map_pIter->first,
					fingerprint_hash_map_pIter->second);
			}

			address_hash_map_pIter=p_analysis_info->address_hash_map.find(0x7C801625);
			POneLocationInfo p_one_location_info=(POneLocationInfo)address_hash_map_pIter->second;
			cout << address_hash_map_pIter->first <<"\n";
			printf("%s: %x %d [%x] block_type=%d\n",__FUNCTION__,
				p_one_location_info->start_addr,//ea_t
				p_one_location_info->flag, //flag_t
				p_one_location_info->function_addr,
				p_one_location_info->block_type);
#endif

#ifdef GENERATE_TWO_LEVEL_FINGERPRINT
			for(fingerprint_hash_map_pIter=p_analysis_info->fingerprint_hash_map.begin();
				fingerprint_hash_map_pIter!=p_analysis_info->fingerprint_hash_map.end();
				fingerprint_hash_map_pIter++)
			
			{	
				if(p_analysis_info->fingerprint_hash_map.count(fingerprint_hash_map_pIter->first)>1)
				{
					string out_string=fingerprint_hash_map_pIter->first;
					
					int addresses_number=0;
					DWORD *addresses=GetMappedAddresses(p_analysis_info,fingerprint_hash_map_pIter->second,CREF_FROM,&addresses_number);
					if(!addresses)
						addresses=GetMappedAddresses(p_analysis_info,fingerprint_hash_map_pIter->second,CREF_TO,NULL);
					if(addresses)
					{
						multimap <DWORD, string>::iterator address_fingerprint_hash_map_Iter;
						for(int i=0;i<addresses_number;i++)
						{
							address_fingerprint_hash_map_Iter=p_analysis_info->address_fingerprint_hash_map.find(addresses[i]);
							if(address_fingerprint_hash_map_Iter!=p_analysis_info->address_fingerprint_hash_map.end())
							{
								out_string+=address_fingerprint_hash_map_Iter->second;
							}
						}
						p_analysis_info->two_level_fingerprint_hash_map.insert(TwoLevelFingerPrintAddress_Pair(out_string.c_str(),addresses));
					}
				}
			}
			printf("%s: Two Level Fingerprint Generation Done [%d entries created]\n",__FUNCTION__,p_analysis_info->two_level_fingerprint_hash_map.size());
#endif
			break;
		}
	}
	return p_analysis_info;
}

DWORD GetBlockAddress(multimap <DWORD, POneLocationInfo> *p_address_hash_map,DWORD address)
{
	while(1)
	{
		if(p_address_hash_map->find(address)!=p_address_hash_map->end())
			break;
		address--;
	}
	return address;
}

void DumpBlockInfo(PAnalysisInfo p_analysis_info,DWORD block_address)
{
	int addresses_number;
	char *type_descriptions[]={"Cref From","Cref To","Call","Dref From","Dref To"};
	for(int i=0;i<sizeof(types)/sizeof(int);i++)
	{
		DWORD *addresses=GetMappedAddresses(
			p_analysis_info,
			block_address,
			types[i],
			&addresses_number);
		if(addresses)
		{
			printf("%s: %s: ",__FUNCTION__,type_descriptions[i]);
			for(int j=0;j<addresses_number;j++)
			{
				printf("%s: %x ",__FUNCTION__,addresses[j]);
			}
			printf("\n");
		}
	}
	printf("%s: fingerprint: %s\n",__FUNCTION__,
		GetFingerPrintFromFingerprintHash(p_analysis_info,block_address)
		);
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define BASIC_INFO_EVENT_OBJ_POS 0
#define SHOW_MATCH_ADDR_EVENT_OBJ_POS 1

void ProcessRequest(DWORD dwEvent)
{
	static AnalysisResult *p_analysis_result=NULL;

	if(dwEvent==WAIT_OBJECT_0+BASIC_INFO_EVENT_OBJ_POS)
	{
		PAnalysisInfo p_analysis_infos[2]={NULL,};
		SOCKET client_sockets[2];

		EnterCriticalSection(&CriticalSection); 
		AnalysisInfoList *pAnalysisInfoListCur=pAnalysisInfoListRoot;
		int analysis_info_i=0;
		while(pAnalysisInfoListCur)
		{
			if(pAnalysisInfoListCur->p_analysis_info)
			{
				p_analysis_infos[analysis_info_i]=pAnalysisInfoListCur->p_analysis_info;
				client_sockets[analysis_info_i]=pAnalysisInfoListCur->socket;
				analysis_info_i++;
				if(analysis_info_i==2)
					break;
			}
			pAnalysisInfoListCur=pAnalysisInfoListCur->next;
		}
		LeaveCriticalSection(&CriticalSection);			

		//Basic Information
		if(analysis_info_i==2)
		{
			printf("%s: Start diffing...\n",__FUNCTION__);
			p_analysis_result=DiffAnalysisInfo(
				p_analysis_infos[0],
				p_analysis_infos[1]
			);
			/*PrintMatchMapInfo(
				p_analysis_result,
				p_analysis_infos[0],
				p_analysis_infos[1]
				);*/
			ShowOnIDA(
				p_analysis_result,
				p_analysis_infos[0],
				client_sockets[0],
				p_analysis_infos[1],
				client_sockets[1]
			);
		}
	}else if(dwEvent==WAIT_OBJECT_0+SHOW_MATCH_ADDR_EVENT_OBJ_POS)
	{
		//SHOW_MATCH_ADDR
		EnterCriticalSection(&CriticalSection); 
		AnalysisInfoList *pAnalysisInfoListCur=pAnalysisInfoListRoot;
		int analysis_info_i=0;
		while(pAnalysisInfoListCur)
		{
			if(pAnalysisInfoListCur->address)
			{
#if DEBUG_LEVEL > 2
				printf("%s: pAnalysisInfoListCur->address= %x p_analysis_result=%p\n",__FUNCTION__,pAnalysisInfoListCur->address,p_analysis_result);
#endif
				if(analysis_info_i==1)
				{
					DWORD block_address=GetBlockAddress(&pAnalysisInfoListCur->p_analysis_info->address_hash_map,pAnalysisInfoListCur->address);
					multimap <DWORD, MappingData>::iterator match_map_iter=p_analysis_result->match_map.find(block_address);

					printf("%s: address: %x block_address: %x\n",__FUNCTION__,
						pAnalysisInfoListCur->address,
						block_address);
					DumpBlockInfo(pAnalysisInfoListCur->p_analysis_info,block_address);

					if(match_map_iter!=p_analysis_result->match_map.end())
					{
						/*
						ShowDiffMap(
							p_analysis_result,
							pAnalysisInfoListRoot,
							pAnalysisInfoListCur->address,
							match_map_iter->second.Address);
						*/
						if(pAnalysisInfoListCur->next)
						{
							SendTLVData(
								pAnalysisInfoListCur->next->socket,
								JUMP_TO_ADDR,
								(PBYTE)&match_map_iter->second.Address,
								sizeof(DWORD));
						}

						while(match_map_iter!=p_analysis_result->match_map.end() &&
							match_map_iter->first==block_address)
						{
							DumpMatchMapIterInfo(match_map_iter);
							match_map_iter++;
						}
					}
				}else if(analysis_info_i==2)
				{
					DWORD block_address=GetBlockAddress(&pAnalysisInfoListCur->p_analysis_info->address_hash_map,pAnalysisInfoListCur->address);
					multimap <DWORD, MappingData>::iterator match_map_iter=
						p_analysis_result->reverse_match_map.find(block_address);

					printf("%s: address: %x block_address: %x\n",__FUNCTION__,
						pAnalysisInfoListCur->address,
						block_address);
					
					DumpBlockInfo(pAnalysisInfoListCur->p_analysis_info,block_address);
					if(match_map_iter!=p_analysis_result->reverse_match_map.end())
					{
						/*
						ShowDiffMap(
							p_analysis_result,
							pAnalysisInfoListRoot,
							match_map_iter->second.Address,
							pAnalysisInfoListCur->address);
						*/
						if(pAnalysisInfoListCur->prev)
						{
							SendTLVData(
								pAnalysisInfoListCur->prev->socket,
								JUMP_TO_ADDR,
								(PBYTE)&match_map_iter->second.Address,
								sizeof(DWORD));
						}
						while(match_map_iter!=p_analysis_result->reverse_match_map.end() &&
							match_map_iter->first==block_address)							
						{
							DumpMatchMapIterInfo(match_map_iter);
							match_map_iter++;
						}
					}
					break;
				}
				pAnalysisInfoListCur->address=NULL;
				break;
			}
			analysis_info_i++;
			pAnalysisInfoListCur=pAnalysisInfoListCur->next;
		}
		LeaveCriticalSection(&CriticalSection);
	}else
	{
		//Error
	}
}

CRITICAL_SECTION CriticalSection;

#define NUMBER_OF_NEW_INFO_EVENTS 2
HANDLE hNewInfoEvents[NUMBER_OF_NEW_INFO_EVENTS];

DWORD CALLBACK BrokerThread(LPVOID lpParam)
{
	while(1)
	{
		DWORD dwEvent=WaitForMultipleObjects(NUMBER_OF_NEW_INFO_EVENTS,
			hNewInfoEvents,
			FALSE,
			INFINITE);
		ProcessRequest(dwEvent);
	}
	return 0;
}

void InitializeBrokerThread()
{
	InitializeCriticalSection(&CriticalSection);

	for(int i=0;i<NUMBER_OF_NEW_INFO_EVENTS;i++)
	{
		hNewInfoEvents[i]=CreateEvent( 
			NULL,         // default security attributes
			FALSE,         // manual-reset event
			TRUE,         // initial state is signaled
			NULL  // object name
		);
		if(hNewInfoEvents[i]==NULL)
			return;
		ResetEvent(hNewInfoEvents[i]);
	}
	CreateThread(
		NULL,
		0,
		BrokerThread,
		(void*)NULL,
		0,
		NULL);	
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD CALLBACK IDAClientWorkerThread(LPVOID lpParam)
{
	SOCKET client_socket=(SOCKET)lpParam;	
	char shared_memory_name[1024];
	_snprintf(shared_memory_name,sizeof(shared_memory_name),"DG Shared Memory - %d - %d",
		GetCurrentProcessId(),
		GetCurrentThreadId());

	DataSharer data_sharer;
	#define SHARED_MEMORY_SIZE 100000
	if(!InitDataSharer(&data_sharer,
		shared_memory_name,
		SHARED_MEMORY_SIZE,
		TRUE))
		return FALSE;
	char data[1024+sizeof(DWORD)];
	*(DWORD *)data=SHARED_MEMORY_SIZE;
	memcpy(data+sizeof(DWORD),shared_memory_name,strlen(shared_memory_name));
	SendTLVData(client_socket,SEND_ANALYSIS_DATA,(PBYTE)data,sizeof(DWORD)+strlen(shared_memory_name)+1);
	PAnalysisInfo p_analysis_info=RetrieveAnalysisInfo(&data_sharer);

	//Client Data Handling Routine
	// Request ownership of the critical section.
	ResetEvent(hNewInfoEvents[BASIC_INFO_EVENT_OBJ_POS]);

	//Adding new entry
	AnalysisInfoList *pAnalysisInfoListNew;
	pAnalysisInfoListNew=(AnalysisInfoList *)malloc(sizeof(AnalysisInfoList));
	pAnalysisInfoListNew->prev=NULL;
	pAnalysisInfoListNew->next=NULL;
	pAnalysisInfoListNew->socket=client_socket;
	pAnalysisInfoListNew->p_analysis_info=p_analysis_info;
	pAnalysisInfoListNew->address=0;

	EnterCriticalSection(&CriticalSection); 
	// Access the shared resource.
	AnalysisInfoList *pAnalysisInfoListCur=pAnalysisInfoListRoot;
	while(pAnalysisInfoListCur->next)
	{
		pAnalysisInfoListCur=pAnalysisInfoListCur->next;
	}
	pAnalysisInfoListCur->next=pAnalysisInfoListNew;
	pAnalysisInfoListNew->prev=pAnalysisInfoListCur;
	// Release ownership of the critical section.
	LeaveCriticalSection(&CriticalSection);

	SetEvent(hNewInfoEvents[BASIC_INFO_EVENT_OBJ_POS]);
	//recv command from client
	while(1)
	{
		char type;
		DWORD length;
		PBYTE data=RecvTLVData(client_socket,&type,&length);
		if(data)
		{
			printf("%s: Type: %d Length: %d data:%x\n",__FUNCTION__,type,length,data);
			if(type==SHOW_MATCH_ADDR && length>=4)
			{
				DWORD address=*(DWORD *)data;
				printf("%s: Showing address=%x\n",__FUNCTION__,address);
				pAnalysisInfoListNew->address=address;
				SetEvent(hNewInfoEvents[SHOW_MATCH_ADDR_EVENT_OBJ_POS]);
			}
		}else
		{
			break;
		}
	}
	closesocket(client_socket);
	EnterCriticalSection(&CriticalSection); 
	// Access the shared resource.
	if(pAnalysisInfoListCur->next)
		pAnalysisInfoListCur->next->prev=pAnalysisInfoListNew->prev;
	if(pAnalysisInfoListNew->prev)
		pAnalysisInfoListNew->prev->next=pAnalysisInfoListNew->next;
	// Release ownership of the critical section.
	LeaveCriticalSection(&CriticalSection);	
	return TRUE;
}

void InitIDACommucation(PVOID param)
{
	unsigned short listening_port=(unsigned short)param;	
	CreateListener(IDAClientWorkerThread,listening_port);
	// Release resources used by the critical section object.
	//DeleteCriticalSection(&CriticalSection);		
}

int StartAnalysisServer(BOOL bCreateNewThread)
{
	pAnalysisInfoListRoot=(AnalysisInfoList *)malloc(sizeof(AnalysisInfoList));
	pAnalysisInfoListRoot->p_analysis_info=NULL;
	pAnalysisInfoListRoot->next=NULL;

	printf("%s: Starting...\n",__FUNCTION__);
	InitializeBrokerThread();

	unsigned short listening_port=DARUNGRIM2_PORT;
	if(bCreateNewThread)
	{
		printf("%s: CreateThread InitIDACommucation\n",__FUNCTION__);
		CreateThread(
			NULL,
			0,
			(LPTHREAD_START_ROUTINE)InitIDACommucation,
			(void*)listening_port,
			0,
			NULL);
	}else{
		CreateListener(IDAClientWorkerThread,listening_port);
	}
	return TRUE;
}

#endif

