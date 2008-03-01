#pragma warning (disable: 4819)
#pragma warning (disable: 4996)
#pragma warning (disable : 4786)
#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <graph.hpp>
#include <iostream>
#include <list>

#include "IdaIncludes.h"
#include "AnalyzerData.h"

#include <winsock.h>
#include "SharedSocket.h"
#include "SharedMemory.h"
#include "AnalysisServer.h"
#include "SocketOperation.h"

using namespace std;
//using namespace stdext;

void idaapi run(int arg);

#include "IDAAnalysis.h"
#include "fileinfo.h"

ea_t exception_handler_addr=0L;

#define DREF 0
#define CREF 1
#define FUNCTION 2
#define STACK 3
#define NAME 4
#define DISASM_LINE 5
#define DATA_TYPE 6

char *output_filename;

static const char generate_db_file_args[]={VT_STR,0 };
static error_t idaapi generate_db_file(value_t *argv,value_t *res)
{
	msg("generate_db_file is called with arg0=%s\n",argv[0].str);
	output_filename=strdup(argv[0].str);
	run(2);
	res->num=1;
	return eOk;
}

int idaapi init(void)
{
	if ( inf.filetype == f_ELF ) return PLUGIN_SKIP;

	set_idc_func("GenerateDBFile",generate_db_file,generate_db_file_args);
	return PLUGIN_KEEP;
}

void idaapi term(void)
{
	set_idc_func("GenerateDBFile",NULL,NULL);
}

bool IsNumber(char *data)
{
	bool is_number=TRUE;
	//hex
	if(strlen(data)>1 && data[strlen(data)-1]=='h')
	{
		int i=0;
		while(i<strlen(data)-2)
		{
			if(
				('0'<=data[i] && data[i]<='9') || 
				('a'<=data[i] && data[i]<='f') || 
				('A'<=data[i] && data[i]<='F')
			)
			{
			}else{
				is_number=FALSE;
				break;
			}
			i++;
		}
	}else{
		int i=0;
		while(data[i])
		{
			if('0'<=data[i] && data[i]<='9')
			{
			}else{
				is_number=FALSE;
				break;
			}
			i++;
		}
	}
	return is_number;
}


void MakeCode(ea_t start_addr,ea_t end_addr)
{
	while(1){
		bool converted=TRUE;
		msg("MakeCode: %x - %x \n",start_addr,end_addr);
		do_unknown_range(start_addr,end_addr-start_addr,false);
		for(ea_t addr=start_addr;addr<=end_addr;addr+=get_item_size(addr)) 
		{
			ua_code(addr);
			if(!isCode(getFlags(addr)))
			{
				converted=FALSE;
				break;
			}
		}
		if(converted)
			break;
		end_addr+=get_item_size(end_addr);
	}
}

void FixExceptionHandlers()
{
	char function_name[1024];
	char name[1024];

	for(int n=0;n<get_segm_qty();n++)
	{
		segment_t *seg_p=getnseg(n);
		if(seg_p->type==SEG_XTRN)
		{
			asize_t current_item_size;
			ea_t current_addr;
			for(current_addr=seg_p->startEA;current_addr<seg_p->endEA;current_addr+=current_item_size)
			{
				get_true_name(current_addr,current_addr,name,sizeof(name));
				if(!stricmp(name,"_except_handler3") || !stricmp(name,"__imp__except_handler3"))
				{
					msg("name=%s\n",name);
					//dref_to
					ea_t sub_exception_handler=get_first_dref_to(current_addr);
					while(sub_exception_handler!=BADADDR)
					{
						exception_handler_addr=sub_exception_handler;
						get_true_name(sub_exception_handler,sub_exception_handler,name,sizeof(name));
						msg("name=%s\n",name);
						ea_t push_exception_handler=get_first_dref_to(sub_exception_handler);
						while(push_exception_handler!=BADADDR)
						{
							msg("push exception_handler: %x\n",push_exception_handler);
							ea_t push_handlers_structure=get_first_cref_to(push_exception_handler);
							while(push_handlers_structure!=BADADDR)
							{
								msg("push hanlders structure: %x\n",push_handlers_structure);
								ea_t handlers_structure_start=get_first_dref_from(push_handlers_structure);
								while(handlers_structure_start!=BADADDR)
								{
									char handlers_structure_start_name[100];
									get_true_name(handlers_structure_start,
										handlers_structure_start,
										handlers_structure_start_name,
										sizeof(handlers_structure_start_name));
									ea_t handlers_structure=handlers_structure_start;
									while(1)
									{
										msg("handlers_structure: %x\n",handlers_structure);
										char handlers_structure_name[100];
										get_true_name(handlers_structure,
											handlers_structure,
											handlers_structure_name,
											sizeof(handlers_structure_name));
										if((handlers_structure_name[0]!=NULL && 
											strcmp(handlers_structure_start_name,handlers_structure_name)) ||
											isCode(getFlags(handlers_structure))
										)
										{
											msg("breaking\n");
											break;
										}
										if((handlers_structure-handlers_structure_start)%4==0)
										{
											int pos=(handlers_structure-handlers_structure_start)/4;
											if(pos%3==1 || pos%3==2)
											{
												msg("Checking handlers_structure: %x\n",handlers_structure);

												ea_t exception_handler_routine=get_first_dref_from(handlers_structure);
												while(exception_handler_routine!=BADADDR)
												{
													msg("Checking exception_handler_routine: %x\n",exception_handler_routine);
													if(!isCode(getFlags(exception_handler_routine)))
													{
														msg("Reanalyzing exception_handler_routine: %x\n",exception_handler_routine);
														ea_t end_pos=exception_handler_routine;
														while(1)
														{
															if(!isCode(getFlags(end_pos)))
																end_pos+=get_item_size(end_pos);
															else
																break;
														}
														if(!isCode(exception_handler_routine))
														{
															msg("routine 01: %x~%x\n",exception_handler_routine,end_pos);
															MakeCode(exception_handler_routine,end_pos);
														}
													}
													exception_handler_routine=get_next_dref_from(handlers_structure,exception_handler_routine);
												}
											}
										}
										msg("checked handlers_structure: %x\n",handlers_structure);
										handlers_structure+=get_item_size(handlers_structure);
									}
									handlers_structure_start=get_next_dref_from(push_handlers_structure,handlers_structure_start);
								}
								push_handlers_structure=get_next_cref_to(push_exception_handler,push_handlers_structure);
							}
							push_exception_handler=get_next_dref_to(sub_exception_handler,push_exception_handler);
						}

						sub_exception_handler=get_next_dref_to(current_addr,sub_exception_handler);
					}

				}
				current_item_size=get_item_size(current_addr);
			}
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef list<MatchInfo *> RangeList;
typedef struct _ChooseListObj_ {
	SOCKET socket;
	RangeList range_list;
} ChooseListObj,*PChooseListObj;


const int column_widths[]={16,32,5,5,16,32,5,5};
const char *column_header[] =
{
	"Address",
	"Name",
	"Matched",
	"Unmatched",
	"Address",
	"Name",
	"Matched",
	"Unmatched"
};

static ulong idaapi size_callback(void *obj)
{
	RangeList range_list=((PChooseListObj)obj)->range_list;
	return range_list.size();
}

static void idaapi line_callback(void *obj,ulong n,char * const *arrptr)
{
	RangeList range_list=((PChooseListObj)obj)->range_list;
	RangeList::iterator range_list_itr;
	ulong i;

	qsnprintf(arrptr[0],MAXSTR,"Unknown");
	qsnprintf(arrptr[1],MAXSTR,"Unknown");
	qsnprintf(arrptr[2],MAXSTR,"Unknown");
	qsnprintf(arrptr[3],MAXSTR,"Unknown");

	if(n==0)
	{
		for(int i=0;i<qnumber(column_header);i++)
			qsnprintf(arrptr[i],MAXSTR,column_header[i]);

		return;
	}
	for(range_list_itr=range_list.begin(),i=0;
		range_list_itr!=range_list.end();
		range_list_itr++,i++)
	{
		if(i==n-1)
		{
			qsnprintf(arrptr[0],MAXSTR,"%x",(*range_list_itr)->addr);
			qsnprintf(arrptr[1],MAXSTR,"%s",(*range_list_itr)->name);

			qsnprintf(arrptr[2],MAXSTR,"%5d",(*range_list_itr)->first_found_match);
			qsnprintf(arrptr[3],MAXSTR,"%5d",(*range_list_itr)->first_not_found_match);


			qsnprintf(arrptr[4],MAXSTR,"%x",(*range_list_itr)->match_addr);
			qsnprintf(arrptr[5],MAXSTR,"%s",(*range_list_itr)->match_name);

			qsnprintf(arrptr[6],MAXSTR,"%5d",(*range_list_itr)->second_found_match);
			qsnprintf(arrptr[7],MAXSTR,"%5d",(*range_list_itr)->second_not_found_match);

			break;
		}
	}
}

static void idaapi enter_callback(void *obj,ulong n)
{
	RangeList range_list=((PChooseListObj)obj)->range_list;
	RangeList::iterator range_list_itr;
	ulong i;

	for(range_list_itr=range_list.begin(),i=0;
		range_list_itr!=range_list.end();
		range_list_itr++,i++)
	{
		if(i==n-1)
		{
			msg("Jump to %x\n",(*range_list_itr)->addr);
			jumpto((*range_list_itr)->addr);
			SendTLVData(
				((PChooseListObj)obj)->socket,
				SHOW_MATCH_ADDR,
				(PBYTE)&(*range_list_itr)->addr,
				sizeof(DWORD));
			break;
		}
	}
}

static int idaapi graph_callback(void *obj, int code, va_list va)
{
	int result=0;
	switch(code)
	{
		case grcode_dblclicked:	 // a graph node has been double clicked
			// in:	graph_viewer_t *gv
			//			selection_item_t *current_item
			// out: 0-ok, 1-ignore click
		 {
			 graph_viewer_t *v	 = va_arg(va, graph_viewer_t *);
			 selection_item_t *s = va_arg(va, selection_item_t *);
			 msg("%x: %sclicked on ", v, code == grcode_clicked ? "" : "dbl");
			if(s && s->is_node)
			{
				DWORD addr=get_screen_ea();
				msg("node %d(%x)\n", s->node,addr);
				msg("Showing Block %x\n",addr);
				SendTLVData(
					((PChooseListObj)obj)->socket,
					SHOW_MATCH_ADDR,
					(PBYTE)&addr,
					sizeof(DWORD));
			}
		 }
		 break;
	}
	return result;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _EARange_ {
	ea_t start;
	ea_t end;
} EARange;

typedef list<EARange> EARangeList;
const int column_widths_for_unidentified_block_choose_list[]={16,16};
const char *column_header_for_unidentified_block_choose_list[] =
{
	"Start",
	"End"
};

static ulong idaapi size_callback_for_unidentified_block_choose_list(void *obj)
{
	return ((EARangeList *)obj)->size();
}

static void idaapi enter_callback_for_unidentified_block_choose_list(void *obj,ulong n)
{
	EARangeList::iterator range_list_itr;
	ulong i;

	for(range_list_itr=((EARangeList *)obj)->begin(),i=0;
		range_list_itr!=((EARangeList *)obj)->end();
		range_list_itr++,i++)
	{
		if(i==n-1)
		{
			msg("Jump to %x\n",(*range_list_itr).start);
			jumpto((*range_list_itr).start);
			break;
		}
	}	
}

static void idaapi line_callback_for_unidentified_block_choose_list(void *obj,ulong n,char * const *arrptr)
{
	EARangeList::iterator range_list_itr;
	ulong i;

	qsnprintf(arrptr[0],MAXSTR,"Unknown");
	qsnprintf(arrptr[1],MAXSTR,"Unknown");


	if(n==0)
	{
		for(int i=0;i<qnumber(column_header_for_unidentified_block_choose_list);i++)
			qsnprintf(arrptr[i],MAXSTR,column_header_for_unidentified_block_choose_list[i]);
		return;
	}
	for(range_list_itr=((EARangeList *)obj)->begin(),i=0;
		range_list_itr!=((EARangeList *)obj)->end();
		range_list_itr++,i++)
	{
		if(i==n-1)
		{
			qsnprintf(arrptr[0],MAXSTR,"%x",(*range_list_itr).start);
			qsnprintf(arrptr[1],MAXSTR,"%x",(*range_list_itr).end);
			break;
		}
	}
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
ChooseListObj unidentified_block_choose_list_obj;
EARangeList unidentified_block_choose_list;
ChooseListObj matched_block_choose_list_obj;
int ProcessCommand(SOCKET data_socket,char type,DWORD length,PBYTE data)
{
	{
		if(type==SEND_ANALYSIS_DATA)
		{
			DataSharer data_sharer;
			DWORD size=0;
			memcpy(&size,data,sizeof(DWORD));
			if(!InitDataSharer(&data_sharer,
				(char *)data+sizeof(DWORD),
				size,
				FALSE))
				return 0;
			AnalyzeIDAData((bool (*)(PVOID context,BYTE type,PBYTE data,DWORD length))PutData,(PVOID)&data_sharer);
		}
		else if(type==ADD_UNINDENTIFIED_ADDR)
		{
			EARange ea_range;

			for(DWORD i=0;i<length/(sizeof(DWORD)*2);i++)
			{
				ea_range.start=((DWORD *)data)[i*2];
				ea_range.end=((DWORD *)data)[i*2+1];
				unidentified_block_choose_list.push_back(ea_range);

				for(
					ea_t ea=ea_range.start;
					ea < ea_range.end;
					ea=nextthat(ea,ea_range.end,f_isCode,NULL)
				)
				{
					set_item_color(ea,0x0000FF);
				}
			}
		}else if(type==ADD_MATCH_ADDR && sizeof(MatchInfo)<=length)
		{
			MatchInfo *p_match_info=(MatchInfo *)data;
			if(p_match_info->block_type==FUNCTION_BLOCK)
			{
				matched_block_choose_list_obj.range_list.push_back(p_match_info);
			}			
			for(
				ea_t ea=p_match_info->addr;
				ea < p_match_info->end_addr;
				ea=nextthat(ea,p_match_info->end_addr,f_isCode,NULL)
			)
			{
				if(p_match_info->match_rate==100)
				{
					set_item_color(ea,0x00ff00);
				}else{
					set_item_color(ea,0x00ffff);
				}
			}
		}
		else if(type==JUMP_TO_ADDR && length>=4)
		{
			jumpto(*(DWORD *)data);
		}
		else if(type==GET_DISASM && length>=4)
		{
		}
		else if(type==SHOW_DATA)
		{
			matched_block_choose_list_obj.socket=data_socket;

			choose2(
				0,
				-1, -1, -1, -1,
				&unidentified_block_choose_list,
				qnumber(column_header_for_unidentified_block_choose_list),
				column_widths_for_unidentified_block_choose_list,
				size_callback_for_unidentified_block_choose_list,
				line_callback_for_unidentified_block_choose_list,
				"Unidentified Blocks",
				-1,
				0,
				NULL,
				NULL,
				NULL,
				NULL,
				enter_callback_for_unidentified_block_choose_list,
				NULL,
				NULL,
				NULL);
			choose2(
				0,
				-1, -1, -1, -1,
				&matched_block_choose_list_obj,
				qnumber(column_header),
				column_widths,
				size_callback,
				line_callback,
				"Matched Blocks",
				-1,
				0,
				NULL,
				NULL,
				NULL,
				NULL,
				enter_callback,
				NULL,
				NULL,
				NULL);

			hook_to_notification_point(HT_GRAPH,graph_callback,(void *)&matched_block_choose_list_obj);				
		}
	}
	return 0;
}
#undef USE_DATABASE

EXTERN_C IMAGE_DOS_HEADER __ImageBase;
void idaapi run(int arg)
{
	msg("Start Analysis\n");

	if(arg==1)
	{
		return;
	}

#ifdef USE_DATABASE
	sqlite3 *db=InitializeDatabase(arg);
	if(!db)
	{
		DumpAddressInfo(get_screen_ea());
		return;
	}
#endif
	FixExceptionHandlers();

/*
#ifdef INTERNAL_SERVER		
	StartAnalysisServer(TRUE);
#else
	StartProcess(EXTERNAL_SERVER);
#endif
*/
#ifdef USE_DATABASE
	AddrMapHash *addr_map_base=NULL;
	LocationInfo *p_first_location_info=NULL;
	AnalyzeRegion(&addr_map_base,&p_first_location_info);
#else //Standalone
	char dllname[1024];
	GetModuleFileName((HMODULE)&__ImageBase, dllname, sizeof(dllname));
	LoadLibrary(dllname);

	SOCKET data_socket=ConnectToServer("127.0.0.1",DARUNGRIM2_PORT);
	SetSharedSocketDataReceiver(ProcessCommand);
	PutSocketToWSAAsyncSelect(data_socket,SharedSocketDataReceiverWndProc,WM_SHARED_SOCKET_EVENT);	
#endif

#ifdef USE_DATABASE
	SaveToDatabase(db,addr_map_base,p_first_location_info);
	DeInitializeDatabase(db);
#endif
	msg("End of Analysis\n");
}

char comment[]="This is a Binary Differ plugin.";
char help[] =
				"A Binary Differ plugin module\n"
				"This module helps you to analyze asm listings.\n"
				"This dumps ida content to sqlite DB.\n";

char wanted_name[]="Binary Differ";
char wanted_hotkey[]="Alt-8";

plugin_t PLUGIN=
{
	IDP_INTERFACE_VERSION,
	0,									 // plugin flags
	init,								// initialize
	term,								// terminate. this pointer may be NULL.
	run,								 // invoke plugin
	comment,						 // long comment about the plugin
												// it could appear in the status line
												// or as a hint
	help,								// multiline help about the plugin
	wanted_name,				 // the preferred short name of the plugin
	wanted_hotkey				 // the preferred hotkey to run the plugin
};

