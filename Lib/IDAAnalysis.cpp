#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

#include "IDAAnalysis.h"
#include "SharedMemory.h"
#include "AnalyzerData.h"
#include "IDAAnalysisCommon.h"

#include <vector>

using namespace std;

#define SKIP_NULL_BLOCK

extern ea_t exception_handler_addr;
#define malloc_wrapper malloc

#define HASH_MAP_SIZE 1001
AddrMapHash *InitAddrMap()
{
	AddrMapHash *addr_map_hash=(AddrMapHash *)malloc_wrapper(sizeof(AddrMapHash)*HASH_MAP_SIZE);
	memset(addr_map_hash,0,sizeof(AddrMapHash)*HASH_MAP_SIZE);
	return addr_map_hash;
}


AddrMapHash *AddToAddrMap(AddrMapHash *addr_map_hash,LocationInfo *p_location_info)
{
	AddrMapHash *current_hash=&addr_map_hash[p_location_info->address%HASH_MAP_SIZE];
	AddrMapHash *leaf_hash=current_hash;
	while(current_hash && current_hash->address)
	{
		leaf_hash=current_hash;
		current_hash=leaf_hash->branch;
	}
	if(!current_hash)
	{
		current_hash=(AddrMapHash *)malloc_wrapper(sizeof(AddrMapHash));
		leaf_hash->branch=current_hash;
	}
	if(current_hash)
	{
		current_hash->address=p_location_info->address;
		current_hash->p_location_info=p_location_info;
		current_hash->branch=NULL;
	}
	return current_hash;
}

LocationInfo *FindFromAddrMap(AddrMapHash *addr_map_hash,ea_t address)
{
	AddrMapHash *current_hash=&addr_map_hash[address%HASH_MAP_SIZE];
	while(current_hash && current_hash->address)
	{
		if(current_hash->address==address)
		{
			//msg("address [%x] current_hash->p_location_info=[%x]\n",address,current_hash->p_location_info);
			return current_hash->p_location_info;
		}
		current_hash=current_hash->branch;
	}
	return NULL;
}

void DumpLocationInfo(AddrMapHash *addr_map_base,ea_t address)
{
	LocationInfo *p_location_info=FindFromAddrMap(addr_map_base,address);

	if(p_location_info)
	{
		msg("****** [p_location_info=%x]\n",p_location_info);
		msg("[address=%x]\n",p_location_info->address);
		msg("[block_size=%x]\n",p_location_info->block_size);
		msg("[block_type=%x]\n",p_location_info->block_type);
		msg("prev_cref\n");
		for(int i=0;i<p_location_info->prev_crefs_size;i++)
		{
			msg("     [%x]\n",p_location_info->prev_crefs[i]);
		}

		msg("prev_dref\n");
		for(int i=0;i<p_location_info->prev_drefs_size;i++)
		{
			msg("   [%x]\n",p_location_info->prev_drefs[i]);
		}

		msg("next_cref\n");
		for(int i=0;i<p_location_info->next_crefs_size;i++)
		{
			msg("   [%x]\n",p_location_info->next_crefs[i]);
		}
		msg("next_dref\n");
		for(int i=0;i<p_location_info->next_drefs_size;i++)
		{
			msg("   [%x]\n",p_location_info->next_drefs[i]);
		}
	}
}

/****************************************************************************************************************/

bool MakeMemberOfFunction(AddrMapHash *addr_map_base,ea_t function_start_address,LocationInfo *p_location_info)
{
	bool found_match=FALSE;
	for(int i=0;i<p_location_info->function_addresses_size;i++)
	{
		if(p_location_info->function_addresses[i]==function_start_address)
		{
			found_match=TRUE;
			break;
		}
	}

	if(!found_match)
	{
		if(p_location_info->function_addresses_size==0)
		{
			//malloc_wrapper
			p_location_info->function_addresses=(ea_t *)malloc_wrapper(sizeof(ea_t)*(p_location_info->function_addresses_size+1));
		}else{
			//realloc
			p_location_info->function_addresses=(ea_t *)realloc(
				p_location_info->function_addresses,
				sizeof(ea_t)*(p_location_info->function_addresses_size+1));
		}
		p_location_info->function_addresses[p_location_info->function_addresses_size]=function_start_address;
		p_location_info->function_addresses_size++;
	}else{
		return 0;
	}

	for(int i=0;i<p_location_info->next_crefs_size;i++)
	{
		LocationInfo *p_next_location_info=FindFromAddrMap(addr_map_base,p_location_info->next_crefs[i]);
		if(p_next_location_info)
		{
			MakeMemberOfFunction(addr_map_base,function_start_address,p_next_location_info);
		}
	}
	return p_location_info->checked_function_consistency;
}


void CheckLocationInfos(AddrMapHash *addr_map_base,LocationInfo *p_first_location_info)
{
	LocationInfo *p_location_info;

	for(p_location_info=p_first_location_info;p_location_info;p_location_info=p_location_info->next)
	{
		for(int i=0;i<p_location_info->next_crefs_size;i++)
		{
			LocationInfo *p_next_location_info=FindFromAddrMap(addr_map_base,p_location_info->next_crefs[i]);
			if(p_next_location_info)
			{
				p_next_location_info->prev_crefs=(ea_t *)realloc(
					p_next_location_info->prev_crefs,
					sizeof(ea_t)*(p_next_location_info->prev_crefs_size+1)
					);
				p_next_location_info->prev_crefs[p_next_location_info->prev_crefs_size]=p_location_info->address;
				p_next_location_info->prev_crefs_size++;
			}
		}
	}

	//Check Function Members
	//get func_t for every members of the function and find whether it matches "root" of members
	//multi-head,multi-tail -_-
	//Check Functions
	for(p_location_info=p_first_location_info;p_location_info;p_location_info=p_location_info->next)
	{
		if(p_location_info->prev_crefs_size==0 && p_location_info->block_type==CODE) //start of functions or handler...
		{
			p_location_info->block_type=FUNCTION;
			MakeMemberOfFunction(addr_map_base,p_location_info->address,p_location_info);
		}
	}
	
	for(p_location_info=p_first_location_info;p_location_info;p_location_info=p_location_info->next)
	{
		if(p_location_info->function_addresses_size>1)
		{
			DEBUG_PRINT("multiple function for [ 0x%x ]=%d\n",p_location_info->address,p_location_info->function_addresses_size);
			for(int i=0;i<p_location_info->function_addresses_size;i++)
			{
				DEBUG_PRINT("     [%x]\n",p_location_info->function_addresses[i]);
			}
		}else if(p_location_info->function_addresses_size>0)
		{
			func_t *cur_func_t=get_func(p_location_info->address);
			if(!cur_func_t || cur_func_t->startEA!=p_location_info->function_addresses[0])
			{
				//not maching
				if(cur_func_t)
					DEBUG_PRINT("function not matching for [%x] mine [%x] IDA [%x]\n",p_location_info->address,p_location_info->function_addresses[0],cur_func_t->startEA);
				else
					DEBUG_PRINT("function not matching for [%x] mine [%x] IDA [failed]\n",p_location_info->address,p_location_info->function_addresses[0]);
			}
		}
	}
	LocationInfo *p_current_location_info;

	for(p_current_location_info=p_first_location_info;p_current_location_info;p_current_location_info=p_current_location_info->next)
	{
		//if code
		if(isCode(p_current_location_info->flag))
		{
			LocationInfo *p_next_location_info=NULL;

			bool found_link=FALSE;
			//This is the case (DarunGrim Functionality #1.1.2)
			if(p_current_location_info->next_crefs_size==1)
			{
				p_next_location_info=FindFromAddrMap(addr_map_base,p_current_location_info->next_crefs[0]);
				if(p_next_location_info && p_next_location_info->prev_crefs_size==1)
				{
					p_next_location_info->saved=TRUE;
					p_current_location_info->linked_node=p_next_location_info;
					found_link=TRUE;
#if DEBUG_LEVEL > 2
					msg("LINK: %x -> %x\n",p_current_location_info->address,p_next_location_info->address);
#endif
				}
			}
			if(!found_link)
			{
				if(p_current_location_info->instruction_count==0 && p_current_location_info->next_crefs_size==1)//null block
				{
					for(int i=0;i<p_current_location_info->prev_crefs_size;i++)
					{
						LocationInfo *p_prev_location_info=FindFromAddrMap(addr_map_base,p_current_location_info->prev_crefs[i]);
						if(p_prev_location_info)
						{
							for(int j=0;j<p_prev_location_info->next_crefs_size;j++)
							{
								if(p_prev_location_info->next_crefs[j]==p_current_location_info->address)
								{
#if DEBUG_LEVEL > 2
									msg("taking out null block at %x [%x->%x]\n",p_current_location_info->address,
												p_prev_location_info->address,
												p_current_location_info->next_crefs[0]);
#endif
									p_current_location_info->saved=TRUE;
									p_prev_location_info->next_crefs[j]=p_current_location_info->next_crefs[0];
								}
							}
						}
					}
				}
			}
		}
	}
}

void DumpAddressInfo(ea_t address)
{
	char function_name[1024];
	char name[1024];

	//
	get_true_name(address,address,name,sizeof(name));
	get_func_name(address,function_name,sizeof(function_name));
	msg("0x%x %s - %s (isCode:%d)\n",address,name,function_name,isCode(getFlags(address)));

	//
	ea_t cref=get_first_cref_from(address);
	while(cref!=BADADDR)
	{
		char cref_name[512]={0,};
		if(get_true_name(cref,cref,cref_name,sizeof(cref_name)))
		{
		}
		msg("cref_from>     -> %s: %x\n",cref_name,cref);
		cref=get_next_cref_from(address,cref);
	}

	cref=get_first_fcref_from(address);
	while(cref!=BADADDR)
	{
		char cref_name[512]={0,};
		if(get_true_name(cref,cref,cref_name,sizeof(cref_name)))
		{
		}
		msg("fcref_from>     -> %s: %x\n",cref_name,cref);
		cref=get_next_fcref_from(address,cref);
	}

	ea_t dref=get_first_dref_from(address);
	while(dref!=BADADDR)
	{
		char dref_name[512]={0,};
		if(get_true_name(dref,dref,dref_name,sizeof(dref_name)))
		{
		}
		msg("dref_from>     -> %s: %x(%u)\n",dref_name,dref,dref);
		dref=get_next_dref_from(address,dref);
	}

	char op_buffer[100];
	ua_mnem(address,op_buffer,sizeof(op_buffer));
	msg("cmd.itype=%x\n",cmd.itype);
	for(int i=0;i<UA_MAXOP;i++)
	{
		if(cmd.Operands[i].type>0)
		{
			msg("cmd.Operands[i].type=%x\n",cmd.Operands[i].type);
			msg("cmd.Operands[i].dtyp=%x\n",cmd.Operands[i].dtyp);
			if(cmd.Operands[i].type==o_imm)
			{
				char operand_buffer[100];
				ua_outop(address,operand_buffer,sizeof(operand_buffer),i);
				tag_remove(operand_buffer,operand_buffer,sizeof(operand_buffer));
				//msg("IsNumber(%s)=%d\n",operand_buffer,IsNumber(operand_buffer));
				msg("cmd.Operands[i].value=%x\n",cmd.Operands[i].value);
			}
		}
	}
	return;
}

bool AnalyzeRegion(AddrMapHash **p_addr_map_base,LocationInfo **p_p_first_location_info)
{
	AddrMapHash *addr_map_base=InitAddrMap();

	LocationInfo *p_first_location_info=NULL;
	LocationInfo *p_location_info=NULL;

	*p_addr_map_base=NULL;
	*p_p_first_location_info=NULL;

#ifdef CHUNKED_ALLOC
	LocationInfo *p_location_array=NULL;
	DWORD location_array_size=0;
	DWORD location_array_i=0;
#endif

	for(int n=0;n<get_segm_qty();n++)
	{
		segment_t *seg_p=getnseg(n);
		size_t current_item_size=0;
		ea_t current_addr;

		bool found_branching=TRUE; //first we branch
		for(current_addr=seg_p->startEA;current_addr<seg_p->endEA;current_addr+=current_item_size)
		{
			current_item_size=get_item_size(current_addr);
			if(found_branching)
			{
#ifdef SAVE_NAME
				flags_t flag=getFlags(current_addr);
				if(isCode(flag))
				{
					get_func_name(current_addr,function_name,sizeof(function_name));
				}
#endif

#ifdef CHUNKED_ALLOC
				//re alloc
				if(location_array_i+1>location_array_size)
				{
					location_array_size+=1000;
					if(!p_location_array)
						p_location_array=(LocationInfo *)malloc_wrapper(location_array_size*sizeof(LocationInfo));
					else
						p_location_array=(LocationInfo *)realloc(p_location_array,location_array_size*sizeof(LocationInfo));
				}

				p_location_info=&p_location_array[location_array_i]
#endif
				LocationInfo *p_prev_location_info=p_location_info;
				p_location_info=(LocationInfo *)malloc_wrapper(sizeof(LocationInfo));
				p_location_info->saved=FALSE;
				if(p_prev_location_info)
				{
					p_prev_location_info->next=p_location_info;
				}else{
					p_first_location_info=p_location_info;
				}

				p_location_info->address=current_addr;
				p_location_info->flag=getFlags(current_addr);
				p_location_info->p_func_t=get_func(current_addr);

				p_location_info->block_size=0;
				p_location_info->instruction_count=0;
				p_location_info->block_reference_count=0;

				p_location_info->prev_drefs_size=0;
				p_location_info->prev_drefs=(ea_t *)malloc_wrapper(sizeof(ea_t)*(p_location_info->prev_drefs_size+1));

				p_location_info->next_drefs_size=0;
				p_location_info->next_drefs=(ea_t *)malloc_wrapper(sizeof(ea_t)*(p_location_info->next_drefs_size+1));

				p_location_info->prev_crefs_size=0;
				p_location_info->prev_crefs=(ea_t *)malloc_wrapper(sizeof(ea_t)*(p_location_info->prev_crefs_size+1));

				p_location_info->next_crefs_size=0;
				p_location_info->next_crefs=(ea_t *)malloc_wrapper(sizeof(ea_t)*(p_location_info->next_crefs_size+1));

				p_location_info->call_addrs_size=0;
				p_location_info->call_addrs=(ea_t *)malloc_wrapper(sizeof(ea_t)*(p_location_info->call_addrs_size+1));

				p_location_info->checked_function_consistency=FALSE;
				flags_t flag=getFlags(current_addr);
				if(isCode(flag))
				{
					p_location_info->block_type=CODE;
				}else{
					p_location_info->block_type=DATA;
				}
				p_location_info->function_addresses=NULL;
				p_location_info->function_addresses_size=NULL;
				p_location_info->linked_node=NULL;
				p_location_info->next=NULL;

#ifdef SAVE_NAME
				qstrncpy(p_location_array[location_array_i].name,name,sizeof(p_location_array[location_array_i].name));
				qstrncpy(p_location_array[location_array_i].function_name,function_name,sizeof(p_location_array[location_array_i].function_name));
				if(!stricmp(name,function_name))
					p_location_info->block_type=FUNCTION;
				else
					p_location_info->block_type=UNKNOWN;
#endif
				AddToAddrMap(addr_map_base,p_location_info);
#ifdef CHUNKED_ALLOC
				location_array_i++;
#endif

#ifdef OLD_TYPE_CREF
				//cref_to
				ea_t cref=get_first_cref_to(current_addr);
				while(cref!=BADADDR)
				{
					char op_buffer[40]={0,};
					ua_mnem(cref,op_buffer,sizeof(op_buffer));
					if(cref+get_item_size(cref)==current_addr 
						|| (cmd.itype!=NN_call && cmd.itype!=NN_callfi && cmd.itype!=NN_callni)
					)
					{
						//not call, j* or flow...
						p_location_info->prev_crefs=(ea_t *)realloc(p_location_info->prev_crefs,sizeof(ea_t)*(p_location_info->prev_crefs_size+1));
						p_location_info->prev_crefs[p_location_info->prev_crefs_size]=cref;
						p_location_info->prev_crefs_size++;
					}
					cref=get_next_cref_to(current_addr,cref);
				}
#endif
			}

			found_branching=FALSE;
			if(p_location_info)
			{
				p_location_info->block_size+=current_item_size;

				//add links
				ea_t cref=get_first_cref_from(current_addr);
				bool cref_to_next_addr=FALSE;
				while(cref!=BADADDR)
				{
					if(cref==current_addr+current_item_size)
					{
						//next instruction...
						cref_to_next_addr=TRUE;
						//
					}else{
						//j* something or call
						char op_buffer[40]={0,};
						ua_mnem(current_addr,op_buffer,sizeof(op_buffer));

						if(cmd.itype==NN_call || cmd.itype==NN_callfi || cmd.itype==NN_callni)
						{
							//this is a call							
							p_location_info->call_addrs=(ea_t *)realloc(
								p_location_info->call_addrs,
								sizeof(ea_t)*(p_location_info->call_addrs_size+1)
								);
							p_location_info->call_addrs[p_location_info->call_addrs_size]=cref;
							p_location_info->call_addrs_size++;
						}else{
							//this is a jump
							found_branching=TRUE; //j* instruction found
							/*
							//check if the current block and next block is connected block(that the child has no other parent than current block
							if(cmd.itype==NN_jmp || cmd.itype==NN_jmpfi || cmd.itype==NN_jmpni || cmd.itype==NN_jmpshort)
							{
								//must be jump
								//count the number of cref to cref
								int number_of_cref_to_cref=0;
								ea_t cref_to_cref=get_first_cref_to(cref);
								while(cref_to_cref!=BADADDR)
								{
									number_of_cref_to_cref+=1;
									cref_to_cref=get_next_cref_from(cref,cref_to_cref);
								}
								if(number_of_cref_to_cref==1)
								{
									//this is a connected block
									//cref is our connected block start address
									
								}
							}else*/{
								//check if the jumped position(cref) is a nop block
#ifdef SKIP_NULL_BLOCK
								ua_mnem(cref,op_buffer,sizeof(op_buffer));
								if(cmd.itype==NN_jmp || cmd.itype==NN_jmpfi || cmd.itype==NN_jmpni || cmd.itype==NN_jmpshort)
								{
									//we add the cref's next position instead cref
									//because this is a null block(doing nothing but jump)
									ea_t cref_from_cref=get_first_cref_from(cref);
									while(cref_from_cref!=BADADDR)
									{
										p_location_info->next_crefs=(ea_t *)realloc(p_location_info->next_crefs,sizeof(ea_t)*(p_location_info->next_crefs_size+1));
										p_location_info->next_crefs[p_location_info->next_crefs_size]=cref_from_cref;
										p_location_info->next_crefs_size++;									
										cref_from_cref=get_next_cref_from(cref,cref_from_cref);
									}
								}else
#endif
								{
									p_location_info->next_crefs=(ea_t *)realloc(
										p_location_info->next_crefs,
										sizeof(ea_t)*(p_location_info->next_crefs_size+1)
										);
									p_location_info->next_crefs[p_location_info->next_crefs_size]=cref;
									p_location_info->next_crefs_size++;
								}
							}
						}
					}
					cref=get_next_cref_from(current_addr,cref);
				}

				//dref_to
				ea_t dref=get_first_dref_to(current_addr);
				while(dref!=BADADDR)
				{
					p_location_info->prev_drefs=(ea_t *)realloc(
						p_location_info->prev_drefs,
						sizeof(ea_t)*(p_location_info->prev_drefs_size+1)
						);
					p_location_info->prev_drefs[p_location_info->prev_drefs_size]=dref;
					p_location_info->prev_drefs_size++;
					dref=get_next_dref_to(current_addr,dref);
				}

				//dref_from
				dref=get_first_dref_from(current_addr);
				while(dref!=BADADDR)
				{
					p_location_info->next_drefs=(ea_t *)realloc(
						p_location_info->next_drefs,
						sizeof(ea_t)*(p_location_info->next_drefs_size+1)
						);
					p_location_info->next_drefs[p_location_info->next_drefs_size]=dref;
					p_location_info->next_drefs_size++;

					if(exception_handler_addr!=0L && dref==exception_handler_addr) //exception handler
					{
						if(p_location_info->next_drefs_size>1)
						{
							ea_t exception_handler_structure_start=p_location_info->next_drefs[p_location_info->next_drefs_size-2];
							char handlers_structure_start_name[100];
							get_true_name(exception_handler_structure_start,
								exception_handler_structure_start,
								handlers_structure_start_name,
								sizeof(handlers_structure_start_name));

							ea_t exception_handler_structure=exception_handler_structure_start;
							while(1)
							{
								char handlers_structure_name[100];
								get_true_name(exception_handler_structure,
									exception_handler_structure,
									handlers_structure_name,
									sizeof(handlers_structure_name));

								if((
									handlers_structure_name[0]!=NULL &&
									strcmp(handlers_structure_start_name,handlers_structure_name))
									||
									isCode(getFlags(exception_handler_structure))
									)
								{
									break;
								}

								if((exception_handler_structure-exception_handler_structure_start)%4==0)
								{
									int pos=((exception_handler_structure-exception_handler_structure_start)/4)%3;
									if(pos==1 || pos==2)
									{
										ea_t exception_handler_routine=get_first_dref_from(exception_handler_structure);
										while(exception_handler_routine!=BADADDR)
										{
											p_location_info->next_crefs=(ea_t *)realloc(
												p_location_info->next_crefs,
												sizeof(ea_t)*(p_location_info->next_crefs_size+1)
												);
											p_location_info->next_crefs[p_location_info->next_crefs_size]=exception_handler_routine;
											p_location_info->next_crefs_size++;

											exception_handler_routine=get_next_dref_from(exception_handler_structure,exception_handler_routine);
										}
									}
								}
								exception_handler_structure+=get_item_size(exception_handler_structure);
							}
						}
					}
					dref=get_next_dref_from(current_addr,dref);
				}

				if(!found_branching)
				{
					p_location_info->instruction_count+=1;
					char name[1024]={0,};
					if(get_true_name(current_addr+current_item_size,current_addr+current_item_size,name,sizeof(name)))
					{
						found_branching=TRUE; //new name found
					}
					if(!found_branching)
					{
						flags_t next_flag=getFlags(current_addr+current_item_size);
						if(isCode(p_location_info->flag)!=isCode(next_flag)) 
						{
							found_branching=TRUE; //code, data type change...
						}
					}
				}
				if(isCode(p_location_info->flag) && found_branching && cref_to_next_addr)
				{
					char op_buffer[40]={0,};
					ea_t cref=current_addr+current_item_size;
					ua_mnem(cref,op_buffer,sizeof(op_buffer));
#ifdef SKIP_NULL_BLOCK
					if(cmd.itype==NN_jmp || cmd.itype==NN_jmpfi || cmd.itype==NN_jmpni || cmd.itype==NN_jmpshort)
					{
						//we add the cref's next position instead cref
						//because this is a null block(doing nothing but jump)
						ea_t cref_from_cref=get_first_cref_from(cref);
						while(cref_from_cref!=BADADDR)
						{
							p_location_info->next_crefs=(ea_t *)realloc(p_location_info->next_crefs,sizeof(ea_t)*(p_location_info->next_crefs_size+1));
							p_location_info->next_crefs[p_location_info->next_crefs_size]=cref_from_cref;
							p_location_info->next_crefs_size++;									
							cref_from_cref=get_next_cref_from(cref,cref_from_cref);
						}
					}else
#endif
					{
						p_location_info->next_crefs[p_location_info->next_crefs_size]=current_addr+current_item_size;
						p_location_info->next_crefs_size++;
					}
				}
			}
		}
	}	
	CheckLocationInfos(addr_map_base,p_first_location_info);

	*p_addr_map_base=addr_map_base;
	*p_p_first_location_info=p_first_location_info;

	/*
	//Check Functions
	for(p_location_info=p_first_location_info;p_location_info;p_location_info=p_location_info->next)
	{
		if(p_location_info->prev_crefs_size==0 && p_location_info->prev_drefs_size==0 && isCode(p_location_info->flag))
		{
			func_t *cur_func_t=get_func(p_location_info->address);
			if(!cur_func_t || cur_func_t->startEA!=p_location_info->address)
			{
				char name[40]={0,};
				get_true_name(p_location_info->address,p_location_info->address,name,sizeof(name));
				msg("not identified function [%x=%s]\n",p_location_info->address,name);
				if(cur_func_t)
				{
					ea_t claimed_start_address=cur_func_t->startEA;
					msg("startEA: [%x]\n",claimed_start_address);
					//del_func cur_func_t
					del_func(p_location_info->address);
					//add_func p_location_info->address
					add_func(p_location_info->address,BADADDR);
					//del_func cur_func_t->startEA
					add_func(claimed_start_address,BADADDR);
				}else{
					//just add_func
					add_func(p_location_info->address,BADADDR);
				}
			}
		}
	}
	*/
	return TRUE;
}

void AnalyzeIDAData(bool (*Callback)(PVOID context,BYTE type,PBYTE data,DWORD length),PVOID Context)
{
	FileInfo file_info;

	DWORD ComputerNameLen=sizeof(file_info.ComputerName);
	GetComputerName(file_info.ComputerName,&ComputerNameLen);
	DWORD UserNameLen=sizeof(file_info.UserName);
	GetUserName(file_info.UserName,&UserNameLen);

#ifdef _USE_IDA_SDK_49_OR_UPPER
	char orignal_file_path[1024]={0,};
#else
	strncpy(file_info.orignal_file_path,get_input_file_path(),sizeof(file_info.orignal_file_path))
#endif
	char *input_file_path=NULL;
#ifdef _USE_IDA_SDK_49_OR_UPPER
	get_input_file_path(file_info.orignal_file_path,sizeof(file_info.orignal_file_path)-1);
#endif

	if(!Callback(Context,
		FILE_INFO,
		(PBYTE)&file_info,
		sizeof(FileInfo)))
		return;

	for(int n=0;n<get_segm_qty();n++)
	{
		segment_t *seg_p=getnseg(n);
		size_t current_item_size=0;
		ea_t current_block_addr=0L;
		ea_t current_addr=0L;
		ea_t cref;

		#define MAX_FINGERPRINT 1024
		char fingerprint_data[MAX_FINGERPRINT];
		int  fingerprint_i=0;
		DWORD function_addr=0L;

		bool found_branching=TRUE; //first we branch
		msg("%x - %x\n",seg_p->startEA,seg_p->endEA);
		for(current_addr=seg_p->startEA;current_addr<seg_p->endEA;current_addr+=current_item_size)
		{
			int next_drefs_size=0;
			bool cref_to_next_addr=FALSE;
			flags_t flag=getFlags(current_addr);

			current_item_size=get_item_size(current_addr);

			MapInfo map_info;
			
			map_info.src=current_addr;

			//New Location Found
			if(found_branching)
			{
				//TODO: Push FingerPrint Data
				if(!Callback(Context,
					FINGERPRINT_INFO,
					(PBYTE)fingerprint_data,
					fingerprint_i))
					break;

				//Reset FingerPrint Data
				memcpy(fingerprint_data,&current_addr,4);
				fingerprint_i=4;

				found_branching=FALSE;
				OneLocationInfo one_location_info;
				one_location_info.function_addr=NULL;

				if(isCode(flag))
				{
					func_t *p_func=get_func(current_addr);
					if(p_func)
					{
						function_addr=p_func->startEA;
						one_location_info.function_addr=p_func->startEA;
					}
				}
				//PUSH THIS:
				current_block_addr=current_addr;
				map_info.src_block=current_block_addr;
				one_location_info.start_addr=current_addr;
				one_location_info.end_addr=0L;
				one_location_info.flag=flag;
				
				if(one_location_info.start_addr==one_location_info.function_addr)
					one_location_info.block_type=FUNCTION_BLOCK;
				else
					one_location_info.block_type=UNKNOWN_BLOCK;

				if(!Callback(Context,
					ONE_LOCATION_INFO,
					(PBYTE)&one_location_info,
					sizeof(one_location_info)))
					break;
				
				TCHAR name[1024];
				if(get_true_name(current_addr,
						current_addr,
						name,
						sizeof(name)))
				{
					if(!Callback(Context,
						NAME_INFO,
						(PBYTE)name,
						strlen(name)+1))
						break;
				}
				/*
				//cref_to
				cref=get_first_cref_to(current_addr);
				while(cref!=BADADDR)
				{
					map_info.type=CREF_TO;
					map_info.dst=cref;
					if(!Callback(Context,
						MAP_INFO,
						(PBYTE)&map_info,
						sizeof(map_info)))
						break;
					cref=get_next_cref_to(current_addr,cref);
				}
				*/		
			}
			map_info.src_block=current_block_addr;
			bool  is_positive_jmp=TRUE;
			//Collect Fingerprint Data
			if(isCode(flag))
			{
				char op_buffer[100]={0,};
				char operand_buffers[UA_MAXOP][MAXSTR+1];
				bool save_fingerprint=TRUE;

				if((sizeof(fingerprint_data)/sizeof(char))<fingerprint_i+7)
				{
					 save_fingerprint=FALSE;
				}

				ua_mnem(current_addr,op_buffer,sizeof(op_buffer));

				//detect hot patching
				//current_block_addr==function_addr
				if(current_addr==current_block_addr && current_addr==function_addr)
				{
					if(cmd.itype==NN_mov &&
						cmd.Operands[0].reg==cmd.Operands[0].reg
					)
					{
						save_fingerprint=FALSE;
					}
				}
				if(
					cmd.itype==NN_ja ||                  // Jump if Above (CF=0 & ZF=0)
					cmd.itype==NN_jae ||                 // Jump if Above or Equal (CF=0)
					cmd.itype==NN_jc ||                  // Jump if Carry (CF=1)
					cmd.itype==NN_jcxz ||                // Jump if CX is 0
					cmd.itype==NN_jecxz ||               // Jump if ECX is 0
					cmd.itype==NN_jrcxz ||               // Jump if RCX is 0
					cmd.itype==NN_je ||                  // Jump if Equal (ZF=1)
					cmd.itype==NN_jg ||                  // Jump if Greater (ZF=0 & SF=OF)
					cmd.itype==NN_jge ||                 // Jump if Greater or Equal (SF=OF)
					cmd.itype==NN_jo ||                  // Jump if Overflow (OF=1)
					cmd.itype==NN_jp ||                  // Jump if Parity (PF=1)
					cmd.itype==NN_jpe ||                 // Jump if Parity Even (PF=1)
					cmd.itype==NN_js ||                  // Jump if Sign (SF=1)
					cmd.itype==NN_jz ||                  // Jump if Zero (ZF=1)
					cmd.itype==NN_jmp ||                 // Jump
					cmd.itype==NN_jmpfi ||               // Indirect Far Jump
					cmd.itype==NN_jmpni ||               // Indirect Near Jump
					cmd.itype==NN_jmpshort ||            // Jump Short
					cmd.itype==NN_jpo ||                 // Jump if Parity Odd  (PF=0)
					cmd.itype==NN_jl ||                  // Jump if Less (SF!=OF)
					cmd.itype==NN_jle ||                 // Jump if Less or Equal (ZF=1 | SF!=OF)
					cmd.itype==NN_jb ||                  // Jump if Below (CF=1)
					cmd.itype==NN_jbe ||                 // Jump if Below or Equal (CF=1 | ZF=1)
					cmd.itype==NN_jna ||                 // Jump if Not Above (CF=1 | ZF=1)
					cmd.itype==NN_jnae ||                // Jump if Not Above or Equal (CF=1)
					cmd.itype==NN_jnb ||                 // Jump if Not Below (CF=0)
					cmd.itype==NN_jnbe ||                // Jump if Not Below or Equal (CF=0 & ZF=0)
					cmd.itype==NN_jnc ||                 // Jump if Not Carry (CF=0)
					cmd.itype==NN_jne ||                 // Jump if Not Equal (ZF=0)
					cmd.itype==NN_jng ||                 // Jump if Not Greater (ZF=1 | SF!=OF)
					cmd.itype==NN_jnge ||                // Jump if Not Greater or Equal (ZF=1)
					cmd.itype==NN_jnl ||                 // Jump if Not Less (SF=OF)
					cmd.itype==NN_jnle ||                // Jump if Not Less or Equal (ZF=0 & SF=OF)
					cmd.itype==NN_jno ||                 // Jump if Not Overflow (OF=0)
					cmd.itype==NN_jnp ||                 // Jump if Not Parity (PF=0)
					cmd.itype==NN_jns ||                 // Jump if Not Sign (SF=0)
					cmd.itype==NN_jnz                 // Jump if Not Zero (ZF=0)
				)
				{
					save_fingerprint=FALSE;
					//map table
					//check last instruction whether it was positive or negative to tweak the map
					if(
							cmd.itype==NN_ja ||                  // Jump if Above (CF=0 & ZF=0)
							cmd.itype==NN_jae ||                 // Jump if Above or Equal (CF=0)
							cmd.itype==NN_jc ||                  // Jump if Carry (CF=1)
							cmd.itype==NN_jcxz ||                // Jump if CX is 0
							cmd.itype==NN_jecxz ||               // Jump if ECX is 0
							cmd.itype==NN_jrcxz ||               // Jump if RCX is 0
							cmd.itype==NN_je ||                  // Jump if Equal (ZF=1)
							cmd.itype==NN_jg ||                  // Jump if Greater (ZF=0 & SF=OF)
							cmd.itype==NN_jge ||                 // Jump if Greater or Equal (SF=OF)
							cmd.itype==NN_jo ||                  // Jump if Overflow (OF=1)
							cmd.itype==NN_jp ||                  // Jump if Parity (PF=1)
							cmd.itype==NN_jpe ||                 // Jump if Parity Even (PF=1)
							cmd.itype==NN_js ||                  // Jump if Sign (SF=1)
							cmd.itype==NN_jz ||                  // Jump if Zero (ZF=1)
							cmd.itype==NN_jmp ||                 // Jump
							cmd.itype==NN_jmpfi ||               // Indirect Far Jump
							cmd.itype==NN_jmpni ||               // Indirect Near Jump
							cmd.itype==NN_jmpshort ||            // Jump Short
							cmd.itype==NN_jnl ||                 // Jump if Not Less (SF=OF)
							cmd.itype==NN_jnle ||                // Jump if Not Less or Equal (ZF=0 & SF=OF)
							cmd.itype==NN_jnb ||                 // Jump if Not Below (CF=0)
							cmd.itype==NN_jnbe                 // Jump if Not Below or Equal (CF=0 & ZF=0)						
						)
					{
						is_positive_jmp=TRUE;
					}else{
						is_positive_jmp=FALSE;
					}
				}
				
				//cmd.Operands[i].type
				//dtyp
				if(save_fingerprint)
				{
					fingerprint_data[fingerprint_i++]=0xcc;
					fingerprint_data[fingerprint_i++]=cmd.itype;
					for(int i=0;i<UA_MAXOP;i++)
					{
						if(cmd.Operands[i].type>0)
						{
							fingerprint_data[fingerprint_i++]=cmd.Operands[i].type;
							fingerprint_data[fingerprint_i++]=cmd.Operands[i].dtyp;
							/*
							if(cmd.Operands[i].type==o_imm)
							{
								if(IsNumber(operand_buffers[i]))
								{
									fingerprint_data[fingerprint_i++]=(cmd.Operands[i].value>>8)&0xff;
									fingerprint_data[fingerprint_i++]=cmd.Operands[i].value&0xff;
								}
							}
							*/
						}
					}
				}	
			}

			//Finding Next CREF/DREF
			vector<ea_t> cref_list;

			//cref from
			//add links
			cref=get_first_cref_from(current_addr);
			while(cref!=BADADDR)
			{
				//if just flowing
				if(cref==current_addr+current_item_size)
				{
					//next instruction...
					cref_to_next_addr=TRUE;
					//
				}else{
					//j* something or call
					char op_buffer[40]={0,};
					ua_mnem(current_addr,op_buffer,sizeof(op_buffer));
					//if branching
					//if cmd type is "call"
					if(cmd.itype==NN_call || cmd.itype==NN_callfi || cmd.itype==NN_callni)
					{

						//this is a call
						//PUSH THIS: call_addrs cref
						map_info.type=CALL;
						map_info.dst=cref;
						if(!Callback(Context,
							MAP_INFO,
							(PBYTE)&map_info,
							sizeof(map_info)))
							break;
					}else{
						//this is a jump
						found_branching=TRUE; //j* instruction found
						{
							//check if the jumped position(cref) is a nop block
#ifdef SKIP_NULL_BLOCK

							//if cmd type is "j*"
							ua_mnem(cref,op_buffer,sizeof(op_buffer));
							if(cmd.itype==NN_jmp || cmd.itype==NN_jmpfi || cmd.itype==NN_jmpni || cmd.itype==NN_jmpshort)
							{
								//we add the cref's next position instead cref
								//because this is a null block(doing nothing but jump)
								ea_t cref_from_cref=get_first_cref_from(cref);
								while(cref_from_cref!=BADADDR)
								{
									//next_ crefs  cref_from_cref
									cref_list.push_back(cref_from_cref);
									cref_from_cref=get_next_cref_from(cref,cref_from_cref);
								}
							}else
#endif
							//all other cases
							{
								//PUSH THIS: next_crefs  cref
								cref_list.push_back(cref);
							}
						}
					}
				}
				cref=get_next_cref_from(current_addr,cref);
			}


			//dref_to
			ea_t dref=get_first_dref_to(current_addr);
			while(dref!=BADADDR)
			{
				//PUSH THIS: dref
				map_info.type=DREF_TO;
				map_info.dst=dref;
				if(!Callback(Context,
					MAP_INFO,
					(PBYTE)&map_info,
					sizeof(map_info)))
					break;
				dref=get_next_dref_to(current_addr,dref);
			}

			//dref_from
			dref=get_first_dref_from(current_addr);
			while(dref!=BADADDR)
			{
				//PUSH THIS: next_drefs dref

				map_info.type=DREF_FROM;
				map_info.dst=dref;
				if(!Callback(Context,
					MAP_INFO,
					(PBYTE)&map_info,
					sizeof(map_info)))
					break;

/*
				//process  exception_handler
				if(exception_handler_addr!=0L && dref==exception_handler_addr) //exception handler
				{
					if(next_drefs_size>1)
					{
						ea_t exception_handler_structure_start=next_drefs[p_location_info->next_drefs_size-2];
						char handlers_structure_start_name[100];
						get_true_name(exception_handler_structure_start,
							exception_handler_structure_start,
							handlers_structure_start_name,
							sizeof(handlers_structure_start_name));

						ea_t exception_handler_structure=exception_handler_structure_start;
						while(1)
						{
							char handlers_structure_name[100];
							get_true_name(exception_handler_structure,
								exception_handler_structure,
								handlers_structure_name,
								sizeof(handlers_structure_name));

							if((
								handlers_structure_name[0]!=NULL &&
								strcmp(handlers_structure_start_name,handlers_structure_name))
								||
								isCode(getFlags(exception_handler_structure))
								)
							{
								break;
							}
							if((exception_handler_structure-exception_handler_structure_start)%4==0)
							{
								int pos=((exception_handler_structure-exception_handler_structure_start)/4)%3;
								if(pos==1 || pos==2)
								{
									ea_t exception_handler_routine=get_first_dref_from(exception_handler_structure);
									while(exception_handler_routine!=BADADDR)
									{
										//PUSH THIS: cref  exception_handler_routine
										exception_handler_routine=get_next_dref_from(exception_handler_structure,exception_handler_routine);
									}
								}
							}
							exception_handler_structure+=get_item_size(exception_handler_structure);
						}
					}
				}
*/
				dref=get_next_dref_from(current_addr,dref);
			}

			//Check if to set  found_branching
			if(!found_branching)
			{
				char name[100]={0,};
				//if name is on current_addr+ current_item_size
				if(get_true_name(current_addr+current_item_size,
					current_addr+current_item_size,
					name,
					sizeof(name)) &&
					name[0]!=NULL
				)
				{
					found_branching=TRUE; //new name found
				}
				if(!found_branching)
				{
					//or if code/data type changes
					if(isCode(flag)!=isCode(getFlags(current_addr+current_item_size))) 
					{
						found_branching=TRUE; //code, data type change...
					}
				}
			}

			//Skip Null Block
			if(isCode(flag) && 
				found_branching && 
				cref_to_next_addr)
			{
				char op_buffer[40]={0,};
				ea_t cref=current_addr+current_item_size;
				ua_mnem(cref,op_buffer,sizeof(op_buffer));
#ifdef SKIP_NULL_BLOCK
				if(cmd.itype==NN_jmp || cmd.itype==NN_jmpfi || cmd.itype==NN_jmpni || cmd.itype==NN_jmpshort)
				{
					//we add the cref's next position instead cref
					//because this is a null block(doing nothing but jump)
					ea_t cref_from_cref=get_first_cref_from(cref);
					while(cref_from_cref!=BADADDR)
					{
						//PUSH THIS: next_crefs  cref_from_cref
						cref_list.push_back(cref_from_cref);
						cref_from_cref=get_next_cref_from(cref,cref_from_cref);
					}
				}else
#endif
				{
					 //PUSH THIS: next_crefs  current_addr+current_item_size
					cref_list.push_back(current_addr+current_item_size);
				}
			}
			
			/*
			if(current_block_addr==0x7CDCCE96 || current_block_addr==0x7CDE8F9B)
			{
				msg("is_positive_jmp=%d\n",is_positive_jmp);
				vector<ea_t>::iterator cref_list_iter;
				for(cref_list_iter=cref_list.begin();
					cref_list_iter!=cref_list.end();
					cref_list_iter++)
				{
					msg("%x -> %x\n",
						current_block_addr,
						*cref_list_iter);
				}				
			}
			*/
			if(is_positive_jmp)
			{
				vector<ea_t>::iterator cref_list_iter;
				for(cref_list_iter=cref_list.begin();
					cref_list_iter!=cref_list.end();
					cref_list_iter++)
				{
					map_info.type=CREF_FROM;
					map_info.dst=*cref_list_iter;
					if(!Callback(Context,
						MAP_INFO,
						(PBYTE)&map_info,
						sizeof(map_info)))
					{
						break;
					}
				}
			}else
			{
				vector<ea_t>::reverse_iterator cref_list_iter;				
				for(cref_list_iter=cref_list.rbegin();
					cref_list_iter!=cref_list.rend();
					cref_list_iter++)
				{
					map_info.type=CREF_FROM;
					map_info.dst=*cref_list_iter;
					if(!Callback(Context,
						MAP_INFO,
						(PBYTE)&map_info,
						sizeof(map_info)))
					{
						break;
					}
				}
			}			
		}
	}
	if(!Callback(Context,
		END_OF_DATA,
		(PBYTE)"A",
		1))
		return;
	msg("Sent All Analysis Info\n");
}