/*-
 * Copyright (c) 2018 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");
 
#include <sys/param.h>
#include <sys/cpuset.h>
#include <sys/event.h>
#include <sys/queue.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/ttycom.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <assert.h>
#include <curses.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <kvm.h>
#include <libgen.h>
#include <limits.h>
#include <math.h>
#include <pmc.h>
#include <pmclog.h>
#include <regex.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <gelf.h>
#include <inttypes.h>

#include <libpmcstat.h>

#include "pmctrace.h"
#include "pmctrace_etm.h"

#include <opencsd/c_api/ocsd_c_api_types.h>
#include <opencsd/c_api/opencsd_c_api.h>

#define	PMCTRACE_ETM_DEBUG
//#undef	PMCTRACE_ETM_DEBUG

static uint8_t test_trc_id_override = 0x00; // no trace ID override.
/* buffer to handle a packet string */
#define PACKET_STR_LEN 1024
static char packet_str[PACKET_STR_LEN];
static ocsd_trace_protocol_t test_protocol = OCSD_PROTOCOL_ETMV4I; // ETMV4 protocl

static int frame_raw_unpacked = 1;
static int frame_raw_packed = 0;

#ifdef	PMCTRACE_ETM_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

#if 1
static struct pmcstat_symbol *
symbol_lookup(const struct mtrace_data *mdata, uint64_t ip, struct pmcstat_image **img)
{
	struct pmcstat_image *image;
	struct pmcstat_symbol *sym;
	struct pmcstat_pcmap *map;
	uint64_t newpc;

	map = pmcstat_process_find_map(mdata->pp, ip);
	if (map != NULL) {
		//dprintf("cpu%d: 0x%lx map found\n", mdata->cpu, ip);
		image = map->ppm_image;
		newpc = ip - (map->ppm_lowpc +
		    (image->pi_vaddr - image->pi_start));

		//printf("looking for newpc %lx, ip %lx, lowpc %llx, offset %llx, pi_vadd %llx, pi_start %llx entry %llx\n",
		//    newpc, ip, map->ppm_lowpc, map->ppm_offset, image->pi_vaddr, image->pi_start, image->pi_entry);
		sym = pmcstat_symbol_search(image, newpc);
		*img = image;

		//if (sym == NULL)
		//	dprintf("cpu%d: symbol 0x%lx not found\n", mdata->cpu, newpc);

		return (sym);
	} else {
		//dprintf("cpu%d: 0x%lx map not found\n", mdata->cpu, ip);
	}

	return (NULL);
}
#endif

static ocsd_err_t
attach_raw_printers(dcd_tree_handle_t dcd_tree_h)
{
    ocsd_err_t err = OCSD_OK;
    int flags = 0;
    if (frame_raw_unpacked)
        flags |= OCSD_DFRMTR_UNPACKED_RAW_OUT;
    if (frame_raw_packed)
        flags |= OCSD_DFRMTR_PACKED_RAW_OUT;
    if (flags)
    {
        err = ocsd_dt_set_raw_frame_printer(dcd_tree_h, flags);
    }
    return err;
}

/* print an array of hex data - used by the packet monitor to print hex data from packet.*/
static int print_data_array(const uint8_t *p_array, const int array_size, char *p_buffer, int buf_size)
{
    int chars_printed = 0;
    int bytes_processed;
    p_buffer[0] = 0;
  
    if(buf_size > 9)
    {
        /* set up the header */
        strcat(p_buffer,"[ ");
        chars_printed+=2;
 
        for(bytes_processed = 0; bytes_processed < array_size; bytes_processed++)
        {
           sprintf(p_buffer+chars_printed,"0x%02X ", p_array[bytes_processed]);
           chars_printed += 5;
           if((chars_printed + 5) > buf_size)
               break;
        }

        strcat(p_buffer,"];");
        chars_printed+=2;
    }
    else if(buf_size >= 4)
    {
        sprintf(p_buffer,"[];");
        chars_printed+=3;
    }
    return chars_printed;
}

static void
packet_monitor(void *context __unused,
    const ocsd_datapath_op_t op,
    const ocsd_trc_index_t index_sop,
    const void *p_packet_in,
    const uint32_t size,
    const uint8_t *p_data)
{
	int offset;

	offset = 0;
 
	//printf("%s: op %d\n", __func__, op);

	switch(op) {
	case OCSD_OP_DATA:
		sprintf(packet_str,"Idx:%"  OCSD_TRC_IDX_STR ";", index_sop);
		offset = strlen(packet_str);
		offset += print_data_array(p_data,size,packet_str+offset,PACKET_STR_LEN-offset);

		/* got a packet - convert to string and use the libraries' message output to print to file and stdoout */
		if (ocsd_pkt_str(test_protocol,p_packet_in,packet_str+offset,PACKET_STR_LEN-offset) == OCSD_OK) {
			/* add in <CR> */
			if (strlen(packet_str) == PACKET_STR_LEN - 1) /* maximum length */
				packet_str[PACKET_STR_LEN-2] = '\n';
			else
				strcat(packet_str,"\n");

			/* print it using the library output logger. */
			ocsd_def_errlog_msgout(packet_str);
			printf("%s: %s", __func__, packet_str);
		}
		break;

	case OCSD_OP_EOT:
		sprintf(packet_str,"**** END OF TRACE ****\n");
		ocsd_def_errlog_msgout(packet_str);
			printf("%s: %s", __func__, packet_str);
		break;
	default:
		printf("unknown op %d\n", op);
		break;
	}
}

#if 0
static uint32_t
cs_etm_decoder__mem_access(const void *context __unused,
    const ocsd_vaddr_t address __unused, const ocsd_mem_space_acc_t mem_space __unused,
    const uint32_t req_size __unused, uint8_t *buffer __unused)
{

	printf("%s\n", __func__);
	//exit(23);

	return (0);
}
#endif

static ocsd_err_t
create_test_memory_acc(dcd_tree_handle_t handle, uint64_t base, uint64_t start, uint64_t end)
{
	ocsd_vaddr_t address;
	uint8_t *p_mem_buffer;
	uint32_t mem_length;
	int ret;

	printf("%s: base %lx start %lx end %lx\n", __func__, base, start, end);

	address = (ocsd_vaddr_t)base;
	p_mem_buffer = (uint8_t *)(base + start);
	mem_length = (end-start);

#if 1
	ret = ocsd_dt_add_buffer_mem_acc(handle, address, OCSD_MEM_SPACE_ANY,
	    p_mem_buffer, mem_length);
	if (ret != OCSD_OK) {
		printf("can't create accessor: ret %d\n", ret);
		exit(3);
	}
#else

	ret = ocsd_dt_add_callback_mem_acc(handle, base+start, base+end-1, OCSD_MEM_SPACE_ANY,
	    cs_etm_decoder__mem_access, NULL);
	if (ret != OCSD_OK) {
		printf("failed\n");
		exit(45);
	}
#endif

	return (ret);

#if 0
	//ocsd_dt_add_callback_mem_acc(handle, const ocsd_vaddr_t st_address, const ocsd_vaddr_t en_address, const ocsd_mem_space_acc_t mem_space, Fn_MemAcc_CB p_cb_func, const void *p_context);
#endif

#if 0
    ocsd_err_t ret = OCSD_OK;
    char mem_file_path[512];
    uint32_t i0adjust = 0x100;
    int i = 0;
 
    /* region list to test multi region memory file API */
    ocsd_file_mem_region_t region_list[4];
  
    /* path to the file containing the memory image traced - raw binary data in the snapshot  */
    strcpy(mem_file_path,default_path_to_snapshot);
    strcat(mem_file_path,memory_dump_filename);
 
    /*
    * decide how to handle the file - test the normal memory accessor (contiguous binary file),
    * a callback accessor or a multi-region file (e.g. similar to using the code region in a .so)
    *
    * The same memory dump file is used in each case, we just present it differently
    * to test the API functions.
    */

    /* memory access callback */
     ret = create_mem_acc_cb(handle,mem_file_path);
	return (ret);
#endif
}

static ocsd_err_t
create_generic_decoder(dcd_tree_handle_t handle, const char *p_name, const void *p_cfg,
    const void *p_context __unused, uint64_t base, uint64_t start, uint64_t end)
{ 
    ocsd_err_t ret = OCSD_OK;
    uint8_t CSID = 0;
  
        /* Full decode - need decoder, and memory dump */
	printf("%s\n", __func__);
  
        /* create the packet decoder and packet processor pair from the supplied name */
        ret = ocsd_dt_create_decoder(handle,p_name,OCSD_CREATE_FLG_FULL_DECODER,p_cfg,&CSID);
        if(ret == OCSD_OK)
        {
                /*
                * print the packets as well as the decode - use the packet processors monitor
                * output this time, as the main output is attached to the packet decoder.
                */
		if (1 == 0)
            ret = ocsd_dt_attach_packet_callback(handle,CSID,OCSD_C_API_CB_PKT_MON,packet_monitor,p_context);
		else
		ret = 0;

            /* attach a memory accessor */
            if(ret == OCSD_OK)
                ret = create_test_memory_acc(handle, base, start, end);

            /* if the attach failed then destroy the decoder. */
            if(ret != OCSD_OK) {
		printf("attach failed\n");
		exit(25);
                ocsd_dt_remove_decoder(handle,CSID);
		}
        } else {
		exit(29);
	}

    return ret;
}

/*** ETMV4 specific settings ***/
static ocsd_err_t
create_decoder_etmv4(dcd_tree_handle_t dcd_tree_h, uint64_t base, uint64_t start, uint64_t end)
{
    ocsd_etmv4_cfg trace_config;
    
    /*
    * populate the ETMv4 configuration structure with
    * hard coded values from snapshot .ini files.
    */
    
    trace_config.arch_ver   = ARCH_V8;
    trace_config.core_prof  = profile_CortexA;
    
    trace_config.reg_configr    = 0x000000C1;
    trace_config.reg_traceidr   = 0x00000010;   /* this is the trace ID -> 0x10, change this to analyse other streams i
n snapshot.*/
         
    if(test_trc_id_override != 0)
    {
        trace_config.reg_traceidr = (uint32_t)test_trc_id_override;
    }
            
    trace_config.reg_idr0   = 0x28000EA1;
    trace_config.reg_idr1   = 0x4100F403;
    trace_config.reg_idr2   = 0x00000488;
    trace_config.reg_idr8   = 0x0;
    trace_config.reg_idr9   = 0x0;
    trace_config.reg_idr10  = 0x0;
    trace_config.reg_idr11  = 0x0;
    trace_config.reg_idr12  = 0x0;
    trace_config.reg_idr13  = 0x0;
     
    /* create an ETMV4 decoder - no context needed as we have a single stream to a single handler. */
    return create_generic_decoder(dcd_tree_h,OCSD_BUILTIN_DCD_ETMV4I,(void *)&trace_config,0,base,start,end);
}

#if 1
static ocsd_datapath_resp_t
gen_trace_elem_print(const void *p_context, const ocsd_trc_index_t index_sop __unused,
    const uint8_t trc_chan_id __unused, const ocsd_generic_trace_elem *elem __unused)
{ 
	const struct mtrace_data *mdata;
	ocsd_datapath_resp_t resp;

	mdata = (const struct mtrace_data *)p_context;

	resp = OCSD_RESP_CONT;
#if 0
	printf("%s: Idx:%d ELEM TYPE %d, st_addr %lx, en_addr %lx\n",
	    __func__, index_sop, elem->elem_type, elem->st_addr, elem->en_addr);
#endif

	//mdata->ip = (elem->st_addr);

	struct pmcstat_symbol *sym;
	struct pmcstat_image *image;

	if (elem->st_addr == 0)
		return (0);
	sym = symbol_lookup(mdata, elem->st_addr, &image);
	if (sym) {
		printf("cpu%d:  IP 0x%lx %s %s\n", mdata->cpu, elem->st_addr,
		    pmcstat_string_unintern(image->pi_name),
		    pmcstat_string_unintern(sym->ps_name));
 	} else {
		//dprintf("cpu%d: symbol 0x%lx not found\n", mdata->cpu, elem->st_addr);
	}

	switch (elem->elem_type) {
	case OCSD_GEN_TRC_ELEM_UNKNOWN:
		break;
	case OCSD_GEN_TRC_ELEM_NO_SYNC:
		/* Trace off */
		break;
	case OCSD_GEN_TRC_ELEM_TRACE_ON:
		break;
	case OCSD_GEN_TRC_ELEM_INSTR_RANGE:
		printf("range\n");
		break;
	case OCSD_GEN_TRC_ELEM_EXCEPTION:
	case OCSD_GEN_TRC_ELEM_EXCEPTION_RET:
	case OCSD_GEN_TRC_ELEM_PE_CONTEXT:
	case OCSD_GEN_TRC_ELEM_EO_TRACE:
	case OCSD_GEN_TRC_ELEM_ADDR_NACC:
	case OCSD_GEN_TRC_ELEM_TIMESTAMP:
	case OCSD_GEN_TRC_ELEM_CYCLE_COUNT:
	case OCSD_GEN_TRC_ELEM_ADDR_UNKNOWN:
	case OCSD_GEN_TRC_ELEM_EVENT:
	case OCSD_GEN_TRC_ELEM_SWTRACE:
	case OCSD_GEN_TRC_ELEM_CUSTOM:
	default:
		break;
	};

	return (resp);
}

#else
/*          
* printer for the generic trace elements when decoder output is being processed
*/
static ocsd_datapath_resp_t gen_trace_elem_print(const void *p_context __unused, const ocsd_trc_index_t index_sop,
    const uint8_t trc_chan_id, const ocsd_generic_trace_elem *elem)
{           
    ocsd_datapath_resp_t resp = OCSD_RESP_CONT;
    int offset = 0;

    sprintf(packet_str,"Idx:%"  OCSD_TRC_IDX_STR "; TrcID:0x%02X; ", index_sop, trc_chan_id);
    offset = strlen(packet_str);

    if(ocsd_gen_elem_str(elem, packet_str+offset,PACKET_STR_LEN - offset) == OCSD_OK)
    {
        /* add in <CR> */
        if(strlen(packet_str) == PACKET_STR_LEN - 1) /* maximum length */
            packet_str[PACKET_STR_LEN-2] = '\n';
        else
            strcat(packet_str,"\n");
    }
    else
    {
        strcat(packet_str,"Unable to create element string\n");
    }    
    
    /* print it using the library output logger. */
    ocsd_def_errlog_msgout(packet_str);
	printf("%s: %s\n", __func__, packet_str);
         
    return resp;
}
#endif

static int
etm_process_chunk(struct mtrace_data *mdata __unused, uint64_t base __unused,
    uint64_t start __unused, uint64_t end __unused)
{
	dcd_tree_handle_t dcdtree_handle;
	int ret;

	dprintf("%s\n", __func__);

	//ocsd_def_errlog_init(OCSD_ERR_SEV_INFO,1);
	ocsd_def_errlog_init(0, 0);
	ret = ocsd_def_errlog_config_output(C_API_MSGLOGOUT_FLG_FILE | C_API_MSGLOGOUT_FLG_STDOUT, "c_api_test.log");

	dcdtree_handle = C_API_INVALID_TREE_HANDLE;
	dcdtree_handle = ocsd_create_dcd_tree(OCSD_TRC_SRC_FRAME_FORMATTED, OCSD_DFRMTR_FRAME_MEM_ALIGN);
	//dcdtree_handle = ocsd_create_dcd_tree(OCSD_TRC_SRC_SINGLE, OCSD_DFRMTR_FRAME_MEM_ALIGN);
 
	if(dcdtree_handle == C_API_INVALID_TREE_HANDLE) {
		printf("can't find dcd tree\n");
		exit(1);
		return (-1);
	}

	ret = create_decoder_etmv4(dcdtree_handle, base, start, end);
	if (ret != OCSD_OK) {
		printf("can't create decoder: base %lx start %lx end %lx\n", base, start, end);
		exit(2);
		return (-2);
	}

	ocsd_tl_log_mapped_mem_ranges(dcdtree_handle);

	if (1 == 1)
		ocsd_dt_set_gen_elem_outfn(dcdtree_handle, gen_trace_elem_print, mdata);
	else
		ocsd_dt_set_gen_elem_printer(dcdtree_handle);

	attach_raw_printers(dcdtree_handle);

	//ocsd_def_errlog_init(OCSD_ERR_SEV_INFO,0);

	int dp_ret;
	int bytes_this_time;
	int block_index;
	uint32_t bytes_done;
	uint32_t block_size;
	uint8_t *p_block;

	bytes_this_time = 0;
	block_index = 0;
	bytes_done = 0;
	block_size = (end-start);
	p_block = (uint8_t *)(base + start);

	ret = OCSD_OK;
	dp_ret = OCSD_RESP_CONT;
	uint32_t block_sz;
	block_sz = 1024;

	dp_ret = ocsd_dt_process_data(dcdtree_handle, OCSD_OP_RESET, 0, 0, NULL, NULL);
	dp_ret = OCSD_RESP_CONT;

	while (bytes_done < (uint32_t)block_size && (ret == OCSD_OK)) {

		if (OCSD_DATA_RESP_IS_CONT(dp_ret)) {
			printf("process data, block_size %d\n", block_size-bytes_done);
			dp_ret = ocsd_dt_process_data(dcdtree_handle, OCSD_OP_DATA,
			    block_index + bytes_done,
			    block_size - bytes_done,
			    ((uint8_t *)p_block) + bytes_done,
			    &bytes_this_time);
			bytes_done += bytes_this_time;
			printf("BYTES DONE %d\n", bytes_done);
		} else if (OCSD_DATA_RESP_IS_WAIT(dp_ret)) {
			printf("IS_WAIT rcvd !\n");
			exit(5);
			dp_ret = ocsd_dt_process_data(dcdtree_handle, OCSD_OP_FLUSH, 0, 0, NULL, NULL);
		} else {
			ret = OCSD_ERR_DATA_DECODE_FATAL;
			exit(6);
		}
	}

#if 0
    ocsd_err_t ret = OCSD_OK;
    uint32_t bytes_done = 0;
    ocsd_datapath_resp_t dp_ret = OCSD_RESP_CONT;
    uint32_t bytes_this_time = 0;
  
    while((bytes_done < (uint32_t)block_size) && (ret == OCSD_OK))
    {
        if(OCSD_DATA_RESP_IS_CONT(dp_ret))
        {
            dp_ret = ocsd_dt_process_data(dcd_tree_h,
                                OCSD_OP_DATA,
                                block_index+bytes_done,
                                block_size-bytes_done,
                                ((uint8_t *)p_block)+bytes_done,
                                &bytes_this_time);
            bytes_done += bytes_this_time;
        }
        else if(OCSD_DATA_RESP_IS_WAIT(dp_ret))
        {
            dp_ret = ocsd_dt_process_data(dcd_tree_h, OCSD_OP_FLUSH,0,0,NULL,NULL);
        }
        else
            ret = OCSD_ERR_DATA_DECODE_FATAL; /* data path responded with an error - stop processing */
    }
#endif

	dprintf("%s: flush done\n", __func__);

	ocsd_dt_process_data(dcdtree_handle, OCSD_OP_EOT, 0,0,NULL,NULL);

	dprintf("%s: done\n", __func__);

	return (0);
}

int
etm_process(struct trace_cpu *tc, struct pmcstat_process *pp,
    uint32_t cpu, uint32_t cycle, uint64_t offset,
    uint32_t flags)
{
	struct mtrace_data *mdata;

	mdata = &tc->mdata;
	mdata->pp = pp;
	mdata->flags = flags;

	dprintf("%s: cpu %d, cycle %d, offset %ld\n",
	    __func__, cpu, cycle, offset);

	//dprintf("tc->base %lx\n", *(uint64_t *)tc->base);
	dprintf("%s: tc->base %lx, *tc->base %lx\n", __func__, (uint64_t)tc->base, *(uint64_t *)tc->base);

	if (offset == tc->offset)
		return (0);

	if (cycle == tc->cycle) {
		if (offset > tc->offset) {
			etm_process_chunk(mdata, (uint64_t)tc->base, tc->offset, offset);
			tc->offset = offset;
		} else if (offset < tc->offset) {
			err(EXIT_FAILURE, "cpu%d: offset already processed %lx %lx",
			    cpu, offset, tc->offset);
		}
	} else if (cycle > tc->cycle) {
		if ((cycle - tc->cycle) > 1)
			err(EXIT_FAILURE, "cpu%d: trace buffers fills up faster than"
			    " we can process it (%d/%d). Consider setting trace filters",
			    cpu, cycle, tc->cycle);
		etm_process_chunk(mdata, (uint64_t)tc->base, tc->offset, tc->bufsize);
		tc->offset = 0;
		tc->cycle += 1;
		//etm_process_chunk(mdata, (uint64_t)tc->base, tc->offset, offset);
		tc->offset = offset;
	}

	return (0);
}
