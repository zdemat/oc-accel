/*
 * Copyright 2019 International Business Machines
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * SNAP HLS_HELLOWORLD_512 EXAMPLE
 *
 * Tasks for the user:
 *   1. Explore HLS pragmas to get better timing behavior.
 *   2. Try to measure the time needed to do data transfers (advanced)
 */

#define OCACCEL

#include <string.h>
#include "ap_int.h"
#include <hls_stream.h>
#include "action_uppercase.H"

#ifdef OCACCEL
#include <osnap_types.h>
#else
#include <snap_types.h>
#endif

enum rcv_state_t {RCV_INIT, RCV_JF_HEADER, RCV_GOOD, RCV_IGNORE};

// Based on https://forums.xilinx.com/t5/High-Level-Synthesis-HLS/ap-axiu-parameters/td-p/635138
struct ap_axiu_for_eth {
	ap_uint<512>     data;
	ap_uint<64>      keep;
	ap_uint<1>       user;
	ap_uint<1>       last;
};

typedef hls::stream<ap_axiu_for_eth> AXI_STREAM;

struct packet_arp_t {
	ap_uint<48> dest_mac;
	ap_uint<48> src_mac;
	ap_uint<48> tar_mac;
	ap_uint<64> tic_rcv;
	ap_uint<64> imsg;
};

#define THOUSAND 1000
#define MILLION  1000000
#define BILLION  1000000000
#define TICKS_PER_MSG (100*MILLION)

//----------------------------------------------------------------------
//---PROCEDURE ---------------------------------------------------------
//----------------------------------------------------------------------
void send_gratious_arp(AXI_STREAM &out)
{
	ap_axiu_for_eth packet_out;
	ap_uint<512> packet = 0;
	packet(47,0) = 0xffffffffffff;

	packet(48+7, 48)     = 0xf2;
	packet(48+15, 48+8)  = 0xee;
	packet(48+23, 48+16) = 0xdd;
	packet(48+31, 48+24) = 0xcc;
	packet(48+39, 48+32) = 0xbb;
	packet(48+47, 48+40) = 0xaa;

	packet( 96+16, 96) = 0x0608; // 0x0806
	ap_uint<32> eth_payload_pos = 14*8; // 112 bits
	packet(eth_payload_pos + 15, eth_payload_pos) = 0x0100; // ETH = 0x0001
	packet(eth_payload_pos + 31, eth_payload_pos + 16) = 0x0008; // IPv4 = 0x0800
	packet(eth_payload_pos + 39, eth_payload_pos + 32) = 0x6;
	packet(eth_payload_pos + 47, eth_payload_pos + 40) = 0x4;
	packet(eth_payload_pos + 63, eth_payload_pos + 48) = 0x0100; // 1 = request
	ap_uint<32> arp_sha_pos = eth_payload_pos + 8*8;

	packet(arp_sha_pos + 7,  arp_sha_pos )     = 0xf2;
	packet(arp_sha_pos + 15, arp_sha_pos + 8)  = 0xee;
	packet(arp_sha_pos + 23, arp_sha_pos + 16) = 0xdd;
	packet(arp_sha_pos + 31, arp_sha_pos + 24) = 0xcc;
	packet(arp_sha_pos + 39, arp_sha_pos + 32) = 0xbb;
	packet(arp_sha_pos + 47, arp_sha_pos + 40) = 0xaa;

	ap_uint<32> arp_spa_pos = arp_sha_pos + 6*8;

	packet(arp_spa_pos + 7,  arp_spa_pos )     = 0xcb;
	packet(arp_spa_pos + 15, arp_spa_pos + 8)  = 0x01;
	packet(arp_spa_pos + 23, arp_spa_pos + 16) = 0x12;
	packet(arp_spa_pos + 31, arp_spa_pos + 24) = 0xac; // AC1201CA 172.18.1.202

	packet_out.data = packet;
	packet_out.last = 1;
	packet_out.keep = 0xFFFFFFFFFFFFFFFF;
	packet_out.user = 0;

	out << packet_out;
}

inline ap_uint<48> get_mac_addr(ap_uint<512> data, size_t position) {
	ap_uint<48> tmp = data(position+47,position);
	ap_uint<48> retval;
	// Swap endian
	for (int i = 0; i < 6; i++) {
#pragma HLS UNROLL
		retval(8*i+7,8*i) = tmp((5-i)*8+7, (5-i)*8);
	}
	return retval;
}

//----------------------------------------------------------------------
//---PROCEDURE ---------------------------------------------------------
//----------------------------------------------------------------------
void emit_gratious_arp_series(AXI_STREAM &out, int num_msgs)
{
	#pragma HLS inline off

	ap_axiu_for_eth packet_out;
	ap_uint<512> packet = 0;
	packet(47,0) = 0xffffffffffff;

	packet(48+7, 48)     = 0xf1;
	packet(48+15, 48+8)  = 0xee;
	packet(48+23, 48+16) = 0xdd;
	packet(48+31, 48+24) = 0xcc;
	packet(48+39, 48+32) = 0xbb;
	packet(48+47, 48+40) = 0xaa;

	packet( 96+16, 96) = 0x0608; // 0x0806
	ap_uint<32> eth_payload_pos = 14*8; // 112 bits
	packet(eth_payload_pos + 15, eth_payload_pos) = 0x0100; // ETH = 0x0001
	packet(eth_payload_pos + 31, eth_payload_pos + 16) = 0x0008; // IPv4 = 0x0800
	packet(eth_payload_pos + 39, eth_payload_pos + 32) = 0x6;
	packet(eth_payload_pos + 47, eth_payload_pos + 40) = 0x4;
	packet(eth_payload_pos + 63, eth_payload_pos + 48) = 0x0100; // 1 = request
	ap_uint<32> arp_sha_pos = eth_payload_pos + 8*8; // 176 bits

	packet(arp_sha_pos + 7,  arp_sha_pos )     = 0xf1;
	packet(arp_sha_pos + 15, arp_sha_pos + 8)  = 0xee;
	packet(arp_sha_pos + 23, arp_sha_pos + 16) = 0xdd;
	packet(arp_sha_pos + 31, arp_sha_pos + 24) = 0xcc;
	packet(arp_sha_pos + 39, arp_sha_pos + 32) = 0xbb;
	packet(arp_sha_pos + 47, arp_sha_pos + 40) = 0xaa;

	ap_uint<32> arp_spa_pos = arp_sha_pos + 6*8; // 224 bits

	packet(arp_spa_pos + 7,  arp_spa_pos )     = 0xca;
	packet(arp_spa_pos + 15, arp_spa_pos + 8)  = 0x01;
	packet(arp_spa_pos + 23, arp_spa_pos + 16) = 0x12;
	packet(arp_spa_pos + 31, arp_spa_pos + 24) = 0xac; // AC1201CA 172.18.1.202

	ap_uint<32> arp_tha_pos = arp_spa_pos + 4*8; // 256 bits

	packet(arp_tha_pos + 7,  arp_tha_pos )     = 0x00;
	packet(arp_tha_pos + 15, arp_tha_pos + 8)  = 0x00;
	packet(arp_tha_pos + 23, arp_tha_pos + 16) = 0x00;
	packet(arp_tha_pos + 31, arp_tha_pos + 24) = 0x00;
	packet(arp_tha_pos + 39, arp_tha_pos + 32) = 0x00;
	packet(arp_tha_pos + 47, arp_tha_pos + 40) = 0x00;

	ap_uint<32> arp_tpa_pos = arp_tha_pos + 6*8; // 304 bits

	packet(arp_tpa_pos + 7,  arp_tpa_pos )     = 0xca;
	packet(arp_tpa_pos + 15, arp_tpa_pos + 8)  = 0x01;
	packet(arp_tpa_pos + 23, arp_tpa_pos + 16) = 0x12;
	packet(arp_tpa_pos + 31, arp_tpa_pos + 24) = 0xac;

	packet_out.data = packet;
	packet_out.last = 1;
	packet_out.keep = 0xFFFFFFFFFFFFFFFF;
	packet_out.user = 0;

	bool bsend = false;
	int j = (TICKS_PER_MSG >> 1) + 1; // offset clock for sending the msg
	int imsg = 1;

	SEND_LOOP:
	for (uint64_t i = 0; i < (uint64_t(num_msgs)*TICKS_PER_MSG); i++) {
		#pragma HLS pipeline II=1
		if (bsend) {
			bsend = false;
			packet(arp_tha_pos + 7,  arp_tha_pos )     = (i & 0x0000000000FF) >> 0;
			packet(arp_tha_pos + 15, arp_tha_pos + 8)  = (i & 0x00000000FF00) >> 8;
			packet(arp_tha_pos + 23, arp_tha_pos + 16) = (i & 0x000000FF0000) >> 16;
			packet(arp_tha_pos + 31, arp_tha_pos + 24) = (i & 0x0000FF000000) >> 24;
			packet(arp_tha_pos + 39, arp_tha_pos + 32) = (i & 0x00FF00000000) >> 32;
			packet(arp_tha_pos + 47, arp_tha_pos + 40) = (i & 0xFF0000000000) >> 40;
			
			packet(arp_tpa_pos + 7,  arp_tpa_pos )     = (imsg & 0x000000FF) >> 0;
			packet(arp_tpa_pos + 15, arp_tpa_pos + 8)  = (imsg & 0x0000FF00) >> 8;
			packet(arp_tpa_pos + 23, arp_tpa_pos + 16) = (imsg & 0x00FF0000) >> 16;
			packet(arp_tpa_pos + 31, arp_tpa_pos + 24) = (imsg & 0xFF000000) >> 24;

			packet_out.data = packet;
			out << packet_out;
			imsg++;
			j = 1;
		} else {
			bsend = (j == (TICKS_PER_MSG-1));
			j++;
		}
	}
}

//----------------------------------------------------------------------
//---PROCEDURE ---------------------------------------------------------
//----------------------------------------------------------------------
void receive_arp_msg(AXI_STREAM &in, packet_arp_t &msg, uint64_t &nmsg_count, int num_msgs)
{
	#pragma HLS inline off

	nmsg_count = 0;
	msg.dest_mac = 0;
	msg.src_mac  = 0;

	rcv_state_t rcv_state = RCV_INIT;

	RCV_LOOP:
	for (uint64_t i = 0; i < (uint64_t(num_msgs)*TICKS_PER_MSG); i++) {
		#pragma HLS pipeline II=1
		ap_axiu_for_eth packet_in;

		if (in.read_nb(packet_in)) {
		
			switch (rcv_state) {
				case RCV_INIT:
					rcv_state = RCV_IGNORE;
					msg.dest_mac = get_mac_addr(packet_in.data,0);
					msg.src_mac  = get_mac_addr(packet_in.data,48);
					msg.tar_mac = packet_in.data(303,256);
					msg.tic_rcv = uint64_t(i);
					msg.imsg = (uint64_t(packet_in.data(311,304)) << 0) | (uint64_t(packet_in.data(319,312)) << 8) | (uint64_t(packet_in.data(327,320)) << 16) | (uint64_t(packet_in.data(335,328)) << 32);		
					nmsg_count++;
					break;
				case RCV_IGNORE:
					break;
			}
		
			if (packet_in.last == 1) rcv_state = RCV_INIT;
		}
	}
}

//----------------------------------------------------------------------
//--- MAIN PROGRAM -----------------------------------------------------
//----------------------------------------------------------------------
static int process_action(snap_membus_t *din_gmem,
	      snap_membus_t *dout_gmem,
	      /* snap_membus_512_t *d_ddrmem, *//* not needed */
	      AXI_STREAM &din_eth,		
	      AXI_STREAM &dout_eth,
	      action_reg *act_reg)
{
    uint32_t size, bytes_to_transfer;
    uint64_t i_idx, o_idx;

    /* byte address received need to be aligned with port width */
    i_idx = act_reg->Data.in.addr >> ADDR_RIGHT_SHIFT;
    o_idx = act_reg->Data.out.addr >> ADDR_RIGHT_SHIFT;
    size = act_reg->Data.in.size;

	ap_uint<512> read_from_memory;

	/* Read in one word_t */
	memcpy((char*) &read_from_memory, din_gmem + i_idx, 512/8);

	int num_msgs = read_from_memory(31, 0);

#ifdef __BLABLA__
    main_loop:
    while (size > 0) {
//#pragma HLS PIPELINE
	word_t text;
	unsigned char i;

	/* Limit the number of bytes to process to a 64B word */
	bytes_to_transfer = MIN(size, BPERDW_512);

    /* Read in one word_t */
	memcpy((char*) text, din_gmem + i_idx, BPERDW_512);

	/* Convert lower cases to upper cases byte per byte */
    uppercase_conversion:
	for (i = 0; i < sizeof(text); i++ ) {
//#pragma HLS UNROLL
	    if (text[i] >= 'a' && text[i] <= 'z')
		text[i] = text[i] - ('a' - 'A');
	}

	/* Write out one word_t */
	memcpy(dout_gmem + o_idx, (char*) text, BPERDW_512);

	size -= bytes_to_transfer;
	i_idx++;
	o_idx++;
    }
#endif // __BLABLA__
	packet_arp_t arp_in;
	uint64_t n_arp;

	receive_arp_msg(din_eth, arp_in, n_arp, num_msgs);
	emit_gratious_arp_series(dout_eth, num_msgs);

	ap_uint<512> save_to_memory;
	save_to_memory(47, 0) = arp_in.dest_mac;
	save_to_memory(95,48) = arp_in.src_mac;
	save_to_memory(191,128) = n_arp;
	save_to_memory(239,192) = arp_in.tar_mac;
	save_to_memory(319,256) = arp_in.tic_rcv;
	save_to_memory(383,320) = arp_in.imsg;

	/* Write out one word_t */
	memcpy(dout_gmem + o_idx, (char*) &save_to_memory, 512/8);

    act_reg->Control.Retc = SNAP_RETC_SUCCESS;
    return 0;
}

//--- TOP LEVEL MODULE -------------------------------------------------
// snap_membus_512_t is defined in actions/include/hls_snap_1024.H
// which deals with both 512 and 1024 bits wide busses
void hls_action(snap_membus_t *din_gmem,
	snap_membus_t *dout_gmem,
	/* snap_membus_512_t *d_ddrmem, // CAN BE COMMENTED IF UNUSED */
    AXI_STREAM &din_eth, AXI_STREAM &dout_eth, volatile ap_uint<1> &eth_reset,
#ifdef OCACCEL
	action_reg *act_reg)
#else
	action_reg *act_reg,
	action_RO_config_reg *Action_Config)
#endif
{
    // Host Memory AXI Interface - CANNOT BE REMOVED - NO CHANGE BELOW
#pragma HLS INTERFACE m_axi port=din_gmem bundle=host_mem offset=slave depth=512 \
  max_read_burst_length=64  max_write_burst_length=64
#pragma HLS INTERFACE s_axilite port=din_gmem bundle=ctrl_reg offset=0x030

#pragma HLS INTERFACE m_axi port=dout_gmem bundle=host_mem offset=slave depth=512 \
  max_read_burst_length=64  max_write_burst_length=64
#pragma HLS INTERFACE s_axilite port=dout_gmem bundle=ctrl_reg offset=0x040

/*  // DDR memory Interface - CAN BE COMMENTED IF UNUSED
 * #pragma HLS INTERFACE m_axi port=d_ddrmem bundle=card_mem0 offset=slave depth=512 \
 *   max_read_burst_length=64  max_write_burst_length=64
 * #pragma HLS INTERFACE s_axilite port=d_ddrmem bundle=ctrl_reg offset=0x050
 */

#pragma HLS INTERFACE axis register off port=din_eth
#pragma HLS INTERFACE axis register off port=dout_eth
#pragma HLS INTERFACE ap_none port=eth_reset

#ifndef OCACCEL
#pragma HLS DATA_PACK variable=Action_Config
#pragma HLS INTERFACE s_axilite port=Action_Config bundle=ctrl_reg offset=0x010
#endif

    // Host Memory AXI Lite Master Interface - NO CHANGE BELOW
#pragma HLS DATA_PACK variable=act_reg
#pragma HLS INTERFACE s_axilite port=act_reg bundle=ctrl_reg offset=0x100
#pragma HLS INTERFACE s_axilite port=return bundle=ctrl_reg

	/* Required Action Type Detection - NO CHANGE BELOW */
	//	NOTE: switch generates better vhdl than "if" */
	// Test used to exit the action if no parameter has been set.
	// Used for the discovery phase of the cards */

#ifndef OCACCEL
	switch (act_reg->Control.flags) {
		case 0:
			Action_Config->action_type = ACTION_TYPE; //TO BE ADAPTED
			Action_Config->release_level = RELEASE_LEVEL;
			act_reg->Control.Retc = 0xe00f;
			return;
			break;
		default:
#endif
			// TODO: High priority - need to have this reset by default at the beginning of the action
			{
#pragma HLS PROTOCOL fixed
				int i = 0;
				eth_reset = 1;
				while (i < 64) {
					i++; ap_wait();
				}
				if (i == 64) eth_reset = 0;
			}
			process_action(din_gmem, dout_gmem, din_eth, dout_eth, act_reg);
#ifndef OCACCEL
		break;
	}
#endif
}

//-----------------------------------------------------------------------------
//-- TESTBENCH BELOW IS USED ONLY TO DEBUG THE HARDWARE ACTION WITH HLS TOOL --
//-----------------------------------------------------------------------------

#ifdef NO_SYNTH

int main(void)
{
#define MEMORY_LINES 1
    int rc = 0;
    unsigned int i;
    static snap_membus_512_t  din_gmem[MEMORY_LINES];
    static snap_membus_512_t  dout_gmem[MEMORY_LINES];

    action_reg act_reg;


    // Processing Phase .....
    // Fill the memory with 'c' characters
    memset(din_gmem,  'c', sizeof(din_gmem[0]));
    printf("Input is : %s\n", (char *)((unsigned long)din_gmem + 0));

    // set flags != 0 to have action processed
    act_reg.Control.flags = 0x1; /* just not 0x0 */

    act_reg.Data.in.addr = 0;
    act_reg.Data.in.size = 64;
    act_reg.Data.in.type = SNAP_ADDRTYPE_HOST_DRAM;

    act_reg.Data.out.addr = 0;
    act_reg.Data.out.size = 64;
    act_reg.Data.out.type = SNAP_ADDRTYPE_HOST_DRAM;

    printf("Action call \n");
    hls_action(din_gmem, dout_gmem, &act_reg);
    if (act_reg.Control.Retc == SNAP_RETC_FAILURE) {
	fprintf(stderr, " ==> RETURN CODE FAILURE <==\n");
	return 1;
    }

    printf("Output is : %s\n", (char *)((unsigned long)dout_gmem + 0));

    return 0;
}

#endif
