#-----------------------------------------------------------
#
# Copyright 2019, International Business Machines
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#-----------------------------------------------------------

set vivadoVer    [version -short]
set root_dir    $::env(SNAP_HARDWARE_ROOT)
set denali_used $::env(DENALI_USED)
set fpga_part   $::env(FPGACHIP)
set log_dir     $::env(LOGS_DIR)
set log_file    $log_dir/create_hbm_host.log

# user can set a specific value for the Action clock lower than the 200MHz nominal clock
set action_clock_freq "200MHz"
#overide default value if variable exist
#set action_clock_freq $::env(FPGA_ACTION_CLK)

set prj_name hbm
set bd_name  hbm_top


# _______________________________________________________________________________
# In this file, we define all the logic to have independent 256MB/2Gb memories
# each with an independent AXI interfaces which will be connected to the action
# Default is HBM_MEM_NUM = 2 interfaces
# TO increase/decrease the number of memory needed, just look to #CHANGE_HBM_INTERFACES_NUMBER
# param and 1) change HBM_MEM_NUM value
# with a value between 1 and 16. If you need more memories, you need to add the 2nd stack
# and 2) set the right params enabling AXI and MC
# -------------------------------------------------------
# If you modify the number of AXI interfaces, don't forget to modify also :
#   actions/hls_hbm_memcopy/hw/hw_action_memcopy.cpp
#   hardware/hdl/hls/action_wrapper.vhd_source
#   hardware/hdl/core/psl_accel_ad9h3.vhd_source
#   --> follow HBM names <--
# _______________________________________________________________________________
#CHANGE_HBM_INTERFACES_NUMBER
set  HBM_MEM_NUM 2

# Create HBM project
create_project   $prj_name $root_dir/ip/hbm -part $fpga_part -force >> $log_file
set_property target_language VHDL [current_project]

#Create block design
create_bd_design $bd_name  >> $log_file
current_bd_design $bd_name

# Create HBM IP
puts "                        generating HBM Host IP with $HBM_MEM_NUM AXI interfaces of 256MB HBM each"

#======================================================
# Create 'sources_1' fileset (if not found)
if {[string equal [get_filesets -quiet sources_1] ""]} {
  create_fileset -srcset sources_1
  }
  set source_set [get_filesets sources_1]

  # Set source set properties
  set_property "generic" "" $source_set


#====================
#create the constants
create_bd_cell -type ip -vlnv xilinx.com:ip:xlconstant:1.1 constant_1_zero
set_property -dict [list CONFIG.CONST_WIDTH {1} CONFIG.CONST_VAL {0}] [get_bd_cells constant_1_zero]

create_bd_cell -type ip -vlnv xilinx.com:ip:xlconstant:1.1 constant_1_one
set_property -dict [list CONFIG.CONST_WIDTH {1} CONFIG.CONST_VAL {1}] [get_bd_cells constant_1_one]

create_bd_cell -type ip -vlnv xilinx.com:ip:xlconstant:1.1 constant_22_zero
set_property -dict [list CONFIG.CONST_WIDTH {22} CONFIG.CONST_VAL {0}] [get_bd_cells constant_22_zero]

create_bd_cell -type ip -vlnv xilinx.com:ip:xlconstant:1.1 constant_32_zero
set_property -dict [list CONFIG.CONST_WIDTH {32} CONFIG.CONST_VAL {0}] [get_bd_cells constant_32_zero]


#====================
#create the buffer to propagate the clocks
#create_bd_cell -type ip -vlnv xilinx.com:ip:util_ds_buf:2.1 refclk_ibufds_inst
#set_property -dict [list CONFIG.C_BUF_TYPE {IBUFDS}] [get_bd_cells refclk_ibufds_inst]

#====================
#create the clocks and the reset signals for the design
#create_bd_cell -type ip -vlnv xilinx.com:ip:util_ds_buf:2.1 refclk_bufg_div3
#set_property -dict [list CONFIG.C_BUF_TYPE {BUFGCE_DIV} CONFIG.C_BUFGCE_DIV {3}] [get_bd_cells refclk_bufg_div3]

create_bd_cell -type ip -vlnv xilinx.com:ip:util_ds_buf:2.1 refclk_bufg_div2
set_property -dict [list CONFIG.C_BUF_TYPE {BUFGCE_DIV} CONFIG.C_BUFGCE_DIV {4}] [get_bd_cells refclk_bufg_div2]

#====================
#connect_bd_net [get_bd_pins constant_1_zero/dout] [get_bd_pins refclk_bufg_div3/BUFGCE_CLR]
#connect_bd_net [get_bd_pins constant_1_one/dout] [get_bd_pins refclk_bufg_div3/BUFGCE_CE]
connect_bd_net [get_bd_pins constant_1_zero/dout] [get_bd_pins refclk_bufg_div2/BUFGCE_CLR]
connect_bd_net [get_bd_pins constant_1_one/dout] [get_bd_pins refclk_bufg_div2/BUFGCE_CE]

#ARESETN is used for HBM reset 
set port [create_bd_port -dir I ARESETN]
#CRESETN is used for converters reset 
set port [create_bd_port -dir I CRESETN]

#This 300MHz clock is used divided by 4 for the APB_CLK of the HBM
#if { ($vivadoVer >= "2019.2")} {
#  set port [create_bd_port -dir I -type clk -freq_hz 300000000 refclk300_n]
#} else {
#  set port [create_bd_port -dir I -type clk refclk300_n]
#  set_property {CONFIG.FREQ_HZ} {300000000} $port
#}
#
#if { ($vivadoVer >= "2019.2")} {
#  set port [create_bd_port -dir I -type clk -freq_hz 300000000 refclk300_p]
#} else {
#  set port [create_bd_port -dir I -type clk refclk300_p]
#  set_property {CONFIG.FREQ_HZ} {300000000} $port 
#}
#connect_bd_net [get_bd_ports refclk300_p] [get_bd_pins refclk_ibufds_inst/IBUF_DS_P] >> $log_file
#connect_bd_net [get_bd_ports refclk300_n] [get_bd_pins refclk_ibufds_inst/IBUF_DS_N] >> $log_file

#connect_bd_net [get_bd_pins refclk_ibufds_inst/IBUF_OUT] [get_bd_pins refclk_bufg_div2/BUFGCE_I]


#====================
#Use the HBM left stack 0 only (16 modules of 256MB/2Gb = 4GB)
set cell [create_bd_cell -quiet -type ip -vlnv {xilinx.com:ip:hbm:*} hbm]

#Common params for the HBM not depending on the number of memories enabled
# The reference clock provided to HBM is at 100MHz (output of refclk_bufg_div3)
# and HBM IP logic generates internally the 800MHz which HBM operates at
#(params provided by AlphaData)

#Setting for Production chips: HBM_REF_CLK=200 or 225MHz
set_property -dict [list                               \
  CONFIG.USER_HBM_DENSITY {4GB}                        \
  CONFIG.USER_HBM_STACK {1}                            \
  CONFIG.USER_AUTO_POPULATE {yes}                      \
  CONFIG.USER_SWITCH_ENABLE_00 {FALSE}                 \
  CONFIG.USER_APB_PCLK_0 {75}                          \
  CONFIG.USER_SINGLE_STACK_SELECTION {RIGHT}           \
  ] $cell >> $log_file


# AXI clk is 200MHZ and is used as HBM_ref_clk 
# AXI clk divided by 2 is used by APB_clock
  set_property -dict [list                               \
    CONFIG.USER_HBM_REF_CLK_0 {200}                      \
    CONFIG.USER_HBM_REF_CLK_PS_0 {2500.00}               \
    CONFIG.USER_HBM_REF_CLK_XDC_0 {5.00}                 \
    CONFIG.USER_HBM_FBDIV_0 {18}                         \
    CONFIG.USER_HBM_CP_0 {6}                             \
    CONFIG.USER_HBM_RES_0 {9}                            \
    CONFIG.USER_HBM_LOCK_REF_DLY_0 {20}                  \
    CONFIG.USER_HBM_LOCK_FB_DLY_0 {20}                   \
    CONFIG.USER_HBM_HEX_CP_RES_0 {0x00009600}            \
    CONFIG.USER_HBM_HEX_LOCK_FB_REF_DLY_0 {0x00001414}   \
    CONFIG.USER_HBM_HEX_FBDIV_CLKOUTDIV_0 {0x00000482}   \
    CONFIG.USER_HBM_TCK_0 {900}                          \
    CONFIG.USER_HBM_TCK_0_PERIOD {1.1111111111111112}    \
    CONFIG.USER_tRC_0 {0x2B}                             \
    CONFIG.USER_tRAS_0 {0x1E}                            \
    CONFIG.USER_tRCDRD_0 {0xD}                           \
    CONFIG.USER_tRCDWR_0 {0x9}                           \
    CONFIG.USER_tRRDL_0 {0x4}                            \
    CONFIG.USER_tRRDS_0 {0x4}                            \
    CONFIG.USER_tFAW_0 {0xF}                             \
    CONFIG.USER_tRP_0 {0xD}                              \
    CONFIG.USER_tWR_0 {0xF}                              \
    CONFIG.USER_tXP_0 {0x7}                              \
    CONFIG.USER_tRFC_0 {0xEA}                            \
    CONFIG.USER_tRFCSB_0 {0x90}                          \
    CONFIG.USER_tRREFD_0 {0x8}                           \
    CONFIG.USER_APB_PCLK_0 {100}                         \
    CONFIG.USER_APB_PCLK_PERIOD_0 {10.0}                 \
    CONFIG.USER_TEMP_POLL_CNT_0 {100000}                 \
    CONFIG.USER_HBM_REF_OUT_CLK_0 {1800}                 \
    CONFIG.USER_MC0_REF_CMD_PERIOD {0x0DB6}              \
    CONFIG.USER_MC1_REF_CMD_PERIOD {0x0DB6}              \
    CONFIG.USER_MC2_REF_CMD_PERIOD {0x0DB6}              \
    CONFIG.USER_MC3_REF_CMD_PERIOD {0x0DB6}              \
    CONFIG.USER_MC4_REF_CMD_PERIOD {0x0DB6}              \
    CONFIG.USER_MC5_REF_CMD_PERIOD {0x0DB6}              \
    CONFIG.USER_MC6_REF_CMD_PERIOD {0x0DB6}              \
    CONFIG.USER_MC7_REF_CMD_PERIOD {0x0DB6}              \
    CONFIG.USER_DFI_CLK0_FREQ {450.000}                  \
  ] $cell >> $log_file
 
#===============================================================================
#== ALL PARAMETERS BELOW DEPEND ON THE NUMBER OF HBM MEMORIES YOU WANT TO USE ==
#===============================================================================
#Define here the configuration you request 
#
#Config below is enabling 2 independent 256MB memory using 2 MC => 1024MB
# MC0 contains S_AXI_00 and MC1 contains S_AXI_02
# Each memory is accessible using address from <0x0000_0000> to <0x0FFF_FFFF> [ 256M ]
#Slave segment </hbm/SAXI_00/HBM_MEM00> is being mapped into address space </S_AXI_0> at <0x0000_0000 [ 256M ]>
#Slave segment </hbm/SAXI_00/HBM_MEM01> is being mapped into address space </S_AXI_0> at <0x1000_0000 [ 256M ]>
#Slave segment </hbm/SAXI_01/HBM_MEM00> is being mapped into address space </S_AXI_1> at <0x0000_0000 [ 256M ]>
#Slave segment </hbm/SAXI_01/HBM_MEM01> is being mapped into address space </S_AXI_1> at <0x1000_0000 [ 256M ]>
#   
#CHANGE_HBM_INTERFACES_NUMBER
#  CONFIG.USER_MEMORY_DISPLAY {1024}  => set the value to 512 by MC used (1024 = 2 MC used)
#  CONFIG.USER_MC_ENABLE_00 {TRUE}    => enable/disable the MC
#  CONFIG.USER_SAXI_00 {true}         => enable/disable each of the AXI interface/HBM memory
set_property -dict [list \
  CONFIG.USER_MEMORY_DISPLAY {512}  \
  CONFIG.USER_CLK_SEL_LIST0 {AXI_00_ACLK}  \
  CONFIG.USER_MC_ENABLE_00 {TRUE}  \
  CONFIG.USER_MC_ENABLE_01 {FALSE}  \
  CONFIG.USER_MC_ENABLE_02 {FALSE}  \
  CONFIG.USER_MC_ENABLE_03 {FALSE}  \
  CONFIG.USER_MC_ENABLE_04 {FALSE}  \
  CONFIG.USER_MC_ENABLE_05 {FALSE}  \
  CONFIG.USER_MC_ENABLE_06 {FALSE}  \
  CONFIG.USER_MC_ENABLE_07 {FALSE}  \
] $cell >> $log_file


#add log_file to remove the warning on screen
connect_bd_net [get_bd_pins constant_1_zero/dout] [get_bd_pins hbm/APB_0_PENABLE] >> $log_file
connect_bd_net [get_bd_pins constant_22_zero/dout] [get_bd_pins hbm/APB_0_PADDR]  >> $log_file
connect_bd_net [get_bd_pins constant_1_zero/dout] [get_bd_pins hbm/APB_0_PSEL]    >> $log_file
connect_bd_net [get_bd_pins constant_32_zero/dout] [get_bd_pins hbm/APB_0_PWDATA] >> $log_file
connect_bd_net [get_bd_pins constant_1_zero/dout] [get_bd_pins hbm/APB_0_PWRITE]  >> $log_file

#connect_bd_net [get_bd_pins refclk_bufg_div3/BUFGCE_O] [get_bd_pins hbm/HBM_REF_CLK_0]
#connect_bd_net [get_bd_pins hbm/HBM_REF_CLK_0] [get_bd_pins refclk_ibufds_inst/IBUF_OUT]  
connect_bd_net [get_bd_pins refclk_bufg_div2/BUFGCE_O] [get_bd_pins hbm/APB_0_PCLK]
connect_bd_net [get_bd_pins ARESETN] [get_bd_pins hbm/APB_0_PRESET_N]

#======
# Connect output ports
set port [create_bd_port -dir O apb_complete]
connect_bd_net [get_bd_ports apb_complete] [get_bd_pins hbm/apb_complete_0]

#====================
#
#-- Set the upper bound of the loop to the number of memory you use --

#--------------------- start loop ------------------
for {set i 0} {$i < $HBM_MEM_NUM} {incr i} {

  #create the axi4 to axi3 converters
  set cell [create_bd_cell -type ip -vlnv {xilinx.com:ip:axi_protocol_converter:*} axi4_to_axi3_$i]
  set_property -dict {      \
    CONFIG.ADDR_WIDTH {64}        \
  } $cell
  

  #create the axi_register_slice converters
  create_bd_cell -type ip -vlnv xilinx.com:ip:axi_register_slice:2.1 axi_register_slice_$i

  #set cell [create_bd_cell -type ip -vlnv {xilinx.com:ip:axi_register_slice:*} axi_register_slice_$i ]
  #set_property -dict {     \
  #  CONFIG.ADDR_WIDTH {33}              \
  #  CONFIG.DATA_WIDTH {256}             \
  #  CONFIG.ID_WIDTH {6}                 \
  #  CONFIG.REG_AW {10}                  \
  #  CONFIG.REG_AR {10}                  \
  #  CONFIG.REG_W {10}                   \
  #  CONFIG.REG_R {10}                   \
  #  CONFIG.REG_B {10}                   \
  #  }  $cell

  #create the ports
  create_bd_intf_port -mode Slave -vlnv xilinx.com:interface:aximm_rtl:1.0 S_AXI_p$i\_HBM
  set_property -dict [list \
      CONFIG.CLK_DOMAIN {S_AXI_p$i\_HBM_ACLK} \
      CONFIG.NUM_WRITE_OUTSTANDING {2}       \
      CONFIG.NUM_READ_OUTSTANDING {2}        \
      CONFIG.DATA_WIDTH {256}                \
  ] [get_bd_intf_ports S_AXI_p$i\_HBM]

  if { $action_clock_freq == "225MHZ" } {
    set_property -dict [list CONFIG.FREQ_HZ {225000000}] [get_bd_intf_ports S_AXI_p$i\_HBM]
  } else {
    set_property -dict [list CONFIG.FREQ_HZ {200000000}] [get_bd_intf_ports S_AXI_p$i\_HBM]
  }
  connect_bd_intf_net [get_bd_intf_ports S_AXI_p$i\_HBM] [get_bd_intf_pins axi4_to_axi3_$i/S_AXI]


  if { ($vivadoVer >= "2019.2")} {
    if { $action_clock_freq == "225MHZ" } {
      set port [create_bd_port -dir I -type clk -freq_hz 225000000 S_AXI_p$i\_HBM_ACLK]
    } else {
      set port [create_bd_port -dir I -type clk -freq_hz 200000000 S_AXI_p$i\_HBM_ACLK]
    }
  } else {
    set port [create_bd_port -dir I -type clk S_AXI_p$i\_HBM_ACLK]
    if { $action_clock_freq == "225MHZ" } {
      set_property {CONFIG.FREQ_HZ} {225000000} $port
    } else {
      set_property {CONFIG.FREQ_HZ} {200000000} $port
    }
  }
  connect_bd_net $port [get_bd_pins axi4_to_axi3_$i/aclk]
  connect_bd_net [get_bd_pins CRESETN] [get_bd_pins axi4_to_axi3_$i/aresetn]
  
  #connect aaxi4_to_axi3 to axi_register_slice
  connect_bd_net [get_bd_ports CRESETN] [get_bd_pins axi_register_slice_$i\/aresetn]
  connect_bd_net [get_bd_ports S_AXI_p$i\_HBM_ACLK] [get_bd_pins axi_register_slice_$i\/aclk]
  connect_bd_intf_net [get_bd_intf_pins axi4_to_axi3_$i/M_AXI] [get_bd_intf_pins axi_register_slice_$i/S_AXI]

  #connect axi_register_slice to hbm
  #Manage 1 vs 2 digits
  if { $i < 10} {
    connect_bd_net [get_bd_pins ARESETN] [get_bd_pins hbm/AXI_0$i\_ARESET_N]
    connect_bd_net [get_bd_pins axi4_to_axi3_$i/aclk] [get_bd_pins hbm/AXI_0$i\_ACLK]
    #connect_bd_intf_net [get_bd_intf_pins axi4_to_axi3_$i/M_AXI] [get_bd_intf_pins hbm/SAXI_0$i]
    connect_bd_intf_net [get_bd_intf_pins axi_register_slice_$i\/M_AXI] [get_bd_intf_pins hbm/SAXI_0$i]
    #create and connect output ports
    #create_bd_port -dir O -from 31 -to 0 -type data AXI_0$i\_RDATA_PARITY
    #connect_bd_net [get_bd_ports AXI_0$i\_RDATA_PARITY] [get_bd_pins hbm/AXI_0$i\_RDATA_PARITY]
  } else {
    connect_bd_net [get_bd_pins ARESETN] [get_bd_pins hbm/AXI_$i\_ARESET_N]
    connect_bd_net [get_bd_pins axi4_to_axi3_$i/aclk] [get_bd_pins hbm/AXI_$i\_ACLK]
    #connect_bd_intf_net [get_bd_intf_pins axi4_to_axi3_$i/M_AXI] [get_bd_intf_pins hbm/SAXI_$i]
    connect_bd_intf_net [get_bd_intf_pins axi_register_slice_$i\/M_AXI] [get_bd_intf_pins hbm/SAXI_0$i]
    #create and connect output ports
    #create_bd_port -dir O -from 31 -to 0 -type data AXI_$i\_RDATA_PARITY
    #connect_bd_net [get_bd_ports AXI_$i\_RDATA_PARITY] [get_bd_pins hbm/AXI_$i\_RDATA_PARITY]
  }

}
#--------------------- end loop ------------------

#This line need to be added after the loop since the S_AXI_p0_HBM_ACLK is not defined before
connect_bd_net [get_bd_pins hbm/HBM_REF_CLK_0] [get_bd_pins S_AXI_p0_HBM_ACLK]
connect_bd_net [get_bd_ports S_AXI_p0_HBM_ACLK] [get_bd_pins refclk_bufg_div2/BUFGCE_I]

assign_bd_address >> $log_file

regenerate_bd_layout
#comment following line if you want to debug this file
validate_bd_design >> $log_file
save_bd_design >> $log_file
#return $bd

#====================
# Generate the Output products of the HBM block design.
# It is important that this are Verilog files and set the synth_checkpoint_mode to None (Global synthesis) before generating targets
puts "                        generating HBM output products"
set_property synth_checkpoint_mode None [get_files  $root_dir/ip/hbm/hbm.srcs/sources_1/bd/hbm_top/hbm_top.bd] >> $log_file
#comment following line if you want to debug this file
generate_target all                     [get_files  $root_dir/ip/hbm/hbm.srcs/sources_1/bd/hbm_top/hbm_top.bd] >> $log_file

make_wrapper -files [get_files $root_dir/ip/hbm/hbm.srcs/sources_1/bd/hbm_top/hbm_top.bd] -top

#Close the project
close_project >> $log_file