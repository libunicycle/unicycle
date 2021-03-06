// Generated by gen_regmap.rb ./drv/net/intel_e1000e.regs

#pragma once

// INTEL 82574 GbE NIC driver
// http://www.intel.com/content/dam/doc/datasheet/82574l-gbe-controller-datasheet.pdf

#define REG_CTRL 0x0                        // Device control register, section 10.2.2.1
#define CTRL_FULL_DUPLEX ((uint64_t)1 << 0) // 0 - Half duplex, 1 - Full duplex
#define CTRL_MASTER_DISABLE ((uint64_t)1 << 2)
#define CTRL_ASDE ((uint64_t)1 << 5)         // Auto-Speed detection
#define CTRL_SLU ((uint64_t)1 << 6)          // Set link up
#define CTRL_SPEED_MASK ((uint64_t)0x3 << 8) // Speed in Mb/s
#define CTRL_SPEED_10 ((uint64_t)0 << 8)
#define CTRL_SPEED_100 ((uint64_t)1 << 8)
#define CTRL_SPEED_1000 ((uint64_t)2 << 8)
#define CTRL_FRCSPD ((uint64_t)1 << 11) // Force speed
#define CTRL_RST ((uint64_t)1 << 26)    // Reset
#define CTRL_PHY_RST ((uint64_t)1 << 31)

#define REG_STATUS 0x8 // Status, R/O
#define STATUS_FULL_DUPLEX ((uint64_t)1 << 0)
#define STATUS_LINK_UP ((uint64_t)1 << 1)
#define STATUS_TXOFF ((uint64_t)1 << 2)
#define STATUS_SPEED_MASK ((uint64_t)0x3 << 6)
#define STATUS_SPEED_10 ((uint64_t)0 << 6)
#define STATUS_SPEED_100 ((uint64_t)1 << 6)
#define STATUS_SPEED_1000 ((uint64_t)2 << 6)

#define REG_MDIC 0x20 // MDI control (PHY access)
#define MDIC_OP_MASK ((uint64_t)0x3 << 26)
#define MDIC_OP_WRITE ((uint64_t)1 << 26)
#define MDIC_OP_READ ((uint64_t)2 << 26)
#define MDIC_R ((uint64_t)1 << 28) // Ready Bit
#define MDIC_I ((uint64_t)1 << 29) // Interrupt Enable
#define MDIC_E ((uint64_t)1 << 30) // Error

#define INTR_LSC ((uint64_t)1 << 2)  // Link Status Change
#define INTR_RXT0 ((uint64_t)1 << 7) // Receiver Timer

#define REG_ICR 0xc0 // Interrupt Cause Read

#define REG_ICS 0xc8 // Interrupt Cause Set

#define REG_IMS 0xd0 // Interrupt Mask Set

#define REG_IMC 0xd8 // Interrupt Mask Clear

#define REG_RXCSUM 0x5000

#define REG_MTA 0x5200 // Multicast Table Array

#define REG_RAL 0x5400

#define REG_RAH 0x5404

#define REG_RCTL 0x100              // Rx Control, section 10.2.5.1
#define RCTL_RST ((uint64_t)1 << 0) // Rx Reset
#define RCTL_EN ((uint64_t)1 << 1)  // Rx Enable
#define RCTL_SBP ((uint64_t)1 << 2) // Store Bad Packates
#define RCTL_UPE ((uint64_t)1 << 3) // Unicast Promisc Enable
#define RCTL_MPE ((uint64_t)1 << 4) // Multicast Promisc Enable
#define RCTL_LPE ((uint64_t)1 << 5) // Long Packet Rx Enable (>1522 bytes)
#define RCTL_LBM_MASK ((uint64_t)0x3 << 6)
#define RCTL_LBM_NORMAL ((uint64_t)0 << 6)
#define RCTL_LBM_MAC_LOOPBACK ((uint64_t)1 << 6) // Test mode
#define RCTL_RDMTS_MASK ((uint64_t)0x3 << 8)     // Receive Descriptor Minimum Threshold Size
#define RCTL_MO_MASK ((uint64_t)0x3 << 12)       // Multicast Offset
#define RCTL_MO_36 ((uint64_t)0 << 12)           // Multicast Filter Offset 36..47
#define RCTL_MO_35 ((uint64_t)1 << 12)           // Multicast Filter Offset 35..46
#define RCTL_MO_34 ((uint64_t)2 << 12)           // Multicast Filter Offset 34..45
#define RCTL_MO_32 ((uint64_t)3 << 12)           // Multicast Filter Offset 32..43
#define RCTL_BAM ((uint64_t)1 << 15)             // Rx Broadcast Packets Enable
#define RCTL_BSIZE_MASK ((uint64_t)0x3 << 16)    // Receive Buffer Size
#define RCTL_BSIZE_2048 ((uint64_t)0 << 16)      // Rx Buffer 2048 * (BSEX * 16)
#define RCTL_BSIZE_1024 ((uint64_t)1 << 16)      // Rx Buffer 1024 * (BSEX * 16)
#define RCTL_BSIZE_512 ((uint64_t)2 << 16)       // Rx Buffer 512 * (BSEX * 16)
#define RCTL_BSIZE_256 ((uint64_t)3 << 16)       // Rx Buffer 256 * (BSEX * 16)
#define RCTL_DPF ((uint64_t)1 << 22)             // Discard Pause Frames
#define RCTL_PMCF ((uint64_t)1 << 23)            // Pass MAC Control Frames
#define RCTL_BSEX ((uint64_t)1 << 25)            // Buffer Size Extension (x16)
#define RCTL_SECRC ((uint64_t)1 << 26)           // Strip CRC Field

#define REG_RDBAL 0x2800 // Rx Descriptor Base Low

#define REG_RDBAH 0x2804 // Rx Descriptor Base High

#define REG_RDLEN 0x2808 // Rx Descriptor Length

#define REG_RDH 0x2810 // Rx Descriptor Head

#define REG_RDT 0x2818 // Rx Descriptor Tail

#define REG_RXDCTL 0x2828               // Rx Descriptor Control
#define RXDCTL_GRAN ((uint64_t)1 << 24) // Writeback granularity. 0 - Cache lines, 1 - Descriptors

#define REG_TCTL 0x0400                 // Tx Control
#define TCTL_RST ((uint64_t)1 << 0)     // Tx Reset
#define TCTL_EN ((uint64_t)1 << 1)      // Tx Enable
#define TCTL_PSP ((uint64_t)1 << 3)     // Pad Short Packets (to 64b)
#define TCTL_SWXOFF ((uint64_t)1 << 22) // XOFF Tx (self-clearing)

#define REG_TDBAL 0x3800 // Tx Descriptor Base Low

#define REG_TDBAH 0x3804 // Tx Descriptor Base High

#define REG_TDLEN 0x3808 // Tx Descriptor Length

#define REG_TDH 0x3810 // Tx Descriptor Head

#define REG_TDT 0x3818 // Tx Descriptor Tail

#define REG_TXDCTL 0x3828               // Tx Descriptor Control
#define TXDCTL_GRAN ((uint64_t)1 << 24) // Writeback granularity. 0 - Cache lines, 1 - Descriptors
