// SPDX-License-Identifier: MIT

#include "ahci.h"

#include "blk.h"
#include "compiler.h"
#include "kalloc.h"
#include "lock.h"
#include "mem.h"
#include "mmu.h"
#include "pci.h"
#include "timer.h"
#include <stdint.h>

#define MAX_CMD_SLOT_CNT 32
#define MAX_PORT_CNT 32
#define MAX_PRDT_CNT 65535 // Max number of PRDT entries in one command table

// Max length of data in one PRDT entry
#define MAX_PRDT_DATA_LENGTH 0x400000

#define SECTOR_SIZE 512

// Bits for HBA Capabilities
#define CAP_NCQ BIT(30) // HBA supports NCQ

// Bits for Global HBA Control register
#define GHC_HBA_RESET BIT(0)
#define GHC_INTERRUPT_ENABLE BIT(1)
#define GHC_AHCI_ENABLE BIT(31)

#define SATA_SIG_ATAPI 0xEB140101
#define SATA_SIG_SEMB 0xC33C0101
#define SATA_SIG_PM 0x96690101

#define PORT_CMD_ST BIT(0)  // Start
#define PORT_CMD_SUB BIT(1) // Spin-Up Device
#define PORT_CMD_POD BIT(2) // Power On Device
#define PORT_CMD_CLO BIT(3) // Command list override
#define PORT_CMD_FRE BIT(4) // Enable FIS receive DMA engine
#define PORT_CMD_FR BIT(14) // FIS DMA engine running
#define PORT_CMD_CR BIT(15)

#define PORT_IRQ_COLD_PRES BIT(31)     // cold presence detect
#define PORT_IRQ_TF_ERR BIT(30)        // task file error
#define PORT_IRQ_HBUS_ERR BIT(29)      // host bus fatal error
#define PORT_IRQ_HBUS_DATA_ERR BIT(28) // host bus data error
#define PORT_IRQ_IF_ERR BIT(27)        // interface fatal error
#define PORT_IRQ_IF_NONFATAL BIT(26)   // interface non-fatal error
#define PORT_IRQ_OVERFLOW BIT(24)      // xfer exhausted available S/G
#define PORT_IRQ_BAD_PMP BIT(23)       // incorrect port multiplier
#define PORT_IRQ_PHYRDY BIT(22)        // PhyRdy changed
#define PORT_IRQ_DEV_ILCK BIT(7)       // device interlock
#define PORT_IRQ_CONNECT BIT(6)        // port connect change status
#define PORT_IRQ_SG_DONE BIT(5)        // descriptor processed
#define PORT_IRQ_UNK_FIS BIT(4)        // unknown FIS rx'd
#define PORT_IRQ_SDB_FIS BIT(3)        // Set Device Bits FIS rx'd
#define PORT_IRQ_DMAS_FIS BIT(2)       // DMA Setup FIS rx'd
#define PORT_IRQ_PIOS_FIS BIT(1)       // PIO Setup FIS rx'd
#define PORT_IRQ_D2H_REG_FIS BIT(0)    // D2H Register FIS rx'd

#define PORT_IRQ_ERROR                                                                                                           \
    (PORT_IRQ_TF_ERR | PORT_IRQ_HBUS_ERR | PORT_IRQ_HBUS_DATA_ERR | PORT_IRQ_IF_ERR | PORT_IRQ_IF_NONFATAL | PORT_IRQ_OVERFLOW | \
     PORT_IRQ_BAD_PMP | PORT_IRQ_PHYRDY | PORT_IRQ_CONNECT | PORT_IRQ_UNK_FIS)

#define PORT_INT_CPD BIT(31)
#define PORT_INT_TFE BIT(30)
#define PORT_INT_HBF BIT(29)
#define PORT_INT_HBD BIT(28)
#define PORT_INT_IF BIT(27)
#define PORT_INT_INF BIT(26)
#define PORT_INT_OF BIT(24)
#define PORT_INT_IPM BIT(23)
#define PORT_INT_PRC BIT(22)
#define PORT_INT_DI BIT(7)
#define PORT_INT_PC BIT(6)
#define PORT_INT_DP BIT(5)
#define PORT_INT_UF BIT(4)
#define PORT_INT_SDB BIT(3)
#define PORT_INT_DS BIT(2)
#define PORT_INT_PS BIT(1)
#define PORT_INT_DHR BIT(0)

#define PORT_CMD_ST BIT(0)
#define PORT_CMD_SUD BIT(1)
#define PORT_CMD_POD BIT(2)
#define PORT_CMD_FRE BIT(4)
#define PORT_CMD_FR BIT(14)
#define PORT_CMD_CR BIT(15)
#define PORT_CMD_ATAPI BIT(24)
#define PORT_CMD_ICC_ACTIVE (1 << 28)
#define PORT_CMD_ICC_MASK (0xf << 28)

#define PORT_TFD_DATA_REQUEST BIT(3)
#define PORT_TFD_BUSY BIT(7)

#define PORT_SCTL_IPM_ACTIVE (1 << 8)
#define PORT_SCTL_IPM_PARTIAL (2 << 8)
#define PORT_SCTL_DET_MASK 0xf
#define PORT_SCTL_DET_INIT 1

#define PORT_SSTS_DET_PRESENT 3

#define PORT_INT_ERROR                                                                                                                   \
    (PORT_INT_TFE | PORT_INT_HBF | PORT_INT_HBD | PORT_INT_IF | PORT_INT_INF | PORT_INT_OF | PORT_INT_IPM | PORT_INT_PRC | PORT_INT_PC | \
     PORT_INT_UF)
#define PORT_INT_MASK (PORT_INT_ERROR | PORT_INT_DP | PORT_INT_SDB | PORT_INT_DS | PORT_INT_PS) // | PORT_INT_DHR

// FIS Types
#define FIS_TYPE_REG_H2D 0x27 // Register FIS - host to device

// SATA Commands
#define SATA_CMD_IDENTIFY_DEVICE 0xec
#define SATA_CMD_READ_DMA 0xc8
#define SATA_CMD_READ_DMA_EXT 0x25
#define SATA_CMD_READ_FPDMA_QUEUED 0x60
#define SATA_CMD_WRITE_DMA 0xca
#define SATA_CMD_WRITE_DMA_EXT 0x35
#define SATA_CMD_WRITE_FPDMA_QUEUED 0x61

struct PACKED __le hba_port {
    uint64_t command_list_addr; // Points to hba_cmd_header[MAX_CMD_SLOT_CNT]
    uint64_t fis_base_addr;
    uint32_t intr_status;
    uint32_t intr_enable;
    uint32_t cmd_status;
    uint32_t _unused0;
    uint32_t task_file_data;
    uint32_t signature;
    uint32_t sata_status;
    uint32_t sata_ctrl;
    uint32_t sata_error;
    uint32_t sata_active;
    uint32_t command_issue;
    uint32_t sata_notify;
    uint32_t fis_switch_ctrl;
    uint32_t device_sleep;
    uint8_t _unused1[0x70 - 0x48];
    uint8_t vendor_specific[0x80 - 0x70];
};
BUILD_PANIC_IF(sizeof(struct hba_port) != 0x80);

struct PACKED __le hba_mem {
    uint32_t host_cap;          // Host Capabilities
    uint32_t host_ctrl;         // Global Host Control
    uint32_t intr_status;       // Interrupt Status
    uint32_t ports_impl;        // Ports Implemented
    uint32_t version;           // Version
    uint32_t ccc_ctrl;          // Command Completion Coalescing Control
    uint32_t ccc_ports;         // Command Completion Coalescing Ports
    uint32_t em_loc;            // Enclosure Management Location
    uint32_t em_ctrl;           // Enclosure Management Control
    uint32_t host_cap_ext;      // Host Capabilities Extended
    uint32_t bios_handoff_ctrl; // BIOS/OS Handoff Control and Status

    uint8_t _unused0[0x60 - 0x2c];  // Reserved
    uint8_t _unused1[0xa0 - 0x60];  // Reserved for NVMHCI
    uint8_t _unused2[0x100 - 0xa0]; // Vendor Specific registers

    struct hba_port ports[MAX_PORT_CNT];
};
BUILD_PANIC_IF(offsetof(struct hba_mem, _unused0) != 0x2c);
BUILD_PANIC_IF(offsetof(struct hba_mem, ports) != 0x100, "Incorrect port address space location");
BUILD_PANIC_IF(sizeof(struct hba_mem) != 0x1100);

struct PACKED __le hba_cmd_header {
    uint8_t cfl : 5;      // Command FIS length in DWORDS, 2 ~ 16
    uint8_t a : 1;        // ATAPI
    uint8_t w : 1;        // Write, 1: H2D, 0: D2H
    uint8_t p : 1;        // Prefetchable
    uint8_t r : 1;        // Reset
    uint8_t b : 1;        // BIST
    uint8_t c : 1;        // Clear busy upon R_OK
    uint8_t _unused0 : 1; // Reserved
    uint8_t pmp : 4;      // Port multiplier port

    uint16_t descr_table_length;         // number of entries in hba_cmd_table pointed by command_table_addr
    volatile uint32_t bytes_transferred; // modified by HW
    uint64_t command_table_addr;         // Points to hba_cmd_table
    uint32_t _unused1[4];
};
BUILD_PANIC_IF(sizeof(struct hba_cmd_header) != 32);

struct PACKED __le hba_prdt_entry {
    uint64_t address;         // Data base address
    uint32_t _unused0;        // Reserved
    uint32_t byte_count : 22; // Byte count, 4M max
    uint32_t _unused1 : 9;    // Reserved
    uint32_t intr : 1;        // Interrupt on completion
};

struct PACKED __le hba_cmd_table {
    uint8_t cfis[64];                   // Command FIS
    uint8_t acmd[16];                   // ATAPI command, 12 or 16 bytes
    uint8_t _unused0[48];               // Reserved
    struct hba_prdt_entry prdt_entry[]; // Physical region descriptor table entries, 0 ~ 65535
};

// Register Host to Device FIS
struct PACKED __le fis_reg_h2d {
    // DWORD 0
    uint8_t fis_type; // FIS_TYPE_REG_H2D

    uint8_t pmport : 4; // Port multiplier
    uint8_t rsv0 : 3;   // Reserved
    uint8_t c : 1;      // 1: Command, 0: Control

    uint8_t command;  // Command register
    uint8_t featurel; // Feature register, 7:0

    // DWORD 1
    uint8_t lba0;   // LBA low register, 7:0
    uint8_t lba1;   // LBA mid register, 15:8
    uint8_t lba2;   // LBA high register, 23:16
    uint8_t device; // Device register

    // DWORD 2
    uint8_t lba3;     // LBA register, 31:24
    uint8_t lba4;     // LBA register, 39:32
    uint8_t lba5;     // LBA register, 47:40
    uint8_t featureh; // Feature register, 15:8

    // DWORD 3
    uint8_t countl;  // Count register, number of sectors
    uint8_t counth;  // Count register, number of sectors
    uint8_t icc;     // Isochronous command completion
    uint8_t control; // Control register

    uint16_t aux;
    uint8_t _unused0[2]; // Reserved
};
BUILD_PANIC_IF(sizeof(struct fis_reg_h2d) != 20, "Incorrect fis_reg_h2d size");

// Frame structure used to send NCQ commands to the device.
// It is similar to fis_reg_h2d with a few changes (see SATA spec 13.6.3.1):
// fis[3]: was feature(7:0) became count(7:0)
// fis[7]: was became FUA bit (7)
// fis[11]: was feature(15:8) became count(15:8)
// fis[12]: was count(7:0) became NCQ TAG at (7:3)
// fis[13]: was count(15:8) became priority at (7:6)
struct PACKED __le fis_reg_h2d_ncq {
    // DWORD 0
    uint8_t fis_type; // FIS_TYPE_REG_H2D

    uint8_t pmport : 4;   // Port multiplier
    uint8_t _unused0 : 3; // Reserved
    uint8_t c : 1;        // 1: Command, 0: Control

    uint8_t command; // Command register
    uint8_t countl;  // Count register, 7:0

    // DWORD 1
    uint8_t lba0; // LBA low register, 7:0
    uint8_t lba1; // LBA mid register, 15:8
    uint8_t lba2; // LBA high register, 23:16
    uint8_t _unused1 : 7;
    uint8_t fua : 1; // Force Unit Access

    // DWORD 2
    uint8_t lba3;   // LBA register, 31:24
    uint8_t lba4;   // LBA register, 39:32
    uint8_t lba5;   // LBA register, 47:40
    uint8_t counth; // Count register, 15:8

    // DWORD 3
    uint8_t ncq_tag : 5; // NCQ tag
    uint8_t _unused2 : 3;
    uint8_t ncq_prio : 2;
    uint8_t _unused3 : 6;
    uint8_t icc;     // Isochronous command completion
    uint8_t control; // Control register

    uint16_t aux;
    uint8_t _unused4[2]; // Reserved
};
BUILD_PANIC_IF(sizeof(struct fis_reg_h2d_ncq) != 20);

// Register Device to Host FIS
struct PACKED __le fis_reg_d2h {
    // DWORD 0
    uint8_t fis_type; // FIS_TYPE_REG_D2H

    uint8_t pmport : 4; // Port multiplier
    uint8_t rsv0 : 2;   // Reserved
    uint8_t i : 1;      // Interrupt bit
    uint8_t rsv1 : 1;   // Reserved

    uint8_t status; // Status register
    uint8_t error;  // Error register

    // DWORD 1
    uint8_t lba0;   // LBA low register, 7:0
    uint8_t lba1;   // LBA mid register, 15:8
    uint8_t lba2;   // LBA high register, 23:16
    uint8_t device; // Device register

    // DWORD 2
    uint8_t lba3; // LBA register, 31:24
    uint8_t lba4; // LBA register, 39:32
    uint8_t lba5; // LBA register, 47:40
    uint8_t rsv2; // Reserved

    // DWORD 3
    uint16_t count;  // Count register
    uint8_t rsv3[2]; // Reserved

    // DWORD 4
    uint8_t rsv4[4]; // Reserved
};

struct PACKED __le fis {
    uint8_t dsfis[0x1c]; // DMA setup FIS
    uint8_t reserved1[0x4];
    uint8_t psfis[0x14]; // PIO setup FIS
    uint8_t reserved2[0x0c];
    uint8_t rfis[0x14]; // D2H register FIS
    uint8_t reserved3[0x4];
    uint8_t sdbfis[0x8]; // set device bits FIS
    uint8_t ufis[0x40];  // unknown FIS
    uint8_t reserved4[0x60];
};
BUILD_PANIC_IF(sizeof(struct fis) != 0x100);

struct ahci_controller_device;

struct ahci_command_context {
    blk_op_callback callback; // User completion callback
    void *context;            // User context of the command in-flight
};

struct ahci_port_device {
    __mmio struct hba_port *port;
    struct ahci_controller_device *controller;
    uint32_t nr;

    struct blk_device blk_dev;
    lock_t lock;

    uint32_t running;    // commands that still handled by the port
    uint32_t processing; // commands that been reported by the device and currently handled by user-space callback
    struct fis fis ALIGNED(256);
    struct hba_cmd_header cmd[MAX_CMD_SLOT_CNT] ALIGNED(1024);
    struct ahci_command_context cmd_ctx[MAX_CMD_SLOT_CNT];
};

struct ahci_controller_device {
    __mmio struct hba_mem *hba;
    struct ahci_port_device *ports[MAX_PORT_CNT];
    __mmio struct hba_port *port_mmio[MAX_PORT_CNT];
    bool ncq_supported;
    lock_t lock;
};

static void ahci_port_irq_handler(struct ahci_controller_device *controller, uint8_t port_no) {
    struct ahci_port_device *port_dev = controller->ports[port_no];
    __mmio struct hba_port *port = controller->port_mmio[port_no];

    printf("ahci.%d IRQ status 0x%x\n", port_no, port->intr_status);

    lock(&port_dev->lock);
    uint32_t intr_status = port->intr_status;
    port->intr_status = intr_status; // clear intr bits

    uint32_t processing;
    if (controller->ncq_supported) {
        processing = port_dev->running & ~port->sata_active;
    } else {
        processing = port_dev->running & ~port->command_issue;
    }
    port_dev->processing |= processing;
    port_dev->running &= ~processing;
    unlock(&port_dev->lock);

    if (intr_status & PORT_IRQ_PHYRDY) {
        port->sata_error = port->sata_error;
    }

    enum blk_op_status status;
    if (intr_status & PORT_IRQ_ERROR) {
        printf("ahci error: 0x%x\n", intr_status);
        status = BLK_OP_ERROR;
    } else {
        status = BLK_OP_SUCCESS;
    }

    while (processing) {
        uint8_t current_cmd = FFS(processing) - 1;
        processing &= ~BIT(current_cmd);

        struct hba_cmd_header *cmd = &port_dev->cmd[current_cmd];
        struct ahci_command_context *ctx = &port_dev->cmd_ctx[current_cmd];
        struct hba_cmd_table *cmd_table = (void *)cmd->command_table_addr;
        ctx->callback(&port_dev->blk_dev, (void *)cmd_table->prdt_entry[0].address, status, ctx->context);

        size_t struct_size = sizeof(struct hba_cmd_table) + cmd->descr_table_length * sizeof(struct hba_prdt_entry);
        struct_size = ROUND_UP(struct_size, 128);
        kfree_size(cmd_table, struct_size);

        lock(&port_dev->lock);
        port_dev->processing &= ~BIT(current_cmd);
        unlock(&port_dev->lock);
    }
}

static void ahci_irq_handler(void *data) {
    struct ahci_controller_device *dev = data;

    // disable interrupts while handling current one
    dev->hba->host_ctrl &= ~GHC_INTERRUPT_ENABLE;

    lock(&dev->lock);
    uint32_t ports = dev->hba->intr_status; // ports required attention
    dev->hba->intr_status = ports;          // clear current interrupts
    unlock(&dev->lock);

    while (ports) {
        uint8_t current_port = FFS(ports) - 1;
        ports &= ~BIT(current_port);
        ahci_port_irq_handler(dev, current_port);
    }

    dev->hba->host_ctrl |= GHC_INTERRUPT_ENABLE;
}

static void ahci_send(struct blk_device *blk, void *data, size_t data_size, size_t start_sector, bool write, blk_op_callback on_complete,
                      void *context) {
    struct ahci_port_device *dev = container_of(blk, struct ahci_port_device, blk_dev);
    __mmio struct hba_port *port = dev->port;
    SHOUT_IF(!port, "AHCI port is incorrectly recognized");

    SHOUT_IF(data_size % SECTOR_SIZE != 0, "Data size must be multiple of sector size");

    // Find a free slot
    lock(&dev->lock);
    uint32_t slots = ~(port->sata_active | port->command_issue | dev->running | dev->processing);
    if (!slots) {
        PANIC("Cannot find a free slots");
    }
    uint8_t current_slot = FFS(slots) - 1;
    dev->running |= BIT(current_slot);
    unlock(&dev->lock);

    // See fis_reg_h2d description in SATA spec section 10.3.4
    struct hba_cmd_header *cmd = &dev->cmd[current_slot];
    memzero(cmd);
    cmd->cfl = sizeof(struct fis_reg_h2d) / sizeof(uint32_t);
    cmd->w = write ? 1 : 0;
    cmd->c = 1;
    size_t prdt_num = DIV_ROUND_UP(data_size, MAX_PRDT_DATA_LENGTH);
    PANIC_IF(prdt_num > MAX_PRDT_CNT, "Number of PRDT entries is over the limit for data of size %ld", data_size);
    cmd->descr_table_length = prdt_num;
    cmd->bytes_transferred = 0;

    size_t struct_size = sizeof(struct hba_cmd_table) + prdt_num * sizeof(struct hba_prdt_entry);
    struct_size = ROUND_UP(struct_size, 128);
    struct hba_cmd_table *cmd_table = kalloc_size(struct_size);
    memset(cmd_table, 0, struct_size);
    cmd->command_table_addr = (uintptr_t)cmd_table;
    PANIC_IF(!IS_ROUNDED(cmd->command_table_addr, 128), "Command table address must be 128 aligned");

    PANIC_IF(!on_complete, "AHCI block driver requires callback function");
    dev->cmd_ctx[current_slot].callback = on_complete;
    dev->cmd_ctx[current_slot].context = context;

    uint64_t addr = (uintptr_t)data;
    size_t bytes_left = data_size;
    for (size_t i = 0; i < prdt_num; i++) {
        size_t byte_count = MIN(bytes_left, MAX_PRDT_DATA_LENGTH);

        struct hba_prdt_entry *ent = &cmd_table->prdt_entry[i];
        ent->address = addr;
        ent->byte_count = byte_count - 1;
        ent->intr = 1;

        addr += byte_count;
        bytes_left -= byte_count;
    }

    bool ncq_supported = dev->controller->ncq_supported;
    // setup command
    if (ncq_supported) {
        struct fis_reg_h2d_ncq *cmdfis = (struct fis_reg_h2d_ncq *)(&cmd_table->cfis);

        cmdfis->fis_type = FIS_TYPE_REG_H2D;
        cmdfis->c = 1;
        cmdfis->command = write ? SATA_CMD_WRITE_FPDMA_QUEUED : SATA_CMD_READ_FPDMA_QUEUED;

        cmdfis->lba0 = (uint8_t)start_sector;
        cmdfis->lba1 = (uint8_t)(start_sector >> 8);
        cmdfis->lba2 = (uint8_t)(start_sector >> 16);
        cmdfis->lba3 = (uint8_t)(start_sector >> 24);
        cmdfis->lba4 = (uint8_t)(start_sector >> 32);
        cmdfis->lba5 = (uint8_t)(start_sector >> 40);

        uint16_t count = data_size / SECTOR_SIZE;
        cmdfis->countl = (uint8_t)count;
        cmdfis->counth = (uint8_t)(count >> 8);

        cmdfis->ncq_tag = current_slot;
        cmdfis->ncq_prio = 0;
    } else {
        struct fis_reg_h2d *cmdfis = (struct fis_reg_h2d *)(&cmd_table->cfis);

        cmdfis->fis_type = FIS_TYPE_REG_H2D;
        cmdfis->c = 1;
        cmdfis->command = write ? SATA_CMD_WRITE_DMA_EXT : SATA_CMD_READ_DMA_EXT;

        cmdfis->lba0 = (uint8_t)start_sector;
        cmdfis->lba1 = (uint8_t)(start_sector >> 8);
        cmdfis->lba2 = (uint8_t)(start_sector >> 16);
        cmdfis->lba3 = (uint8_t)(start_sector >> 24);
        cmdfis->lba4 = (uint8_t)(start_sector >> 32);
        cmdfis->lba5 = (uint8_t)(start_sector >> 40);
        cmdfis->device = BIT(6); // Set LBA mode

        uint16_t count = data_size / SECTOR_SIZE;
        cmdfis->countl = (uint8_t)count;
        cmdfis->counth = (uint8_t)(count >> 8);
    }

    if (ncq_supported) {
        port->sata_active = BIT(current_slot);
    }

    port->command_issue = BIT(current_slot);
    // TODO: add a completion timer
}

static void ahci_reset(__mmio struct hba_mem *hba) {
    hba->host_ctrl |= GHC_AHCI_ENABLE;
    hba->host_ctrl |= GHC_HBA_RESET;

    // wait till the device reset, it should take less than a second
    wait_for_clear(&hba->host_ctrl, GHC_HBA_RESET, time_sec_from_now(1));
}

static void ahci_enable(__mmio struct hba_mem *hba) {
    if (hba->host_ctrl & GHC_AHCI_ENABLE)
        return;

    for (int i = 0; i < 5; i++) {
        hba->host_ctrl |= GHC_AHCI_ENABLE;
        if (hba->host_ctrl & GHC_AHCI_ENABLE)
            return;
        sleep_us(10000);
    }

    printf("Cannot enable AHCI HBA\n");
}

static bool ahci_port_enable(struct ahci_port_device *dev) {
    __mmio struct hba_port *port = dev->port;

    uint32_t cmd = port->cmd_status;
    if (cmd & PORT_CMD_ST)
        return true;
    if (!(cmd & PORT_CMD_FRE)) {
        printf("ahci.%d: cannot enable port without FRE enabled\n", dev->nr);
        return false;
    }
    bool timeout = wait_for_clear(&port->cmd_status, PORT_CMD_CR, time_ms_from_now(500));
    if (timeout) {
        printf("ahci.%d: dma engine still running when enabling port\n", dev->nr);
        return false;
    }
    cmd |= PORT_CMD_ST;
    port->cmd_status = cmd;
    return true;
}

static void ahci_port_disable(struct ahci_port_device *dev) {
    __mmio struct hba_port *port = dev->port;

    uint32_t cmd = port->cmd_status;
    if (!(cmd & PORT_CMD_ST))
        return;

    cmd &= ~PORT_CMD_ST;
    port->cmd_status = cmd;

    bool timeout = wait_for_clear(&port->cmd_status, PORT_CMD_CR, time_ms_from_now(500));
    if (timeout) {
        printf("ahci.%d: port disable timed out\n", dev->nr);
    }
}

// returns true is the port was reset, false otherwise
static bool ahci_port_reset(struct ahci_port_device *dev) {
    __mmio struct hba_port *port = dev->port;

    // disable port
    ahci_port_disable(dev);

    // clear error
    port->sata_error = port->sata_error;

    // wait for device idle
    bool timeout = wait_for_clear(&port->task_file_data, PORT_TFD_BUSY | PORT_TFD_DATA_REQUEST, time_sec_from_now(1));
    if (timeout) {
        // if busy is not cleared, do a full comreset
        printf("ahci.%d: timed out waiting for port idle, resetting\n", dev->nr);
        // v1.3.1, 10.4.2 port reset
        port->sata_ctrl = PORT_SCTL_IPM_ACTIVE | PORT_SCTL_IPM_PARTIAL | PORT_SCTL_DET_INIT;
        sleep_us(1000);
        port->sata_ctrl &= ~PORT_SCTL_DET_MASK;
    }

    // enable port
    bool ok = ahci_port_enable(dev);
    if (!ok)
        return false;

    // wait for device detect
    timeout = wait_for_set(&port->sata_status, PORT_SSTS_DET_PRESENT, time_sec_from_now(1));
    if (timeout) {
        printf("ahci.%d: no device detected\n", dev->nr);
        return false;
    }

    // clear error
    port->sata_error = port->sata_error;
    return true;
}

static struct ahci_port_device *ahci_port_initialize(struct ahci_controller_device *controller, __mmio struct hba_port *port,
                                                     uint32_t portno) {
    uint32_t cmd = port->cmd_status;
    if (cmd & (PORT_CMD_ST | PORT_CMD_FRE | PORT_CMD_CR | PORT_CMD_FR)) {
        printf("ahci.%d: port busy\n", portno);
        return NULL;
    }

    struct ahci_port_device *dev = kalloc(struct ahci_port_device);
    memzero(dev);
    dev->nr = portno;
    dev->controller = controller;
    dev->port = port;

    port->command_list_addr = (uintptr_t)dev->cmd;
    PANIC_IF(!IS_ROUNDED(port->command_list_addr, 1024), "Command list must be 1K aligned");
    port->fis_base_addr = (uintptr_t)&dev->fis;
    PANIC_IF(!IS_ROUNDED(port->fis_base_addr, 256), "FIS must be 256 bytes aligned");

    // clear port interrupts
    port->intr_status = port->intr_status;

    // clear error
    port->sata_error = port->sata_error;

    // spin up
    cmd |= PORT_CMD_SUD;
    port->cmd_status = cmd;

    // activate link
    cmd &= ~PORT_CMD_ICC_MASK;
    cmd |= PORT_CMD_ICC_ACTIVE;
    port->cmd_status = cmd;

    // enable FIS receive
    cmd |= PORT_CMD_FRE;
    port->cmd_status = cmd;

    return dev;
}

static void ahci_port_free(struct ahci_port_device *dev) { kfree(dev); }

static const char *ahci_port_signature_name(uint32_t signature) {
    if (signature == SATA_SIG_ATAPI) {
        return "SATAPI";
    } else if (signature == SATA_SIG_SEMB) {
        return "SEMB";
    } else if (signature == SATA_SIG_PM) {
        return "PM";
    } else {
        return "SATA";
    }
}

INIT_CODE static void ahci_probe(struct pci_device_info *info) {
    struct pci_bar bar;
    pci_bar_get(&bar, info->id, 5);
    size_t size = ROUND_UP(bar.size, PAGE_SIZE); // Some motherboards have size less than a page
    page_table_set_bit((uintptr_t)bar.address, size, PAGE_PRESENT | PAGE_WRITABLE | PAGE_CACHE_DISABLE,
                       PAGE_PRESENT | PAGE_WRITABLE | PAGE_CACHE_DISABLE);

    __mmio struct hba_mem *hba = bar.address;

    printf("HBA version %d.%d\n", (hba->version >> 16), hba->version & 0xffff);

    /*    hba->host_cap &= ~BIT(26);
        hba->host_cap &= ~BIT(14);
    */
    ahci_reset(hba);
    ahci_enable(hba);

    struct ahci_controller_device *controller = kalloc(struct ahci_controller_device);
    memzero(controller);
    controller->hba = hba;
    controller->ncq_supported = hba->host_cap & CAP_NCQ;

    // detect ports
    uint32_t ports = hba->ports_impl;
    while (ports) {
        uint32_t active = FFS(ports) - 1;
        ports &= ~BIT(active);

        // !!!!XXXX we need to wait a bit until the port becomes active
        __mmio struct hba_port *port = &hba->ports[active];
        controller->port_mmio[active] = port;

        struct ahci_port_device *dev = ahci_port_initialize(controller, port, active);
        dev->blk_dev.send = ahci_send;
        dev->port = port;

        // port enable
        bool ok = ahci_port_enable(dev);
        if (!ok) {
            ahci_port_free(dev);
            continue;
        }

        // enable interrupts
        port->intr_enable = PORT_INT_MASK;
        ok = ahci_port_reset(dev);
        if (!ok) {
            ahci_port_free(dev);
            continue;
        }
        controller->ports[active] = dev;

        printf("AHCI port %d has a drive of type %s\n", active, ahci_port_signature_name(port->signature));

        blk_dev_register(&dev->blk_dev);
    }

    hba->intr_status = hba->intr_status; // clear interrupts
    hba->host_ctrl |= GHC_INTERRUPT_ENABLE;

    pci_enable_bus_master(info, true);
    PANIC_IF(info->intr_type != PCI_INTR_MSI, "AHCI supports MSI only");
    pci_register_msi_irq(info, 0, ahci_irq_handler, controller);
}

PCI_DEVICE(0x8086, 0xa102, ahci_probe);
PCI_DEVICE(0x8086, 0x2922, ahci_probe);
