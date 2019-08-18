// SPDX-License-Identifier: MIT

#include "compiler.h"
#include "intel_e1000e.regs.h"
#include "interrupt.h"
#include "kalloc.h"
#include "mem.h"
#include "mmio.h"
#include "mmu.h"
#include "net/eth.h"
#include "pci.h"
#include "shout.h"
#include "stdio.h"
#include "timer.h"
#include "x86.h"
#include <stdint.h>

#define TCTL_CT(n) ((n) << 4)      // Collision Threshold (rec 15)
#define TCTL_COLD_HD (0x200 << 12) // Collision Distance Half Duplex
#define TCTL_COLD_FD (0x40 << 12)  // Collision Distance Full Duplex
#define TCTL_RESERVED (BIT(2) | BIT(23) | (0xfu << 25) | BIT(31))

#define MDIC_GET_DATA(val) ((val)&0xffff)
#define MDIC_PUT_DATA(val) ((val)&0xffff)
#define MDIC_GET_REGADD(val) (((val) >> 16) & 0x1f)
#define MDIC_PUT_REGADD(val) (((val)&0x1f) << 16)
#define MDIC_GET_PHYADD(val) (((val) >> 21) & 0x1f)
#define MDIC_PUT_PHYADD(val) (((val)&0x1f) << 21)

#define MAX_PHY_ADDR 0x1f

// PHY registers

// PHY Control Register
#define PHY_PCTRL 0x00
#define PHY_PCTRL_EN_COLL_TEST BIT(7)
#define PHY_PCTRL_FULL_DUPLEX BIT(8)
#define PHY_PCTRL_RESTART_AUTONEG BIT(9)
#define PHY_PCTRL_ISOLATE BIT(10)
#define PHY_PCTRL_POWER_DOWN BIT(11)
#define PHY_PCTRL_EN_AUTONEG BIT(12)
#define PHY_PCTRL_EN_LOOPBACK BIT(14)
#define PHY_PCTRL_RESET BIT(15)

// PHY Identifier Register (LSB)
#define PHY_PID 0x02

// TODO: does this HW support more than 32 buffers?
#define NUM_RX_DESC 128
#define RX_BUFFER_SIZE 2048
#define NUM_TX_DESC 128

#define REG(name) MMIO32(dev->addr + REG_##name)

// Legacy rx descriptor, Section 7.1.4.1
struct PACKED __le e1000e_rx_desc {
    uint64_t addr;
    uint16_t length;
    uint16_t checksum;
    uint8_t status;
    uint8_t errors;
    uint16_t vlan_tag;
};
BUILD_PANIC_IF(sizeof(struct e1000e_rx_desc) != 16);

// e1000e_rx_desc status field bits
#define RXD_STATUS_DONE BIT(0)
#define RXD_STATUS_EOP BIT(1)   // End-Of-Packet
#define RXD_STATUS_UDPCS BIT(4) // UDP checksum calculated on the packet
#define RXD_STATUS_TCPCS BIT(5) // TCP checksum calculated on the packet
#define RXD_STATUS_IPCS BIT(5)  // IP checksum calculated on the packet

#define RXD_ERROR_CE BIT(0)   // CRC or Alignment error
#define RXD_ERROR_SE BIT(1)   // Symbol error
#define RXD_ERROR_SEQ BIT(2)  // Sequence error
#define RXD_ERROR_CXE BIT(4)  // Carrier extension error
#define RXD_ERROR_TCPE BIT(5) // TCP/UDP Checksum error
#define RXD_ERROR_IPE BIT(6)  // IPv4 Checksum error
#define RXD_ERROR_RXE BIT(7)  // Rx Data error

// Legacy fetch mode tx descriptor, Section 7.2.2.1
struct PACKED __le e1000e_tx_desc {
    uint64_t addr;
    uint16_t length;
    uint8_t cso; // checksum offset
    uint8_t cmd;
    uint8_t status;
    uint16_t __reserved0;
    uint8_t vlan_tag;
};
BUILD_PANIC_IF(sizeof(struct e1000e_tx_desc) != 16, "incorrect size of e1000e descriptor");

// e1000e_tx_desc status field bits
#define TXD_STATUS_DONE BIT(0)

// e1000e_tx_desc cmd field bits (Spec 7.2.10.1.4)
#define TXD_COMMAND_EOP BIT(0)  // end of packet
#define TXD_COMMAND_IFCS BIT(1) // insert FCS (CRC)
#define TXD_COMMAND_IC BIT(2)   // insert checksum
#define TXD_COMMAND_RS BIT(3)   // report status
#define TXD_COMMAND_DEXT BIT(5) // descriptor extension
#define TXD_COMMAND_VLE BIT(6)  // VLAN Packet enable
#define TXD_COMMAND_IDE BIT(7)  // interrupt delay enable

struct e1000e_dev {
    struct eth_device eth_dev;

    __mmio void *addr;
    size_t rx_rd;
    size_t tx_rd;
    size_t tx_wr;
    struct e1000e_rx_desc rx_desc[NUM_RX_DESC] ALIGNED(16);
    struct e1000e_tx_desc tx_desc[NUM_TX_DESC] ALIGNED(16);
};

static void e1000e_hw_reset(struct e1000e_dev *dev) {
    REG(IMC) = 0xffffffff; // Clear the interrupt mask first
    REG(IMS) = 0;
    REG(RCTL) = 0;
    REG(TCTL) = TCTL_PSP;

    REG(CTRL) |= CTRL_RST;
    sleep_us(5);
    SHOUT_IF(REG(CTRL) & CTRL_RST, "Reset failed");
}

static void e1000e_linkup(struct e1000e_dev *dev) {
    REG(CTRL) = CTRL_SLU | CTRL_ASDE;
    sleep_us(15);

    uint32_t status = REG(STATUS);
    if (status & STATUS_LINK_UP) {
        uint32_t speed = status & STATUS_SPEED_MASK;
        const char *speed_str = NULL;
        if (speed == STATUS_SPEED_10) {
            speed_str = "10Mb/s";
        } else if (speed == STATUS_SPEED_100) {
            speed_str = "100Mb/s";
        } else if (speed == STATUS_SPEED_1000) {
            speed_str = "1000Mb/s";
        } else {
            speed_str = "Unknown";
        }

        const char *duplex = (status & STATUS_FULL_DUPLEX) ? "Full Duplex" : "Half Duplex";
        printf("Link is up at %s %s\n", speed_str, duplex);
    } else {
        printf("Link NOT up\n");
    }
}

static void e1000e_interrupt_enable(struct e1000e_dev *dev) {
    REG(IMC) = 0xffffffff; // Clear the interrupt mask
    REG(IMS) = INTR_LSC | INTR_RXT0;
    REG(ICR); // clear pending interrupts
}

static void e1000e_rxinit(struct e1000e_dev *dev) {
    memset(dev->rx_desc, 0, sizeof(dev->rx_desc));
    for (int i = 0; i < NUM_RX_DESC; i++) {
        dev->rx_desc[i].addr = (uintptr_t)kalloc_size(RX_BUFFER_SIZE);
    }

    uintptr_t desc_addr = (uintptr_t)dev->rx_desc;
    REG(RDBAL) = (uint32_t)desc_addr;
    REG(RDBAH) = (uint32_t)(desc_addr >> 32);

    REG(RDLEN) = NUM_RX_DESC * sizeof(struct e1000e_rx_desc);

    REG(RDH) = 0;
    REG(RDT) = NUM_RX_DESC - 1;
    dev->rx_rd = 0;

    REG(RXCSUM) = 0;

    REG(RXDCTL) = (4 << 0) | BIT(8) | BIT(16) | RXDCTL_GRAN;

    REG(RCTL) |= RCTL_BSIZE_2048 | RCTL_DPF | RCTL_SECRC | RCTL_BAM | RCTL_MPE | RCTL_EN;
}

static void e1000e_txinit(struct e1000e_dev *dev) {
    memset(dev->tx_desc, 0, sizeof(dev->tx_desc));

    uintptr_t desc_addr = (uintptr_t)dev->tx_desc;
    REG(TDBAL) = (uint32_t)desc_addr;
    REG(TDBAH) = (uint32_t)(desc_addr >> 32);

    REG(TDLEN) = NUM_TX_DESC * sizeof(struct e1000e_tx_desc);

    REG(TDH) = 0;
    REG(TDT) = NUM_TX_DESC - 1;
    dev->tx_rd = 0;
    dev->tx_wr = 0;

    REG(TXDCTL) = (1 << 16) /* WTHRESH */ | TXDCTL_GRAN;
    uint32_t tctl = REG(TCTL);
    tctl &= TCTL_RESERVED;
    tctl |= /* collision threshold */ (15 << 4) | TCTL_COLD_FD | TCTL_EN;
    REG(TCTL) = tctl;
}

/*
static bool phy_read(struct e1000e_dev *dev, uint8_t phyadd, uint8_t regadd, uint16_t *result) {
    uint32_t mdic = MDIC_PUT_PHYADD(phyadd) | MDIC_PUT_REGADD(regadd) | MDIC_OP_READ;
    REG(MDIC) = mdic;
    bool ok = wait_for_set(&REG(MDIC), MDIC_R, time_ms_from_now(5));
    if (ok) {
        *result = MDIC_GET_DATA(REG(MDIC));
    } else {
        printf("intel-eth: timed out waiting for MDIC to be ready\n");
    }
    return ok;
}

static bool phy_write(struct e1000e_dev *dev, uint8_t phyadd, uint8_t regadd, uint16_t value) {
    uint32_t mdic = MDIC_PUT_DATA(value) | MDIC_PUT_PHYADD(phyadd) | MDIC_PUT_REGADD(regadd) | MDIC_OP_WRITE;
    REG(MDIC) = mdic;
    bool ok = wait_for_set(&REG(MDIC), MDIC_R, time_ms_from_now(5));
    if (!ok) {
        printf("intel-eth: timed out waiting for MDIC to be ready\n");
    }
    return ok;
}

static bool get_phy_addr(struct e1000e_dev *dev, uint8_t *phy_addr) {
    for (uint8_t addr = 1; addr <= MAX_PHY_ADDR; addr++) {
        uint16_t pid;
        bool ok = phy_read(dev, addr, PHY_PID, &pid);
        if (ok && pid) {
            *phy_addr = pid;
            return true;
        }
    }
    printf("intel-eth: unable to identify valid PHY address\n");
    return false;
}

static bool e1000e_enable_phy(struct e1000e_dev *dev) {
    uint8_t phy_addr;
    bool ok = get_phy_addr(dev, &phy_addr);
    if (!ok) {
        return false;
    }

    uint16_t phy_ctrl;
    ok = phy_read(dev, phy_addr, PHY_PCTRL, &phy_ctrl);
    if (!ok) {
        return false;
    }

    if (phy_ctrl & PHY_PCTRL_POWER_DOWN) {
        return phy_write(dev, phy_addr, PHY_PCTRL, phy_ctrl & ~PHY_PCTRL_POWER_DOWN);
    }
    return true;
}
*/

static void e1000e_start(struct e1000e_dev *dev, struct pci_device_info *pci) {
    // TODO: handle errors, unset master when the device is failed or goes down
    pci_enable_bus_master(pci, true);

    // e1000e_enable_phy(dev);

    e1000e_hw_reset(dev);

    e1000e_linkup(dev);

    // clear multicast filter
    for (int i = 0; i < 128; i++)
        REG(MTA + i * 4) = 0;

    e1000e_rxinit(dev);
    e1000e_txinit(dev);

    e1000e_interrupt_enable(dev);
}

static void e1000e_received(struct e1000e_dev *dev) {
    size_t rx_rd = dev->rx_rd;
    while (true) {
        struct e1000e_rx_desc *desc = &dev->rx_desc[rx_rd];
        if (!(desc->status & RXD_STATUS_DONE)) {
            break;
        }
        buffer_t *buff = kalloc(buffer_t);
        buff->area = (void *)desc->addr;
        buff->pos = buff->area;
        buff->area_size = RX_BUFFER_SIZE;
        buff->data_size = desc->length;
        // TODO: mark only desc->length of the receive buffer as ASAN RW. The rest of the buffer
        // should be marked invalid.
        eth_receive(&dev->eth_dev, buff);

        desc->status = 0;
        desc->addr = (uintptr_t)kalloc_size(RX_BUFFER_SIZE);

        REG(RDT) = rx_rd;
        rx_rd = (rx_rd + 1) % NUM_RX_DESC;
    }
    dev->rx_rd = rx_rd;
}

static void e1000e_handler(void *data) {
    struct e1000e_dev *dev = data;

    uint32_t status = REG(ICR);

    if (status & INTR_RXT0)
        e1000e_received(dev);
    if (status & INTR_LSC) {
        // TODO: suspend device when the Link is down?
        printf("Intel e1000e Link status has changed\n");
    }
}

static void e1000e_reap_tx_buffers(struct e1000e_dev *dev) {
    size_t tx_rd = dev->tx_rd;
    while (true) {
        struct e1000e_tx_desc *desc = &dev->tx_desc[tx_rd];
        if (!(desc->status & TXD_STATUS_DONE))
            break;
        SHOUT_IF(!desc->addr, "Trying to free a descriptor without buffer");
        kfree_size((void *)desc->addr, RX_BUFFER_SIZE);
        desc->addr = 0;
        desc->status = 0;

        tx_rd = (tx_rd + 1) % NUM_TX_DESC;
    }
    dev->tx_rd = tx_rd;
}

// Send data over eth
static void e1000e_send(struct eth_device *eth, buffer_t *buff) {
    struct e1000e_dev *dev = container_of(eth, struct e1000e_dev, eth_dev);

    e1000e_reap_tx_buffers(dev);

    // insert current buffer into the ring
    size_t tx_wr = dev->tx_wr;
    struct e1000e_tx_desc *desc = &dev->tx_desc[tx_wr];
    SHOUT_IF(desc->addr, "TX buffer overflow");
    memzero(desc);
    desc->addr = (uintptr_t)buff->pos;
    if (buff->data_size < 60) {
        SHOUT_IF(buff->area_size < 60);
        // pad short packages
        memset(buff->pos + buff->data_size, 0, 60 - buff->data_size);
        buff->data_size = 60;
    }
    desc->length = buff->data_size;
    desc->cmd = TXD_COMMAND_EOP | TXD_COMMAND_IFCS | TXD_COMMAND_RS;
    tx_wr = (tx_wr + 1) % NUM_TX_DESC;
    REG(TDT) = tx_wr;
    dev->tx_wr = tx_wr;

    kfree(buff); // freeing buffer head here. The buffer area will be freed in tx buffer reap function
}

INIT_CODE static void e1000e_probe(struct pci_device_info *info) {
    printf("Initializing Intel Pro/1000 Ethernet adapter Rev %i\n", info->revision);

    struct pci_bar bar;
    pci_bar_get(&bar, info->id, 0);

    if (bar.flags & PCI_BAR_IO) {
        printf("e1000e IO space is not supported\n");
        return;
    }

    page_table_set_bit((uintptr_t)bar.address, bar.size, PAGE_PRESENT | PAGE_WRITABLE | PAGE_CACHE_DISABLE,
                       PAGE_PRESENT | PAGE_WRITABLE | PAGE_CACHE_DISABLE);
    asan_mark_memory_region((uintptr_t)bar.address, bar.size, ASAN_TAG_RW);

    struct e1000e_dev *dev = kalloc(struct e1000e_dev);
    memzero(dev);
    dev->addr = bar.address;

    uint32_t ral = REG(RAL);
    uint32_t rah = REG(RAH);

    ethaddr_t mac;
    mac.addr[0] = ral;
    mac.addr[1] = ral >> 8;
    mac.addr[2] = ral >> 16;
    mac.addr[3] = ral >> 24;
    mac.addr[4] = rah;
    mac.addr[5] = rah >> 8;
    dev->eth_dev.addr = mac;

    printf("MAC addr " ETHADDR_PRINT_FMT "\n", ETHADDR_PRINT_PARAMS(mac));

    // XXX currently we use legacy PCI interface
    // add code that uses extended config space, MSI-X/MSI
    // void *config = pci_extended_config_space(info->id);
    // uint16_t device_id = MMIO16(config + PCI_CONFIG_DEVICE_ID);

    if (info->intr_type == PCI_INTR_MSIX) {
        printf("e100e MSIX intr size is %d\n", info->intr_msix.size);
        pci_register_msix_irq(info, 0, e1000e_handler, dev);
    } else if (info->intr_type == PCI_INTR_MSI) {
        pci_register_msi_irq(info, 0, e1000e_handler, dev);
    } else if (info->intr_type == PCI_INTR_LEGACY) {
        irq_register(info->intr_legacy.line, e1000e_handler, dev);
    }

    e1000e_start(dev, info);

    dev->eth_dev.send = e1000e_send;
    eth_dev_register(&dev->eth_dev);
}

PCI_DEVICE(0x8086, 0x100e, e1000e_probe);
PCI_DEVICE(0x8086, 0x100f, e1000e_probe);
PCI_DEVICE(0x8086, 0x109a, e1000e_probe);
PCI_DEVICE(0x8086, 0x10d3, e1000e_probe);
PCI_DEVICE(0x8086, 0x1503, e1000e_probe);
PCI_DEVICE(0x8086, 0x15b7, e1000e_probe);
