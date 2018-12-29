#include "interrupt.h"
#include "kalloc.h"
#include "mem.h"
#include "mmio.h"
#include "net/eth.h"
#include "pci.h"

#define REG_MAC0 0x0000
#define REG_MAC1 0x0004
#define REG_MAR7 0x0008
#define REG_MAR3 0x000c
#define REG_TNPDS_LOW 0x0020
#define REG_TNPDS_HIGH 0x0024
#define REG_CR 0x0037
#define REG_TPPOLL 0x0038
#define REG_IMR 0x003c
#define REG_ISR 0x003e
#define REG_TCR 0x0040
#define REG_RCR 0x0044
#define REG_9436CR 0x0050
#define REG_PHYSTATUS 0x006c
#define REG_RMS 0x00da
#define REG_CPLUSCR 0x00e0
#define REG_RDSAR_LOW 0x00e4
#define REG_RDSAR_HIGH 0x00e8
#define REG_MTPS 0x00ec

#define TX_DESC_LS BIT(12)
#define TX_DESC_FS BIT(13)
#define TX_DESC_EOR BIT(14)
#define TX_DESC_OWN BIT(15)

#define RX_DESC_EOR BIT(14)
#define RX_DESC_OWN BIT(15)

#define RTL_CR_RST BIT(4)
#define RTL_CR_RE BIT(3)
#define RTL_CR_TE BIT(2)

#define RTL_TPPOLL_NPQ BIT(6)

#define RTL_INT_MASK ((1 << 14) | 0x3ff)
#define RTL_INT_LINKCHG BIT(5)
#define RTL_INT_TOK BIT(2)
#define RTL_INT_ROK BIT(0)

#define RTL_TCR_IFG_MASK ((3 << 24) | 1 << 19)
#define RTL_TCR_IFG96 ((3 << 24) | 0)
#define RTL_TCR_MXDMA_MASK (7 << 8)
#define RTL_TCR_MXDMA_UNLIMITED (7 << 8)

#define RTL_RCR_MXDMA_MASK (7 << 8)
#define RTL_RCR_MXDMA_UNLIMITED (7 << 8)
#define RTL_RCR_ACCEPT_MASK (RTL_RCR_AB | RTL_RCR_AM | RTL_RCR_APM | RTL_RCR_AAP)
#define RTL_RCR_AB BIT(3)
#define RTL_RCR_AM BIT(2)
#define RTL_RCR_APM BIT(1)
#define RTL_RCR_AAP BIT(0)

#define RTL_9436CR_EEM_MASK (3 << 6)
#define RTL_9436CR_EEM_LOCK (0 << 6)
#define RTL_9436CR_EEM_UNLOCK (3 << 6)

#define RTL_PHYSTATUS_LINKSTS BIT(1)

#define RTL_RMS_RMS_MASK 0x3fff

#define RTL_CPLUSCR_RXVLAN BIT(6)
#define RTL_CPLUSCR_RXCHKSUM BIT(5)

#define RTL_MTPS_MTPS_MASK 0x1f

#define REG32(name) MMIO32(dev->addr + REG_##name)
#define REG16(name) MMIO16(dev->addr + REG_##name)
#define REG8(name) MMIO8(dev->addr + REG_##name)

// 64 Rx and Tx descriptors
#define DESC_COUNT 64
#define BUFFER_SIZE 2048

struct PACKED rtl8168_rx_desc {
    uint16_t length;
    uint16_t status;
    uint32_t _unused;
    uint64_t addr;
};
BUILD_PANIC_IF(sizeof(struct rtl8168_rx_desc) != 16);

struct PACKED rtl8168_tx_desc {
    uint16_t length;
    uint16_t status;
    uint32_t _unused;
    uint64_t addr;
};
BUILD_PANIC_IF(sizeof(struct rtl8168_tx_desc) != 16);

struct rtl8168_dev {
    struct eth_device eth_dev;
    struct rtl8168_rx_desc rx_descs[DESC_COUNT];
    struct rtl8168_tx_desc tx_descs[DESC_COUNT];
    size_t rx_rd;
    size_t tx_wr;

    __mmio void *addr;
};

static bool rtl8168_isonline(struct rtl8168_dev *dev) { return REG8(PHYSTATUS) & RTL_PHYSTATUS_LINKSTS; }

static void rtl8168_handler(void *data) {
    struct rtl8168_dev *dev = data;

    uint16_t isr = REG16(ISR);
    if (isr & RTL_INT_LINKCHG) {
        printf("rtl8168 changed link status to %s\n", rtl8168_isonline(dev) ? "online" : "offline");
    }
    if (isr & RTL_INT_TOK) {
        // TX buffer got freed
        // we get this interrupt only if rtl8168_enable_tx_intr is enabled
    }
    if (isr & RTL_INT_ROK) {
        while (!(dev->rx_descs[dev->rx_rd].status & RX_DESC_OWN)) {
            struct rtl8168_rx_desc *desc = &dev->rx_descs[dev->rx_rd];

            buffer_t *buff = kalloc(buffer_t);
            buff->area = (void *)desc->addr;
            buff->pos = buff->area;
            buff->area_size = BUFFER_SIZE;
            buff->data_size = desc->length;
            eth_receive(&dev->eth_dev, buff);

            bool is_end = dev->rx_rd == (DESC_COUNT - 1);
            desc->length = BUFFER_SIZE;
            desc->status = RX_DESC_OWN | (is_end ? RX_DESC_EOR : 0);

            dev->rx_rd = (dev->rx_rd + 1) % DESC_COUNT;
        }
    }

    REG16(ISR) = 0xffff;
}

UNUSED static void rtl8168_enable_tx_intr(struct rtl8168_dev *dev) {
    REG16(IMR) |= RTL_INT_TOK;
    REG16(ISR) = RTL_INT_TOK;
}

UNUSED static void rtl8168_disable_tx_intr(struct rtl8168_dev *dev) { REG16(IMR) &= ~RTL_INT_TOK; }

static void rtl8168_send(struct eth_device *eth, buffer_t *buff) {
    struct rtl8168_dev *dev = container_of(eth, struct rtl8168_dev, eth_dev);

    if (dev->tx_descs[dev->tx_wr].status & TX_DESC_OWN) {
        PANIC("TX buffer overflow\n");
        return;

        // TODO rtl8168_enable_tx_intr() then add the buffer to a waiting list
    }

    struct rtl8168_tx_desc *desc = &dev->tx_descs[dev->tx_wr];
    bool is_end = dev->tx_wr == (DESC_COUNT - 1);

    desc->addr = (uintptr_t)buff->pos;
    desc->length = buff->data_size;
    desc->status = (is_end ? TX_DESC_EOR : 0) | TX_DESC_OWN | TX_DESC_FS | TX_DESC_LS;

    REG8(TPPOLL) |= RTL_TPPOLL_NPQ;

    dev->tx_wr = (dev->tx_wr + 1) % DESC_COUNT;

    kfree(buff);
}

static void rtl8168_init_buffers(struct rtl8168_dev *dev) {
    for (int i = 0; i < DESC_COUNT; i++) {
        dev->rx_descs[i].status = RX_DESC_OWN;
        dev->rx_descs[i].length = BUFFER_SIZE;
        dev->rx_descs[i].addr = (uintptr_t)kalloc_size(BUFFER_SIZE);
        dev->rx_descs[i]._unused = 0;
    }
    dev->rx_descs[DESC_COUNT - 1].status |= RX_DESC_EOR;
    dev->rx_rd = 0;

    memzero(dev->tx_descs);
    dev->tx_wr = 0;
}

static void rtl8168_init_hw(struct rtl8168_dev *dev) {
    // C+CR needs to be configured first - enable rx VLAN detagging and checksum offload
    REG16(CPLUSCR) |= RTL_CPLUSCR_RXVLAN | RTL_CPLUSCR_RXCHKSUM;

    // Reset the controller and wait for the operation to finish
    REG8(CR) |= RTL_CR_RST;
    while (REG8(CR) & RTL_CR_RST)
        ;

    // Unlock the configuration registers
    REG8(9436CR) = (REG8(9436CR) & RTL_9436CR_EEM_MASK) | RTL_9436CR_EEM_UNLOCK;

    // Set the tx and rx maximum packet size
    REG8(MTPS) = (REG8(MTPS) & RTL_MTPS_MTPS_MASK) | ROUND_UP(BUFFER_SIZE, 128) / 128;
    REG16(RMS) = (REG16(RMS) & RTL_RMS_RMS_MASK) | BUFFER_SIZE;

    // Set the rx/tx descriptor ring addresses
    REG32(RDSAR_LOW) = (uint32_t)((uintptr_t)dev->rx_descs);
    REG32(RDSAR_HIGH) = (uint32_t)((uintptr_t)dev->rx_descs >> 32);
    REG32(TNPDS_LOW) = (uint32_t)((uintptr_t)dev->tx_descs);
    REG32(TNPDS_HIGH) = (uint32_t)((uintptr_t)dev->tx_descs >> 32);

    // Set the interframe gap and max DMA burst size in the tx config register
    uint32_t tcr = REG32(TCR) & ~(RTL_TCR_IFG_MASK | RTL_TCR_MXDMA_MASK);
    REG32(TCR) = tcr | RTL_TCR_IFG96 | RTL_TCR_MXDMA_UNLIMITED;

    // Disable interrupts except link change and rx-ok and then clear all interrupts
    REG16(IMR) = (REG16(IMR) & ~RTL_INT_MASK) | RTL_INT_LINKCHG | RTL_INT_ROK;
    REG16(ISR) = 0xffff;

    // Lock the configuration registers and enable rx/tx
    REG8(9436CR) = (REG8(9436CR) & RTL_9436CR_EEM_MASK) | RTL_9436CR_EEM_LOCK;
    REG8(CR) |= RTL_CR_RE | RTL_CR_TE;

    // Configure the max dma burst, what types of packets we accept, and the multicast filter
    uint32_t rcr = REG32(RCR) & ~(RTL_RCR_MXDMA_MASK | RTL_RCR_ACCEPT_MASK);
    REG32(RCR) = rcr | RTL_RCR_MXDMA_UNLIMITED | RTL_RCR_AB | RTL_RCR_AM | RTL_RCR_APM;
    REG32(MAR7) = 0xffffffff; // Accept all multicasts
    REG32(MAR3) = 0xffffffff;

    // Read the MAC and link status
    uint32_t mac0 = REG32(MAC0);
    uint32_t mac1 = REG32(MAC1);
    ethaddr_t mac;
    mac.addr[0] = mac0;
    mac.addr[1] = mac0 >> 8;
    mac.addr[2] = mac1;
    mac.addr[3] = mac1 >> 8;
    mac.addr[4] = mac1 >> 16;
    mac.addr[5] = mac1 >> 24;
    dev->eth_dev.addr = mac;

    printf("MAC addr " ETHADDR_PRINT_FMT "\n", ETHADDR_PRINT_PARAMS(mac));

    // dev->online = REG8(PHYSTATUS) & RTL_PHYSTATUS_LINKSTS;
}

INIT_CODE static void rtl8168_probe(struct pci_device_info *info) {
    SHOUT_IF(info->intr_type != PCI_INTR_MSIX, "RTL8168 driver supports MSIX interrupt model only");

    struct pci_bar bar;
    pci_bar_get(&bar, info->id, 2);

    if (bar.flags & PCI_BAR_IO) {
        printf("rtl8168 IO space is not supported\n");
        return;
    }

    struct rtl8168_dev *dev = kalloc(struct rtl8168_dev);
    memzero(dev);
    dev->addr = bar.address;

    uint32_t version = REG32(TCR) & 0x7cf00000;
    printf("Realtek RTL8168 Ethernet adapter, version 0x%08x\n", version);

    if (info->intr_type == PCI_INTR_MSIX) {
        pci_register_msix_irq(info, 0, rtl8168_handler, dev);
    } else if (info->intr_type == PCI_INTR_MSI) {
        pci_register_msi_irq(info, 0, rtl8168_handler, dev);
    } else if (info->intr_type == PCI_INTR_LEGACY) {
        irq_register(info->intr_legacy.line, rtl8168_handler, dev);
    }

    rtl8168_init_buffers(dev);
    rtl8168_init_hw(dev);

    dev->eth_dev.send = rtl8168_send;
    eth_dev_register(&dev->eth_dev);
}

PCI_DEVICE(0x10ec, 0x8168, rtl8168_probe);