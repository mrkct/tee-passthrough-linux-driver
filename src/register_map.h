#ifndef REGISTER_MAP_H
#define REGISTER_MAP_H

#define TP_MMIO_BASE_ADDRESS                    0x0b000000 
#define TP_MMIO_AREA_SIZE                       0x00000200

#define TP_MMIO_REG_OFFSET_OPEN_TEE             0x0
#define TP_MMIO_REG_OFFSET_CLOSE_TEE            0x8

#define TP_MMIO_REG_OFFSET_STATUS               0x10
#define TP_MMIO_REG_STATUS_FLAG_BUSY            (1 << 0)
#define TP_MMIO_REG_STATUS_FLAG_ERROR           (1 << 1)

#define TP_MMIO_REG_IOCTL_NUM                   0x18
#define TP_MMIO_REG_IOCTL_PHYS_DATA_BUFFER      0x20
#define TP_MMIO_REG_IOCTL_PHYS_DATA_BUFFER_LEN  0x28
#define TP_MMIO_REG_IOCTL_FD                    0x30

#endif