#ifndef REGISTER_MAP_H
#define REGISTER_MAP_H

#define TP_MMIO_BASE_ADDRESS                0x0b000000 
#define TP_MMIO_AREA_SIZE                   0x00000200

#define TP_MMIO_REG_OFFSET_OPEN_TEE         0x0
#define TP_MMIO_REG_OFFSET_CLOSE_TEE        0x8
#define TP_MMIO_REG_OFFSET_STATUS           0x10
#define TP_MMIO_REG_STATUS_FLAG_ERROR       1

#endif