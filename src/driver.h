#ifndef TPTEE_DRIVER_H
#define TPTEE_DRIVER_H

#include "register_map.h"

inline void wait_until_not_busy(void);
inline bool last_operation_completed_successfully(void);

struct tee_passthrough_data {
	int fd;
};

#endif