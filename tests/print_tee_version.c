#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <linux/tee.h>
#include <string.h>
#include <assert.h>

int main(int argc, char **argv)
{
	struct tee_ioctl_version_data tee_version;
	int rc;
	char const *tee_path = "/dev/tee0";

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--help") == 0 ||
		    strcmp(argv[i], "-h") == 0) {
			printf("You can pass the path to the TEE device to query, otherwise "
			       "by default this programs queries /dev/tee0\n");

			return 0;
		} else {
			tee_path = argv[i];
		}
	}

	int fd = open(tee_path, O_RDONLY);
	rc = errno;
	if (fd < 0) {
		perror("failed to open TEE");
		fprintf(stderr, "\n");
		return fd;
	}

	rc = ioctl(fd, TEE_IOC_VERSION, &tee_version);
	if (rc) {
		fprintf(stderr, "failed to query TEE: %s (rc=%d)", strerror(rc),
			rc);
		return rc;
	}

	printf("\tid:\t%u\n"
	       "\ttee_specific_capabilities:\t%x\n"
	       "\tgeneric_capabilities:\t%x\n",
	       tee_version.impl_id, tee_version.impl_caps,
	       tee_version.gen_caps);

	return 0;
}
