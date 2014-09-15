#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "utl/fips_cryptodev.h"

int cryptodev_op(struct session_op session, struct crypt_op op) {
	int cryptofd, result;

	if((cryptofd = open("/dev/crypto", O_RDWR, 0)) < 0) return 0;
	if(ioctl(cryptofd, CIOCGSESSION, &session)) goto err;
	op.ses = session.ses;

	result = !ioctl(cryptofd, CIOCCRYPT, &op);

	if(ioctl(cryptofd, CIOCFSESSION, &session.ses)) goto err;
	close(cryptofd);
	return result;

err:
	close(cryptofd);
	return 0;
}
