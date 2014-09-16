#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "utl/fips_cryptodev.h"

int cryptodev_op(struct session_op session, struct crypt_op op) {
	int cryptofd, result;

	if(!cryptodev_start_session(&session, &cryptofd)) return 0;
	result = cryptodev_session_op(session, cryptofd, op);
	return cryptodev_end_session(session, cryptofd) && result;
}

int cryptodev_start_session(struct session_op *session, int *cryptofd) {
	int cryptofdtmp = open("/dev/crypto", O_RDWR, 0);
	if(cryptofdtmp < 0) return 0;
	if(ioctl(cryptofdtmp, CIOCGSESSION, session)) {
		close(cryptofdtmp);
		return 0;
	}
	*cryptofd = cryptofdtmp;
	return 1;
}

int cryptodev_session_op(struct session_op session, int cryptofd, struct crypt_op op) {
	op.ses = session.ses;
	return !ioctl(cryptofd, CIOCCRYPT, &op);
}

int cryptodev_end_session(struct session_op session, int cryptofd) {
	int success = !ioctl(cryptofd, CIOCFSESSION, &session.ses);
	    success = success && close(cryptofd);
	return success;
}
