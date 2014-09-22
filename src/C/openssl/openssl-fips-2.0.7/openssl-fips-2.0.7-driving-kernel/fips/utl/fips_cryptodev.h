#include <crypto/cryptodev.h>

// typical usage: either call cryptodev_op for a one-off operation, or:
// 1. start a session with cryptodev_start_session
//    - takes session information as input, and outputs to session information
//    - on success, writes to cryptofd as output
// 2. run any number of operations with cryptodev_session_op
//    - takes the session information and cryptofd produced by cryptodev_start_session as input
//    - takes an operation structure as input and, on success may write to some of the pointers in the operation structure
// 3. end the session with cryptodev_end_session
//    - takes the session information and cryptofd produced by cryptodev_start_session as input
//    - these structures should not be used for further calls to cryptodev_session_op or cryptodev_end_session until reinitialized by a call to cryptodev_start_session
// all operations return 0 on failure, non-0 on success

// Implementation note: actually, passing a whole session structure (instead of
// just the session id, for example) is probably a bit wasteful. But it makes
// for a very uniform interface, is hard to get wrong, and probably doesn't
// cost *too* much compared to crossing a kernel boundary anyway.

int cryptodev_op(struct session_op session, struct crypt_op op);
int cryptodev_start_session(struct session_op *session, int *cryptofd);
int cryptodev_session_op(struct session_op session, int cryptofd, struct crypt_op op);
int cryptodev_end_session(struct session_op session, int cryptofd);
