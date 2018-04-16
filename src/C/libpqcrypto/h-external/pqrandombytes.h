#ifndef pqrandombytes_H
#define pqrandombytes_H

#define pqrandombytes pqrandombytes_internal
#define pqrandombytes_calls pqrandombytes_internal_calls
#define pqrandombytes_bytes pqrandombytes_internal_bytes

#ifdef __cplusplus
extern "C" {
#endif

extern void pqrandombytes(unsigned char *,unsigned long long) __attribute__((visibility("default")));
extern unsigned long long pqrandombytes_calls __attribute__((visibility("default")));
extern unsigned long long pqrandombytes_bytes __attribute__((visibility("default")));

#ifdef __cplusplus
}
#endif

#endif
