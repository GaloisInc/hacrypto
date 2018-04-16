#ifndef randombytes_H
#define randombytes_H

#define randombytes pqrandombytes_impl
#define randombytes_calls pqrandombytes_impl_calls
#define randombytes_bytes pqrandombytes_impl_bytes

#ifdef __cplusplus
extern "C" {
#endif

extern void randombytes(unsigned char *,unsigned long long) __attribute__((visibility("default")));
extern unsigned long long randombytes_calls __attribute__((visibility("default")));
extern unsigned long long randombytes_bytes __attribute__((visibility("default")));

#ifdef __cplusplus
}
#endif

#endif
