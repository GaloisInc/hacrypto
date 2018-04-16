#ifndef pqkernelrandombytes_h
#define pqkernelrandombytes_h

#define pqkernelrandombytes pqkernelrandombytes_impl
#define pqkernelrandombytes_implementation pqkernelrandombytes_impl_implementation

#ifdef __cplusplus
extern "C" {
#endif

extern void pqkernelrandombytes(unsigned char *,unsigned long long) __attribute__((visibility("default")));
extern const char pqkernelrandombytes_implementation[] __attribute__((visibility("default")));

#ifdef __cplusplus
}
#endif

#endif
