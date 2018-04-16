#ifndef kernelrandombytes_h
#define kernelrandombytes_h

#define kernelrandombytes pqkernelrandombytes_impl
#define kernelrandombytes_implementation pqkernelrandombytes_impl_implementation

#ifdef __cplusplus
extern "C" {
#endif

extern void kernelrandombytes(unsigned char *,unsigned long long) __attribute__((visibility("default")));
extern const char kernelrandombytes_implementation[] __attribute__((visibility("default")));

#ifdef __cplusplus
}
#endif

#endif
