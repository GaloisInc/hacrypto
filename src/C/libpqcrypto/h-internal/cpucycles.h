#ifndef cpucycles_H
#define cpucycles_H

#define cpucycles pqcpucycles_impl
#define cpucycles_persecond pqcpucycles_impl_persecond
#define cpucycles_implementation pqcpucycles_impl_implementation

#ifdef __cplusplus
extern "C" {
#endif

extern long long cpucycles(void) __attribute__((visibility("default")));
extern long long cpucycles_persecond(void) __attribute__((visibility("default")));
extern const char cpucycles_implementation[] __attribute__((visibility("default")));

#ifdef __cplusplus
}
#endif

#endif
