#ifndef pqcpucycles_H
#define pqcpucycles_H

#define pqcpucycles pqcpucycles_impl
#define pqcpucycles_persecond pqcpucycles_impl_persecond
#define pqcpucycles_implementation pqcpucycles_impl_implementation

#ifdef __cplusplus
extern "C" {
#endif

extern long long pqcpucycles(void) __attribute__((visibility("default")));
extern long long pqcpucycles_persecond(void) __attribute__((visibility("default")));
extern const char pqcpucycles_implementation[] __attribute__((visibility("default")));

#ifdef __cplusplus
}
#endif

#endif
