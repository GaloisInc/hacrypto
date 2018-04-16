#ifndef measure_h
#define measure_h

extern void printentry(long long,const char *,long long *,long long);
extern unsigned char *alignedcalloc(unsigned long long);
extern const char *primitiveimplementation;
extern const char *implementationversion;
extern const char *compiler;
extern const char *sizenames[];
extern const long long sizes[];
extern void preallocate(void);
extern void allocate(void);
extern void measure(void);

#define LOOPS 1

#endif
