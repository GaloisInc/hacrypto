CC = gcc

CFLAGS =

INCLUDES = 

LFLAGS = test_sha.a -L/usr/local/lib -lsodium

LIBS = -L/usr/local/lib -lsodium

SRCS = SHA256_compare.c Ccommon_test.c run_tests.c

OBJS = $(SRCS:.c=.o)

MAIN = tests

.PHONY: depend clean

all:    $(MAIN)

$(MAIN): $(OBJS) 
	$(CC) $(CFLAGS) $(INCLUDES) -o $(MAIN) $(OBJS) $(LFLAGS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@

clean:
	$(RM) *.o *~ $(MAIN)

depend: $(SRCS)
	makedepend $(INCLUDES) $^

# DO NOT DELETE THIS LINE -- make depend needs it