CC = gcc
CXX = g++ -g -Wall
CFLAGS = -g -Wall
LDFLAGS = 
PROGS = hw2 logger.so sample

all: $(PROGS)



%: %.c
	$(CC) -o $@ $(CFLAGS) $< $(LDFLAGS)

%: %.cpp
	$(CXX) -o $@ $(CFLAGS) $< $(LDFLAGS)

logger.so: logger.c
	$(CC) -o $@ -shared -fPIC $< -ldl

hw2:  hw2.o
	$(CXX) -o logger $^ $(LDFLAGS)

clean:
	rm -f *~ $(PROGS)
	rm -f *.o
	rm -f *.so
