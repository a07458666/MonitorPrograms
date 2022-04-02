CC = gcc
CXX = g++ -g -Wall
CFLAGS = -g -Wall
LDFLAGS = 
PROGS = hw2

all: $(PROGS)

%: %.c
	$(CC) -o $@ $(CFLAGS) $< $(LDFLAGS)

%: %.cpp
	$(CXX) -o $@ $(CFLAGS) $< $(LDFLAGS)


hw2: logger.o hw2.o
	$(CXX) -o logger $^ $(LDFLAGS)

clean:
	rm -f *~ $(PROGS)
	rm -f *.o
