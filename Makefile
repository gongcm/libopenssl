

all:
	make -C client
	make -C server


clean:
	rm -rf *.o
	make -C client clean
	make -C server clean
