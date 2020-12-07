PWD=$(shell pwd)
CXX = gcc
CXXFLAGS =  -g -I$(PWD)/../ -I$(PWD)
LDFLAGS = 
LBLIBS := -lssl -lcrypto

SRC = $(wildcard *.c $(PWD)/../*.c)
OBJ = $(SRC:.c=.o)
EXEC = client

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CXX) $(LDFLAGS) -o $@ $(OBJ) $(LBLIBS)

clean:
	rm -rf $(OBJ) $(EXEC)


%.o:%.c
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c $< -o $@
