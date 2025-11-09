CXX = g++
CC  = gcc
CXXFLAGS = -g -Wall -Wextra -std=c++17 -O2
CCFLAGS  = -g -Wall -Wextra -O2 -I /usr/lib/jvm/java-21-openjdk-amd64/include -I /usr/lib/jvm/java-21-openjdk-amd64/include/linux
LDFLAGS = -g 
#SRC = 
#OBJ = $(SRC:.cpp=.o)

#TARGET = progSpi

#all: $(TARGET)

#$(TARGET): $(OBJ)
#        $(CXX) $(OBJ) -o $@ $(LDFLAGS)


all: "../bin/LinuxKeyrings.so"



"../bin/LinuxKeyrings.so": LinuxKeyrings.c LinuxKeyrings.h
	gcc -shared -fPIC -nostdlib -nostartfiles -o ../bin/LinuxKeyrings.so $(CCFLAGS) LinuxKeyrings.c


LinuxKeyrings.h: LinuxKeyrings.java
	javac -h . -d ../bin LinuxKeyrings.java 


#%.o: %.cpp
#        $(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f ../bin/$(OBJ) ../bin/$(TARGET)

.PHONY: all clean
