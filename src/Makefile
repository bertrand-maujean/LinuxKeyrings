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

#%.o: %.cpp
#        $(CXX) $(CXXFLAGS) -c $< -o $@


all: "../bin/LinuxKeyrings.so" "../bin/App.class" "../bin/ErrnoException.class" "../bin/LinuxKeyrings.class"

"../bin/LinuxKeyrings.so": LinuxKeyrings.c LinuxKeyrings.h
	gcc -shared -fPIC -nostdlib -nostartfiles -o ../bin/LinuxKeyrings.so $(CCFLAGS) LinuxKeyrings.c

LinuxKeyrings.h: LinuxKeyrings.java
	javac -h . -d ../bin LinuxKeyrings.java 

"../bin/LinuxKeyrings.class":
	javac -d ../bin LinuxKeyrings.java

"../bin/ErrnoException.class":
	javac -d ../bin ErrnoException.java 

"../bin/App.class":
	javac -d ../bin App.java



clean:
	#rm -f ../bin/$(OBJ) ../bin/$(TARGET)
	rm -f ../bin/*
	rm -f LinuxKeyrings.h
	rm -f *.class


.PHONY: all clean
