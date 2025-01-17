#
# Tyler Filla
# CS 3780
# Project 1
#

CXX=c++
CXXFLAGS=-g -std=c++11 -lcrypto -I$(HOME)/.local/include -L$(HOME)/.local/lib

all: login usergen crack

login: login.cpp
	$(CXX) $(CXXFLAGS) -o login login.cpp

usergen: usergen.cpp
	$(CXX) $(CXXFLAGS) -o usergen usergen.cpp

crack: crack.cpp
	$(CXX) $(CXXFLAGS) -o crack crack.cpp

clean:
	rm -f login usergen crack

.PHONY: clean
.SECONDARY:
