#
# Tyler Filla
# CS 3780
# Project 1
#

CXX=c++
CXXFLAGS=-std=c++11 -lcrypto -I$(HOME)/.local/include -L$(HOME)/.local/lib

login: login.cpp
	$(CXX) $(CXXFLAGS) -o login login.cpp

clean:
	rm login

all: login

.PHONY: clean
.SECONDARY:
