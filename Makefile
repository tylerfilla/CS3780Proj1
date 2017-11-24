#
# Tyler Filla
# CS 3780
# Project 1
#

login: login.cpp
	c++ -std=c++11 -lcrypto -I${HOME}/.local/include -L${HOME}/.local/lib -o login login.cpp
