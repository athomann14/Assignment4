#pragma once

#include "common.h"
#include "icmp.h"



int main(int argc, char* argv[])
{

	WSADATA wsaData;
	//Initialize WinSock 
	WORD wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0) {
		printf("WSAStartup error %d\n", WSAGetLastError());
		WSACleanup();
		return -1;
	}
	string inputString = "";
	inputString = argv[1];


	struct hostent *remote;
	remote = gethostbyname(inputString.c_str());
	
	struct in_addr addr;
	addr.s_addr = *(u_long *)remote->h_addr_list[0];
	//printf("\tIP Address: %s\n", inet_ntoa(addr));





	ICMP hello;
	hello.createSock();
	hello.constructSendAddr(inet_ntoa(addr));
	hello.createRequest();
	


	return 0;
}