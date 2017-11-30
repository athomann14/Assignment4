#pragma once

#include "common.h"
#include "icmp.h"



int main(int argc, char* argv[])
{
	char wait = 1;  // so the black window will not disappear
	WSADATA wsaData;
	//Initialize WinSock 
	WORD wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0) {
		printf("WSAStartup error %d\n", WSAGetLastError());
		WSACleanup();
		return -1;
	}

	if (argc == 2) {
		
		string inputString = "";
		inputString = argv[1];


		struct hostent *remote;
		remote = gethostbyname(inputString.c_str());
		if (remote == NULL) {
			printf("Invalid Tracert call, Exiting Program\n");
		}
		else {
			struct in_addr addr;
			addr.s_addr = *(u_long *)remote->h_addr_list[0];
			//printf("\tIP Address: %s\n", inet_ntoa(addr));

			ICMP hello;
			hello.createSock();
			hello.constructSendAddr(inet_ntoa(addr));
			hello.createRequest();
		}
	}
	else {
		printf("Invalid number of input arguments\n");
	}
	

	printf("Enter any letter to finish ");
	wait = getchar();
	return 0;
}