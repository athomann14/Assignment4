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


	ICMP hello;
	hello.createSock();

	return 0;
}