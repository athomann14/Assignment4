#include "icmp.h"



void ICMP::createSock(void)
{
	/*Code provided by professor in TraceRT assignment document*/
	/* ready to create a socket */
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock == INVALID_SOCKET)
	{
		printf("Unable to create a raw socket: %d\n", WSAGetLastError());
		WSACleanup();
		exit(-1);
	}
}