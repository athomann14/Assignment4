#include "icmp.h"



void ICMP::createSock(void)
{
	/*Code provided by professor in TraceRT assignment document*/
	/* ready to create a socket */
	ICMP::sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (ICMP::sock == INVALID_SOCKET)
	{
		printf("Unable to create a raw socket: %d\n", WSAGetLastError());
		WSACleanup();
		exit(-1);
	}	
}

void ICMP::createRequest(void)
{
	
	// buffer for the ICMP header
	 send_buf = new char[MAX_ICMP_SIZE]; /* IP header is not present here */
	 //class requestMessage *reqMessage = (requestMessage *)send_buf;
	 
	icmp = (ICMPHeader *)send_buf;
	
	 
	// set up the echo request
	// no need to flip the byte order since fields are 1 byte each
	 icmp->type = ICMP_ECHO_REQUEST;
	 icmp->code = 0;
	 // set up optional fields as needed
	 icmp->id = (u_short)GetCurrentProcessId();
	 // initialize checksum to zero
	 icmp->checksum = 0;
	 // set up optional fields as needed
	 // initialize checksum to zero
	 icmp->checksum = 0;
	 /* calculate the checksum */
	 int packet_size = sizeof(ICMPHeader); // 8 bytes
	 icmp->checksum = ip_checksum((u_short *)send_buf, packet_size);
	 // set proper TTL
	 int ttl = 1;
	 // need Ws2tcpip.h for IP_TTL
	 if (setsockopt(ICMP::sock, IPPROTO_IP, IP_TTL, (const char *)&ttl,
		 sizeof(ttl)) == SOCKET_ERROR) {
		 printf("error code: %d", WSAGetLastError());
		 perror("setsockopt failed\n");
		 closesocket(ICMP::sock);
		 // some cleanup
		 exit(-1);
	 }

	 /*
	 struct sockaddr_in send_addr;
	 send_addr.sin_family = AF_INET;
	 send_addr.sin_addr.S_un.S_addr = inet_addr(DNS::localDNSIP.c_str()); // 208.67.222.222

	 */
	 int send_addrSize = sizeof(struct sockaddr_in);
	 int sentbytes = sendto(sock, send_buf, packet_size, 0, (struct sockaddr*) &send_addr, send_addrSize);
	 // use regular sendto on the above socket 
	 printf("complete!\n");

	 recieveReply();
	 printf("complete!\n");
}


void ICMP::constructSendAddr(char * dest)
{
	send_addr.sin_family = AF_INET;
	send_addr.sin_addr.S_un.S_addr = inet_addr(dest);
	printf("done\n");
}

void ICMP::recieveReply(void)
{
	char rec_buf[MAX_REPLY_SIZE];/* this buffer starts with an IP header */
	IPHeader *router_ip_hdr = (IPHeader *)rec_buf;
	ICMPHeader *router_icmp_hdr = (ICMPHeader *)(router_ip_hdr + 1);
	IPHeader *orig_ip_hdr = (IPHeader *)(router_icmp_hdr + 1);
	ICMPHeader *orig_icmp_hdr = (ICMPHeader *)(orig_ip_hdr + 1);
	// receive from the socket into buffer rec_buf




	int send_addrSize = sizeof(struct sockaddr_in);


	struct timeval tp;
	tp.tv_sec = 10;
	tp.tv_usec = 0;
	int recvbytes = 0;

	fd_set fd;
	FD_ZERO(&fd); // clear the set
	FD_SET(sock, &fd); // add your socket to the set

	if (select(0, &fd, NULL, NULL, &tp)>0) {
		printf("hello!!!\n");
		recvbytes = recvfrom(sock,rec_buf, MAX_REPLY_SIZE, 0, (sockaddr *)&send_addr, &send_addrSize);
	}
	if (recvbytes == 0) {
		printf("Nothing recieved!!!\n");
	}
	printf("hello!\n");
	printf("hello version 2 \n");
	
}




/*
* ======================================================================
* ip_checksum: compute ICMP header checksum.
*
* Returns the checksum. No errors possible.
*
* ======================================================================
*/
u_short ICMP::ip_checksum(u_short * buffer, int size)
{
	u_long cksum = 0;

	/* sum all the words together, adding the final byte if size is odd */
	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(u_short);
	}

	if (size)
		cksum += *(u_char *)buffer;

	/* do a little shuffling */
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);

	/* return the bitwise complement of the resulting mishmash */
	return (u_short)(~cksum);
}