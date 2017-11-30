#include "icmp.h"


//Function creates RAW socket with IP protocol ICMP
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

/*
Function performs Tracert operation by transmitting ICMP packet with a TTL value of 1, 
then increasing the TTL value and repeating transmission every time an ICMP reply is type 11 code 0.
Type 11 and code 0 indicates the TTL value has expired. 
This process continues until either a Type 0 code 0 or a type 3 code 3 occurs, indicating the Tracert has arrived at the destination.
*/

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
	 /* calculate the checksum */
	 int packet_size = sizeof(ICMPHeader); // 8 bytes
	 icmp->checksum = ip_checksum((u_short *)send_buf, packet_size);
	 
	 int ttl = 1;
	 totalTime = 0;
	 
	 tracertComplete = false;
	 while (!tracertComplete && ttl <30) {
		 
		 //insert TTL value into packet
		 if (setsockopt(ICMP::sock, IPPROTO_IP, IP_TTL, (const char *)&ttl,
			 sizeof(ttl)) == SOCKET_ERROR) {
			 printf("error code: %d", WSAGetLastError());
			 perror("setsockopt failed\n");
			 closesocket(ICMP::sock);
			 // some cleanup
			 exit(-1);
		 }

		 send_addrSize = sizeof(struct sockaddr_in);
		 int sentbytes = sendto(sock, send_buf, packet_size, 0, (struct sockaddr*) &send_addr, send_addrSize);
		 timer = clock();
		 //printf("packet sent!\n");

		 int probeNum = 1;
		 while (probeNum < 4) {
			 if (recieveReply()) {
				 //reply recieved, so print and add timer to total time
				 printf("%d  %s (%s)\t%d ms\t(%d)\n", ttl, routerDns.c_str(), routerIP.c_str(), timer,probeNum);
				 totalTime += timer;
				 break;
			 }
			 else{
				 //probe failed so send another
				 probeNum++;
				 int sentbytes = sendto(sock, send_buf, packet_size, 0, (struct sockaddr*) &send_addr, send_addrSize);
			 }
		 }
		 //all 3 probes timed out
		 if (probeNum == 4) {
			 printf("%d  <ICMP TIMEOUT>\n", ttl);
		 }
		 //reply was recieved so need to increment TTL value by 1
		 ttl++;
	 }
	 if (ttl == 30 && !tracertComplete) {
		 printf("MAXIMUM NUMBER OF HOPS EXCEEDED");
	 }
	 printf("Total Execution time: %d ms\n\n", totalTime);
	 //printf("DONE!\n");
	 delete[] send_buf;

}

/*
	This process sets the ICMP objects sockaddr_in parameters such as IP address and Port number
*/
void ICMP::constructSendAddr(char * dest)
{
	send_addr.sin_family = AF_INET;
	send_addr.sin_addr.S_un.S_addr = inet_addr(dest);
	u_short port = 27015;
	send_addr.sin_port = htons(port);
	//printf("done\n");
}

/*
Function recieves and parses the ICMP replies
Function returns True if packet recieved's ID matches the current process ID
*/
bool ICMP::recieveReply(void)
{

	char rec_buf[MAX_REPLY_SIZE];/* this buffer starts with an IP header */
	//initializing ICMP variables
	bool replyrecieved = false;
	routerIP = "";
	routerDns = "";

	//timeout parameters
	struct timeval tp;
	//CHANGE THIS VALUE IN ORDER TO CHANGE TIMEOUT INTERVAL
	tp.tv_sec = 0;
	tp.tv_usec = 100000;
	//tp.tv_usec = 0;
	int recvbytes = 0;

	fd_set fd;
	FD_ZERO(&fd); // clear the set
	FD_SET(sock, &fd); // add your socket to the set

	struct sockaddr_in recv_addr;
	int recv_addrSize = sizeof(struct sockaddr_in);

	if (select(0, &fd, NULL, NULL, &tp)>0) {
		recvbytes = recvfrom(sock, rec_buf, MAX_REPLY_SIZE,0, (sockaddr *)&recv_addr, &recv_addrSize);
		timer = clock() - timer;
	}


	if (recvbytes == 0) {
		return replyrecieved;
	}
	//reply recieved
	else {
		IPHeader *router_ip_hdr = (IPHeader *)rec_buf;
		int index = 1;
		//if header is larger than 20 bytes then change index accordingly
		if ((router_ip_hdr->h_len) != 5) {
			index = 32 * ((router_ip_hdr->h_len) - 5);
			index++;
		}
		ICMPHeader *router_icmp_hdr = (ICMPHeader *)(router_ip_hdr + index);
		
		replyrecieved = true;
		int replyType = (int)(router_icmp_hdr->type);
		int replyCode = (int)(router_icmp_hdr->code);
		//type 11
		if (replyType == 11 && replyCode == 0) {
			
			//printf("Type 11!!!\n");
			IPHeader *orig_ip_hdr = (IPHeader *)(router_icmp_hdr + 1);
			ICMPHeader *orig_icmp_hdr = (ICMPHeader *)(orig_ip_hdr + 1);

			//check if process ID matches
			if ((orig_icmp_hdr->id)==(u_short)GetCurrentProcessId()) {

				//perform DNS lookup of router source ip
				//struct hostent *source;
				struct in_addr destAddr;
				destAddr.S_un.S_addr = (router_ip_hdr->source_ip);
				routerIP = inet_ntoa(destAddr);
				DNSlookup(destAddr);

			}
			else {
				return false;
			}			
		}
		//Type 0
		else if (replyType == 0 && replyCode == 0) {
			//perform DNS lookup of router source ip
			struct in_addr destAddr;
			destAddr.S_un.S_addr = (router_ip_hdr->source_ip);
			routerIP = inet_ntoa(destAddr);
			DNSlookup(destAddr);
			//printf("Type 0!!!\n");
			tracertComplete = true;
		}
		else if (replyType == 3 && replyCode == 3) {
			struct in_addr destAddr;
			destAddr.S_un.S_addr = (router_ip_hdr->source_ip);
			routerIP = inet_ntoa(destAddr);
			DNSlookup(destAddr);
			tracertComplete = true;
			//printf("Type 3!!!\n");

		}

	}
	return replyrecieved;
	
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


/*
Function performs DNS lookup and places the resolved name into the RouterDNS string, else it places no DNS entry
*/
void ICMP::DNSlookup(struct in_addr destAddr) {
	struct hostent *source;

	source = gethostbyaddr((char *)&destAddr, 4, AF_INET);

	//DNS lookup failed
	if (source == NULL) {
		routerDns = "<no DNS entry>";

	}
	else {
		struct in_addr addr;
		addr.s_addr = *(u_long *)source->h_addr_list[0];
		//printf("\tIP Address: %s\n", dest->h_name);
		routerDns = source->h_name;
	}
}