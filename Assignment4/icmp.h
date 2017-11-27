#pragma once
#include "common.h"
#include "icmpMessage.h"


class ICMP {
	public:
		void createSock();
		void createRequest();
		void recieveReply();
		u_short ip_checksum(u_short * buffer, int size);
		void constructSendAddr(char * dest);

	private:
			SOCKET sock;
			char recv_buf[512];
			class ICMPHeader *icmp;
			char * send_buf;
			struct sockaddr_in send_addr;

};