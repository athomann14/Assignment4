#pragma once
#include "common.h"

class ICMP {
	public:
		void createSock();

	private:
			SOCKET sock;
			char recv_buf[512];
};