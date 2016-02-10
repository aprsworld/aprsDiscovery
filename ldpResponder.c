#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
 
#define BUFLEN 30  //Max length of bufffer
#define PORT 30718   //The port on which to listen for incoming data
 
void die(char *s) {
	perror(s);
	exit(1);
}

void build_response_aprs(char *buff) {
	memset((char *) buff, 0, sizeof(buff));
	
	buff[3]=0xf7;
	buff[24]=0xde;
	buff[25]=0xad;
	buff[26]=0xbe;
	buff[27]=0xef;
	buff[28]=0x01;
	buff[29]=0x23;

}
 
int main(void) {
	struct sockaddr_in si_me, si_other;
     
	int s, i, slen = sizeof(si_other) , recv_len;
	char buff[BUFLEN];
     
	/* create UDP socket */
	if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		die("socket");
	}
     
	/* clear structure */
	memset((char *) &si_me, 0, sizeof(si_me));
     
	si_me.sin_family = AF_INET;
	/* port from define */
	si_me.sin_port = htons(PORT);
	/* any interface */
	si_me.sin_addr.s_addr = htonl(INADDR_ANY);
     
	/* bind socket to port */
	if( bind(s , (struct sockaddr*)&si_me, sizeof(si_me) ) == -1) {
		die("bind");
	}
     
	//keep listening for data
	while(1) {
		printf("Waiting for data...\n");
		fflush(stdout);
         
		//try to receive some data, this is a blocking call
		if ((recv_len = recvfrom(s, buff, BUFLEN, 0, (struct sockaddr *) &si_other, &slen)) == -1) {
			die("recvfrom()");
		}
         
		//print details of the client/peer and the data received
		printf("Received packet from %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
		printf("Recv_len: %d\n",recv_len);
		printf("Data: %s\n" , buff);
		for ( i=0 ; i<recv_len ; i++ ) {
			printf("buff[%d]=0x%02x\n",i,buff[i]);
		}

		/* check if we got the magic packet */
		if ( 4==recv_len && 0==buff[0] && 0==buff[1] && 0==buff[2] && 0xf6==buff[3] ) {
			printf("# got magic packet ... need to respond\n");

			/* build response packet */
			memset((char *) buff, 0, sizeof(buff));
			buff[3]=0xF7;

			/* build our response and put in buff */
			build_response_aprs(buff);

			/* send response */
			if (sendto(s, buff, sizeof(buff), 0, (struct sockaddr*) &si_other, slen) == -1) {
				die("sendto()");
			}
		}
	}
 
	close(s);
	return 0;
}
