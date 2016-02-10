#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <inttypes.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

 
#define BUFLEN 30  //Max length of bufffer
#define PORT 30719   //The port on which to listen for incoming data
 
void die(char *s) {
	perror(s);
	exit(1);
}


int getSerialNumber(int *serialPrefix, int *serialNumber) {
	char hostname[64];
	int startNumeric=0;

	*serialPrefix=0;
	*serialNumber=0;
	
	if ( 0 != gethostname(hostname,sizeof(hostname)) )  {
		/* error reading hostname */
		return -1;
	}


	/* serial number starts at the first number */
	for ( startNumeric=0 ; startNumeric<=strlen(hostname) ; startNumeric++ ) {
		if ( startNumeric==strlen(hostname) ) {
			/* not found by end of string */
			return -2;
		}
		if ( isdigit(hostname[startNumeric]) ) {
			/* found */
			break;
		}
	}

	*serialNumber=atoi(&hostname[startNumeric]);

	/* serial prefix is the first character before numeric */
	if ( startNumeric>0 ) {
		*serialPrefix=hostname[startNumeric-1];
	}

	return 0;
}
 
 
void build_response_aprs(char *buff, int len, char *interfaceA, char *interfaceB) {
	int serialPrefix,serialNumber;
	struct ifaddrs *ifaddr=NULL;
	struct ifaddrs *ifa = NULL;
	int i = 0;

	/* zero out packet */
	memset((char *) buff, 0, len);
	
	/* always respond with 0xf7 */
	buff[3]=0xf7;

	/* get serial number */
	if ( 0 == getSerialNumber(&serialPrefix,&serialNumber) ) {
		printf("# Setting serial number details\n");
		buff[5]=(char) (serialPrefix&0xff);
		buff[6]=(char) ((serialNumber>>8)&0xff);
		buff[7]=(char) (serialNumber&0xff);
	}

//	for ( i=0 ; i<len ; i++ ) printf("\t[%d] 0x%02x\n",i,buff[i]);

	/* iterate through interfaces and fill in interfaceA and interfaceB MAC and IP, if available */
	if ( getifaddrs(&ifaddr) == -1) {
		/* nothing left to do if we can't get interface details */
		return;
	}
		
	for ( ifa = ifaddr ; ifa != NULL ; ifa = ifa->ifa_next ) {
		int offset=0;

		/* interface name */
		printf("# Interface: %-8s ", ifa->ifa_name); 

		if ( 0 == strcmp(interfaceA,ifa->ifa_name) ) {
			offset=20;
		} else if ( 0 == strcmp(interfaceB,ifa->ifa_name) ) {
			offset=10;
		} else {
			printf(" skipping\n");
			continue;
		}

		/* add MAC address */
		if ( (ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET) ) {
			struct sockaddr_ll *s = (struct sockaddr_ll*) ifa->ifa_addr;


			/* mac address */
			for ( i=0 ; i < s->sll_halen && 6==s->sll_halen ; i++) {
				buff[offset+4+i]=(s->sll_addr[i]);
				printf("%02x%c", (s->sll_addr[i]), (i+1!=s->sll_halen)?':':'\t');
			}
		}
 
		/* add IP address if IF_INET (IPv4) */
		if( ifa->ifa_addr != 0 ) {
			int family = ifa->ifa_addr->sa_family;
			if( family == AF_INET ) {

				/* interface IP address */
				struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
				unsigned char *ip = (unsigned char *)&sin->sin_addr.s_addr;
				printf("%d.%d.%d.%d\t", ip[0], ip[1], ip[2], ip[3]);
				for ( i=0 ; i<4 ; i++ ) {
					buff[offset+i]=ip[i];
				}

			}
		}
		printf("\n");
	}
 
	/* free memory allocated by getifaddrs */
	freeifaddrs( ifaddr );

//	for ( i=0 ; i<len ; i++ ) printf("\t[%d] 0x%02x\n",i,buff[i]);
}
 
int main(int argc, char **argv) {
	struct sockaddr_in si_me, si_other;
     
	int s, i, slen = sizeof(si_other) , recv_len;
	char buff[BUFLEN];
	char response_buff[BUFLEN];

	if  ( 3 != argc ) {
		printf("usage: aprsDiscoveryResponder firstInterface secondInterface\n");
		exit(1);
	}

     
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
	
		/*
		for ( i=0 ; i<recv_len ; i++ ) {
			printf("buff[%d]=0x%02x\n",i,buff[i]);
		}
		*/

		/* check if we got the magic packet */
		if ( 4==recv_len && 0==buff[0] && 0==buff[1] && 0==buff[2] && 0xf6==buff[3] ) {
			/* got query packet */
			/* build our response and put in buff */
			build_response_aprs(response_buff,sizeof(response_buff),argv[1],argv[2]);

			/* send response */
			if (sendto(s, response_buff, sizeof(response_buff), 0, (struct sockaddr*) &si_other, slen) == -1) {
				die("sendto()");
			}
		}
	}
 
	close(s);
	return 0;
}
