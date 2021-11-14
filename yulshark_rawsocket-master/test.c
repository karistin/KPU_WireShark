#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/udp.h> //udp 헤더
#include <netinet/tcp.h> //tcp 헤더
#include <netinet/ip.h> // ip 헤더
#include <netinet/if_ether.h> // 10Mb/s 이더넷 헤더 구조
#include <sys/socket.h> 
#include <arpa/inet.h>
#include <unistd.h>
#include <memory.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
//디렉토리 생성 라이브러리
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
//시스템 관련 헤더
#include <netinet/ip_icmp.h>  //icmp_추가
#include "dns.h"

#define BUFFER_SIZE 65536

void print_menu();
int packet_handler();
void print_menu(){
	printf("\n=====Program Menu=====\n");
	printf("1.Capture Start \n");
	printf("7.exit \n");
}
int main(int argc , char *argv[]){
	int input , end_flag=0;
	socklen_t len;
	
	while(!end_flag){
		print_menu();
		printf("\n input:");
		scaf("%d",&input);
		int count =0;
		switch(input){
			case 1:
				packet_handler();
				break;
			case 7:
				exit(1);
			default:
				printf("Check input\n");
				break;
		}
	}
	return 0;
}



int packet_handler(){
	struct sockaddr addr;
	//소켓 구조체
	int saddr_len = sizeof(addr);
	//구조체 크기 
	unsigned short iphdrlen;
	//IP 헤더 크기(20)
	int protocol =0, source_port=0,dest_port=0;
	unsigned char (*buffer) =(unsigned char*)malloc(BUFFER_SIZE);
	
}















