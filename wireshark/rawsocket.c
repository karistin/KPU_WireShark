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
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/ip_icmp.h>  //icmp_추가
#include "dns.h"

#define BUFFER_SIZE 65536
#define PATH_SIZE 512

// 포트번호 지정
#define ICMP 1
#define TCP 6
#define UDP 17
#define DNS 53
#define HTTP 80

// http 헤더 구조체
typedef struct http_header{
    unsigned char http_first[3000];
}http_header;

int rawsocket;
int packet_num=0;
int remaining_data = 0;
int file_num;
FILE *log_file;
FILE *log_file_dir;
FILE *read_file = NULL;
char filter[80],filter2[80],filter3[80];
char file_token[4][40];
char file_list[10000][100];

struct sockaddr_in source, dest;
struct sigaction act;
struct http_header *hh;

// 패킷 관련 함수
int packet_handler(void);
int packet_analyze(char *filter);
int packet_list();
void close_sighandler(void);

// 로그 파일 관련 함수
void log_eth(struct ethhdr *eth);
void log_ip(struct iphdr *ip);
void log_icmp(struct icmp *icmp, struct ih_idseq *ih_idseq);

void log_ih_idseq(struct ih_idseq *ih_idseq);
void log_tcp(struct tcphdr *tcp);
void log_udp(struct udphdr *udp);
void log_dns(struct dns_header *dns, struct dns_question *que, struct dns_resource_record *res, struct dns_handle *han);

void log_data(unsigned char *data, int remaining_data, int protocol);
void log_data_char(unsigned char *data, int remaining_data, int protocol);

// 메뉴 출력
void print_menu();
void tokenizer(char str[1024]);

// 디렉토리 관련 함수
void make_logdir();
void delete_logdir();
void get_logdir();
int rmdirs(const char *path, int force);
int list_view(char *filters);

int associate_file(int ch, int flag);
int file_select(const struct dirent *entry);
void file_read(int ch);
void packetSelect();

// 핑 전송 함수
void *ping_transfer();

// 오류 처리 함수
int fatal(char *s);

int main(int argc, char *argv[]){
    int input, end_flag = 0;
    socklen_t len;
	pthread_t pings;
	
    while(!end_flag){
        print_menu();
        printf("\n메뉴 선택 : ");
        scanf("%d",&input);
        int count = 0;
        char p1[] = "thread ping";
        long st;
        
        switch (input)
        {
        case 1: // 패킷 수집
            packet_handler();
            break;
        case 2: // 로그 디렉토리 탐색 후 파일 리스트 출력
            packet_analyze("");
            list_view("");
            break;
        case 3: // 패킷 선택
            packetSelect();
            break;
        case 4: // 프로토콜 필터 설정
            printf("\nfilter input : ");
            scanf("%s",filter);
            printf("필터가 %s로 설정되었습니다.\n",filter);
            break;
        case 5: // 로그 파일 이름 내 ip주소 또는 특정 프로토콜 이름 필터 설정
            printf("연관 프레임 번호를 입력하세요 : ");
            scanf(" %d",&input);
            getchar();
            associate_file(input,0);
            break;
        case 6: // 필터 초기화
            strcpy(filter,"");
            strcpy(filter2,"");
            printf("필터가 초기화되었습니다.\n");
            break;
        case 7: // 핑 전송
            pthread_create(&pings,NULL,ping_transfer,(void*)p1);
            pthread_join(pings,(void*)st);
			break;    
        case 8: // 디렉토리 삭제 후 종료
            delete_logdir();
            exit(1); 
            break;
        default:
            printf("\n[ 입력이 잘못되었습니다. 메뉴를 다시 입력하세요 ]\n");
            break;
        }
    }
    return 0;
}

int packet_handler(){

    // 소켓 및 프로토콜 변수 선언 및 초기화
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);
    unsigned short iphdr_len;
    int protocol = 0, source_port = 0, dest_port = 0;
    unsigned char *buffer = (unsigned char*) malloc(BUFFER_SIZE);
    unsigned char protocol_name[10];
    int packet_len = 0;

    // CTRL + C 입력시 시그널 설정
    act.sa_handler = (void*)close_sighandler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGINT, &act, 0);

    // 패킷 소켓 생성
    /*
    === AF_PACKET 사용 이유 ===
    -> 디바이스 드라이버 레벨(OSI 2계층)에서 패킷 송수신이 가능하도록 함
    -> 시스템 콜을 통해 만들어진 프로토콜 패킷을 2계층에서 모든 상위 계층으로 데이터를 직접 만들어서 전송 가능
     * ETH_P_ALL = 이더넷 내 모든 프로토콜 수집
     https://mangkyu.tistory.com/16
    */
    rawsocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(rawsocket < 0)
    {
        printf("pcap end\n");
        return -1;
    }

    printf(" | Num |  \t");
    printf("  | Source |\t\t");
    printf("   | Dest |\t");
    printf("\t  | Protocol |\n");
    while(1){
        // sockaddr 구조체 초기화 및 버퍼 동적 할당
        struct sockaddr saddr;  // raw 소켓으로 소켓 주소를 표현하므로 sockaddr을 사용
        saddr_len = sizeof(saddr);
        iphdr_len = 0;
        protocol = 0, source_port = 0, dest_port = 0;
        buffer = (unsigned char*)malloc(BUFFER_SIZE);
        protocol_name[10]; 
        protocol_name[0] = '\0';    // 문자열 공백 초기화
        packet_len = 0;
        
        memset(buffer, 0, BUFFER_SIZE); // 버퍼 0으로 초기화

        // recvfrom 함수를 통해 송신지와 도착지의 데이터를 자세하게 확인 가능
        int buflen = recvfrom(rawsocket, buffer, 65536, 0, &saddr, (socklen_t*)&saddr_len);

        if(buflen < 0){
            printf("error in reading recvfrom \n");
            return 0;
        }
        
        buffer[buflen] = 0;

        //https://www.researchgate.net/figure/Packet-structure-of-ECM-the-customized-ICMP-packet_fig2_261380601

        // 데이터 링크 계층 (이더넷) 설정
        struct ethhdr *eth = (struct ethhdr *)(buffer);

        // 네트워크 계층 설정
        struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        iphdr_len = ip->ihl * 4; // ip 헤더 길이
        memset(&source,0,sizeof(source));
        source.sin_addr.s_addr = ip->saddr;
        memset(&dest,0,sizeof(dest));
        dest.sin_addr.s_addr = ip->daddr;
        protocol = (unsigned int)ip->protocol;

        unsigned char *data = (buffer + iphdr_len + sizeof(struct ethhdr)); // 이더넷 데이터가 포함된 기본 데이터 설정
        remaining_data = buflen - (iphdr_len + sizeof(struct ethhdr)); // 기본 잔여 공간 설정
        
        // 각 프로토콜 데이터 추가
        // https://m.blog.naver.com/6yujin6/221634449540
        if(protocol == ICMP){
            struct icmp *icmp = (struct icmp*)(buffer + sizeof(struct ethhdr) + iphdr_len);
            struct ih_idseq *ih_idseq = (struct ih_idseq*)(buffer + iphdr_len + sizeof(struct ethhdr) + sizeof(struct ih_idseq));

            strcpy(protocol_name, "ICMP");
            source_port = ntohs(ip->saddr);
            dest_port = ntohs(ip->daddr);
            data = (buffer + iphdr_len + sizeof(struct ethhdr) + sizeof(struct icmp));
            remaining_data = buflen - (iphdr_len + sizeof(struct ethhdr) + sizeof(struct icmp));
        }else if(protocol == TCP){
            struct tcphdr *tcp = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + iphdr_len);
            strcpy(protocol_name, "TCP");
            source_port = ntohs(tcp->source);
            dest_port = ntohs(tcp->dest);
            data = (buffer + iphdr_len + sizeof(struct ethhdr) + sizeof(struct tcphdr));
            remaining_data = buflen - (iphdr_len + sizeof(struct ethhdr) + sizeof(struct tcphdr));
        }else if(protocol == UDP){
            struct udphdr *udp = (struct udphdr*)(buffer + sizeof(struct ethhdr) + iphdr_len);
            strcpy(protocol_name, "UDP");
            source_port = ntohs(udp->source);
            dest_port = ntohs(udp->dest);
            data = (buffer + iphdr_len + sizeof(struct ethhdr) + sizeof(struct udphdr));
            remaining_data = buflen - (iphdr_len + sizeof(struct ethhdr) + sizeof(struct udphdr));
        }
        // https://gsk121.tistory.com/205
        else if(protocol == DNS){
            struct dns_header *dns = (struct dns_header *)(buffer + sizeof(struct ethhdr) + sizeof(struct udphdr) + iphdr_len);
            struct dns_question *que = (struct dns_question *)(buffer + iphdr_len + sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct dns_question));
            struct dns_resource_record *res = (struct dns_resource_record*)(buffer + iphdr_len + sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct dns_resource_record));
            struct dns_handle *han = (struct dns_handle*)(buffer + iphdr_len + sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct dns_handle));
        }else{
            if(protocol == 80){ // HTTP 프로토콜
                protocol = 12;
            }
            sprintf(protocol_name, "%d", protocol);
        }

        // http://www.ktword.co.kr/test/view/view.php?m_temp1=3132

        if(DNS == source_port || DNS == dest_port) // DNS 포트 번호(53) 확인
            strcpy(protocol_name, "DNS");
        else if((HTTP == source_port || HTTP == dest_port) && (buflen > 80 && buflen < 2000)){  // HTTP 포트 번호(80) 확인
            strcpy(protocol_name, "HTTP");
        }else if(443 == source_port || 433 == dest_port){   // HTTPS 포트 번호(433) 확인
            strcpy(protocol_name, "https-tls");
        }

        // HTTP 데이터 처리
        if(strcmp(protocol_name,"HTTP")==0){
            hh = (struct http_header*)(buffer + sizeof(struct ethhdr) + iphdr_len + sizeof(struct tcphdr));
            int http_size = remaining_data;
        }

        make_logdir();  // 로그 디렉토리 생성
        char filename[500]; // 로그 파일 이름 배열
        char str_frame[10]; // 패킷 프레임 번호 배열

        // 패킷 넘버 숫자 정렬
        if(packet_num < 10){
            sprintf(str_frame,"000%d",packet_num);
        }else if(10 <= packet_num && packet_num < 100){
            sprintf(str_frame,"00%d",packet_num);
        }else if(100 <= packet_num && packet_num < 1000){
            sprintf(str_frame,"0%d",packet_num);
        }else if(1000 <= packet_num && packet_num < 10000){
            sprintf(str_frame,"%d", packet_num);
        }

        // 다음 프로토콜 이외에 프로토콜 패킷 캡쳐 무시
        if(!(strcmp("HTTP",protocol_name)==0 || (strcmp("ICMP",protocol_name)==0) || (strcmp("DNS",protocol_name) == 0) || (strcmp("https-tls",protocol_name) == 0))){
            continue;
        }

        char destIP[60];
        strcpy(destIP, inet_ntoa(dest.sin_addr));   // 목적지 IP 설정
        sprintf(filename,"./logdir/%s_%s_%s_%s.txt",str_frame,inet_ntoa(source.sin_addr),destIP,protocol_name); // 수집한 패킷 파일 이름 설정
        log_file = fopen(filename, "w");   // 파일 오픈
        log_eth(eth);   // 이더넷 로그 작성
        log_ip(ip); // ip 로그 작성

        // 각 프로토콜 별 로그 작성
        if(protocol == ICMP){
            struct icmp *icmp = (struct icmp*)(buffer + sizeof(struct ethhdr) + iphdr_len);
            struct ih_idseq *ih_idseq = (struct ih_idseq*)(buffer + iphdr_len + sizeof(struct ethhdr) + sizeof(struct ih_idseq));

            log_icmp(icmp,ih_idseq);
        }else if(protocol == TCP){
            struct tcphdr *tcp = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + iphdr_len);

            log_tcp(tcp);
        }else if(protocol == UDP){
            struct udphdr *udp = (struct udphdr*)(buffer + sizeof(struct ethhdr) + iphdr_len);

            log_udp(udp);
        }

        // DNS 로그 작성
        if(strcmp(protocol_name, "DNS") == 0){
            struct dns_header *dns = (struct dns_header *)(buffer + sizeof(struct ethhdr) + sizeof(struct udphdr) + iphdr_len);
            struct dns_question *que = (struct dns_question *)(buffer + iphdr_len + sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct dns_question));
            struct dns_resource_record *res = (struct dns_resource_record *)(buffer + iphdr_len + sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct dns_resource_record));
            struct dns_handle *han = (struct dns_handle *)(buffer + iphdr_len + sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct dns_handle));

            log_dns(dns,que,res,han);
        }

        // HTTP, HTTPS 로그 작성
        if(strcmp(protocol_name, "HTTP") == 0){
            fprintf(log_file, "=====HTTP===== \n");
            fprintf(log_file, "%s \n", hh->http_first);
            protocol = HTTP;
        }
        if(strcmp(protocol_name, "https-tls") == 0)
            protocol = 443;

        log_data(data, remaining_data, protocol);
        log_data_char(data, remaining_data, protocol);

        // 파일 종료
        fclose(log_file);
        get_logdir();

        char str1[60];
        char str2[60];

        strcpy(str1,inet_ntoa(source.sin_addr));
        strcpy(str2,inet_ntoa(dest.sin_addr));

        // 수집 내용 출력
        printf("  %04d | \t",packet_num);
        switch (strlen(str1))
        {
            case 7:
                printf(" %-20s  \t",str1);
                break;
            case 8:
                printf(" %-19s  \t",str1);
                break;
            case 9:
                printf(" %-18s  \t",str1);
                break;
            case 10:
                printf(" %-17s  \t",str1);
                break;
            case 11:
                printf(" %-16s  \t",str1);
                break;
            case 12:
                printf(" %-15s  \t",str1);
                break;
            case 13:
                printf(" %-14s  \t",str1);
                break;
            case 14:
                printf(" %-13s  \t",str1);
                break;
            case 15:
                printf(" %-12s  \t",str1);
                break;
            default:
                break;
        }         
        
        switch (strlen(str2))
        {
            case 7:
                printf(" %-20s  \t",str2);
                break;
            case 8:
                printf(" %-19s  \t",str2);
                break;
            case 9:
                printf(" %-18s  \t",str2);
                break;
            case 10:
                printf(" %-17s  \t",str2);
                break;
            case 11:
                printf(" %-16s  \t",str2);
                break;
            case 12:
                printf(" %-15s  \t",str2);
                break;
            case 13:
                printf(" %-14s  \t",str2);
                break;
            case 14:
                printf(" %-13s  \t",str2);
                break;
            case 15:
                printf(" %-12s  \t",str2);
                break;
            default:
                break;
        }
        printf("    %s  \t \n",protocol_name);

        packet_num++;
        file_num = packet_num;

        free(buffer);
    }

    return 1;
}

void make_logdir(){
    char path[] = {"./logdir"};
    mkdir(path, 0755);
}

// 파일 리스트 ls
void get_logdir(){
    log_file_dir = fopen("logdir_list.txt", "w");
    DIR *dir = opendir("logdir");
    if(dir == NULL){
        printf("failed open\n");
    }

    struct dirent *de = NULL;

    while((de = readdir(dir))!= NULL)
    {
        fprintf(log_file_dir, "%s\n",de->d_name);
    }
    closedir(dir);
    fclose(log_file_dir);
}

// 로그 디렉토리 삭제
void delete_logdir(){
    char path[] = {"./logdir"};
    int result = rmdirs(path,1);

    if(result == -1){
        printf("delete_logdir Error\n");
    }
}

// 로그 디렉토리 내 파일 삭제
int rmdirs(const char *path, int force){
    DIR *dir_ptr = NULL;
    struct dirent *file = NULL;
    struct stat buf;
    char filename[1024];

    if((dir_ptr = opendir(path)) == NULL){
        return unlink(path);
    }

    while((file = readdir(dir_ptr)) != NULL){
        if(strcmp(file->d_name,".")==0 || strcmp(file->d_name,"..")==0){
            continue;
        }

        sprintf(filename, "%s/%s", path, file->d_name);

        if(lstat(filename,&buf)==-1){
            continue;
        }

        if(S_ISDIR(buf.st_mode)){
            if(rmdirs(filename,force)==-1 && !force){
                return -1;
            }
        }
        else if(S_ISREG(buf.st_mode) || S_ISLNK(buf.st_mode)){
            if(unlink(filename)==-1&&!force){
                return -1;
            }
            printf("파일삭제 %s\n",file->d_name);
        }
    }

    close((long int)dir_ptr);
    return rmdir(path);
}

// 로그 디렉토리 내 파일 갯수 확인
int packet_analyze(char *filters){
	struct dirent **namelist;
	int plus = 0;
	int count = 0;
	int idx;
	
	const char *path = "./logdir";
	
	if((count = scandir(path, &namelist, NULL, alphasort)) == -1){
		fprintf(stderr,"%s direntory scan error\n",path);
		return -1;
	}
	
	if(strcmp(filter,"")==0 && strcmp(filter2,"")==0){
		plus = 2;
	}
	else{
		plus = 2;
	}
	
	for(idx = plus;idx<count;idx++){
		strcpy(file_list[idx-plus],namelist[idx]->d_name);
	}
	
	printf("반환된 count : %d\n",count);
	
	for(idx = 0; idx<count; idx++){
		free(namelist[idx]);
	}
	
	free(namelist);
	
	return 0;
}

// 파일 리스트 출력
int list_view(char *filters){
	struct dirent **namelist;
	int plus = 0;
	int count = 0;
	int idx;

	const char *path = "./logdir";

	printf("Filter : %s // %s  \n", filter, filter2);	

	if((count = scandir(path, &namelist, file_select, alphasort)) == -1){
		fprintf(stderr, "%s direntory scan error\n", path);
		return -1;
	}

	// .이나 ..을 계산에서 제외시키기 위함이다.
	if(strcmp(filter,"")==0 && strcmp(filter2,"")==0){
		plus = 2;
	}


	for(idx = plus; idx < count; idx++){
		//파일의 이름 출력
		printf("%s\n", namelist[idx]->d_name);
	}

	printf("반환된 count : %d\n", count);

	//file_list에 데이터 저장, 디버깅 완료

	for(idx = 0; idx < count; idx++){
		free(namelist[idx]);
	}

	free(namelist);

	return count;

}

// 이더넷 로그 파일 작성
void log_eth(struct ethhdr *eth){
    fprintf(log_file, "\n===== Ethernet Header =====\n");
    fprintf(log_file, "Source Address %.2X %.2X %.2X %.2X %.2X %.2X \n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[0]);
    fprintf(log_file, "Destination Address : %.2X %.2X %.2X %.2X %.2X %.2X \n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
}

// IP 로그 파일 작성
void log_ip(struct iphdr *ip){
    memset(&source, 0,sizeof(source));
    source.sin_addr.s_addr = ip->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip->daddr;

    fprintf(log_file, "\n===== IP Header =====\n");
    fprintf(log_file," -Version : %d \n",(unsigned int)ip->version);
    fprintf(log_file," -Internet Header Length(IHL) : %d bits \n",(unsigned int)ip->ihl * 4);
    fprintf(log_file," -Type of Service : %d \n", (unsigned int)ip->tos);
    fprintf(log_file," -Total Length : %d Bytes \n",ntohs(ip->tot_len));
    fprintf(log_file," -Identification : %d \n",ntohs(ip->id));
    fprintf(log_file," -Time To Live : %d \n",(unsigned int)ip->ttl);
    fprintf(log_file," -Protocol : %d \n",(unsigned int)ip->protocol);
    fprintf(log_file," -Header Checksum : %d \n",htons(ip->check));
    fprintf(log_file," -Source IP : %s \n",inet_ntoa(source.sin_addr));
    fprintf(log_file," -Destination IP : %s \n",inet_ntoa(dest.sin_addr));
}

// ICMP 로그 파일 작성
void log_icmp(struct icmp *icmp,struct ih_idseq *ih_idseq){		
	fprintf(log_file, "===== ICMP =====\n");									
	fprintf(log_file, "-Type : %d \n", (unsigned int)icmp->icmp_type);			
	fprintf(log_file, "-Code : %d \n", (unsigned int)icmp->icmp_code);		
	fprintf(log_file, "-Checksum : Ox%.4x\n", (unsigned int)icmp->icmp_cksum); 
	fprintf(log_file, "-Identifier(LE) : Ox%.4x \n", ih_idseq->icd_id); 
	fprintf(log_file, "-Sequence number(LE) : Ox%.4x \n", ih_idseq->icd_seq);					
}	

// TCP 로그 파일 작성
void log_tcp(struct tcphdr *tcp){
	fprintf(log_file,"===== TCP =====\n");
	fprintf(log_file, " -Source Port : %d \n", ntohs(tcp->source));
	fprintf(log_file," -Destination Port : %d \n", ntohs(tcp->dest));
	fprintf(log_file," -Sequence Number : %x \n", tcp->seq);
	fprintf(log_file," -Acknowldge Number : %x \n", tcp->ack_seq);
}

// UDP 로그 파일 작성
void log_udp(struct udphdr *udp){
	fprintf(log_file,"===== UDP =====\n");
	fprintf(log_file, " -Source Port : %d \n", ntohs(udp->source));
	fprintf(log_file," -Destination Port : %d \n", ntohs(udp->dest));
	fprintf(log_file," -UDP Length : %d \n", ntohs(udp->len));
	fprintf(log_file," -Checksum  : %d \n", ntohs(udp->check));
}

// HTTP(S) 로그 파일 작성
void log_data(unsigned char *data, int remaining_data, int protocol){
	if(protocol == HTTP){
		return;
	}

	fprintf(log_file,"===== DATA =====\n");
	for(int i = 0; i < remaining_data; i++){
		if(i!=0){
			fprintf(log_file, "%.2x ", data[i]);
			if(i%16 == 0)
				fprintf(log_file, "\n");
		}
    }
	fprintf(log_file, "\n");	
}

void log_data_char(unsigned char *data, int remaining_data, int protocol){
	fprintf(log_file,"===== CHAR DATA =====\n");
	for(int i = 0; i < remaining_data; i++){
		if(i!=0){
			if(('!' < data[i] && data[i] < 'z')){
				fprintf(log_file,"%c", data[i]);
			}
			else{
				fprintf(log_file,"%c", '.');
			}
		
			if(i%16 == 0)
				fprintf(log_file, "\n");
		}
	}
	fprintf(log_file, "\n");	
}

// dns 로그 파일 작성
void log_dns(struct dns_header *dns, struct dns_question *que, struct dns_resource_record *res, struct dns_handle *han) {
	unsigned char *data;
	fprintf(log_file, "===== DNS =====\n"); 
	fprintf(log_file, "-Transaction ID :Ox%x \n", dns->xid);
	fprintf(log_file, "Flags : %d \n", dns->flags);
	if (dns->flags == 1) {
		fprintf(log_file, "Flags: Standard query \n");
	}
	else if (dns->flags == 32897) {
		fprintf(log_file, "Flags : Standard query response, No error \n");
	}
	fprintf(log_file, "Questions : %d \n", dns->qdcount / 256);       
	fprintf(log_file, "Answer RRs : %d \n", dns->ancount / 256);      
	fprintf(log_file, "Authority RRs : %d \n", dns->nscount / 256);   
	fprintf(log_file, "Additional RRs : %d \n", dns->arcount / 256);  

	if ((long int)que->name == 1986096645) { 
		fprintf(log_file, "Queries name : www.naver.com \n"); 
	} 
	else if ((long int)que->name == 1869571846) { 
		fprintf(log_file, "Queries name : www.google.com \n"); 
	}
	else if ((long int)que->name == 1970301699) {
		fprintf(log_file, "Queries name : www.kpu.ac.kr \n"); 
	} 
	if ((long int)que->name == 1986096645 && que->type == 28015) { 
		fprintf(log_file, "Queries type : A \n");
	} 
	if ((long int)que->name == 1986096645 && que->class == 0) { 
		fprintf(log_file, "Queries class : IN \n");
	} 
	if ((long int)que->name == 1986096645 && que->class == 28165) { 
		fprintf(log_file, "Queries class : IN \n"); 
	} 
	if ((long int)que->name == 1869571846 && que->type == 28515) {
		fprintf(log_file, "Queries type : A \n"); 
	} 
	if ((long int)que->name == 1869571846 && que->class == 109) {
		fprintf(log_file, "Queries class : IN \n");
	}if ((long int)que->name == 1970301699 && que->type == 29291) {
		fprintf(log_file, "Queries type : A \n"); 
	} 
	if ((long int)que->name == 1970301699 && que->class == 0) {
		fprintf(log_file, "Queries class : IN \n");
	} 
}

// 선택 패킷의 도착지 주소를 패킷2로 저장한다.
int associate_file(int ch, int flag){

	// ch범위를 벗어나면 필터동작 X, 번호를 다시 확인
	if(0 <= ch && ch <= packet_num){
		tokenizer(file_list[ch]);
		printf("연관 필터 적용 : %s \n", file_token[1]);
		strcpy(filter2 ,file_token[1]);
	}
	else{
		printf("입력값 재확인  \n");
	}
}

// 파일 선택 함수 
int file_select(const struct dirent *entry)
{
	char temp_filter[80] = "";
	strcpy(temp_filter, entry->d_name); // 파일 이름 복사

	// 파일 이름 내에서 필터 검색
	if(strstr(temp_filter, filter) && (strstr(temp_filter, filter2))){
		return 1;
	}
	else{
		return 0;
	}
}

// ch. ch패킷 선택
void file_read(int ch)
{
	read_file = NULL;
	char dir_path[120] = "./logdir/";	// 로그 파일 디렉토리 지정
	char path[120]; 
	
	strcpy(path, file_list[ch]);		// 파일 리스트 저장
	strcat(dir_path, path);				// 로그 파일 디렉토리 갱신

	read_file = fopen(dir_path,"r");	// 로그 파일 오픈
	printf("입력 확인 %d \n", ch);
	printf("실행 파일  %s \n", dir_path);

	if(read_file != NULL)
	{
		char strTemp[4096];
		char *pStr;

		// 파일 읽고 출력
		while( !feof(read_file))
		{
			pStr = fgets(strTemp, sizeof(strTemp), read_file);
			printf("%s", strTemp);
		}
		fclose(read_file);
	}
	else
	{
		printf("read_file Error \n");
	}

}

void packetSelect(){
	int input = 0;
	printf("분석할 패킷의 프레임 번호 : ");
	scanf(" %d",&input);
	getchar();
	
	if(input > packet_num || input < 0){
		printf("잘못된 입력 \n");
		return;
	}
	
	file_read(input);
}

// 메뉴
void print_menu(){
	printf("\n=====Program Menu=====\n");
	printf("1.Capture Start \n");
	printf("2.List View \n");
	printf("3.Select Packet\n");
	printf("4.set Filter \n");
	printf("5.set associate Filter \n");
	printf("6.reset Filter \n");
    printf("7.ping transfer \n");
    printf("8.exit \n");
}

// 시그널 설정 함수
void close_sighandler(void){
    printf("\n=====Pcap End=====\n");
    close(rawsocket);
}

// 문자열 분리
void tokenizer(char str[1024]){
	char temp[1024];
	char *ptr;
	int i = 0;

	strcpy(temp, str);
	ptr = strtok(temp, "_");
	
	while(ptr != NULL){
		strcpy(file_token[i], ptr);
		i++;
		ptr = strtok(NULL, "_");
	}
}

// 핑 전송
void *ping_transfer()
{
    system("ping computer.kpu.ac.kr&"); // 백그라운드로 실행 ctrl+c 입력시 종료
    printf("\n");
}
