# KPU_WireShark (2021.10~12)

> rawsocket을 이용한 패킷 캡처 프로그램  

## 서버 환경

### 1. 프로토콜 별 시현 서버  

    HTTP– www.kpu.ac.kr  
    DNS – ns.kpu.ac.kr  
    ICMP –  google.com  

### 2. 클라이언트 환경

- 구동 운영체제  
  - 리눅스 ( 우분투 18.04.0 LTS )
- 사용 명령어
  - Curl  
  - Nslookup
  - Ping

## 실행 방법

```bash
> cd wireshark
> make
> sudo ./rawsocker #관리자 권한이 필요하다.

=====Program Menu=====
1.Capture Start  # 패킷 캡처
2.List View      # 캡처링한 패킷들 보기 
3.Select Packet  # 패킷 세부 내용 보기 , ./logdir에 저장된다.
4.set Filter     # 필터링 
5.set associate Filter # 2중 필터링
6.reset Filter   # 필터 제거
7.exit           # 종료

input :
```  

## 패킷 캡처

<img src="./images/capture.jpg">

> 네트웍 인터페이스 카드에 들어오는 모든 패킷들에 대해서 접근할 수 있다.  


## 패킷 세부 내용 보기

> 분석한 패킷은 http, dns, icmp프로토콜에 대해서 조사했다.  
> 아래 예제는 icmp 패킷의 예이다.  
> "./Document/구현결과.pptx"에서 자세히 설명했다.  

```bash
===== Ethernet Header =====
Source Address 00 15 5D A3 AA AE 
Destination Address :00 15 5D 4C 3E E4 

===== IP Header =====
 -Version :4 
 -Internet Header Length(IHL) : 20 bits 
 -Type Of Service :0 
 -Total Length :84 Bytes 
 -Identification :9257 
 -Time To Live :64 
 -Protocol :1 
 -Header Checksum :2472 
 -Source IP :172.18.94.196 
 -Destination IP :1.1.1.1 
===== ICMP =====
-Type : 8 
-Code : 0 
-Checksum : Oxb8cd
-Identifier(LE) : Oxfe01 
-Sequence number(LE) : Ox8502 
===== DATA =====
15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 
25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 
35 36 37 
===== CHAR DATA =====
............."#$
%&'()*+,-./01234
567
```

> Ping 통신시 캡처링된 패킷의 예시  
