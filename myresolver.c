/**
 * DNS resolver
 * This DNS resolver takes a valid domain name as input and 
 * iteratively query DNS name servers for the corresponding 
 * IP address.
 * (reference: http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/)
 * 
 * Author: Dongpu Jin
 * Date: 3/18/2013
 */ 
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <unistd.h> // for getpid()
#include <netdb.h>  // gethostbyname(), used only on root servers
#include <arpa/inet.h>

#define BUFLEN 65536
#define PORT 53
#define T_A 1  // host address  
#define T_NS 2 // name server
#define T_CNAME 5 // primary name for an alias 

/**
 * struct for the message header
 */
typedef struct HEADER {
    unsigned short id; // 16 bit id

    unsigned char rd : 1; // 1 bit, recursion desired
    unsigned char tc : 1; // 1 bit, truncated 
    unsigned char aa : 1; // 1 bit, authoritative answer 
    unsigned char opcode : 4; // 4 bit, opcode 
    unsigned char qr : 1; // 1 bit, question or response   

	unsigned char rcode : 4; // 4 bit, response code
	unsigned char z : 3; // for future, set to zero 
	unsigned char ra : 1; // recursion available 

    unsigned short qdcount; // number of questions entries 
    unsigned short ancount; // number of RRs in answer section 
    unsigned short nscount; // # of ns RRs in authority record section  
    unsigned short arcount; // # of RRs in additional records section  
} HEADER;

/**
 * struct for the fix portion of the the question segment
 */ 
typedef struct QUESTION_FIX{ // fixed portion of the question 
    unsigned short qtype; // 16 bit, type of the query
    unsigned short qclass; // 16 bit, class of the query
}QUESTION_FIX;

/**
 * struct for the question segment
 */ 
typedef struct QUESTION{
    unsigned char *qname;  // name with vary size
    QUESTION_FIX *question_fix; 
}QUESTION; 

/**
 * struct for the fix portion of resource record
 */  
typedef struct __attribute__((__packed__))RR_FIX{
    unsigned short type;  // 16 bit, one of the RR type code 
    unsigned short _class; //16 bit, class of data in RDATA field
    unsigned int ttl; // 32, time interval RR be cached before discard
    unsigned short rdlength; // 16, length of rdata field 
}RR_FIX; 

/**
 * struct for the resource record 
 */ 
typedef struct RR{
    unsigned char *name;  // domain name 
    RR_FIX * rr_fix; 
    unsigned char *rdata; // describes the resource 
} RR; 

/**
 * struct to store RR in the response message
 */ 
typedef struct RESULTS {
	unsigned short aa; // authoritative answer 
    unsigned short rcode; // error
	
    unsigned short ancount; // number of RRs in answer section 
    unsigned short nscount; // # of ns RRs in authority record section  
    unsigned short arcount; // # of RRs in additional records section  
	
	RR answers[20]; // array to store answers 
	RR auth[20];  // array to store authority
	RR addit[20];  // array to additional 
} RESULTS;

/**
 * struct to store IP results
 */
typedef struct IP_RESULTS {
	unsigned int cnt; // number of ip addresses
	 char* names[20]; // hostname list
	 char* ips[20]; // a list of ip, maximum 20
} IP_RESULTS;
 
/**
 * function signatures 
 */ 
void error(char*);  
IP_RESULTS myGetHostByName(unsigned char*);
RESULTS getIP(unsigned char*, unsigned char*, int); 
unsigned char* binToDecIP(unsigned char*);  
unsigned char* getRootIP();
void htonName(unsigned char*, unsigned char []);
unsigned char* ReadName(unsigned char*, unsigned char*, int*); 

/**
 * entry of the program
 */ 
int main(int argc, char* argv[]){ 
	// check number of arguments 
	if (argc != 2){
		printf("Invalid number of arguments. Exit!\n"); 
		exit(1); 
	}
	
	// get host name and root server ip address 
	unsigned char *hostname = argv[1];
 
	// print ip address for hostname if exist
	IP_RESULTS ip_results; 
	ip_results = myGetHostByName(hostname); 
	
	// print the ip address for the given hostname
	int i;  
	for (i = 0; i < ip_results.cnt; i++){
		printf("%s A = %s\n", ip_results.names[i], ip_results.ips[i]); 
	}
	 
    return 0; 
}

/**
 * get the IP address for a given host, start from root
 */ 
IP_RESULTS myGetHostByName(unsigned char* hostname){
	unsigned char *ip_addr = getRootIP(); 
	 
	RESULTS results, results2;  // stores RR in the response
	int found = 0; // found flag, 0: not found yet; 1: found;  
	int cnt; // counter 
	
	// iteratively visit name servers until find auth server
	while(found == 0) {  	
		memset(&results, 0, sizeof(results)); // clear memory
		//printf("test: host: %s, ip: %s\n", hostname, ip_addr); 
		results = getIP(hostname, ip_addr, T_A); 
		if (results.aa != 0){ // found 
			found = 1; // set found flag to 1
			
			// invalid name, print error 
			if(results.rcode == 3){ 
				printf("%s A = does not exist\n", hostname);
				exit(1); 
			}
			
			IP_RESULTS ip_list; // stores ip addresses
			memset(&ip_list, 0, sizeof(ip_list)); 
			// valid name, print ip
			for (cnt = 0; cnt < results.ancount; cnt++){
				if (ntohs(results.answers[cnt].rr_fix->type) == T_CNAME){ // aliases, follow the chain
					printf("%s A = CNAME to %s\n", results.answers[cnt].name, results.answers[cnt].rdata); 
					hostname = results.answers[cnt].rdata; // get alias hostname
					ip_addr = getRootIP(); // get root ip address 
					found = 0; // reset found
					ip_list.cnt = 0; // reset cnt in the ip list 
					break; 
				}
				if(ntohs(results.answers[cnt].rr_fix->type) == T_A) { // ip addresses
					ip_list.names[ip_list.cnt] = (char*) malloc (100 * sizeof(char));
					strcpy(ip_list.names[ip_list.cnt], results.answers[cnt].name);
					
					ip_list.ips[ip_list.cnt] = (char*) malloc (100 * sizeof(char));
					strcpy(ip_list.ips[ip_list.cnt], binToDecIP(results.answers[cnt].rdata)); 
					
					ip_list.cnt++; 
				}
			}
			
			if (ip_list.cnt > 0) { // return a list of ip addr list 
				return ip_list; 
			}
		}
		else{ // not found 
			if (results.arcount != 0){ // there are additional sections
				// find first suggested NS that has no error 
				for (cnt = 0; cnt < results.arcount; cnt++){  
					if (ntohs(results.addit[cnt].rr_fix->type) == T_A) { // check type
						ip_addr = binToDecIP(results.addit[cnt].rdata); // ip
						memset(&results2, 0, sizeof(results2)); // clear memory
						results2 = getIP(hostname, ip_addr, T_A);
						if(results2.rcode == 0 || results2.rcode == 3) { 
							break; // no error but allow name error
						}
					}
				} // end for
				
				// cannot find, all NSs are down
				if (cnt != 0 && cnt == results.arcount){ 
					printf("Namer servers are down. Exit!\n"); 
					exit(1); 
				}
			}
			else if (results.nscount != 0){ // there is no addi section but auth section 
				// search ip for ns in auth section and start from root 
				for (cnt = 0; cnt < results.nscount; cnt++){ // find first available ns
					if (ntohs(results.auth[cnt].rr_fix->type) == T_NS) { // check type 
						unsigned char* authns = NULL; // to store ip for ns in auth section
						authns = results.auth[cnt].rdata;
						// get ip for this ns 
						if (authns != NULL){ 
							IP_RESULTS ip_list2 = myGetHostByName(authns); 
							if(ip_list2.cnt > 0){ // get first ip 
								ip_addr = ip_list2.ips[0];
								break; 
							}
						} 
					}
				} // end for
				
			}
			else{ // there is no addi and auth section
				printf("%s A = does not exist. Exit!\n", hostname);
				exit(1); 
			}
		} // end of "else not found"
	}// end of while
}

/**
 * get the IP address for a given host 
 */ 
RESULTS getIP(unsigned char* hostname, unsigned char* ip_addr, int query_type){
	int i, j; // loop counters
	int stop; // number of bytes into name field 
    struct sockaddr_in dest; // socket addr send to 
    int s; // socket file descriptor  
    char buf[BUFLEN]; // message to send 

    // create socket
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); // internet, datagram, udp
    
    if(s == -1) error ("socket"); // error

    // initialize socket which send to
    dest.sin_family = AF_INET; // internet 
    dest.sin_port = htons(PORT); // which port server listen to
	dest.sin_addr.s_addr = inet_addr(ip_addr); // set server IP addr
    
    // initialize the header 
    HEADER *msg_h = NULL; 
    msg_h = (HEADER *)&buf; // points to beginning of buf
    msg_h->id = (unsigned short) htons(getpid()); // process id
    msg_h->qr = 0; // query
    msg_h->opcode = 0; // standard query
    msg_h->aa = 0; // not authoritative 
    msg_h->tc = 0; // not truncated
	msg_h->rd = 0; // no recursion, not multi-byte, no conversion
    msg_h->ra = 0; // recursion not available 
    msg_h->z = 0; 
    msg_h->rcode = 0; // no error
    msg_h->qdcount = htons(1); // 1 question
    msg_h->ancount = 0; // 0 answer
    msg_h->nscount = 0; // 0 NS RR
    msg_h->arcount = 0; // 0 addition RR
    
    // qname points to first byte of question field 
    unsigned char * qname;
    qname = (unsigned char*)&buf[sizeof(HEADER)]; 
    htonName(qname, hostname); // build name
	
    QUESTION_FIX * question_fix = NULL; 
    question_fix = (QUESTION_FIX*) &buf[sizeof(HEADER) + strlen(qname) + 1]; // including '\0'
    question_fix->qtype = htons(query_type); // T_A
    question_fix->qclass = htons(1); // internet
    
    if(sendto(s, buf, sizeof(HEADER) + strlen(qname) + 1 + sizeof(QUESTION_FIX), 0, (struct sockaddr*)&dest, sizeof(dest)) == -1){
        error("sendto()"); 
    }
	
    // receiving message, stored in dest
    memset(&buf, 0, sizeof(buf)); // clear out the buf
    int slen = sizeof(dest);
    if (recvfrom(s, buf, BUFLEN, 0, (struct sockaddr*)&dest, &slen) == -1) {
        error("recvfrom()");
    }
    close(s); // close the socket
	
	// parse the response message 
    HEADER * msg2_h; 
    msg2_h = (HEADER *) buf; 
	
	// check if message id match
	if (msg_h->id != msg2_h->id) {
		printf("Messages ID mismatch. Exit!\n"); 
		exit(1); 
	}
	
	// check if it is a response
	if (msg2_h->qr == 0) {
		printf("Message is not a response. Exit!\n"); 
		exit(1); 
	}
	  
	RESULTS results;  // stores RR in the response 
	results.aa = ntohs(msg2_h->aa); // ??
	results.rcode = msg2_h->rcode; 
	results.ancount = ntohs(msg2_h->ancount); 
	results.nscount = ntohs(msg2_h->nscount); 
	results.arcount = ntohs(msg2_h->arcount); 
	
	unsigned char *reader; // reading RR from memory 
    reader = &buf[sizeof(HEADER) + strlen(qname) + 1 + sizeof(QUESTION_FIX)];

	// reading answers  
	for (i = 0; i < ntohs(msg2_h->ancount); i++){
		// Note here reader is pointer, but is passed by value
		results.answers[i].name = ReadName(reader, buf, &stop); 
		// reader points to first byte of RR_FIX field 
        reader  = reader + stop; 
		
		results.answers[i].rr_fix = (RR_FIX*) reader;
		//reader points to first byte of rdata field 
		reader = reader + sizeof(RR_FIX);
		
		int rdlength = ntohs(results.answers[i].rr_fix->rdlength); // get length of rdata
		int type = ntohs(results.answers[i].rr_fix->type); // get answer type 
  
		if(type == 1){ // A, ip
			// allocate space for rdata field
			results.answers[i].rdata = (unsigned char*)malloc(rdlength);
			
			// read each char from rdata
			for (j = 0; j < rdlength; j++){
				results.answers[i].rdata[j] = reader[j];
			}
			
			// place a null char at the end
			results.answers[i].rdata[rdlength] = '\0';
			// reader points to the beginning of next RR
			reader = reader + rdlength; 
		}  
		else{ // not ip, must be domain name?
			results.answers[i].rdata = ReadName(reader, buf, &stop);
			reader = reader + stop; 
		}
		
	}
	
	// read authoritives 
	for (i = 0; i < ntohs(msg2_h->nscount); i++){
		results.auth[i].name = ReadName(reader, buf, &stop);
		// reader points to rr_fix field 
		reader = reader + stop; 
		
		results.auth[i].rr_fix = (RR_FIX*)reader; 
		// reader points to rdata field 
		reader = reader + sizeof(RR_FIX);

		results.auth[i].rdata = ReadName(reader, buf, &stop); 
		// reader points to next RR field 
		reader = reader + stop; 
	}
	
	// read additionals 
	for (i = 0; i < ntohs(msg2_h->arcount); i++){
		results.addit[i].name = ReadName(reader, buf, &stop);
		// reader points to rr_fix field 
		reader = reader + stop; 
		
		results.addit[i].rr_fix = (RR_FIX*)reader; 
		// reader points to rdata field 
		reader = reader + sizeof(RR_FIX); 
		
		int type = ntohs(results.addit[i].rr_fix->type); // get type 
		int rdlength = ntohs(results.addit[i].rr_fix->rdlength); // get rdata length
		
		// read rdata
		if(type == 1 || 28){ // A: ip; AAAA: ipv6
			// allocate space for rdata
			results.addit[i].rdata = (unsigned char*)malloc(rdlength);
			for(j = 0; j < rdlength; j++){
				// read each char from rdata
				results.addit[i].rdata[j] = reader[j];
			}
			
			// set last char to '\0'
			results.addit[i].rdata[rdlength] = '\0';   
			 
			// reader points to next RR
			reader = reader + rdlength; 
		} else{ // not A, domain name? 
			results.addit[i].rdata = ReadName(reader, buf, &stop);
			// reader points to next RR
			reader = reader + stop; 
		}
	}
	
	return results;  
}

/**
 * Convert 32-bit binary IP address to dot seperated char array
 */ 
unsigned char* binToDecIP(unsigned char* binIP){
	return inet_ntoa(*((struct in_addr *)binIP)); // convert
}

/**
 * get the ip address of the given root 
 */ 
unsigned char* getRootIP(){
	// the list of root servers 
	char* rootServerList[13] = {
		"a.root-servers.net", 
		"b.root-servers.net", 
		"c.root-servers.net",
		"d.root-servers.net",
		"e.root-servers.net",
		"f.root-servers.net",
		"g.root-servers.net",
		"h.root-servers.net",
		"i.root-servers.net",
		"j.root-servers.net",
		"k.root-servers.net",
		"l.root-servers.net",
		"m.root-servers.net",
	}; 
	
	// find the first available root server 
	int i; // counter 
	struct hostent *lh; 
	for (i = 0; i < 13; i++){
		if(lh = gethostbyname(rootServerList[i])){ 
			return binToDecIP(lh->h_addr);
		}
	} 
	
	printf("Cannot access root servers. Exit!\n");
	exit(1); 
	return; 
}

/**
 * Read domain main from RR and convert it from 3unl3edu0 format 
 * to unl.edu format. 
 * reader: points to curr location in memory
 * buffer: the char array stores message
 * count: count how far we are in the name field 
 */ 
unsigned char* ReadName(unsigned char* reader, unsigned char* buffer, int* count){
	// allocate space for name
	unsigned char *name; 
	name = (unsigned char*) malloc(256); 
	name[0] = '\0'; // in case the name is empty 

    unsigned int jumped = 0; // tells us whether there is compression 
    unsigned int p = 0; // index of name
    unsigned int offset; // offset in ptr
	
	// always points to the next byte after the 
	// last read char in the name field
	*count = 1;  
	
    // read name in 3unl3edu0 format, reader loop through all chars
	while(*reader != 0){ // name always ends with 0
		if (*reader >= 192){ // 11000000 = 192, ptr
            // calculate offset
            // 256: shift left 8 bits of the left part
            // 49152: 11000000 00000000
            offset = (*reader) * 256 + *(reader + 1) - 49152; 
            
            // move reader to new position pointed by offset
            // buffer points to begining: position 1
            reader = buffer + offset; 
            jumped = 1; // jumped, no count
		}
        else{
            name[p] = *reader; // read current char
            p = p + 1; // point to next available slot
			reader = reader + 1; // point to next char, ptr arithmetic
        }

        if (jumped == 0){
            *count = *count + 1; // if no jump, count
        }
	} // end of while 

    name[p] = '\0'; // end of char array

    //makes sense, points to last byte of offset
    if (jumped == 1){
		// number of steps moved forward in name field
        *count = *count + 1; 
    }

    // convert 3unl3edu0 to unl.edu
    int i, j, num; 
    for(i = 0; i < strlen(name); i++){ // loop through each char
        num = name[i]; // get leading number
        for(j = 0; j < (int)num; j++){ // loop through each section
            name[i] = name[i + 1]; 
            i = i + 1; 
        }
        // now, i points to the char before next leading number
        name[i] = '.'; // replace by dot
    }
    // remove last .
    name[i - 1] = '\0'; 

    return name; 
}

/**
 * convert host name format (unl.edu or unl.edu.) to DNS
 * format (3unl3edu0). 
 */ 
void htonName(unsigned char* target,unsigned char host[]) 
{
	int lock = 0; // points to first char of a segment in host
	int i, j; // counters 
	int l; // length of each segment
	if (host[strlen((char*)host) - 1] != '.'){
		strcat((char*)host, "."); // append dot at the end
	}
	  
	for(i = 0 ; i < strlen((char*)host) ; i++) 
	{
		if(host[i]=='.') 
		{
			l = i - lock; // get segment length 
			*target = l; // leading number (NOT CHAR!!!)
			target = target + 1; // points to next position
			for(j = 0; j < l; j++)
			{
				*target = host[lock + j]; 
				target = target + 1; // points to next position
			}
			lock = i + 1; // upcate lock
		}
	}
	*target = 0; // tailing 0
	target = target + 1; 
	*target = '\0'; // end of char array
}

/**
 * report error with given string
 */ 
void error(char *s){
    perror(s); 
    exit(1); 
}
