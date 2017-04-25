/*#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //memset
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/if_ether.h>	//For ETH_P_ALL
#include<net/ethernet.h>	//For ether_header
#include<unistd.h>      //close fn*/


#define buffer_size 65536 

int stop_prog=0;	//to see if user requested to stop program
int pause_prog=0;	//to see if user requested to pause program
int reset_prog=0;	//to see if user requested to reset statistics
FILE* fp;			//file pointer to write ontottp
FILE* fp_http;
FILE* fp_ftp;
FILE* fp_tcp;
FILE* fp_udp;
FILE* fp_ip;
FILE* fp_arp;
struct sockaddr_in source;
struct sockaddr_in destination;
char endpacket[100]="###########################################################";

void analyse_FTP(unsigned char*, int);
void analyse_HTTP(unsigned char*, int);
void analyse_TCP(unsigned char*, int);
void analyse_UDP(unsigned char*, int);
void analyse_IP(unsigned char*, int);
void analyse_ARP(unsigned char*, int);
void WriteDataToFile (FILE*, unsigned char*, int);


struct packet_count{	//structure that maintains all packet count

int total_ip;
int total_arp;
int total_tcp;
int total_udp;
int total_http;
int total_ftp;
int total;




};



struct arp_header{

    u_int16_t hardware_type;    /* Hardware Type           */ 
    u_int16_t protocol_type;    /* Protocol Type           */ 
    u_char hardare_len;        /* Hardware Address Length */ 
    u_char protcol_len;        /* Protocol Address Length */ 
    u_int16_t oper_code;     /* Operation Code          */ 
    u_char sender_hardware_addr[6];      /* Sender hardware address */ 
    u_char sender_ip_addr[4];      /* Sender IP address       */ 
    u_char target_hardware_addr[6];      /* Target hardware address */ 
    u_char target_ip_addr[4];		/*Target IP address*/

};

void analyse_packet();

struct packet_count* counter;


void reset_counter(){	//function to reset file and stats

counter->total_ftp=0;
counter->total_http=0;
counter->total_udp=0;
counter->total_tcp=0;
counter->total_arp=0;
counter->total_ip=0;
counter->total=0;
fp=fopen("Log_File.txt","w");
if(fp==NULL){
	printf("Unable to create global log file\n");
	}


fp_tcp=fopen("Log_File_TCP.txt","w");
if(fp_tcp==NULL){
	printf("Unable to create TCP file\n");
	}


fp_http=fopen("Log_File_HTTP.txt","w");
if(fp_http==NULL){
	printf("Unable to create HTTP file\n");
	}


fp_ftp=fopen("Log_File_FTP.txt","w");
if(fp_ftp==NULL){
	printf("Unable to create FTP file\n");
	}

fp_udp=fopen("Log_File_UDP.txt","w");
if(fp_udp==NULL){
	printf("Unable to create UDP log file\n");
	}



fp_ip=fopen("Log_File_IP.txt","w");
if(fp_ip==NULL){
	printf("Unable to create IP log file\n");
	}

fp_arp=fopen("Log_File_ARP.txt","w");
if(fp_arp==NULL){
	printf("Unable to create ARP file\n");
	}









}


/*int main(){

int raw_socket;
raw_socket=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); //open raw socket and sniff onyl IP and ARP packets
int size_socket_addr;	
struct sockaddr socket_addr;
int packet_size;

unsigned char *buffer = (unsigned char *)malloc(buffer_size); 	 //intialise buffer
counter=(struct packet_count*)malloc(sizeof(struct packet_count));	  	//intialise counter pointer to store all packet count
reset_counter();											   //reset all stats intitally








if(raw_socket < 0)
    {
        printf("Unable to create socket\n");
        return -1;
    }

 while(stop_prog!=1)	//run loop until user wants to stop program in which case stop_prog is set to 1 
    {

    	if(reset_prog==1){	// if user has pressed reset then reset_prog is set to 1 and stats are reset and then reset_prog is changed back to 0

    		reset_counter();
    		reset_prog=0;
    	}

    	if(pause_prog==0){	// if user has paused execution
    		//NOTE: A user can reset even if the program is paused

        size_socket_addr = sizeof(socket_addr);
        packet_size = recvfrom(raw_socket,buffer,buffer_size,0,&socket_addr,&size_socket_addr);
        	if(packet_size<0)
        	{
            	printf("Cannot recieve packets\n");
            	return -1;
        	}
        
        analyse_packet(buffer,packet_size);// buffer is sent for analysing

        if(stop_prog==1)	// check if user wants to stop_prog
        	{
        		break;
        	

        	}
    	}


    }
    close(raw_socket);
    printf("Analysing Finished..Thank you for using our application");
    return 0;    




}*/

void analyse_packet(unsigned char* buffer, int buff_size){


counter->total++;
analyse_ARP(buffer,buff_size);

struct iphdr *ip_header = (struct iphdr*)(buffer+ sizeof(struct ethhdr));
analyse_IP(buffer,buff_size);
switch(ip_header->protocol){

case 6:analyse_TCP(buffer,buff_size);break;
case 17:analyse_UDP(buffer,buff_size);break;

}






}

void analyse_HTTP(unsigned char* buffer, int buff_size){

counter->total_http++;
    fprintf(fp,"\n\nHTTP Packet\n");
	fprintf(fp_http,"\n\nHTTP Packet\n");
WriteDataToFile(fp,buffer,buff_size);
WriteDataToFile(fp_http,buffer,buff_size);


}

void analyse_FTP(unsigned char* buffer, int buff_size){
	counter->total_ftp++;
    fprintf(fp,"\n\nFTP Packet\n");
	fprintf(fp_http,"\n\nFTP Packet\n");
WriteDataToFile(fp,buffer,buff_size);
WriteDataToFile(fp_http,buffer,buff_size);


}


void analyse_ARP(unsigned char* buffer, int buff_size){


///////////////////////
	counter->total_arp++;
struct arp_header *arph = (struct arp_header *)(buffer+14); /* Point to the ARP header */ 
int is_ether=0,is_ip=0,i;
	 fprintf(fp_arp,"Hardware type: ");
	 fprintf(fp,"Hardware type: ");
	if(ntohs(arph->hardware_type)==1){
		fprintf(fp_arp,"Ethernet\n");
		fprintf(fp,"Ethernet\n");
		is_ether=1;
	}
	else 
		fprintf(fp_arp,"Can't say\n");
		fprintf(fp,"Can't say\n");
	fprintf(fp_arp,"Protocol type: ");
	fprintf(fp,"Protocol type: ");
	if(ntohs(arph->protocol_type)==0x0800){
		fprintf(fp_arp,"IPv4\n");
		fprintf(fp,"IPv4\n");
		is_ip=1;
	}
	else 
		fprintf(fp_arp,"Can't say\n");
		fprintf(fp,"Can't say\n");

	fprintf(fp_arp,"Operations: ");
	fprintf(fp,"Operations: ");
 	if(ntohs(arph->oper_code)==1){
 		fprintf(fp_arp,"Request for ARP\n");
 		fprintf(fp,"Request for ARP\n");
}
 	else{
 		fprintf(fp_arp,"Reply for ARP\n");
		fprintf(fp,"Reply for ARP\n");
}
  
 		if(is_ip==1&&is_ether==1){

    fprintf(fp_arp,"Sender MAC: "); 
    fprintf(fp,"Sender MAC: "); 
    for(i=0; i<6;i++){
        fprintf(fp_arp,"%02X:", arph->sender_hardware_addr[i]); 
        fprintf(fp,"%02X:", arph->sender_hardware_addr[i]); 
}

    fprintf(fp_arp,"\nSender IP: "); 
fprintf(fp,"\nSender IP: "); 
    for(i=0; i<4;i++){
        fprintf(fp_arp,"%d.", arph->sender_ip_addr[i]); 
        fprintf(fp,"%d.", arph->sender_ip_addr[i]); 
}
    fprintf(fp_arp,"\nTarget MAC: "); 
    fprintf(fp,"\nTarget MAC: "); 
    for(i=0; i<6;i++){
        fprintf(fp_arp,"%02X:", arph->target_hardware_addr[i]); 
       fprintf(fp,"%02X:", arph->target_hardware_addr[i]); 

}
    fprintf(fp_arp,"\nTarget IP: "); 
    fprintf(fp,"\nTarget IP: "); 
    for(i=0; i<4; i++){
        fprintf(fp_arp,"%d.", arph->target_ip_addr[i]);
        fprintf(fp,"%d.", arph->target_ip_addr[i]);
} 
    
	fprintf(fp_arp,"%s\n",endpacket);    
	fprintf(fp,"%s\n",endpacket);    
	//fprintf(fp_arp,"\n"); 


    
  
}

////////////////////////////////////////////////////


}

void analyse_IP(unsigned char* buffer, int buff_size){

	counter->total_ip++;
	unsigned int ip_header_len;     
    struct iphdr *ip_header = (struct iphdr *)buffer;
    ip_header_len =ip_header->ihl*4;	//convert into bytes
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip_header->saddr;
     
    memset(&destination, 0, sizeof(destination));
    destination.sin_addr.s_addr = ip_header->daddr;
     
    fprintf(fp,"IP Header\n");
    fprintf(fp,"\tIP Version        : %d\n",(unsigned int)ip_header->version);
    fprintf(fp,"\tIP Header Length  : %d Bytes\n",((unsigned int)(ip_header->ihl))*4);
    fprintf(fp,"\tIP Total Length   : %d Bytes(Packet Size)\n",ntohs(ip_header->tot_len));
	fprintf(fp,"\tTime To Live      : %d\n",(unsigned int)ip_header->ttl);
    /*NOTE: REMOVE IF REQUIRED*/


    //fprintf(fp,"\tIdentification    : %d\n",ntohs(iph->id));
    //fprintf(fp,"\tReserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(fp,"\tDont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(fp,"\tMore Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    
    fprintf(fp,"\tProtocol : %d\n",(unsigned int)ip_header->protocol);
    fprintf(fp,"\tChecksum : %d\n",ntohs(ip_header->check));
    fprintf(fp,"\tSource IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(fp,"\tDestination IP   : %s\n",inet_ntoa(destination.sin_addr));
	
	fprintf(fp,"%s\n",endpacket);




	 fprintf(fp_ip,"IP Header\n");
    fprintf(fp_ip,"\tIP Version        : %d\n",(unsigned int)ip_header->version);
    fprintf(fp_ip,"\tIP Header Length  : %d Bytes\n",((unsigned int)(ip_header->ihl))*4);
    fprintf(fp_ip,"\tIP Total Length   : %d Bytes(Packet Size)\n",ntohs(ip_header->tot_len));
	fprintf(fp_ip,"\tTime To Live      : %d\n",(unsigned int)ip_header->ttl);
    /*NOTE: REMOVE IF REQUIRED*/


    //fprintf(fp_ip,"\tIdentification    : %d\n",ntohs(iph->id));
    //fprintf(fp_ip,"\tReserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(fp_ip,"\tDont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(fp_ip,"\tMore Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    
    fprintf(fp_ip,"\tProtocol : %d\n",(unsigned int)ip_header->protocol);
    fprintf(fp_ip,"\tChecksum : %d\n",ntohs(ip_header->check));
    fprintf(fp_ip,"\tSource IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(fp_ip,"\tDestination IP   : %s\n",inet_ntoa(destination.sin_addr));
	fprintf(fp_ip,"%s\n",endpacket);

}

void analyse_TCP(unsigned char* buffer, int buff_size){
    counter->total_tcp++;
    unsigned int ip_header_len;     
    struct iphdr *ip_header = (struct iphdr *)buffer;
    ip_header_len =ip_header->ihl*4;    //convert into bytes

    struct tcphdr *tcp_header=(struct tcphdr*)(buffer + ip_header_len);

    fprintf(fp,"\n\nTCP Packet\n");

    //analyse_IP(buffer, buff_size);

    fprintf(fp,"\n");
    fprintf(fp,"TCP Header\n");
    fprintf(fp,"\tSource Port      : %u\n",ntohs(tcp_header->source));
    fprintf(fp,"\tDestination Port : %u\n",ntohs(tcp_header->dest));
    fprintf(fp,"\tSequence Number    : %u\n",ntohl(tcp_header->seq));
    fprintf(fp,"\tAcknowledge Number : %u\n",ntohl(tcp_header->ack_seq));
    fprintf(fp,"\tHeader Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcp_header->doff,(unsigned int)tcp_header->doff*4);
    //fprintf(fp,"\tCWR Flag : %d\n",(unsigned int)tcp_header->cwr);
    //fprintf(fp,"\tECN Flag : %d\n",(unsigned int)tcp_header->ece);
    fprintf(fp,"\tUrgent Flag          : %d\n",(unsigned int)tcp_header->urg);
    fprintf(fp,"\tAcknowledgement Flag : %d\n",(unsigned int)tcp_header->ack);
    fprintf(fp,"\tPush Flag            : %d\n",(unsigned int)tcp_header->psh);
    fprintf(fp,"\tReset Flag           : %d\n",(unsigned int)tcp_header->rst);
    fprintf(fp,"\tSynchronise Flag     : %d\n",(unsigned int)tcp_header->syn);
    fprintf(fp,"\tFinish Flag          : %d\n",(unsigned int)tcp_header->fin);
    fprintf(fp,"\tWindow         : %d\n",ntohs(tcp_header->window));
    fprintf(fp,"\tChecksum       : %d\n",ntohs(tcp_header->check));
    fprintf(fp,"\tUrgent Pointer : %d\n",tcp_header->urg_ptr);
    fprintf(fp,"\n");
    fprintf(fp,"\t\tDATA Dump\t\t");
    fprintf(fp,"\n");

    fprintf(fp,"IP Header\n");
    WriteDataToFile(fp,buffer,ip_header_len);

    fprintf(fp,"TCP Header\n");
    WriteDataToFile(fp,buffer+ip_header_len,tcp_header->doff*4);

    fprintf(fp,"Data Payload\n");
    WriteDataToFile(fp,buffer + ip_header_len + tcp_header->doff*4 , (buff_size - tcp_header->doff*4-ip_header->ihl*4) );


	fprintf(fp,"%s\n",endpacket);
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

fprintf(fp_tcp,"\n");
    fprintf(fp_tcp,"TCP Header\n");
    fprintf(fp_tcp,"\tSource Port      : %u\n",ntohs(tcp_header->source));
    fprintf(fp_tcp,"\tDestination Port : %u\n",ntohs(tcp_header->dest));
    fprintf(fp_tcp,"\tSequence Number    : %u\n",ntohl(tcp_header->seq));
    fprintf(fp_tcp,"\tAcknowledge Number : %u\n",ntohl(tcp_header->ack_seq));
    fprintf(fp_tcp,"\tHeader Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcp_header->doff,(unsigned int)tcp_header->doff*4);
    //fprintf(fp_tcp,"\tCWR Flag : %d\n",(unsigned int)tcp_header->cwr);
    //fprintf(fp_tcp,"\tECN Flag : %d\n",(unsigned int)tcp_header->ece);
    fprintf(fp_tcp,"\tUrgent Flag          : %d\n",(unsigned int)tcp_header->urg);
    fprintf(fp_tcp,"\tAcknowledgement Flag : %d\n",(unsigned int)tcp_header->ack);
    fprintf(fp_tcp,"\tPush Flag            : %d\n",(unsigned int)tcp_header->psh);
    fprintf(fp_tcp,"\tReset Flag           : %d\n",(unsigned int)tcp_header->rst);
    fprintf(fp_tcp,"\tSynchronise Flag     : %d\n",(unsigned int)tcp_header->syn);
    fprintf(fp_tcp,"\tFinish Flag          : %d\n",(unsigned int)tcp_header->fin);
    fprintf(fp_tcp,"\tWindow         : %d\n",ntohs(tcp_header->window));
    fprintf(fp_tcp,"\tChecksum       : %d\n",ntohs(tcp_header->check));
    fprintf(fp_tcp,"\tUrgent Pointer : %d\n",tcp_header->urg_ptr);
    fprintf(fp_tcp,"\n");
    fprintf(fp_tcp,"\t\tDATA Dump\t\t");
    fprintf(fp_tcp,"\n");

    fprintf(fp_tcp,"IP Header\n");
    WriteDataToFile(fp_tcp,buffer,ip_header_len);

    fprintf(fp_tcp,"TCP Header\n");
    WriteDataToFile(fp_tcp,buffer+ip_header_len,tcp_header->doff*4);

    fprintf(fp_tcp,"Data Payload\n");
    WriteDataToFile(fp_tcp,buffer + ip_header_len + tcp_header->doff*4 , (buff_size - tcp_header->doff*4-ip_header->ihl*4) );
fprintf(fp_tcp,"%s\n",endpacket);
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



	if(ntohs(tcp_header->source)==80||ntohs(tcp_header->dest)==80){
		
	analyse_HTTP(buffer + ip_header_len + tcp_header->doff*4 , (buff_size - tcp_header->doff*4-ip_header->ihl*4) );

	}
	else if(ntohs(tcp_header->source)==20||ntohs(tcp_header->dest)==20){
	analyse_FTP(buffer + ip_header_len + tcp_header->doff*4 , (buff_size - tcp_header->doff*4-ip_header->ihl*4));	
	}

	else if(ntohs(tcp_header->source)==21||ntohs(tcp_header->dest)==21){
	analyse_FTP(buffer + ip_header_len + tcp_header->doff*4 , (buff_size - tcp_header->doff*4-ip_header->ihl*4));	
	}


}

void analyse_UDP(unsigned char* buffer, int buff_size){
    counter->total_udp++;
    unsigned int ip_header_len;     
    struct iphdr *ip_header = (struct iphdr *)buffer;
    ip_header_len =ip_header->ihl*4;    //convert into bytes

    struct udphdr *udp_header = (struct udphdr*)(buffer + ip_header_len);

    fprintf(fp,"\n\nUDP Packet\n");

    //analyse_IP(buffer, buff_size);

    fprintf(fp,"\nUDP Header\n");
    fprintf(fp,"\tSource Port      : %d\n" , ntohs(udp_header->source));
    fprintf(fp,"\tDestination Port : %d\n" , ntohs(udp_header->dest));
    fprintf(fp,"\tUDP Length       : %d\n" , ntohs(udp_header->len));
    fprintf(fp,"\tUDP Checksum     : %d\n" , ntohs(udp_header->check));

    fprintf(fp,"\n");
    fprintf(fp,"IP Header\n");
    WriteDataToFile(fp,buffer , ip_header_len);

    fprintf(fp,"UDP Header\n");
    WriteDataToFile(fp,buffer+ip_header_len , sizeof udp_header);

    fprintf(fp,"Data Payload\n");
    WriteDataToFile(fp,buffer + ip_header_len + sizeof udp_header ,( buff_size - sizeof udp_header - ip_header->ihl * 4 ));
	
fprintf(fp,"%s\n",endpacket);
////////////////////////////

    fprintf(fp_tcp,"\n\nUDP Packet\n");

    //analyse_IP(buffer, buff_size);

    fprintf(fp_tcp,"\nUDP Header\n");
    fprintf(fp_tcp,"\tSource Port      : %d\n" , ntohs(udp_header->source));
    fprintf(fp_tcp,"\tDestination Port : %d\n" , ntohs(udp_header->dest));
    fprintf(fp_tcp,"\tUDP Length       : %d\n" , ntohs(udp_header->len));
    fprintf(fp_tcp,"\tUDP Checksum     : %d\n" , ntohs(udp_header->check));

    fprintf(fp_tcp,"\n");
    fprintf(fp_tcp,"IP Header\n");
    WriteDataToFile(fp_tcp,buffer , ip_header_len);

    fprintf(fp_udp,"UDP Header\n");
    WriteDataToFile(fp_tcp,buffer+ip_header_len , sizeof udp_header);

    fprintf(fp_udp,"Data Payload\n");
    WriteDataToFile(fp_tcp,buffer + ip_header_len + sizeof udp_header ,( buff_size - sizeof udp_header - ip_header->ihl * 4 ));
	fprintf(fp_tcp,"%s\n",endpacket);

////////////////////////////

}

void WriteDataToFile (FILE* filp, unsigned char* alp , int len)
{
int i,j;


    for(i=0 ; i < len ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(filp,"         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(alp[j]>=32 && alp[j]<=128)
                    fprintf(filp,"%c",(unsigned char)alp[j]); //if its a number or alphabet

                else fprintf(filp,"."); //otherwise print a dot
            }
            fprintf(filp,"\n");
        }

        if(i%16==0) fprintf(filp,"   ");
            fprintf(filp," %02X",(unsigned int)alp[i]);

        if( i==len-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) fprintf(filp,"   "); //extra spaces

            fprintf(filp,"         ");

            for(j=i-i%16 ; j<=i ; j++)
            {
                if(alp[j]>=32 && alp[j]<=128) fprintf(filp,"%c",(unsigned char)alp[j]);
                else fprintf(filp,".");
            }
            fprintf(filp,"\n");
        }
    }
}

