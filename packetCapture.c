#include <gtk/gtk.h>
#include <glib/gprintf.h>
#include <stdlib.h>
//#include <openssl/md5.h>
#include <gdk/gdkkeysyms.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/if_ether.h>	//For ETH_P_ALL
#include<net/ethernet.h>	//For ether_header
#include<unistd.h>      //close fn

#include "driver.c"

int limit;

#define NUM_COMMANDS 2


//FOR COMPILATION
//gcc `pkg-config --cflags gtk+-3.0` -o packetc packetCapture.c `pkg-config --libs gtk+-3.0` -rdynamic
//FOR RUNNING: ./packetc


GtkBuilder* builder; 
    GtkWidget* window;
    GtkWidget* headerView;
    GObject* button;

    GtkTextIter iter, startIter, endIter, s1, e1, s2, e2, s3, e3, s4, e4;
    GtkTextBuffer* tbuffer;


    FILE* log_fp;
    FILE* log_al;
    FILE* log_tl;
    FILE* log_nl;
    FILE* log_ll;

    //GtkWidget *scrollView;




///////////////////////////////////////////////////////////////////
//SIGNAL HANDLERS FOR BUTTONS
///////////////////////////////////////////////////////////////////

void get_application_layer(GtkWidget* widget){

	//code here

	gtk_text_buffer_get_start_iter(tbuffer, &s1);

	//FILE* fp = fopen("log.txt", "r");

	if(log_al == NULL){
		printf("Error in opening file\n");
		return;
	}

	char output[10000];

	while(fgets(output, 10000, log_al) != NULL){

		gtk_text_buffer_insert(tbuffer, &s1, output, -1);

		if(strcmp(output, "###########################################################\n") == 0){
			break;
		}

	}

	//gtk_text_buffer_insert(tbuffer, &startIter, "dihfghidsahfb\n", -1);

	//gtk_text_buffer_insert(tbuffer, &startIter, "coooool\n", -1);

	gtk_text_buffer_get_end_iter(tbuffer, &e1);
	gtk_text_buffer_delete(tbuffer, &s1, &e1);
	gtk_text_buffer_get_end_iter(tbuffer, &s1);

}

void get_transport_layer(GtkWidget* widget){

	//code here

	gtk_text_buffer_get_start_iter(tbuffer, &s2);

	//FILE* fp = fopen("log.txt", "r");

	if(log_tl == NULL){
		printf("Error in opening file\n");
		return;
	}

	char output[10000];

	while(fgets(output, 10000, log_tl) != NULL){

		gtk_text_buffer_insert(tbuffer, &s2, output, -1);

		if(strcmp(output, "###########################################################\n") == 0){
			break;
		}

	}

	//gtk_text_buffer_insert(tbuffer, &startIter, "dihfghidsahfb\n", -1);

	//gtk_text_buffer_insert(tbuffer, &startIter, "coooool\n", -1);

	gtk_text_buffer_get_end_iter(tbuffer, &e2);
	gtk_text_buffer_delete(tbuffer, &s2, &e2);
	gtk_text_buffer_get_end_iter(tbuffer, &s2);

}

void get_network_layer(GtkWidget* widget){

	//code here

	gtk_text_buffer_get_start_iter(tbuffer, &s3);

	//FILE* fp = fopen("log.txt", "r");

	if(log_nl == NULL){
		printf("Error in opening file\n");
		return;
	}

	char output[10000];

	while(fgets(output, 10000, log_nl) != NULL){

		gtk_text_buffer_insert(tbuffer, &s3, output, -1);

		if(strcmp(output, "###########################################################\n") == 0){
			break;
		}

	}

	//gtk_text_buffer_insert(tbuffer, &startIter, "dihfghidsahfb\n", -1);

	//gtk_text_buffer_insert(tbuffer, &startIter, "coooool\n", -1);

	gtk_text_buffer_get_end_iter(tbuffer, &e3);
	gtk_text_buffer_delete(tbuffer, &s3, &e3);
	gtk_text_buffer_get_end_iter(tbuffer, &s3);

}

void get_link_layer(GtkWidget* widget){

	//code here

	gtk_text_buffer_get_start_iter(tbuffer, &s4);

	//FILE* fp = fopen("log.txt", "r");

	if(log_ll == NULL){
		printf("Error in opening file\n");
		return;
	}

	char output[10000];

	while(fgets(output, 10000, log_ll) != NULL){

		gtk_text_buffer_insert(tbuffer, &s4, output, -1);

		if(strcmp(output, "###########################################################\n") == 0){
			break;
		}

	}

	//gtk_text_buffer_insert(tbuffer, &startIter, "dihfghidsahfb\n", -1);

	//gtk_text_buffer_insert(tbuffer, &startIter, "coooool\n", -1);

	gtk_text_buffer_get_end_iter(tbuffer, &e4);
	gtk_text_buffer_delete(tbuffer, &s4, &e4);
	gtk_text_buffer_get_end_iter(tbuffer, &s4);

}

void show_all_layers(GtkWidget* widget){

	//code here

	gtk_text_buffer_get_start_iter(tbuffer, &startIter);

	//FILE* fp = fopen("log.txt", "r");

	if(log_fp == NULL){
		printf("Error in opening file\n");
		return;
	}

	char output[10000];

	while(fgets(output, 10000, log_fp) != NULL){

		gtk_text_buffer_insert(tbuffer, &startIter, output, -1);

		if(strcmp(output, "###########################################################\n") == 0){
			break;
		}

	}

	//gtk_text_buffer_insert(tbuffer, &startIter, "dihfghidsahfb\n", -1);

	//gtk_text_buffer_insert(tbuffer, &startIter, "coooool\n", -1);

	gtk_text_buffer_get_end_iter(tbuffer, &endIter);
	gtk_text_buffer_delete(tbuffer, &startIter, &endIter);
	gtk_text_buffer_get_end_iter(tbuffer, &startIter);

}

void get_graph(GtkWidget* widget){	//check

	//code here

	char * commandsForGnuplot[] = {"set title \"Packet Analysis Graph\"", "plot 'data.temp'"};
    double xvals[4] = {1.0, 2.0, 3.0, 4.0};
    double yvals[4] = {5.0 ,3.0, 1.0, 3.0};
    FILE * temp = fopen("data.temp", "w");
  
    FILE * gnuplotPipe = popen ("gnuplot -persistent", "w");
    int i;
    for (i=0; i < 4; i++){
    	fprintf(temp, "%lf %lf \n", xvals[i], yvals[i]); //Write the data to a temporary file
    }

    for (i=0; i < NUM_COMMANDS; i++){
    	fprintf(gnuplotPipe, "%s \n", commandsForGnuplot[i]); //Send commands to gnuplot one by one.
    }

}


void ctrl_start(GtkWidget* widget){

	//code here
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
        return ;
    }

int i=0;

 while(i<limit)	//run loop until user wants to stop program in which case stop_prog is set to 1 
    {

    	if(reset_prog==1){	// if user has pressed reset then reset_prog is set to 1 and stats are reset and then reset_prog is changed back to 0

    		reset_counter();
    		reset_prog=0;
    	}

    	if(pause_prog==0){	// if user has paused execution
    		/*NOTE: A user can reset even if the program is paused*/

        size_socket_addr = sizeof(socket_addr);
        packet_size = recvfrom(raw_socket,buffer,buffer_size,0,&socket_addr,&size_socket_addr);
        	if(packet_size<0)
        	{
            	printf("Cannot recieve packets\n");
            	return ;
        	}
        
        analyse_packet(buffer,packet_size);// buffer is sent for analysing

        if(stop_prog==1)	// check if user wants to stop_prog
        	{
        		break;
        	

        	}
    	}

    	i++;


    }
    close(raw_socket);
    printf("Analysing Finished..Thank you for using our application");

}

void ctrl_get_next_packet(GtkWidget* widget){

	//code here

	gtk_text_buffer_get_start_iter(tbuffer, &startIter);

	//FILE* fp = fopen("log.txt", "r");

	if(log_fp == NULL){
		printf("Error in opening file\n");
		return;
	}

	char output[10000];

	while(fgets(output, 10000, log_fp) != NULL){

		gtk_text_buffer_insert(tbuffer, &startIter, output, -1);

		if(strcmp(output, "###########################################################\n") == 0){
			break;
		}

	}

	//gtk_text_buffer_insert(tbuffer, &startIter, "dihfghidsahfb\n", -1);

	//gtk_text_buffer_insert(tbuffer, &startIter, "coooool\n", -1);

	gtk_text_buffer_get_end_iter(tbuffer, &endIter);
	gtk_text_buffer_delete(tbuffer, &startIter, &endIter);
	gtk_text_buffer_get_end_iter(tbuffer, &startIter);

}

void ctrl_stop(GtkWidget* widget){

	//code here

}

void ctrl_clear(GtkWidget* widget){

	//code here

	gtk_text_buffer_get_start_iter(tbuffer, &startIter);

	gtk_text_buffer_insert(tbuffer, &startIter, "", -1);

	gtk_text_buffer_get_end_iter(tbuffer, &endIter);
	gtk_text_buffer_delete(tbuffer, &startIter, &endIter);
	gtk_text_buffer_get_end_iter(tbuffer, &startIter);

}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

//Close main window after work
void on_window1_destroy(){

	gtk_main_quit();
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////


int main(int argc, char ** argv){

	//printf("goooooo\n");

	printf("Write number of packets to be captured : ");
	scanf("%d", &limit);

    gtk_init(&argc, &argv);


    builder = gtk_builder_new();
    gtk_builder_add_from_file (builder, "packet_capture.glade", NULL);

    window = GTK_WIDGET(gtk_builder_get_object(builder, "window1"));	//name of main window in glade file reqd
    //gtk_builder_connect_signals(builder, NULL);

    headerView = GTK_WIDGET(gtk_builder_get_object(builder, "header_view"));

    //scrollView = gtk_scrolled_window_new( NULL, NULL );

    /////////////////////////////////////////////////////////////////////////////

    button = gtk_builder_get_object (builder, "start_button");
  	g_signal_connect (button, "clicked", G_CALLBACK (ctrl_start), NULL);

  	button = gtk_builder_get_object (builder, "stop_button");
  	g_signal_connect (button, "clicked", G_CALLBACK (ctrl_stop), NULL);

  	button = gtk_builder_get_object (builder, "get_next_packet_button");
  	g_signal_connect (button, "clicked", G_CALLBACK (ctrl_get_next_packet), NULL);

  	button = gtk_builder_get_object (builder, "clear_button");
  	g_signal_connect (button, "clicked", G_CALLBACK (ctrl_clear), NULL);

  	button = gtk_builder_get_object (builder, "get_application_layer_button");
  	g_signal_connect (button, "clicked", G_CALLBACK (get_application_layer), NULL);

  	button = gtk_builder_get_object (builder, "get_transport_layer_button");
  	g_signal_connect (button, "clicked", G_CALLBACK (get_transport_layer), NULL);

  	button = gtk_builder_get_object (builder, "get_network_layer_button");
  	g_signal_connect (button, "clicked", G_CALLBACK (get_network_layer), NULL);

  	button = gtk_builder_get_object (builder, "get_link_layer_button");
  	g_signal_connect (button, "clicked", G_CALLBACK (get_link_layer), NULL);

  	button = gtk_builder_get_object (builder, "show_all_layers_button");
  	g_signal_connect (button, "clicked", G_CALLBACK (show_all_layers), NULL);

  	button = gtk_builder_get_object (builder, "get_graph_button");
  	g_signal_connect (button, "clicked", G_CALLBACK (get_graph), NULL);

  	/////////////////////////////////////////////////////////////////////////////

    tbuffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(headerView));
    //gtk_text_iter_set_offset(&iter, -1);

    //gtk_container_add(GTK_CONTAINER(scrollView), headerView);


    //opening log file
    log_fp = fopen("Log_File.txt", "r");
    log_al = fopen("Log_File_HTTP.txt", "r");
    log_tl = fopen("Log_File_TCP.txt", "r");
    log_nl = fopen("Log_File_IP.txt", "r");
    log_ll = fopen("Log_File_ARP.txt", "r");
    

    

    g_object_unref(builder);	//free builder reference

    gtk_widget_show(window);
    gtk_main();

    return 0;

}//end of main