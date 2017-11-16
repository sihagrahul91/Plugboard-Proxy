#include "mystruct.h"

int max(int a,int b);
int init_ctr(struct ctr_state *state, const unsigned char iv[8]);
int fencrypt(unsigned char *buffer, unsigned char *encrypted, const unsigned char *aes_key, int rcv_len);
int fdecrypt(unsigned char *buffer, unsigned char *decrypted, const unsigned char *aes_key, int rcv_len);
void ns();


int client_mode(char *dst, int dst_port, char *key) {

	int sock = 0, max_sd, activity;
	struct sockaddr_in serv_addr;
	int opt = TRUE; 
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("\n Client Socket creation error \n");
		return -1;
	}

	memset(&serv_addr, '0', sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(dst_port);

	// Convert IPv4 and IPv6 addresses from text to binary form
	if(inet_pton(AF_INET, dst, &serv_addr.sin_addr)<=0) {
		fprintf(stderr,"\nClient Mode - Destination address invalid/ Address not supported\n");
		return -1;
	}
	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		fprintf(stderr,"\nClient Mode - Client to Server Connection Failed\n");
		return -1;
	}
	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt)) < 0) {
		fprintf(stderr,"\nClient Mode - Can't set Server Socket with no-delay option\n");
	}

	struct timespec  time;
	char buffer[1024];
	memset(buffer,'\0',sizeof(buffer));
	int rcv_len=0,send_len=0;

	struct ctr_state state;
	unsigned char IV[8];
	AES_KEY aes_key;

	//Initializing the encryption KEY
	if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
		fprintf(stderr, "\nCould not set encryption key.\n");
		exit(1);
	}
	while(1) {
		//set of socket descriptors 
		fd_set readfds;
		//clear the socket set 
		FD_ZERO(&readfds);  

		//add socket and stdin to set 
		FD_SET(sock, &readfds);  
		FD_SET(0, &readfds);  

		max_sd = sock;  
		//wait for an activity on one of the sockets , timeout is NULL , 
		//so wait indefinitely 
		activity = select( max_sd + 1 , &readfds , NULL , NULL , NULL);  
		if ((activity < 0) && (errno!=EINTR))  
		{  
			fprintf(stderr,"\nselect error\n"); 
			return 0; 
		} 
		//If something happened on the socket , 
		//then its an incoming connection ( From stdin )
		if (FD_ISSET(0, &readfds))  
		{ 
			rcv_len = read(0, buffer, sizeof(buffer));
			if (rcv_len == 0) {
				break;
			} else if (rcv_len < 0) {
				fprintf(stderr, "\nCannot receive data from STDIN\n");
				break;
			}
			unsigned char encrypted[rcv_len + 8 + 4 + 1];
			memcpy(encrypted, (char *)&rcv_len, sizeof(int)); //Copy the length

			int ret = fencrypt(buffer, encrypted + 4, &aes_key, rcv_len);
			if(ret == -1) break;
			send_len = write(sock, encrypted, rcv_len + 8 + 4);

			memset(buffer,'\0',sizeof(buffer));
			time.tv_sec = 0;
			time.tv_nsec = 10*10000;
			nanosleep(&time, NULL);
		}
		//If something happened on the socket , data from server 
		if (FD_ISSET(sock, &readfds)) { 
			int rcv_len_ = 0;
			rcv_len = read(sock, buffer , 4);
			memcpy(&rcv_len_, buffer, 4);
			rcv_len = read(sock, buffer , rcv_len_ + 8);
			if(rcv_len<=0) break;
			if(rcv_len < rcv_len_ + 8) {
				// Wait to get the number of bytes specified in packet.
				while(rcv_len < rcv_len_+8){
					rcv_len+=read(sock,buffer+rcv_len,rcv_len_+8-rcv_len);
				}
			}
			// Decryption
			unsigned char decrypted[rcv_len - 8 + 1];
			memset(decrypted, '\0', sizeof(decrypted));
			int ret = fdecrypt(buffer, decrypted, &aes_key, rcv_len);
			send_len = write(1, decrypted, rcv_len-8);
			memset(buffer,'\0',sizeof(buffer));
		}
	}
	close(sock);
	return 0;

}
int handler(int client_sock, char *dst, int dst_port, char * key){

	int server_sock = 0,max_sd,activity;
	struct sockaddr_in serv_addr;
	int opt = TRUE;
	if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("\n Server Socket creation error \n");
		return -1; 
	}   

	memset(&serv_addr, '0', sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	//fprintf(stderr,"DESTINATION PORT : %d",dst_port);
	serv_addr.sin_port = htons(dst_port);
	
	char buffer[1024];
	memset(buffer,'\0',sizeof(buffer));
	
	// Convert IPv4 and IPv6 addresses from text to binary form
	if(inet_pton(AF_INET, dst, &serv_addr.sin_addr)<=0) {
		printf("\nServer Mode - Destination Service Address Invalid / Address not supported \n");
		return -1; 
	} 
	if (connect(server_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		printf("\nServer Mode - Connection to Service Failed\n");
		return -1;
	}
	if (setsockopt(server_sock, IPPROTO_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt)) < 0) {
		printf("\nServer Mode - Can't set Server Socket with no-delay option \n");
	}
	if (setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt)) < 0) {
		printf("\nServer Mode - Can't set Client Socket with no-delay option \n");
	}

	int send_len, rcv_len;
	int send_bytes, recv_bytes;
	struct timespec  time;
	unsigned char IV[8];
	AES_KEY aes_key;

	if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
		fprintf(stderr, "\nError Setting Encryption Key\n");
		exit(1);
	}

	while(1) {
		//set of socket descriptors 
		fd_set readfds;
		//clear the socket set 
		FD_ZERO(&readfds);

		//add sockets to set 
		FD_SET(client_sock, &readfds);
		FD_SET(server_sock, &readfds);

		max_sd = max(client_sock,server_sock);
		//wait for an activity on one of the sockets , timeout is NULL , 
		//so wait indefinitely 
		activity = select( max_sd + 1 , &readfds , NULL , NULL , NULL);
		if ((activity < 0) && (errno!=EINTR))
		{
			printf("select error");
		}
		//If something happened on the client socket i.e. got packet from client, sent to server 
		if (FD_ISSET(client_sock, &readfds))
		{

			int rcv_len_ = 0;
			rcv_len = read(client_sock, buffer, 4);
			memcpy(&rcv_len_, buffer, 4);
			rcv_len = read(client_sock, buffer , rcv_len_ + 8);
			if (rcv_len == 0) {
				break;
			} else if (rcv_len < 0) {
				break;
			}
			if(rcv_len < rcv_len_ + 8) {
				// Wait to get the number of bytes specified in packet.
				while(rcv_len < rcv_len_+8){
					rcv_len+=read(client_sock,buffer+rcv_len,rcv_len_+8-rcv_len);
				}
			}
			// Decryption
			memcpy(IV,buffer,8);
			unsigned char decrypted[rcv_len - 8 + 1];
			memset(decrypted, '\0', sizeof(decrypted));
			int ret = fdecrypt(buffer, decrypted, &aes_key, rcv_len);
			fprintf(stderr,"\nEncrypted Buffer : %s\n",buffer);
			fprintf(stderr,"\nOriginal Buffer  : %s\n",decrypted);

			send_len = write(server_sock, decrypted, rcv_len - 8);
			memset(buffer,'\0',sizeof(buffer));
			time.tv_sec = 0;
			time.tv_nsec = 10*10000;
			nanosleep(&time, NULL);
		}
		//If something happened on the client socket i.e. got packet from client, sent to server 
		if (FD_ISSET(server_sock, &readfds))
		{
			rcv_len = read(server_sock, buffer, sizeof(buffer));
			if (rcv_len == 0) {
				break;
			} else if (rcv_len < 0) {
				fprintf(stderr, "\nCannot receive data on server socket !!!\n");
				break;
			}
			// Encryption
			unsigned char encrypted[rcv_len + 8 + 4 + 1];
			memcpy(encrypted, (char *)&rcv_len, sizeof(int)); //Copy the length

			int ret = fencrypt(buffer, encrypted + 4, &aes_key, rcv_len);
			if(ret == -1) break;

			send_len = write(client_sock, encrypted, rcv_len + 8 + 4);
			memset(buffer,'\0',sizeof(buffer));
			time.tv_sec = 0;
			time.tv_nsec = 10*10000;
			nanosleep(&time, NULL);


		}

	} 
	close(client_sock);
	close(server_sock);
	return 0;


}
int server_mode(int proxy_port, char *dst, int dst_port, char *key) {

	int proxy_sock = 0;
	struct sockaddr_in serv_addr;

	if ((proxy_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("\n Server Socket creation error \n");
		return -1;
	}

	memset(&serv_addr, '0', sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(proxy_port);
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	
	//bind the socket
	if (bind(proxy_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr))<0)  
	{  
		printf("\nBind FAILED\n");
		perror("bind failed");  
		return -1;
	}  

	// try to specify maximum of 30 pending connections for the master socket 
	if (listen(proxy_sock, 30) < 0)  
	{  
		perror("listen");  
		return -1;
	}  

	struct timespec time;
        time.tv_sec = 0;
        time.tv_nsec = 10*100000;
        nanosleep(&time, NULL);	
	struct sockaddr_in *address;
	int new_socket;
	int ret,max_sd,activity,addrlen;
	addrlen = sizeof(address);
	// accept the incoming connections 
	while(1) {
		// set of socket descriptors 
		fd_set readfds;
		// clear the socket set 
                FD_ZERO(&readfds);

                // add socket to set 
                FD_SET(proxy_sock, &readfds);

                max_sd = proxy_sock;
                // wait for an activity on one of the sockets , timeout is NULL , 
                // so wait indefinitely 
                activity = select( max_sd + 1 , &readfds , NULL , NULL , NULL);
                if ((activity < 0) && (errno!=EINTR))
                {
                        printf("select error");
                }
                // If something happened on the socket , 
                // then its an incoming connection
                if (FD_ISSET(proxy_sock, &readfds))
                {
			if ((new_socket = accept(proxy_sock,(struct sockaddr *)&address, (socklen_t*)&addrlen))<0)  
			{  
				perror("Can't accept client connection");  
				return -1;
			}
			fprintf(stderr,"\n####################################  Got new request ####################################\n"); 
			ret = handler(new_socket, dst, dst_port, key); 
                }
		
	}
	return 0;
}
int main(int argc, char const *argv[])
{

	char *key_file = NULL, *proxy_port_ = NULL,*ptr = NULL;
	unsigned char hexKey[36];
	memset(hexKey,'\0',sizeof(hexKey));
	char key[20];
	memset(key,'\0',sizeof(key));
	int c;
	int proxy_port = -1;
	while ((c = getopt (argc, argv, "l:k:")) != -1) {
		switch (c) {
			case 'k':
				key_file = optarg;
				break;
			case 'l':
				proxy_port_ = optarg;
				break;
			case '?':
				if (isprint(optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr,
							"Unknown option character `\\x%x'.\n",
							optopt);
				return -1;
		}
	}
	FILE *file = fopen(key_file, "r");
	if (!file) {
		fprintf(stderr, "\nUnable to open Key file. Make sure key file exists\n");
		return 1;
	}
	// Key is 16 bytes long and represented in hexadecimal. 32 bytes in hex. Assuming there are no spaces in hexadecimal string.
	ptr = fgets(hexKey, 35, file);
	if (strlen(hexKey) != 33) {
		fprintf(stderr, "\nKey must be 16 bytes long for AES 128 - not %d hexBytes\n",strlen(hexKey));
	}
	hexKey[32] = '\0';
	int itr_= 0, itr = 0;
	for(itr_ = 0; itr_ < 32; itr_+=2) {
			key[itr++] = hex_to_ascii(hexKey[itr_],hexKey[itr_+1]);
	}
	key[itr]='\0';

	if(proxy_port_) {
		proxy_port = (int)strtol(proxy_port_, NULL, 10);
		// Port 0 Case. Handled the same way as netcat
		if(proxy_port == 0 ) {
			fprintf(stderr, "\nError: Invalid local port: 0\n");
			return -1;
		}
		if(proxy_port<0 || proxy_port>65535) {
			fprintf(stderr, "\nPort numbers must be between 1-65535\n");
			return -1;
		}
		
	}
	char *dst = NULL, *dst_port_ = NULL;
	if(optind == argc-2) {
		dst = argv[optind];
		dst_port_ = argv[optind+1];
	}
	if(!dst || !dst_port_) {
		fprintf(stderr, "\nPlease specify both destination service host and port\n");
		return -1;
	}
	int dst_port = (int)strtol(dst_port_, NULL, 10);
	if(dst_port<0 || dst_port>65535) {
		fprintf(stderr, "\nPort numbers must be between 0-65535\n");
		return -1;
	}
	struct hostent *he;
        if ((he=gethostbyname(dst)) == NULL) {
		herror("gethostbyname");
                return -1;
        }
	
	struct in_addr **addr_list;

	// Resolve host IP Address
	char dst_ip[25];
	memset(dst_ip,'\0',sizeof(dst_ip));
	addr_list = (struct in_addr **) he->h_addr_list;
	strcpy(dst_ip , inet_ntoa(*addr_list[0]));
	fprintf(stderr,"\nResolved IP of Host %s: %s\n",dst, dst_ip);

	if(proxy_port!=-1) {
		fprintf(stderr,"SERVER MODE	| Key: %s | Destination: %s | Dest. Port: %d | Proxy Port: %d\n",key,dst,dst_port,proxy_port);
		server_mode(proxy_port,dst_ip,dst_port,key);					
	}
	else {
		fprintf(stderr,"CLIENT MODE	| Key: %s | Destination: %s | Dest. Port: %d\n",key,dst,dst_port);
		client_mode(dst_ip, dst_port, key);
	}
	return 0;
}
