#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <errno.h> 
#include <unistd.h> 
#include <arpa/inet.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <sys/time.h>
#include <errno.h>
#include <openssl/aes.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <netinet/tcp.h> 
#include <fcntl.h>
#include <netdb.h>

/* References:  http://www.geeksforgeeks.org/socket-programming-cc/
		http://www.geeksforgeeks.org/socket-programming-in-cc-handling-multiple-clients-on-server-without-multi-threading/
		http://www.geeksforgeeks.org/multithreading-c-2/
		http://www.gurutechnologies.net/blog/aes-ctr-encryption-in-c/
*/

#define TRUE   1 
#define FALSE  0

int max(int a,int b) {
	return a>b?a:b;
}

struct ctr_state {
        unsigned char ivec[AES_BLOCK_SIZE];
        unsigned int num;
        unsigned char ecount[AES_BLOCK_SIZE];
};

int init_ctr(struct ctr_state *state, const unsigned char iv[8]) {
        /* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
         * first call. */
        state->num = 0;
        memset(state->ecount, 0, AES_BLOCK_SIZE);

        /* Initialise counter in 'ivec' to 0 */
        memset(state->ivec + 8, 0, 8);

        /* Copy IV into 'ivec' */
        memcpy(state->ivec, iv, 8);
}

int fencrypt(unsigned char *buffer, unsigned char *encrypted, const unsigned char *aes_key, int rcv_len)
{
	struct ctr_state state;
	unsigned char IV[8];

	// Mind your IV. Generate Random Bytes for IV
	if(!RAND_bytes(IV, 8)) {
		fprintf(stderr, "Error Generating Random Bytes.\n");
		return -1;
	}
	// Initialise Counter
	init_ctr(&state, IV);
	//Copy IV
	memcpy(encrypted,IV,8); 
	/* Encrypt buffer. AES_ctr128_encrypt implementation takes care of incrementing the counter ( counter = (nonce) IV + ctrVal. i.e. increments ctrVal).
	It divides the buffer into chunks of 128bits and encrypt. In few implementations of AES user explicitly has to do this buffer divison 
	example here - http://www.gurutechnologies.net/blog/aes-ctr-encryption-in-c/ */
	AES_ctr128_encrypt(buffer, encrypted + 8, rcv_len, aes_key, state.ivec, state.ecount, &state.num);
	return 0;
}
int fdecrypt(unsigned char *buffer, unsigned char *decrypted, const unsigned char *aes_key, int rcv_len)
{
	struct ctr_state state;
	// IV in first 8 bytes of the buffer. Initialise Counter
	init_ctr(&state, buffer);
	AES_ctr128_encrypt(buffer+8, decrypted, rcv_len-8, aes_key, state.ivec, state.ecount, &state.num);
	return 0;
}

void ns()
{
	struct timespec time;
        time.tv_sec = 0;
        time.tv_nsec = 10*10000;
        nanosleep(&time, NULL);
}
// below code is taken from https://stackoverflow.com/questions/5403103/hex-to-ascii-string-conversion
int hex_to_int(char c){
        int first = c / 16 - 3;
        int second = c % 16;
        int result = first*10 + second;
        if(result > 9) result--;
        return result;
}

int hex_to_ascii(char c, char d){
        int high = hex_to_int(c) * 16;
        int low = hex_to_int(d);
        return high+low;
}

