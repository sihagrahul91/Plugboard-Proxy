Plugboard Proxy
-------------------------------------------------------------------------------

Data Flow:
----------

ssh <--stdin/stdout--> pbproxy-c <--socket 1--> pbproxy-s <--socket 2--> sshd
\______________________________/                \___________________________/
             client                                        server      


How to use:
-----------

SERVER:
pbproxy -k mykey -l $port $destn 22
where $port is PORT on which pbproxy will be listening and $destn is the address of ssh server 

CLIENT:
ssh -o "ProxyCommand pbproxy -k mykey $destn $port" localhost
$destn and $port are the address and port of pbproxy server.

For examples see testing.txt

Compile & Run:
--------------
1. The program contains four files - mystruct.h(header file), pbproxy.c(source file), mykey and a Makefile
2. Use make to compile the program and make clean to delete the executables.
3. Make sure the service is running and accepting connections.I 
4. Key should be 16 bytes long (it is read as hexadecimal string and thus 32 bytes from key file). It should be same on both client and server. If key is not same, client can't connect.
5. Assumptiomn - there are no spaces in hexadecimal key string.

Details & Implementation:
-------------------------
pbproxy adds an extra layer of encryption to connections towards TCP services. Instead of connecting directly to the service, clients connect to pbproxy (running on the same
server), which then relays all traffic to the actual service. Before relaying the traffic, pbproxy *always* decrypts it using a static symmetric key. This
means that if the data of any connection towards the protected server is not properly encrypted, then it will turn into garbage before reaching the protected service.

1. Client creates a socket and connect to pbproxy. Clients reads data from stdin, encrypts it and send it to the pbproxy. 
2. pbproxy monitors for both client and service socket.
2. pbproxy receives data, decrypt it and sends it to the service.
3. pbproxy, after getting the data(reply) back from the service, encrypts it again and send it back to the client that decrypts it and write it on stdout.
3. Select system call is used to monitor multiple sockets at client and pbproxy.
4. pbproxy can serve only one client at a time.
5. TCP Coalescing is prevented by sending length of data along with the data. Data contains Length + IV + Payload. Also, a small delay is also introduced after sending data for the same.
6. Buffer size is kept 1024 (<MTU). It supports different TCP stacks.
7. For every encryption and decryption different random IV is used. Counter increment is taken care by the AES ancryption API.
8. Sufficient inline comments have been added in the code to explain the functionality.

*service - means any service like SSH, netcat, HTTP we want to protect. Testing has been done on the aforementioned three.

Sample Run:
-----------

Server:
rahuls-MacBook-Pro:NetSecAss3 rsihag$ ./pbproxy -k mykey -l 65535 localhost 22

Resolved IP of Host localhost: 127.0.0.1
SERVER MODE     | Key: abcd1234abcd1234 | Destination: localhost | Dest. Port: 22 | Proxy Port: 65535

####################################  Got new request ####################################
DESTINATION PORT : 22
Encrypted Buffer : ??3??.?ns?沜@?Z߇VC>??.q?

Original Buffer  : SSH-2.0-OpenSSH_7.4


Client:
rahuls-MacBook-Pro:NetSecAss3 rsihag$ ssh -o "ProxyCommand ./pbproxy -k mykey localhost 65535" localhost

Resolved IP of Host localhost: 127.0.0.1
CLIENT MODE     | Key: abcd1234abcd1234 | Destination: localhost | Dest. Port: 65535
Password:
Last login: Sun Nov 12 17:10:52 2017 from 127.0.0.1
rahuls-MacBook-Pro:~ rsihag$

For more test cases refer, testing.txt

Testing:
--------
Testing has been done thoroughly and all the test cases are included in testing.txt file. pbproxy has been tested against stress tests and all worked.
Testing has been done both on single machine and two machines (MacOS - Ubuntu).

References:
-----------
http://www.geeksforgeeks.org/socket-programming-cc/
http://www.geeksforgeeks.org/socket-programming-in-cc-handling-multiple-clients-on-server-without-multi-threading/
http://www.geeksforgeeks.org/multithreading-c-2/
http://www.gurutechnologies.net/blog/aes-ctr-encryption-in-c/


