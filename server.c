/******************************************************************************

PROGRAM:  server.c
AUTHOR:   Tomas Auruskevicius
COURSE:   CS469 - Distributed Systems (Regis University)
SYNOPSIS: This program is a small server application that receives incoming TCP 
          connections from clients and simply exchanges messages, i.e., it 
          functions as a simple echo server. The purpose is to demonstrate the 
          basics of network communication using TCP and sockets.

******************************************************************************/
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define DEFAULT_PORT      4433
#define BUFFER_SIZE       256
#define ERR_INVALID_OP    0
#define ERR_TOO_FEW_ARGS  1
#define ERR_TOO_MANY_ARGS 2

/******************************************************************************

This function does the basic necessary housekeeping to establish TCP connections
to the server.  It first creates a new socket, binds the network interface of the 
machine to that socket, then listens on the socket for incoming TCP connections.

*******************************************************************************/
int create_socket(unsigned int port)
{
    int    s;
    struct sockaddr_in addr;

    // First we set up a network socket. An IP socket address is a combination
    // of an IP interface address plus a 16-bit port number. The struct field
    // sin_family is *always* set to AF_INET. Anything else returns an error.
    // The TCP port is stored in sin_port, but needs to be converted to the
    // format on the host machine to network byte order, which is why htons()
    // is called. Setting s_addr to INADDR_ANY binds the socket and listen on
    // any available network interface on the machine, so clients can connect
    // through any, e.g., external network interface, localhost, etc.

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Create a socket (endpoint) for network communication.  The socket()
    // call returns a socket descriptor, which works exactly like a file
    // descriptor for file system operations we worked with in CS431
    //
    // Sockets are by default blocking, so the server will block while reading
    // from or writing to a socket. For most applications this is acceptable.
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
      {
	fprintf(stderr, "Server: Unable to create socket: %s", strerror(errno));
	exit(EXIT_FAILURE);
      }

    // When you create a socket, it exists within a namespace, but does not have
    // a network address associated with it.  The bind system call creates the
    // association between the socket and the network interface.
    //
    // An error could result from an invalid socket descriptor, an address already
    // in use, or an invalid network address
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0)
      {
	fprintf(stderr, "Server: Unable to bind to socket: %s", strerror(errno));
	exit(EXIT_FAILURE);
      }

    // Listen for incoming TCP connections using the newly created and configured
    // socket. The second argument (1) indicates the number of pending connections
    // allowed, which in this case is one.  That means if the server is connected
    // to one client, a second client attempting to connect may receive an error,
    // e.g., connection refused.
    //
    // Failure could result from an invalid socket descriptor or from using a socket
    // descriptor that is already in use.
    if (listen(s, 1) < 0)
      {
	fprintf(stderr, "Server: Unable to listen: %s", strerror(errno));
	exit(EXIT_FAILURE);
      }

    fprintf(stdout, "Server: Listening on TCP port %u\n", port);

    return s;
}

//function to add two integers
int add (int a, int b){
	return a + b;
}

int main(int argc, char *argv[])
{
  struct sockaddr_in serv_addr;
  struct sockaddr_in client_addr;
  int                listensockfd, clientfd;
  unsigned int       port;
  unsigned int       len = sizeof(client_addr);
  char               client_addr_str[INET_ADDRSTRLEN];
  char               buffer[BUFFER_SIZE];
  int                nbytes_read;
  int                nbytes_written;
  int                x;
  int                y;
  char               dummy[2];

  // Port can be specified on the command line. If it's not, use the default port 
  switch(argc)
    {
    case 1:
      port = DEFAULT_PORT;
      break;
    case 2:
      port = atoi(argv[1]);
      break;
    default:
      fprintf(stderr, "Usage: server <port> (optional)\n");
      exit(EXIT_FAILURE);
    }
  
  // This will create a network socket and return a socket descriptor, which is
  // and works just like a file descriptor, but for network communcations. Note
  // we have to specify which TCP/UDP port on which we are communicating as an
  // argument to our user-defined create_socket() function.
  listensockfd = create_socket(port);

  // Wait for incoming connections and handle them as the arrive
  while(true)
    {
      clientfd = accept(listensockfd, (struct sockaddr *) &client_addr, &len);
      if (clientfd < 0)
	{
	  fprintf(stderr, "Server: Error accepting TCP connection: %s\n", strerror(errno));
	  continue;
	}
      else
	{
	  // Display the IPv4 network address of the connected client
	  inet_ntop(AF_INET, (struct in_addr*) &client_addr.sin_addr, client_addr_str, INET_ADDRSTRLEN);
	  fprintf(stdout, "Server: Established TCP connection with client (%s) on port %u\n", client_addr_str, port);
	}

      // This is where the server actually does the work receiving and sending messages
      bzero(buffer, BUFFER_SIZE);
      nbytes_read = read(clientfd, buffer, BUFFER_SIZE);
	
	  //check if message received
      if (nbytes_read < 0)
	fprintf(stderr, "Server: Error reading from socket: %s\n", strerror(errno));
      else
	fprintf(stdout, "Server: Message received from client: \"%s\"\n", buffer);
      
      //check if message properly formatted
      if (strncmp(buffer, "add ", 4) != 0) {
    	sprintf(buffer, "error %d", ERR_INVALID_OP);
	  }
	  else if (sscanf(buffer, "add %d %d", &x, &y) < 2){
		sprintf(buffer, "error %d", ERR_TOO_FEW_ARGS);
	  }
	  else if (sscanf(buffer, "add %d %d %1s", &x, &y, dummy) != 2) {
	  	sprintf(buffer, "error %d", ERR_TOO_MANY_ARGS);
	  }
	  else if (sscanf(buffer, "add %d %d", &x, &y) == 2){
		sprintf(buffer, "reply %d", add(x,y));
	  }	
      
      //write reply back to socket descriptor
	  nbytes_written = write(clientfd, buffer, strlen(buffer)+1);
	  if (nbytes_written < 0)
	    {
	      fprintf(stderr, "Server: Could not write message to socket: %s\n", strerror(errno));
	      exit(EXIT_FAILURE);
	    }
	  else
	    printf("Server: Sending reply message \"%s\" to client\n", buffer);
	        
      // Terminate the TCP connection by closing the socket descriptor
      fprintf(stdout, "Server: Terminating TCP connection with client (%s)\n", client_addr_str);
      close(clientfd);
    }
  
  return 0; 
}
