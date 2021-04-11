/******************************************************************************

PROGRAM:  client.c
AUTHOR:   Tomas Auruskevicius
COURSE:   CS469 - Distributed Systems (Regis University)
SYNOPSIS: This program is a small client application that establishes a TCP connection
          to a server and simply exchanges messages. The server acts as an echo server 
          in that whatever message is sent to the server is repeated back to the client.
          The purpose is to demonstrate how to set up a TCP connection and read/write
          messages to and from a socket.

******************************************************************************/
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define DEFAULT_PORT          4433
#define MAX_HOSTNAME_LENGTH   256
#define BUFFER_SIZE           256
#define TEMP_SIZE             10
#define ERR_INVALID_OP        0
#define ERR_TOO_FEW_ARGS      1
#define ERR_TOO_MANY_ARGS     2

/******************************************************************************

This function does the basic necessary housekeeping to establish a TCP
connection to the server specified by 'hostname'.

*******************************************************************************/
int create_socket(char* hostname, unsigned int port)
{
  int                sockfd;
  struct hostent*    host;
  struct sockaddr_in dest_addr;

  host = gethostbyname(hostname);
  if (host == NULL)
    {
      fprintf(stderr, "Client: Cannot resolve hostname %s\n",  hostname);
      exit(EXIT_FAILURE);
    }
  
  // Create a socket (endpoint) for network communication.  The socket()
  // call returns a socket descriptor, which works exactly like a file
  // descriptor for file system operations we worked with in CS431
  //
  // Sockets are by default blocking, so the server will block while reading
  // from or writing to a socket. For most applications this is acceptable.
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    {
      fprintf(stderr, "Server: Unable to create socket: %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
  
  // First we set up a network socket. An IP socket address is a combination
  // of an IP interface address plus a 16-bit port number. The struct field
  // sin_family is *always* set to AF_INET. Anything else returns an error.
  // The TCP port is stored in sin_port, but needs to be converted to the
  // format on the host machine to network byte order, which is why htons()
  // is called. The s_addr field is the network address of the remote host
  // specified on the command line. The earlier call to gethostbyname()
  // retrieves the IP address for the given hostname.
  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(port);
  dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);
  
  // Now we connect to the remote host.  We pass the connect() system call the
  // socket descriptor, the address of the remote host, and the size in bytes
  // of the remote host's address
  if (connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) < 0)
    {
      fprintf(stderr, "Client: Cannot connect to host %s [%s] on port %d: %s\n",
	      hostname, inet_ntoa(dest_addr.sin_addr), port, strerror(errno));
      exit(EXIT_FAILURE);
    }

  return sockfd;
}

int main(int argc, char *argv[])
{
  int                sockfd;
  int                nbytes_read;
  int                nbytes_written;
  unsigned int       port = DEFAULT_PORT;
  char               remote_host[MAX_HOSTNAME_LENGTH];
  char               buffer[BUFFER_SIZE];
  char*              temp_ptr;
  int                err_no;
  int                x;
  
  if (argc != 2)
    {
      fprintf(stderr, "Client: Usage: client <server name>:<port>\n");
      exit(EXIT_FAILURE);
    }
  else
    {
      // Search for ':' in the argument to see if port is specified
      temp_ptr = strchr(argv[1], ':');
      if (temp_ptr == NULL)    // Hostname only. Use default port
	  strncpy(remote_host, argv[1], MAX_HOSTNAME_LENGTH);
      else
	{
	  // Argument is formatted as <hostname>:<port>. Need to separate
	  // First, split out the hostname from port, delineated with a colon
	  // remote_host will have the <hostname> substring
	  strncpy(remote_host, strtok(argv[1], ":"), MAX_HOSTNAME_LENGTH);
	  // Port number will be the substring after the ':'. At this point
	  // temp is a pointer to the array element containing the ':'
	  port = (unsigned int) atoi(temp_ptr+sizeof(char));
	}
    }
  
  // Create the underlying TCP socket connection to the remote host
  sockfd = create_socket(remote_host, port);
  if(sockfd != 0)
    fprintf(stderr, "Client: Established TCP connection to '%s' on port %u\n", remote_host, port);
  else
    {
      fprintf(stderr, "Client: Could not establish TCP connection to %s on port %u\n", remote_host, port);
      exit(EXIT_FAILURE);
    }
  
  fprintf(stdout, "Client: Enter the operation and two integers: ");
  bzero(buffer, BUFFER_SIZE);
  fgets(buffer, BUFFER_SIZE-1, stdin);

  // Remove trailing newline character
  buffer[strlen(buffer)-1] = '\0';
  
  nbytes_written = write(sockfd, buffer, strlen(buffer));
  if (nbytes_written < 0)
    {
      fprintf(stderr, "Client: Could not write message to socket: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }
  else
    fprintf(stdout, "Client: Successfully sent message \"%s\" to %s on port %u\n", buffer, remote_host, port);
  
  bzero(buffer, BUFFER_SIZE);

  //read the response from server
  nbytes_read = read(sockfd, buffer, BUFFER_SIZE);
  
  if (sscanf(buffer, "error %d", &err_no) == 1) {
    	if (err_no == ERR_INVALID_OP){
    		fprintf(stderr, "ERROR: Invalid operation name\n");
		}
		if (err_no == ERR_TOO_FEW_ARGS){
    		fprintf(stderr, "ERROR: Too few arguments. Enter two integers for the operation\n");
		}
		if (err_no == ERR_TOO_MANY_ARGS){
    		fprintf(stderr, "ERROR: Too many arguments. Enter two integers for the operation\n");
		}
  }
  else if (sscanf(buffer, "reply %d", &x) == 1){
		fprintf(stdout, "Result of the operation: %d\n", x);
  } 
  
  return 0;
}
