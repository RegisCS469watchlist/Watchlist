/******************************************************************************

PROGRAM:  ssl-client.c for Watchlist Project
AUTHOR:   Thomas, Riley, Stephanie
COURSE:   CS469 - Distributed Systems (Regis University)
SYNOPSIS: This program is a small client application that establishes a secure
TCP connection to a server and simply exchanges messages.  It uses a SSL/TLS
connection using X509 certificates generated with the openssl application.
The purpose is to demonstrate how to establish and use secure communication
channels between a client and server using public key cryptography.

Some of the code and descriptions can be found in "Network Security with
OpenSSL", O'Reilly Media, 2002.

 ******************************************************************************/
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define DEFAULT_PORT 4433
#define DEFAULT_HOST "localhost"
#define MAX_HOSTNAME_LENGTH 256
#define BUFFER_SIZE 256
#define PATH_LENGTH 248
#define STR_LENGTH 512

/******************************************************************************

  This function does the basic necessary housekeeping to establish a secure TCP
  connection to the server specified by 'hostname'.

 *******************************************************************************/
int create_socket(char *hostname, unsigned int port) {
  int sockfd;
  struct hostent *host;
  struct sockaddr_in dest_addr;

  host = gethostbyname(hostname);
  if (host == NULL) {
    fprintf(stderr, "Client: Cannot resolve hostname %s\n", hostname);
    exit(EXIT_FAILURE);
  }

  // Create a socket (endpoint) for network communication.  The socket()
  // call returns a socket descriptor, which works exactly like a file
  // descriptor for file system operations we worked with in CS431
  //
  // Sockets are by default blocking, so the server will block while reading
  // from or writing to a socket. For most applications this is acceptable.
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
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
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(port);
  dest_addr.sin_addr.s_addr = *(long *)(host->h_addr);

  // Now we connect to the remote host.  We pass the connect() system call the
  // socket descriptor, the address of the remote host, and the size in bytes
  // of the remote host's address
  if (connect(sockfd, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr)) <
      0) {
    fprintf(stderr, "Client: Cannot connect to host %s [%s] on port %d: %s\n",
            hostname, inet_ntoa(dest_addr.sin_addr), port, strerror(errno));
    exit(EXIT_FAILURE);
  }

  return sockfd;
}

/******************************************************************************

  The sequence of steps required to establish a secure SSL/TLS connection is:

  1.  Initialize the SSL algorithms
  2.  Create and configure an SSL context object
  3.  Create an SSL session object
  4.  Create a new network socket in the traditional way
  5.  Bind the SSL object to the network socket descriptor
  6.  Establish an SSL session on top of the network connection

  Once these steps are completed successfully, use the functions SSL_read() and
  SSL_write() to read from/write to the socket, but using the SSL object rather
  then the socket descriptor.  Once the session is complete, free the memory
  allocated to the SSL object and close the socket descriptor.

 ******************************************************************************/
int main(int argc, char **argv) {
  const SSL_METHOD *method;
  unsigned int port = DEFAULT_PORT;
  char remote_host[MAX_HOSTNAME_LENGTH];
  char filename[PATH_LENGTH] = {0};
  char buffer[BUFFER_SIZE] = {0};
  char *temp_ptr;
  int sockfd;
  int writefd;
  int rcount;
  int error_code;
  int total = 0;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  char title[BUFFER_SIZE] = {0};
  char newTitle[BUFFER_SIZE] = {0};
  int type, status, rating;
  char description[500] = {0};
  char opChar[20];
  char updateChar[20];
  char s[800];
  char temp[STR_LENGTH];

  if (argc != 2) {
    fprintf(stderr, "Client: Usage: ssl-client <server name>:<port>\n");
    exit(EXIT_FAILURE);
  } else {
    // Search for ':' in the argument to see if port is specified
    temp_ptr = strchr(argv[1], ':');
    if (temp_ptr == NULL) // Hostname only. Use default port
      strncpy(remote_host, argv[1], MAX_HOSTNAME_LENGTH);
    else {
      // Argument is formatted as <hostname>:<port>. Need to separate
      // First, split out the hostname from port, delineated with a colon
      // remote_host will have the <hostname> substring
      strncpy(remote_host, strtok(argv[1], ":"), MAX_HOSTNAME_LENGTH);
      // Port number will be the substring after the ':'. At this point
      // temp is a pointer to the array element containing the ':'
      port = (unsigned int)atoi(temp_ptr + sizeof(char));
    }
  }

  // Initialize OpenSSL ciphers and digests
  OpenSSL_add_all_algorithms();

  // SSL_library_init() registers the available SSL/TLS ciphers and digests.
  if (SSL_library_init() < 0) {
    fprintf(stderr, "Client: Could not initialize the OpenSSL library!\n");
    exit(EXIT_FAILURE);
  }

  // Use the SSL/TLS method for clients
  method = SSLv23_client_method();

  // Create new context instance
  ssl_ctx = SSL_CTX_new(method);
  if (ssl_ctx == NULL) {
    fprintf(stderr, "Unable to create a new SSL context structure.\n");
    exit(EXIT_FAILURE);
  }

  // This disables SSLv2, which means only SSLv3 and TLSv1 are available
  // to be negotiated between client and server
  SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);

  // Create a new SSL connection state object
  ssl = SSL_new(ssl_ctx);

  // Create the underlying TCP socket connection to the remote host
  sockfd = create_socket(remote_host, port);
  if (sockfd != 0)
    fprintf(stderr, "Client: Established TCP connection to '%s' on port %u\n",
            remote_host, port);
  else {
    fprintf(stderr,
            "Client: Could not establish TCP connection to %s on port %u\n",
            remote_host, port);
    exit(EXIT_FAILURE);
  }

  // Bind the SSL object to the network socket descriptor.  The socket
  // descriptor will be used by OpenSSL to communicate with a server. This
  // function should only be called once the TCP connection is established,
  // i.e., after create_socket()
  SSL_set_fd(ssl, sockfd);

  // Initiates an SSL session over the existing socket connection. SSL_connect()
  // will return 1 if successful.
  if (SSL_connect(ssl) == 1)
    fprintf(stdout, "Client: Established SSL/TLS session to '%s' on port %u\n",
            remote_host, port);
  else {
    fprintf(stderr,
            "Client: Could not establish SSL session to '%s' on port %u\n",
            remote_host, port);
    exit(EXIT_FAILURE);
  }

  do {
    fprintf(stdout, "Please choose an operation: ('c' = create, 'f' = find, "
                    "'d' = display, 'u' = update, 'r' = remove)\n");
    fgets(opChar, 20, stdin);
    switch (opChar[0]) {
    case 'c':
    case 'C':
      // create
      fprintf(stdout, "Enter the title:\n");
      fgets(title, BUFFER_SIZE, stdin);
      title[strlen(title) - 1] = '\0';
      fprintf(stdout,
              "Enter type (1 - movie, 2 - Tv show, 3 - cartoon, 4 - anime):\n");
      fgets(temp, BUFFER_SIZE, stdin);
      type = atoi(temp);
      bzero(temp, sizeof(temp));
      fprintf(stdout, "Enter description (max of %d characters):\n",
              STR_LENGTH);
      fgets(description, STR_LENGTH, stdin);
      description[strlen(description) - 1] = '\0';
      fprintf(stdout, "Enter status (1 - Plan to watch, 2 - Watching "
                      "currently, 3 - Completed):\n");
      fgets(temp, BUFFER_SIZE, stdin);
      status = atoi(temp);
      bzero(temp, sizeof(temp));
      if (status > 1) {
        fprintf(stdout, "Enter rating (1 - 5, 1 being terrible and 5 being "
                        "amazing):\n"); // for 1 or 2
        fgets(temp, BUFFER_SIZE, stdin);
        rating = atoi(temp);
        bzero(temp, sizeof(temp));
        sprintf(s, "c:%s:%d:%s:%d:%d", title, type, description, status,
                rating);
      } else {
        sprintf(s, "c:%s:%d:%s:%d", title, type, description, status);
      }
      break;

    case 'f':
    case 'F':
      // find
      fprintf(stdout, "Enter title you wish to search for:\n");
      fgets(title, BUFFER_SIZE, stdin);
      title[strlen(title) - 1] = '\0';
      sprintf(s, "f:%s", title);

      break;

    case 'd':
    case 'D':
      // display whole list
      fprintf(stdout, "The whole list will be displayed:\n");
      sprintf(s, "d");
      break;

    case 'u':
    case 'U':
      // update
      fprintf(stdout, "Enter title you wish to update:\n");
      fgets(title, BUFFER_SIZE, stdin);
      title[strlen(title) - 1] = '\0';
      fprintf(stdout, "Which field would you like to update? (Title, Media "
                      "Type, Description, Status, Rating)\n");
      fgets(updateChar, 20, stdin);
      switch (updateChar[0]) {
      case 't':
      case 'T':
        fprintf(stdout, "Enter new title:\n");
        fgets(newTitle, BUFFER_SIZE, stdin);
        newTitle[strlen(newTitle) - 1] = '\0';
        sprintf(s, "u:t:%s%s", title, newTitle);
        break;

      case 'm':
      case 'M':
        fprintf(stdout, "Enter new type:\n");
        fgets(temp, BUFFER_SIZE, stdin);
        type = atoi(temp);
        bzero(temp, sizeof(temp));
        sprintf(s, "u:m:%s%d", title, type);
        break;

      case 'd':
      case 'D':
        fprintf(stdout, "Enter new description:\n");
        fgets(description, BUFFER_SIZE, stdin);
        title[strlen(description) - 1] = '\0';
        sprintf(s, "u:d:%s%s", title, description);
        break;

      case 's':
      case 'S':
        fprintf(stdout, "Enter new status:\n");
        fgets(temp, BUFFER_SIZE, stdin);
        status = atoi(temp);
        bzero(temp, sizeof(temp));
        sprintf(s, "u:s:%s%d", title, status);
        break;

      case 'r':
      case 'R':
        fprintf(stdout, "Enter new rating:\n");
        fgets(temp, BUFFER_SIZE, stdin);
        rating = atoi(temp);
        bzero(temp, sizeof(temp));
        sprintf(s, "u:r:%s%d", title, rating);
        break;
      }
      break;

    case 'r':
    case 'R':
      // remove
      fprintf(stdout, "Enter title of entry you wish to delete:\n");
      fgets(temp, sizeof(temp), stdin);
      sprintf(s, "r:%s", temp);
      break;

    default:
      fprintf(stdout, "Invalid statement\n");
    }
    // send message to server
    SSL_write(ssl, s, strlen(s));

    fprintf(stdout, "built string: '%s'\n", s);
    fprintf(stdout,
            "Would you like to choose another operation? (yes or no)\n");
    fgets(temp, BUFFER_SIZE, stdin);
    SSL_write(ssl, temp, strlen(s));

  } while (temp[0] == 'y' || temp[0] == 'Y');

  //  Request filename from user and strip trailing newline character
  //  fprintf(stdout, "Enter file name: ");
  //  fgets(filename, PATH_LENGTH, stdin);
  //  filename[strlen(filename)-1] = '\0';
  //
  //  // Marshal the parameter into an RPC message
  //  sprintf(buffer, "getfile %s", filename);
  //  SSL_write(ssl, buffer, strlen(buffer));
  //
  //  // Clear the buffer and await the reply
  //  bzero(buffer, BUFFER_SIZE);
  //  rcount = SSL_read(ssl, buffer, BUFFER_SIZE);
  //  if (sscanf(buffer, "error %d", &error_code) == 1) {
  //    fprintf(stderr, "Client: Could not retrieve file: %s\n",
  //    strerror(error_code));
  //  } else {
  //    writefd = creat(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  //    do {
  //      total += rcount;
  //      write(writefd, buffer, rcount);
  //      rcount = SSL_read(ssl, buffer, BUFFER_SIZE);
  //    } while (rcount > 0);
  //    close(writefd);
  //    fprintf(stdout, "Client: Successfully transferred file '%s' (%d bytes)
  //    from server\n", filename, total);
  //  }
  //
  //  // Deallocate memory for the SSL data structures and close the socket
  //  SSL_free(ssl);
  //  SSL_CTX_free(ssl_ctx);
  //  close(sockfd);
  //  fprintf(stdout, "Client: Terminated SSL/TLS connection with server
  //  '%s'\n", remote_host);

  return (0);
}
