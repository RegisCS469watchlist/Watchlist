/******************************************************************************

PROGRAM:  ssl-server.c for Watchlist Project
AUTHOR:   Thomas, Riley, Stephanie
COURSE:   CS469 - Distributed Systems (Regis University)
SYNOPSIS: This program is a small server application that receives incoming TCP
          connections from clients and transfers a requested file from the
          server to the client.  It uses a secure SSL/TLS connection using
          a certificate generated with the openssl application.

          To create a self-signed certificate your server can use, at the
command prompt type:

          openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365
-out cert.pem

          This will create two files: a private key contained in the file
'key.pem' and a certificate containing a public key in the file 'cert.pem'. Your
          server will require both in order to operate properly.

          Some of the code and descriptions can be found in "Network Security
with OpenSSL", O'Reilly Media, 2002.

Some code provided by Prof. Hemmes for use in these projects. This is the server
side for the Watchlist project.

******************************************************************************/
#include <arpa/inet.h>
#include <fcntl.h>
#include <gdbm.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define BUFFER_SIZE 800
#define PATH_LENGTH 256
#define DEFAULT_PORT 4433
#define CERTIFICATE_FILE "cert.pem"
#define KEY_FILE "key.pem"

/******************************************************************************

  This function does the basic necessary housekeeping to establish TCP
 connections to the server.  It first creates a new socket, binds the network
 interface of the machine to that socket, then listens on the socket for
 incoming TCP connections.

 *******************************************************************************/
int create_socket(unsigned int port) {
  int s;
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
  if (s < 0) {
    fprintf(stderr, "Server: Unable to create socket: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }

  // When you create a socket, it exists within a namespace, but does not have
  // a network address associated with it.  The bind system call creates the
  // association between the socket and the network interface.
  //
  // An error could result from an invalid socket descriptor, an address already
  // in use, or an invalid network address
  if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    fprintf(stderr, "Server: Unable to bind to socket: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }

  // Listen for incoming TCP connections using the newly created and configured
  // socket. The second argument (1) indicates the number of pending connections
  // allowed, which in this case is one.  That means if the server is connected
  // to one client, a second client attempting to connect may receive an error,
  // e.g., connection refused.
  //
  // Failure could result from an invalid socket descriptor or from using a
  // socket descriptor that is already in use.
  if (listen(s, 1) < 0) {
    fprintf(stderr, "Server: Unable to listen: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }

  fprintf(stdout, "Server: Listening on TCP port %u\n", port);

  return s;
}

/******************************************************************************

  This function does some initialization of the OpenSSL library functions used
 in this program.  The function SSL_load_error_strings registers the error
 strings for all of the libssl and libcrypto functions so that appropriate
 textual error messages can be displayed when error conditions arise.
 OpenSSL_add_ssl_algorithms registers the available SSL/TLS ciphers and digests
 used for encryption.

 ******************************************************************************/
void init_openssl() {
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
}

/******************************************************************************

  EVP_cleanup removes all of the SSL/TLS ciphers and digests registered earlier.

 ******************************************************************************/
void cleanup_openssl() { EVP_cleanup(); }

/******************************************************************************

  An SSL_CTX object is an instance of a factory design pattern that produces SSL
  connection objects, each called a context. A context is used to set parameters
  for the connection, and in this program, each context is configured using the
  configure_context() function below. Each context object is created using the
  function SSL_CTX_new(), and the result of that call is what is returned by
 this function and subsequently configured with connection information.

  One other thing to point out is when creating a context, the SSL protocol must
  be specified ahead of time using an instance of an SSL_method object.  In this
  case, we are creating an instance of an SSLv23_server_method, which is an
  SSL_METHOD object for an SSL/TLS server. Of the available types in the OpenSSL
  library, this provides the most functionality.

 ******************************************************************************/
SSL_CTX *create_new_context() {
  const SSL_METHOD
      *ssl_method; // This should be declared 'const' to avoid getting
  // a warning from the call to SSLv23_server_method()
  SSL_CTX *ssl_ctx;

  // Use SSL/TLS method for server
  ssl_method = SSLv23_server_method();

  // Create new context instance
  ssl_ctx = SSL_CTX_new(ssl_method);
  if (ssl_ctx == NULL) {
    fprintf(stderr, "Server: cannot create SSL context:\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  return ssl_ctx;
}

/******************************************************************************

  We will use Elliptic Curve Diffie Hellman anonymous key agreement protocol for
  the session key shared between client and server.  We first configure the SSL
  context to use that protocol by calling the function SSL_CTX_set_ecdh_auto().
  The second argument (onoff) tells the function to automatically use the
 highest preference curve (supported by both client and server) for the key
 agreement.

  Note that for error conditions specific to SSL/TLS, the OpenSSL library does
  not set the variable errno, so we must use the built-in error printing
 routines.

 ******************************************************************************/
void configure_context(SSL_CTX *ssl_ctx) {
  SSL_CTX_set_ecdh_auto(ssl_ctx, 1);

  // Set the certificate to use, i.e., 'cert.pem'
  if (SSL_CTX_use_certificate_file(ssl_ctx, CERTIFICATE_FILE,
                                   SSL_FILETYPE_PEM) <= 0) {
    fprintf(stderr, "Server: cannot set certificate:\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  // Set the private key contained in the key file, i.e., 'key.pem'
  if (SSL_CTX_use_PrivateKey_file(ssl_ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
    fprintf(stderr, "Server: cannot set certificate:\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
}
// Struct entry in database
struct entry {
  char title[256];
  char description[500];
  int type;
  int status;
  int rating;
};

// Struct user entry in database
struct user {
  char username[32];
  char hash[256];
  char salt[12];
};

/******************************************************************************

  The sequence of steps required to establish a secure SSL/TLS connection is:

  1.  Initialize the SSL algorithms
  2.  Create and configure an SSL context object
  3.  Create a new network socket in the traditional way
  4.  Listen for incoming connections
  5.  Accept incoming connections as they arrive
  6.  Create a new SSL object for the newly arrived connection
  7.  Bind the SSL object to the network socket descriptor

  Once these steps are completed successfully, use the functions SSL_read() and
  SSL_write() to read from/write to the socket, but using the SSL object rather
  then the socket descriptor.  Once the session is complete, free the memory
  allocated to the SSL object and close the socket descriptor.

 ******************************************************************************/
int main(int argc, char **argv) {
  SSL_CTX *ssl_ctx;
  unsigned int sockfd;
  unsigned int port;
  char buffer[BUFFER_SIZE];
  char filename[PATH_LENGTH];
  char title[BUFFER_SIZE] = {0};
  char username[32];
  char hash[256];
  char verifyHash[256];
  char salt[12];
  int type, status, rating;
  char *verify;
  char description[500] = {0};
  char temp[500] = {0};
  char opChar, uOpChar;
  char *ptr;

  // Initialize and create SSL data structures and algorithms
  init_openssl();
  ssl_ctx = create_new_context();
  configure_context(ssl_ctx);

  // Pointer to a GDBM file
  GDBM_FILE dbf;

  // Represents the database file name
  const char *dbfilename = "watchlist.db";

  // Open the database for read/write, create if it doesn't already exist
  /*dbf = gdbm_open(dbfilename, 0, GDBM_WRCREAT, 0776, 0);
    if (!dbf) {
    fprintf (stderr, "Could not open database file %s: %s\n", dbfilename,
    gdbm_strerror(GDBM_FILE_OPEN_ERROR));
    return EXIT_FAILURE;
    }*/

  // Port can be specified on the command line. If it's not, use the default
  // port
  switch (argc) {
  case 1:
    port = DEFAULT_PORT;
    break;
  case 2:
    port = atoi(argv[1]);
    break;
  default:
    fprintf(stderr, "Usage: ssl-server <port> (optional)\n");
    exit(EXIT_FAILURE);
  }

  // This will create a network socket and return a socket descriptor, which is
  // and works just like a file descriptor, but for network communcations. Note
  // we have to specify which TCP/UDP port on which we are communicating as an
  // argument to our user-defined create_socket() function.
  sockfd = create_socket(port);

  struct entry tempEntry;

  // Wait for incoming connections and handle them as the arrive
  while (1) {
    SSL *ssl;
    int client;
    int readfd;
    int rcount;
    struct sockaddr_in addr;
    unsigned int len = sizeof(addr);
    char client_addr[INET_ADDRSTRLEN];
    char *titlePtr;
    char *usernamePtr;
    char values[BUFFER_SIZE];

    // Once an incoming connection arrives, accept it.  If this is successful,
    // we now have a connection between client and server and can communicate
    // using the socket descriptor
    client = accept(sockfd, (struct sockaddr *)&addr, &len);
    if (client < 0) {
      fprintf(stderr, "Server: Unable to accept connection: %s\n",
              strerror(errno));
      exit(EXIT_FAILURE);
    }

    // Display the IPv4 network address of the connected client
    inet_ntop(AF_INET, (struct in_addr *)&addr.sin_addr, client_addr,
              INET_ADDRSTRLEN);
    fprintf(stdout,
            "Server: Established TCP connection with client (%s) on port %u\n",
            client_addr, port);

    // Here we are creating a new SSL object to bind to the socket descriptor
    ssl = SSL_new(ssl_ctx);

    // Bind the SSL object to the network socket descriptor.  The socket
    // descriptor will be used by OpenSSL to communicate with a client. This
    // function should only be called once the TCP connection is established.
    SSL_set_fd(ssl, client);

    // The last step in establishing a secure connection is calling
    // SSL_accept(), which executes the SSL/TLS handshake.  Because network
    // sockets are blocking by default, this function will block as well until
    // the handshake is complete.
    if (SSL_accept(ssl) <= 0) {
      fprintf(stderr, "Server: Could not establish secure connection:\n");
      ERR_print_errors_fp(stderr);
    } else
      fprintf(stdout,
              "Server: Established SSL/TLS connection with client (%s)\n",
              client_addr);

    SSL_read(ssl, buffer, BUFFER_SIZE);

    switch (buffer[0] - '0') {
    case 1:

      // Open the database for read/write, create if it doesn't already exist
      dbf = gdbm_open("users.db", 0, GDBM_WRCREAT, 0776, 0);
      if (!dbf) {
        fprintf(stderr, "Could not open database file %s: %s: %s\n", "users.db",
                gdbm_strerror(GDBM_FILE_OPEN_ERROR), strerror(errno));
        return EXIT_FAILURE;
      }
      // store values in variables
      fprintf(stdout, "%s\n", buffer);
      ptr = strtok(buffer, ":");
      strcpy(&opChar, ptr);
      ptr = strtok(NULL, ":");
      strcpy(username, ptr);
      ptr = strtok(NULL, ":");
      strcpy(hash, ptr);
      ptr = strtok(NULL, ":");
      strcpy(salt, ptr);

      sprintf(temp, "%s:%s", hash, salt);

      fprintf(stdout, "%s:%s:%s\n", username, hash, salt);

      usernamePtr = username;

      // Create a key-value pair to insert in the database. Must specify the
      // size of each datum in bytes.
      datum userKey = {usernamePtr, strlen(usernamePtr)};
      datum userValue = {temp, strlen(temp)};

      // Add the key-value pair to the database
      gdbm_store(dbf, userKey, userValue, GDBM_INSERT);
      fprintf(stdout, "Successfully inserted new username with key: %s\n",
              userKey.dptr);
      break;

    case 2:
      // Open the database for read/write, create if it doesn't already exist
      dbf = gdbm_open("users.db", 0, GDBM_WRCREAT, 0776, 0);
      if (!dbf) {
        fprintf(stderr, "Could not open database file %s: %s: %s\n", "users.db",
                gdbm_strerror(GDBM_FILE_OPEN_ERROR), strerror(errno));
        return EXIT_FAILURE;
      }

      // store values in variables (only capturing username)
      ptr = strtok(buffer, ":");
      strcpy(&opChar, ptr);
      ptr = strtok(NULL, ":");
      strcpy(username, ptr);

      usernamePtr = username;

      datum loginKey = {usernamePtr, strlen(usernamePtr)};
      datum loginValue = gdbm_fetch(dbf, loginKey);

      // access salt and write back to client
      ptr = strtok(loginValue.dptr, ":");
      strcpy(hash, ptr);
      ptr = strtok(NULL, ":");
      strcpy(salt, ptr);

      SSL_write(ssl, salt, sizeof(salt));

      // read hash from client
      SSL_read(ssl, verifyHash, sizeof(hash));

      fprintf(stdout, "server: hash = |%s|, verifyHash = |%s|\n", hash, verifyHash);

      if (strncmp(hash, verifyHash, BUFFER_SIZE) == 0) {
        fprintf(stdout, "Passwords match. User authenticated\n");
        verify = "1";
      } else {
        fprintf(stdout, "Passwords do not match\n");
        verify = "0";
      }

      SSL_write(ssl, verify, sizeof(verify));
      break;

    default:
      fprintf(stdout, "server: error, please input 0 or 1\n");
    }

    gdbm_close(dbf);
    dbf = gdbm_open(dbfilename, 0, GDBM_WRCREAT, 0776, 0);
    if (!dbf) {
      fprintf(stderr, "Could not open database file %s: %s: %s\n", dbfilename,
              gdbm_strerror(GDBM_FILE_OPEN_ERROR), strerror(errno));
      return EXIT_FAILURE;
    }

    do {

      bzero(buffer, BUFFER_SIZE);
      SSL_read(ssl, buffer, BUFFER_SIZE);

      switch (buffer[0]) {

      case 'c':
      case 'C':
        // store values in variables
        ptr = strtok(buffer, ":");
        strcpy(&opChar, ptr);
        ptr = strtok(NULL, ":");
        strcpy(title, ptr);
        ptr = strtok(NULL, "");
        // Represents the key and value for the database entry
        titlePtr = title;
        strcpy(values, ptr);

        // Create a key-value pair to insert in the database. Must specify the
        // size of each datum in bytes.
        datum cKey = {titlePtr, strlen(titlePtr)};
        datum cValue = {values, strlen(values)};

        // Add the key-value pair to the database
        gdbm_store(dbf, cKey, cValue, GDBM_INSERT);
        fprintf(stdout, "Successfully inserted new item with key: %s\n",
                cKey.dptr);
        break;
      case 'f':
      case 'F':
        fprintf(stdout, "begin find op\n");
        // store values in variables
        ptr = strtok(buffer, ":");
        strcpy(&opChar, ptr);
        ptr = strtok(NULL, ":");
        strcpy(title, ptr);
        ptr = strtok(NULL, "");
        // Represents the key and value for the database entry
        titlePtr = title;
        datum fKey = {titlePtr, strlen(titlePtr)};
        datum fValue = gdbm_fetch(dbf, fKey);
        fprintf(stdout, "value fetched: %s\n", fValue.dptr);
        break;
      case 'd':
      case 'D':
        fprintf(stdout, "begin display op\n");
        datum dKey = gdbm_firstkey(dbf);
        // fprintf(stdout, "dbf val: %s\n", dKey.dptr);
        struct entry tempEntry;
        while (dKey.dptr) {
          datum dValue = gdbm_fetch(dbf, dKey);
          ptr = strtok(dValue.dptr, ":");
          tempEntry.type = atoi(ptr);
          ptr = strtok(NULL, ":");
          strcpy(tempEntry.description, ptr);
          ptr = strtok(NULL, ":");
          tempEntry.status = atoi(ptr);
          ptr = strtok(NULL, ":");
          tempEntry.rating = atoi(ptr);
          fprintf(stdout, "The entry is: %s, %s, %d, %d, %d\n", dKey.dptr,
                  tempEntry.description, tempEntry.type, tempEntry.status,
                  tempEntry.rating);
          free(dValue.dptr);
          free(dKey.dptr);
          gdbm_nextkey(dbf, dKey);
        }
        break;

      case 'u':
      case 'U':
        strtok(buffer, ":");
        ptr = strtok(NULL, ":");
        strcpy(&uOpChar, ptr);
        ptr = strtok(NULL, ":");
        strcpy(title, ptr);
        ptr = strtok(NULL, ":");
        strcpy(temp, ptr);

        fprintf(stdout, "begin update op\n");
        // Represents the key and value for the database entry
        titlePtr = title;
        datum uKey = {titlePtr, strlen(titlePtr)};

        if (gdbm_exists(dbf, fKey)) {
          datum uValue = gdbm_fetch(dbf, uKey);
          ptr = strtok(uValue.dptr, ":");
          strcpy(tempEntry.description, ptr);
          ptr = strtok(NULL, ":");
          tempEntry.type = atoi(ptr);
          ptr = strtok(NULL, ":");
          tempEntry.status = atoi(ptr);
          ptr = strtok(NULL, ":");
          tempEntry.rating = atoi(ptr);
          ptr = strtok(NULL, ":");
          switch (uOpChar) {
          case 't':
          case 'T':
            strcpy(tempEntry.title, temp);
            break;

          case 'm':
          case 'M':
            tempEntry.type = atoi(temp);
            break;

          case 'd':
          case 'D':
            strcpy(tempEntry.description, temp);
            break;

          case 's':
          case 'S':
            tempEntry.status = atoi(temp);
            break;

          case 'r':
          case 'R':
            tempEntry.rating = atoi(temp);
            break;
          }

        } else {
          fprintf(stdout, "Item %s doesn't exist \n", title);
        }
      case 'r':
      case 'R':
        fprintf(stdout, "begin delete op\n");
        strtok(buffer, ":");
        ptr = strtok(NULL, "");
        strcpy(temp, ptr);
        datum rKey = {temp, strlen(temp)};

        // store values in variables
        if (gdbm_exists(dbf, rKey)) {
          ptr = strtok(buffer, ":");
          strcpy(&opChar, ptr);
          ptr = strtok(NULL, ":");
          strcpy(title, ptr);
          ptr = strtok(NULL, "");
          // Represents the key and value for the database entry
          titlePtr = title;
          datum rKey = {titlePtr, strlen(titlePtr)};
          gdbm_delete(dbf, rKey);
          fprintf(stdout, "Successfully deleted %s\n", title);
        } else {
          fprintf(stdout, "Item %s doesn't exist \n", title);
        }
        break;
        //      case 1:
        //      	gdbm_close(dbf);
        //
        //      	// Open the database for read/write, create if it
        //      doesn't already exist
        //	    dbf = gdbm_open("users.db", 0, GDBM_WRCREAT, 0776, 0);
        //	    if (!dbf) {
        //	      fprintf(stderr, "Could not open database file %s: %s:
        //%s\n", "users.db", 	              gdbm_strerror(GDBM_FILE_OPEN_ERROR),
        //strerror(errno)); 	      return EXIT_FAILURE;
        //	    }
        //	    // store values in variables
        //        ptr = strtok(buffer, ":");
        //        strcpy(&opChar, ptr);
        //        ptr = strtok(NULL, ":");
        //        strcpy(username, ptr);
        //        ptr = strtok(NULL, "");
        //        strcpy(hash, ptr);
        //        ptr = strtok(NULL, ":");
        //        strcpy(salt, ptr);
        //        ptr = strtok(NULL, ":");
        //
        //        sprintf(temp, "%s:%s", hash, salt);
        //
        //        usernamePtr = username;
        //
        //        // Create a key-value pair to insert in the database. Must
        //        specify the
        //	    // size of each datum in bytes.
        //	    datum userKey = {usernamePtr, strlen(usernamePtr)};
        //	    datum userValue = {temp, strlen(temp)};
        //
        //	    // Add the key-value pair to the database
        //        gdbm_store(dbf, userKey, userValue, GDBM_INSERT);
        //        fprintf(stdout, "Successfully inserted new username with key:
        //        %s\n",
        //                userKey.dptr);
        //        break;
      }
      SSL_read(ssl, buffer, BUFFER_SIZE);

    } while (buffer[0] == 'y' || buffer[0] == 'Y');
    gdbm_close(dbf);

    //	// Receive RPC request and transfer the file
    //	bzero(buffer, BUFFER_SIZE);
    //	rcount = SSL_read(ssl, buffer, BUFFER_SIZE);
    //	if (sscanf(buffer, "getfile %s", filename) == 1) {
    //	  readfd = open(filename, O_RDONLY);
    //	  if (readfd < 0) {
    //	    fprintf(stderr, "Server: Could not open file \"%s\": %s\n",
    // filename, strerror(errno)); 	    sprintf(buffer, "error %d", errno);
    //	    SSL_write(ssl, buffer, strlen(buffer)+1);
    //	  } else {
    //	    do {
    //	      rcount = read(readfd, buffer, BUFFER_SIZE);
    //	      SSL_write(ssl, buffer, rcount);
    //	    } while (rcount > 0);
    //	    close(readfd);
    //	    // File transfer complete
    //	    fprintf(stdout, "Server: Completed file transfer to client (%s)\n",
    // client_addr);
    //	  }
    //	}

    // Terminate the SSL session, close the TCP connection, and clean up
    fprintf(
        stdout,
        "Server: Terminating SSL session and TCP connection with client (%s)\n",
        client_addr);
    SSL_free(ssl);
    close(client);
  }

  // Tear down and clean up server data structures before terminating
  SSL_CTX_free(ssl_ctx);
  gdbm_close(dbf);
  cleanup_openssl();
  close(sockfd);
  fprintf(stdout, "server: closed successfully\n");
  return 0;
}
