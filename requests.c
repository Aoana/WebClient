#include "requests.h"
#include "helpers.h"
#include "parson.h"
#include <arpa/inet.h>
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <stdio.h>
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <unistd.h>     /* read, write, close */

char *compute_get_request(char *host, char *url, char *cookie, char *target)
{
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));

    // writes the method name, URL and protocol type
    sprintf(line, "GET %s HTTP/1.1", url);

    compute_message(message, line);

    // adds the host
    memset(line, 0, LINELEN);
    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    // adds the cookie
    if (cookie != NULL) {
        memset(line, 0, LINELEN);
        strcat(line, "Cookie: ");

        strcat(line, cookie);
        strcat(line, ";");
        //sprintf(line, "Cookie:%s", cookie);

        compute_message(message, line);
    }

    // adds the target
    if (target != NULL) {
        memset(line, 0, LINELEN);
        strcat(line, "Authorization: Bearer ");

        strcat(line, target);
        compute_message(message, line);
    }

    // adds new line
    compute_message(message, "");

    free(line);
    return message;
}


char *compute_post_request(char *host, char *url, char* content_type, 
                                            char *target, char *jwt) {
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));

    // writes the method name, URL and protocol type
    sprintf(line, "POST %s HTTP/1.1", url);
    compute_message(message, line);
    
    // adds the host
    memset(line, 0, LINELEN);
    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    //adds the target in authorization
    if (jwt != NULL) {
        sprintf(line, "Authorization: Bearer %s", jwt);
        compute_message(message, line);
    }

    sprintf(line, "Content-Type: %s", content_type);
    compute_message(message, line);

    // adds payload length
    int length = strlen(target);
    sprintf(line, "Content-Length: %d", length);
    compute_message(message, line);

    compute_message(message, "");   

    // adds payload
    memset(line, 0, LINELEN);
    strcat(message, target);


    free(line);
    return message;
}


char *compute_delete_request(char *host, char *url, char* token)
{
    char *message = (char*) calloc(BUFLEN, sizeof(char));
    char *line = (char*) calloc(LINELEN, sizeof(char));

    // Step 1: write the method name, URL and protocol type
    sprintf(line, "DELETE %s HTTP/1.1", url);
    compute_message(message, line);

    // Step 2: add the host
    memset(line, 0, LINELEN);
    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    // Step 3 (optional): add token
    if (token != NULL) {
        memset(line, 0, LINELEN);
        sprintf(line, "%s %s", "Authorization: Bearer", token);
        compute_message(message, line);
    }

    // Step 4: add final new line
    compute_message(message, "");

    free(line);
    return message;
}