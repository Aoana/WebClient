#include "helpers.h"
#include "requests.h"
#include "parson.h"
#include <arpa/inet.h>
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <unistd.h>     /* read, write, close */
#include <limits.h>


#define HOST "34.254.242.81"
#define PORT 8080
#define LEN 300
#define ACCESS_ROUTE_REGISTER "/api/v1/tema/auth/register"
#define ACCESS_ROUTE_LOGIN "/api/v1/tema/auth/login"
#define ACCESS_ROUTE "/api/v1/tema/library/access"
#define BOOK_DETAILS "/api/v1/tema/library/books"
#define GET_BOOK "/api/v1/tema/library/books/"
#define ADD_BOOKS "/api/v1/tema/library/books"
#define ACCESS_ROUTE_LOGOUT "/api/v1/tema/auth/logout"
#define PAYLOAD_TYPE "application/json"

void free_memory(void* ptr) {
	if (ptr != NULL) {
		free(ptr);
	}
}

void free_memory_again(void* ptr) {
	if (ptr != NULL) {
		free(ptr);
		ptr = NULL;
	}
}

char* send_post_request(int sockfd, char* host, char* route, char* payload_type, char* json) {
	// compute request, send to server and get response
	char* message = compute_post_request(host, route, payload_type, json, NULL);
	send_to_server(sockfd, message);
	char* response = receive_from_server(sockfd);
	free(message);
	return response;

}

char* send_post_request_new(int sockfd, char* host, char* route, char* payload_type, char* target, char* jwt) {
	// compute request, send to server and get response
	char* message = compute_post_request(host, route, payload_type, target, jwt);
	send_to_server(sockfd, message);
	char* response = receive_from_server(sockfd);
	free(message);
	return response;

}

char* get_post_request(int sockfd, char* host, char* route, char* cookie) {
	// compute request, send to server and get response
	char *message = compute_get_request(host, route, cookie, NULL);
	send_to_server(sockfd, message);
	char* response = receive_from_server(sockfd);
	free(message);
	return response;

}

char* get_post_request_new(int sockfd, char* host, char* route, char* jwt) {
	// compute request, send to server and get response
	char *message = compute_get_request(host, route, NULL, jwt);
	send_to_server(sockfd, message);
	char* response = receive_from_server(sockfd);
	free(message);
	return response;

}

char* delete_post_request(int sockfd, char* host, char* var, char* jwt) {
	// compute request, send to server and get response
	char *message = compute_delete_request(host, var, jwt);
	send_to_server(sockfd, message);
	char* response = receive_from_server(sockfd);
	free(message);
	return response;
}

void register_requests(int sockfd) {
	char *response;
	char *username = calloc(LEN, sizeof(char));
	char *password = calloc(LEN, sizeof(char));

	// read username
	printf("username=");
	fgets(username, LEN, stdin);
	username[strlen(username) - 1] = '\0';

	// read password
	printf("password=");
	fgets(password, LEN, stdin);
	password[strlen(password) - 1] = '\0';

	// make sure username or password don t have spaces in it
	if (strchr(username, ' ') != NULL || strchr(password, ' ') != NULL) {
		printf("No spaces allowed\n");

		free(username);
		free(password);
		return;
	}

	// want to create json objects
	JSON_Value *value = json_value_init_object();
	JSON_Object *object = json_value_get_object(value);
	json_object_set_string(object, "username", username);
	json_object_set_string(object, "password", password);

	sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
	char *json = json_serialize_to_string_pretty(value);

	// get the response from the server using the functions above
	response = send_post_request(sockfd, HOST, ACCESS_ROUTE_REGISTER, PAYLOAD_TYPE, json);

	// parse response
	char *no_user = "{\"error\":\"The username ";
	if(strstr(response, no_user) != NULL) {
		printf("Username is already taken\n");
	} else {
		printf ("200 - OK - user registred succesfully!\n");
	}

	free(username);
	free(password);
	json_free_serialized_string(json);
	json_value_free(value);
	free(response);
	close_connection(sockfd);  
}

char* login_requests(int sockfd) {
	char *response, *cookie;

	// alloc memory
	char *username = calloc(LEN, sizeof(char));
	char *password = calloc(LEN, sizeof(char));
	char *cookie_buf = (char *) calloc(LEN, sizeof(char));

	// read username
	printf("username=");
	fgets(username, LEN, stdin);
	username[strlen(username) - 1] = '\0';

	// read password
	printf("password=");
	fgets(password, LEN, stdin);
	password[strlen(password) - 1] = '\0';

	// make sure username or password don t have spaces in it
	if (strchr(username, ' ') != NULL || strchr(password, ' ') != NULL) {
		printf("No spaces allowed\n");
		free(username);
		free(password);
		return NULL;
	}

	// want to create json objects
	JSON_Value *value = json_value_init_object();
	JSON_Object *object = json_value_get_object(value);
	json_object_set_string(object, "username", username);
	json_object_set_string(object, "password", password);
	sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

	char *json = json_serialize_to_string_pretty(value);

	// get the response from the server using the functions above
	response = send_post_request(sockfd, HOST, ACCESS_ROUTE_LOGIN, PAYLOAD_TYPE, json);

	// parse response
	char *no_credential = "{\"error\":\"No account with this username!\"}";
	if(strstr(response, no_credential) != NULL) {
		printf("Credentials don't match registered credentials, try again\n");
	} else {
		printf("200 - OK - user logged succesfully!\n");
	}

	// parse session cookie
	memset(cookie_buf, 0, LEN);
	cookie = strstr(response, "Set-Cookie: ");
	if(cookie != NULL) {
		sscanf(cookie, "Set-Cookie: %s;", cookie_buf);
		cookie_buf[strlen(cookie_buf) - 1] = 0;
	}

	// free memory
	free(username);
	free(password);
	json_free_serialized_string(json);
	json_value_free(value);
	free(response);
	close_connection(sockfd);

	return cookie_buf;
}

char* enter_library_requests(int sockfd, char *cookie) {
	char *response, *jwt;
	char *token = (char *) calloc(LEN, sizeof(char));
	sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

	// get the response from the server using the functions above
	response = get_post_request(sockfd, HOST, ACCESS_ROUTE, cookie);

	// parse response
	char *not_logged = "{\"error\":\"You are not logged in!\"}";
	if(strstr(response, not_logged) != NULL) {
		printf("Try to log in first\n");
	} else {
		printf("User got access to the library\n");
		// parse jwt
		jwt = strstr(response,"{\"token");

		if (jwt != NULL) {
			JSON_Value *value = json_parse_string(jwt);             
			const char *get_token = json_object_get_string(json_object(value), "token");
			memcpy(token, get_token, strlen(get_token));
			json_value_free(value);
			free(response);
			return token;
		}
	}

	// free memory
	free(token);
	free(response);

	close_connection(sockfd);
	return NULL;
}

void get_books_requests(int sockfd, char *jwt) {
	char *response;
	char *final_array_of_json;

	sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

	// get the response from the server using the functions above
	response = get_post_request_new(sockfd, HOST, BOOK_DETAILS, jwt);

	// parse response
	char *no_auth = "{\"error\":\"Authorization header is missing!\"}";
	if(strstr(response, no_auth) != NULL) {
		printf("Current user(if any) didn't prove he is authorized to access the library\n");
	} else {
		printf ("Got all books down below:\n");
		final_array_of_json = strstr(response, "[");
		puts(final_array_of_json);
	}

	free(response);
	close_connection(sockfd);
}

void get_book_requests(int sockfd, char *jwt) {
	char *response;
	char id[20], var[100];
	char *final_array_of_json;

	sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

	// read id
	printf("id=");
	scanf("%s", id);
	// put the route in var to concactenate with id
	strcpy(var, "/api/v1/tema/library/books/");
	strcat(var, id);

	// get the response from the server using the functions above
	response = get_post_request_new(sockfd, HOST, var, jwt);

	// parse response
	char *no_auth = "{\"error\":\"Authorization header is missing!\"}";
	char *no_book = "{\"error\":\"No book was found!\"}";
	if(strstr(response, no_auth) != NULL) {
		printf("Current user don't have access to the library\n");
	} else if(strstr(response, no_book) != NULL) {
		printf("Book does not exist in the library\n");
	} else {
		printf("200 - OK - Here is your book:\n");
		final_array_of_json = strstr(response, "{");
		printf("%s\n", final_array_of_json);
	}

	free(response);
	close_connection(sockfd);
}

void add_book_requests(int sockfd, char *jwt) {
	char *response;
	char title[LEN], author[LEN], genre[LEN], publisher[LEN];
	char str_page_count[LEN];
	int page_count = INT_MIN;

	sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

	// read title
	printf("title=");
	fgets(title, LEN, stdin);
	title[strlen(title) - 1] = '\0';
	// read author
	printf("author=");
	fgets(author, LEN, stdin);
	author[strlen(author) - 1] = '\0';
	// read genre
	printf("genre=");
	fgets(genre, LEN, stdin);
	genre[strlen(genre) - 1] = '\0';
	// read number of pages
	printf("page_count=");
	fgets(str_page_count, LEN, stdin);
	sscanf(str_page_count, "%d", &page_count);
	// read publisher
	printf("publisher=");
	fgets(publisher, LEN, stdin);
	publisher[strlen(publisher) - 1] = '\0';

	// get the error for the wrong format
	if (page_count == INT_MIN) {
		printf("%s", "Try to respect the format down below:\n"
			"title: String,\n"
			"author: String,\n"
			"genre: String,\n"
			"page_count: Number,\n"
			"publisher: String\n"
		);

		// if no good format, close and don t add the book
		close_connection(sockfd);
		return;
	}

	JSON_Value *my_value = json_value_init_object();
	JSON_Object *my_object = json_value_get_object(my_value);

	// set with the book info
	json_object_set_string(my_object, "title", title);
	json_object_set_string(my_object, "author", author);
	json_object_set_string(my_object, "genre", genre);
	json_object_set_number(my_object, "page_count", page_count);
	json_object_set_string(my_object, "publisher", publisher);

	// converts the json to string
	char *target = json_serialize_to_string_pretty(my_value);

	// get the response from the server using the functions above
	response = send_post_request_new(sockfd, HOST, ADD_BOOKS, PAYLOAD_TYPE, target, jwt);

	// parse response
	char *no_auth = "{\"error\":\"Authorization header is missing!\"}";
	if(strstr(response, no_auth) != NULL) {
		printf("Current user(if any) didn't prove he is authorized to access the library\n or\n");
		printf("Try to respect the format down below:\n"
				"title: String,\n"
				"author: String,\n"
				"genre: String,\n"
				"page_count: Number,\n"
				"publisher: String\n"
		);
	} else {
		printf("200 - OK - The book was added\n");
	}

	// free memory
	free(response);
	free(target);
	json_value_free(my_value);
	close_connection(sockfd);
}

void delete_book_requests(int sockfd, char *jwt) {
	char*response;
	char id[100], var[100];

	// get the response from the server using the functions above
	sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

	//read id;
	printf("id=");
	scanf("%s", id);

	// put the route in var to concactenate with id
	strcpy(var, "/api/v1/tema/library/books/");
	strcat(var, id);

	// get the response from the server using the functions above
	response = delete_post_request(sockfd, HOST, var, jwt);

	// parse response
	char *no_auth = "{\"error\":\"Authorization header is missing!\"}";
	char *no_book = "{\"error\":\"No book was deleted!\"}";
	if(strstr(response, no_auth) != NULL) {
		printf("Current user don't have access to the library\n");
	} else if(strstr(response, no_book) != NULL) {
		printf("Book does not exist in the library\n");
	} else {
		printf("200 - OK - The book was deleted\n");
	}

	free(response);
	close_connection(sockfd);
}

void logout_request(int sockfd, char* cookie, char* jwt) {
	char *response;

	sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

	// get the response from the server using the functions above
	response = get_post_request(sockfd, HOST, ACCESS_ROUTE_LOGOUT, cookie);

	// parse response
	char *not_logged = "{\"error\":\"You are not logged in!\"}";
	if (strstr(response, not_logged)) {
		printf("You have to be logged in first to log out\n");
	} else {
		printf("200 - OK - User logged out\n");
	}

	// free memory
	free(response);
	// free login cookie when logout
	free_memory(cookie);
	free_memory(jwt);
	close_connection(sockfd);
}

int main(int argc, char *argv[]) {
	int sockfd = -1;
	char command[LEN];
	char *cookie = NULL, *jwt = NULL;
	while (1) {
		fgets(command, LEN, stdin);
		command[strlen(command) - 1] = '\0';

		if(strncmp(command, "exit", 4) == 0) {
			// free resources when exit
			free_memory_again(cookie);
			free_memory_again(jwt);

			break;
		} else if (strncmp(command, "register", 8) == 0) {
			register_requests(sockfd);
		} else if (strncmp(command, "login", 5) == 0) {
			cookie = login_requests(sockfd);
		} else if (strncmp(command, "enter_library", 13) == 0) {
			jwt = enter_library_requests(sockfd, cookie);
		} else if (strncmp(command, "get_books", 9) == 0) {
			get_books_requests(sockfd, jwt);
		} else if (strncmp(command, "get_book", 8) == 0) {
			get_book_requests(sockfd, jwt);
		} else if (strncmp(command, "add_book", 8) == 0) {
			add_book_requests(sockfd, jwt);
		} else if (strncmp(command, "delete_book", 11) == 0) {
			delete_book_requests(sockfd, jwt);
		} else if (strncmp(command, "logout", 6) == 0) {
			logout_request(sockfd, cookie, jwt);
			cookie = NULL;
			jwt = NULL;
		} else if (command[0] != 0) {
			printf("Invalid request\n");
		}

		memset(command, 0, LEN);
	}
	return 0;
}
