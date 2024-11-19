// Implemented by: xdvory00 (Artem Dvorychanskyi)

#include <iostream>
#include <string>
#include <regex>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <map>
#include <stdexcept>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h> 
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "imap.hh"

/* @brief Print error to stderr and throw an exception. */
void IMAP::error(std::string err_msg, unsigned err_code){
    this->err_code = err_code;
    throw std::runtime_error(err_msg);
}

/* @brief Return true if error happened in the last action. */
bool IMAP::error_happened(){
    return err_code != 0;
}

/*
 * @brief Return last error message.
 */
std::string IMAP::get_error(){
    return this->err_msg;
}

void IMAP::clear_error(){
    err_code = 0;
    err_msg = "";
}

/* @brief Constructor:
 * set error code to 0
 */
IMAP::IMAP(){
    err_code = 0;
    message_id = 0;
}

/*
 * @brief Connect to the server.
 *
 * @param host - server hostname
 * @param port - server port
 * @return true if an error occurred
 */
bool IMAP::connect_to_server(std::string host, int port){
    secure = false;
    clear_error();
    
    struct addrinfo hints, *res, *p;
    int status;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    std::string port_str = std::to_string(port);
    if ((status = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res)) != 0){
        error("getaddrinfo: " + std::string(gai_strerror(status)), 2);
    }
    
    int sock;
    for(p = res; p != NULL; p = p->ai_next){
        if ((sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1){
            continue;
        }
        
        if (connect(sock, p->ai_addr, p->ai_addrlen) == -1){
            close(sock);
            continue;
        }
        
        break;
    }
    
    if (p == NULL){
        freeaddrinfo(res);
        error("Cannot connect to server", 4);
    }
    
    freeaddrinfo(res); 
    
    connection_sock = sock;
    return error_happened();
}

/*
 * @brief Connect to the server using TLS.
 *
 * @param host - server hostname
 * @param port - server port
 * @param file - certificate file
 * @param dir  - certificate directory
 * @return true if an error occurred
 */
bool IMAP::connect_to_server_s(std::string host, int port, std::string file, std::string dir){
    secure = true;
    clear_error();
    
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx)
        error ("CTX failed", 5);
    SSL_CTX_set_default_verify_paths(ctx);
    SSL *ssl;
    
    // Load certificate
    if (! SSL_CTX_load_verify_locations(ctx, (file.empty() ? NULL: file.c_str()), (dir.empty() ? NULL : dir.c_str())))
        error("Could not load certificate", 4);
    
    // New connection
    connection_sock_s = BIO_new_ssl_connect(ctx);
    if (!connection_sock_s)
        error("BIO_new_ssl_connect failed", 5);
    
    BIO_get_ssl(connection_sock_s, &ssl);
    if(!ssl){
        error("Cannot get SSL pointer", 5);
    }
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    
    // Set connection hostname
    std::string host_port = host + ":" + std::to_string(port);
    BIO_set_conn_hostname(connection_sock_s, host_port.c_str());
    
    // Connect
    if (BIO_do_connect(connection_sock_s) <= 0){
        error(ERR_reason_error_string(ERR_get_error()), 5);
    }
    
    if (SSL_get_verify_result(ssl) != X509_V_OK){
        error("Certificate could not be verified", 8);
    }
    
    return error_happened();
}

/* @brief Login to the server */
/* @brief Login to the server */
bool IMAP::login(std::string login, std::string password){
    clear_error();
    std::string response = communicate("LOGIN " + login + " " + password);

    //print 

    // Check for specific failure indicators in the server response
    if (response.find("AUTHENTICATIONFAILED") != std::string::npos) {
        err_msg = "Login failed: " + response; // Save the full server response
        err_code = 6; // Custom error code for login failure
        return true; // Indicate an error occurred
    }
    return error_happened(); // Return false if no error occurred
}

/* @brief Check if the incoming message has ended.
 *
 * @param msg - the received message so far
 * @param id  - the command ID
 * @return true if the message has ended
 */
bool IMAP::message_ended(const std::string& msg, const std::string& id) {
    std::string end_marker = "\r\n" + id + " ";
    if (msg.find(end_marker + "OK") != std::string::npos ||
        msg.find(end_marker + "NO") != std::string::npos ||
        msg.find(end_marker + "BAD") != std::string::npos) {
        return true; // Command has ended
    }
    return false;
}



/*
 * @brief Send a command to the server and return the response.
 *
 * @param message - command to send
 * @return server response
 */
std::string IMAP::communicate(std::string message){
    if (secure)
        return communicate_s(message);
    
    std::string msg_id = "A" + std::to_string(message_id++);
    std::string msg = msg_id + " " + message + "\r\n";

    // Send the message
    if (send(connection_sock, msg.c_str(), msg.size(), 0) == -1)
        error("Cannot send a message",5);
    
    char buf[4096];
    std::string answer;
    int received;
    fd_set set;
    struct timeval timeout;
    
    while (true) {
        FD_ZERO(&set);
        FD_SET(connection_sock, &set);
        timeout.tv_sec = 15; // Увеличьте таймаут, если это временная проблема
        timeout.tv_usec = 0;

        int rv = ::select(connection_sock + 1, &set, NULL, NULL, &timeout);

        if (rv == -1) {
            error("Select error while waiting for server response", 10);
        } else if (rv == 0) {
            error("Timeout while waiting for server response", 10);
        } 
    
        received = recv(connection_sock, buf, sizeof(buf), 0);

        if (received <= 0) {
            if (received == 0) {
                std::cerr << "Connection closed by server.\n";
            }
            error("Error while receiving data from server", 10);
        }

        answer.append(buf, received);
        if (message_ended(answer, msg_id)){
            break;
        }
}

    std::size_t last_line_b = answer.find_last_of("\n");
    if (last_line_b == std::string::npos)
        last_line_b = 0;
    std::string command_completed = answer.substr(last_line_b + 1);
    std::string final_answer = answer.substr(0, last_line_b);
    
    std::size_t start_pos = msg_id.size() + 2;
    std::size_t found = command_completed.find("NO");
    if (found == start_pos)
        error(final_answer, 6);
    else {
        found = command_completed.find("BAD");
        if (found == start_pos)
            error(final_answer, 7);
    }
    return final_answer;
}   

/*
 * @brief Communicate with the server securely.
 *
 * See communicate method for better understanding.
 */
std::string IMAP::communicate_s(std::string message){
    std::string msg_id = "A" + std::to_string(message_id++);
    std::string msg = msg_id + " " + message + "\r\n";

    // Send the message
    while (BIO_write(connection_sock_s, msg.c_str(), msg.size()) <= 0){
        if (!BIO_should_retry(connection_sock_s)){
            error("Could not send data to the server", 9);
        }
    }
    
    char buf[4096];
    std::string answer;
    int received;
    fd_set set;
    struct timeval timeout;
    
    int bio_fd;
    if (BIO_get_fd(connection_sock_s, &bio_fd) <= 0){
        error("Invalid BIO file descriptor", 10);
    }
    
    while (true){
        FD_ZERO(&set);
        FD_SET(bio_fd, &set);
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        
        int rv = ::select(bio_fd + 1, &set, NULL, NULL, &timeout);
        if(rv == -1){
            error("Select error while waiting for server response", 10);
        }
        else if(rv == 0){
            error("Timeout while waiting for server response", 10);
        }
        
        received = BIO_read(connection_sock_s, buf, sizeof(buf));
        if (received <= 0){
            if(BIO_should_retry(connection_sock_s)){
                continue;
            }
            error("Error while receiving data from server", 10);
        }
        
        answer.append(buf, received);
        
        if (message_ended(answer, msg_id))
            break;
    }
    
    // Parse the answer
    std::size_t last_line_b = answer.find_last_of("\n");
    if (last_line_b == std::string::npos)
        last_line_b = 0;
    std::string command_completed = answer.substr(last_line_b + 1);
    std::string final_answer = answer.substr(0, last_line_b);
    
    std::size_t start_pos = msg_id.size() + 2;
    std::size_t found = command_completed.find("NO");
    if (found == start_pos)
        error(final_answer, 6);
    else {
        found = command_completed.find("BAD");
        if (found == start_pos)
            error(final_answer, 7);
    }
    return final_answer;
}

/*
 * @brief Logout from the account.
 */
bool IMAP::logout(){
    clear_error();
    communicate("LOGOUT");
    return error_happened();
}

/*
 * @brief Cleanup before exiting.
 */
void IMAP::finish(){
    if (secure){
        if (connection_sock_s) {
            BIO_free_all(connection_sock_s);
            connection_sock_s = nullptr;
        }
        if (ctx) {
            SSL_CTX_free(ctx);
            ctx = nullptr;
        }
    } else {
        if (connection_sock != -1) {
            close(connection_sock);
            connection_sock = -1;
        }
    }
}
/*
 * @brief Select mailbox to work with.
 *
 * @param mailbox - name of the mailbox
 * @return server response
 */
std::string IMAP::select(std::string mailbox){
    clear_error();
    std::string answer;
    // Добавляем кавычки вокруг имени почтового ящика
    answer = communicate("SELECT \"" + mailbox + "\"");
    return answer;
}


/*
 * @brief Get one or range of messages from server.
 *
 * @param mailbox - id or range of ids of messages to fetch
 * @param type - type of data to fetch
 */
std::string IMAP::fetch(std::string ids, std::string type){
    clear_error();
    std::string answer;
    answer = communicate("FETCH " + ids + " " + type);
    return answer;
}

/*
 * @brief Find all message ids that follow some condition.
 *
 * @param args - condition by which messages are selected
 */
std::string IMAP::search(std::string args){
    clear_error();
    std::string answer;
    answer = communicate("SEARCH " + args);
    return answer;
}

std::string get_mailbox_name(const std::string& msg, std::regex r){
    std::smatch match;
    if (std::regex_search(msg, match, r))
        return match[1];
    else{
        return "";
    }
}
