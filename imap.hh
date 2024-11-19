// Implemented by: xdvory00 (Artem Dvorychanskyi)

#ifndef IMAP_HH
#define IMAP_HH

#include <string>
#include <openssl/bio.h>
#include <openssl/ssl.h>

class IMAP {
public:
    IMAP();
    ~IMAP() { finish(); }

    /* Error handling */
    void error(std::string err_msg, unsigned err_code);
    bool error_happened();
    std::string get_error();
    void clear_error();

    /* Connection methods */
    bool connect_to_server(std::string host, int port);
    bool connect_to_server_s(std::string host, int port, std::string file, std::string dir);
    bool login(std::string login, std::string password);
    bool logout();
    void finish();

    /* IMAP commands */
    std::string select(std::string mailbox);
    std::string fetch(std::string ids, std::string type);
    std::string search(std::string args);
    std::string list(std::string parent = "", std::string del = "");

private:
    /* Helper methods */
    bool message_ended(const std::string& msg, const std::string& id);
    std::string communicate(std::string message);
    std::string communicate_s(std::string message);

    /* Member variables */
    int connection_sock;
    BIO* connection_sock_s;
    SSL_CTX* ctx;
    bool secure;
    unsigned err_code;
    std::string err_msg;
    unsigned long message_id;
};

#endif // IMAP_HH
