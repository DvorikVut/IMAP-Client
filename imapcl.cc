// Implemented by: xdvory00 (Artem Dvorychanskyi)

#include "imap.hh"
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <algorithm>
#include <map>
#include <regex>
#include <stdexcept>
#include <sstream>


/* @brief Print an error message and exit with the specified code. */
void error(std::string err_msg, int err_code){
    std::cerr << err_msg << std::endl;
    exit(err_code);
}

/* 
 * @brief Structure to hold all command-line arguments.
 */
struct config{
    std::string server;
    int port = 0;
    bool imaps = false;
    std::string certfile = "";
    std::string certaddr = "";
    bool n = false;
    bool h = false;
    std::string auth_file = "";
    std::string mailbox = "INBOX";
    std::string out_dir = "";
    bool help = false;
};

struct config config;


/*
 * @brief Print help and exit.
 */
void help(){
    std::cout << "IMAP client with TLS" << std::endl;
    std::cout << std::endl;
    std::cout << "Usage:" << std::endl;
    std::cout << "     imapcl --help   -> show this help and exit\n";
    std::cout << "     imapcl server [-p port] [-T [-c certfile] [-C certaddr]]";
    std::cout << "[-n] [-h] -a auth_file [-b MAILBOX] -o out_dir\n";
    exit(0);
}

/*
 * @brief Parse all command-line arguments.
 *
 * @param argc - number of arguments
 * @param argv - list of arguments
 * 
 * Creates a config structure, fills it with passed or default values, and returns it.
 */
struct config createConfig(int argc, char* argv[]){
    struct config conf;
    
    if (argc < 2){
        throw std::runtime_error("Wrong arguments, use --help to learn more.");
    }
    
    std::vector<std::string> args(argv +1 , argv + argc);
    
    // Get the server argument
    if (args.empty()){
        throw std::runtime_error("Host was not specified.");
    }
    conf.server = args[0];
    args.erase(args.begin());
    
    // Parse options
    for (size_t i = 0; i < args.size(); ++i){
        if (args[i] == "-T"){
            conf.imaps = true;
            // Parse optional -c and -C
            if (i +1 < args.size() && args[i+1] == "-c"){
                if (i +2 < args.size()){
                    conf.certfile = args[i+2];
                    i +=2;
                }
                else{
                    throw std::runtime_error("Argument -c needs a parameter.");
                }
            }
            if (i +1 < args.size() && args[i+1] == "-C"){
                if (i +2 < args.size()){
                    conf.certaddr = args[i+2];
                    i +=2;
                }
                else{
                    throw std::runtime_error("Argument -C needs a parameter.");
                }
            }
        }
        else if (args[i] == "-p"){
            if (i +1 < args.size()){
                std::string port_str = args[i+1];
                if (!std::all_of(port_str.begin(), port_str.end(), ::isdigit)){
                    throw std::runtime_error("Port is not a valid number.");
                }
                conf.port = std::stoi(port_str);
                i++;
            }
            else{
                throw std::runtime_error("Argument -p needs a parameter.");
            }
        }
        else if (args[i] == "-n"){
            conf.n = true;
        }
        else if (args[i] == "-h"){
            conf.h = true;
        }
        else if (args[i] == "-a"){
            if (i +1 < args.size()){
                conf.auth_file = args[i+1];
                i++;
            }
            else{
                throw std::runtime_error("Argument -a needs a parameter.");
            }
        }
        else if (args[i] == "-b"){
            if (i +1 < args.size()){
                conf.mailbox = args[i+1];
                i++;
            }
            else{
                throw std::runtime_error("Argument -b needs a parameter.");
            }
        }
        else if (args[i] == "-o"){
            if (i +1 < args.size()){
                conf.out_dir = args[i+1];
                if (conf.out_dir.back() != '/')
                    conf.out_dir += '/';
                i++;
                std::string command = "mkdir -p " + conf.out_dir;
                system(command.c_str());

                std::string clear_command = "rm -rf " + conf.out_dir + "*";
                system(clear_command.c_str());
                
            }
            else{
                throw std::runtime_error("Argument -o needs a parameter.");
            }
        }
        else{
            throw std::runtime_error("Unknown argument: " + args[i]);
        }
    }
    
    // Set defaults
    if (conf.port == 0){
        if (conf.imaps)
            conf.port = 993;
        else
            conf.port = 143;
    }
    
    if (conf.imaps && conf.certaddr.empty() && conf.certfile.empty()){
        conf.certaddr = "/etc/ssl/certs";
    }
    
    // Check required arguments
    if (conf.auth_file.empty()){
        throw std::runtime_error("Authentication file was not specified.");
    }
    
    if (conf.out_dir.empty()){
        throw std::runtime_error("Output directory was not specified.");
    }
    
    return conf;
}

/*
 * @brief Extract the length of the next message from the server response.
 *
 * @param msg - message from which to get the length
 * @param r   - regular expression for matching the message style
 * 
 * Each message contains its length, and it needs to be parsed to read the full message.
 */
int get_next_message_bytes(const std::string& msg, const std::regex& r){
    std::smatch match;
    if (std::regex_search(msg, match, r))
        return std::stoi(match[1]);
    else{
        throw std::runtime_error("Wrong return format from server");
    }
}

/*
 * @brief Extract the body content from the raw email message.
 *
 * @param raw_email - the complete email message in raw format
 * @return the body of the email message
 */
std::string extract_body_from_raw_email(const std::string& raw_email) {
    size_t body_start = raw_email.find("\r\n") + 2;
    if (body_start == std::string::npos) {
        throw std::runtime_error("Failed to find start of email body.");
    }

    size_t body_end = raw_email.rfind("\r\n)") - 1;
    if (body_end == std::string::npos || body_end <= body_start) {
        throw std::runtime_error("Failed to find end of email body.");
    }

    return raw_email.substr(body_start, body_end - body_start);
}


/*
 * @brief Decode MIME-encoded headers (Base64 or Quoted-Printable).
 *
 * @param encoded - the encoded header value
 * @return the decoded string
 */
std::string decode_mime_header(const std::string& encoded) {
    static std::regex mime_regex(R"(=\?([^?]+)\?([BQ])\?([^?]+)\?=)");
    std::smatch match;
    std::string decoded;

    auto decode_base64 = [](const std::string& encoded_text) {
        BIO* bio = BIO_new_mem_buf(encoded_text.data(), encoded_text.size());
        BIO* b64 = BIO_new(BIO_f_base64());
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

        std::vector<char> buffer(encoded_text.size());
        int decoded_size = BIO_read(bio, buffer.data(), buffer.size());
        BIO_free_all(bio);

        return std::string(buffer.begin(), buffer.begin() + decoded_size);
    };

    auto decode_quoted_printable = [](const std::string& encoded_text) {
        std::string decoded;
        for (size_t i = 0; i < encoded_text.size(); ++i) {
            if (encoded_text[i] == '=') {
                if (i + 2 < encoded_text.size()) {
                    int hex = std::stoi(encoded_text.substr(i + 1, 2), nullptr, 16);
                    decoded += static_cast<char>(hex);
                    i += 2;
                }
            } else {
                decoded += (encoded_text[i] == '_') ? ' ' : encoded_text[i];
            }
        }
        return decoded;
    };

    size_t pos = 0;
    while (std::regex_search(encoded.begin() + pos, encoded.end(), match, mime_regex)) {
        decoded += encoded.substr(pos, match.position());
        std::string charset = match[1].str();
        char encoding = match[2].str()[0];
        std::string encoded_text = match[3].str();

        if (encoding == 'B') { 
            decoded += decode_base64(encoded_text);
        } else if (encoding == 'Q') { 
            decoded += decode_quoted_printable(encoded_text);
        }

        pos += match.position() + match.length();
    }
    decoded += encoded.substr(pos);
    return decoded;
}


/*
 * @brief Decode a Base64-encoded string.
 *
 * @param encoded - the Base64-encoded string
 * @return the decoded string
 */
std::string decode_base64(const std::string& encoded) {
    std::string sanitized_encoded;
    for (char c : encoded) {
        if (c != '\n' && c != '\r') {
            sanitized_encoded += c;
        }
    }

    BIO* bio = BIO_new_mem_buf(sanitized_encoded.data(), sanitized_encoded.size());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    std::vector<char> buffer(sanitized_encoded.size());
    int decoded_size = BIO_read(bio, buffer.data(), buffer.size());
    BIO_free_all(bio);

    if (decoded_size <= 0) {
        std::cerr << "Base64 decoding failed. Encoded data: " << sanitized_encoded << std::endl;
        return "";
    }

    return std::string(buffer.begin(), buffer.begin() + decoded_size);
}


/*
 * @brief Extract headers and body from a raw email message.
 *
 * @param raw_email - the complete email message in raw format
 * @return formatted string containing headers and body
 */

std::string extract_headers_and_body(const std::string& raw_email) {
    std::string sanitized_email = extract_body_from_raw_email(raw_email);

    std::istringstream iss(sanitized_email);
    std::string line;
    std::map<std::string, std::string> header_map;
    std::string body;
    bool is_body = false;

    auto to_lowercase = [](const std::string& str) {
        std::string lower;
        std::transform(str.begin(), str.end(), std::back_inserter(lower), ::tolower);
        return lower;
    };
    
    while (std::getline(iss, line)) {
        if (line == "\r" || line.empty()) {
            is_body = true;
            continue;
        }
        if (is_body) {
            body += line + "\n";
        } else {
            size_t colon_pos = line.find(':');
            if (colon_pos != std::string::npos) {
                std::string header_name = line.substr(0, colon_pos);
                std::string header_value = line.substr(colon_pos + 1);

                header_name.erase(std::remove_if(header_name.begin(), header_name.end(), ::isspace), header_name.end());
                header_value.erase(0, header_value.find_first_not_of(" \t"));

                header_map[to_lowercase(header_name)] = decode_mime_header(header_value);
            }
        }
    }

    std::vector<std::string> header_order = {
        "date", "from", "to", "subject", "message-id"
    };

    std::ostringstream filtered_headers;
    for (const auto& header : header_order) {
        if (header_map.find(header) != header_map.end()) {
            std::string formatted_header = header;
            formatted_header[0] = toupper(formatted_header[0]);
            filtered_headers << formatted_header << ": " << header_map[header] << "\n";
        }
    }

    std::string decoded_body = body;
    if (header_map.find("content-transfer-encoding") != header_map.end() &&
        header_map["content-transfer-encoding"].find("base64") != std::string::npos) {
        decoded_body = decode_base64(body);
    }

    std::ostringstream final_email;

    if (config.h)
        return filtered_headers.str();

    final_email << filtered_headers.str() << "\n" << decoded_body;

    return final_email.str();
}






/*
 * Retrieve the UID of a message from the server response.
 *
 * @param msg - server response containing the UID
 * @param r   - regular expression for extracting the UID
 * @return the UID as a string
 */

std::string get_msg_uid(const std::string& msg, const std::regex& r){
    std::smatch match;
    if (std::regex_search(msg, match, r))
        return match[1];
    else{
        throw std::runtime_error("Wrong return format from server");
    }
}


/*
 * Main function of the IMAP client.
 */
int main(int argc, char* argv[]) {
    try {
        
        config = createConfig(argc, argv);

        IMAP con = IMAP();
        if (config.imaps) {
            con.connect_to_server_s(config.server, config.port, config.certfile, config.certaddr);
        } else {
            con.connect_to_server(config.server, config.port);
        }

        if (con.error_happened())
            throw std::runtime_error("Connection failed: " + con.get_error());

        // Authentication
        std::ifstream auth_file(config.auth_file);
        if (!auth_file.is_open())
            throw std::runtime_error("Auth file missing.");

        std::string login, passwd, line;
        getline(auth_file, line);
        login = line.substr(11);
        getline(auth_file, line);
        passwd = line.substr(11);

        if (con.login(login, passwd))
            throw std::runtime_error("Login failed.");

        con.select(config.mailbox);
        std::string messages = con.search(config.n ? "UNSEEN" : "ALL");

        std::istringstream iss(messages);
        std::string msg_id;

        int count = 0;

        while (iss >> msg_id) {


            if (!std::all_of(msg_id.begin(), msg_id.end(), ::isdigit))continue;

            try {
                // Fetch the raw email content
                std::string raw_email = con.fetch(msg_id, "BODY[]");

                // Process the email: extract headers and body
                std::string formatted_email = extract_headers_and_body(raw_email);

                std::regex date_regex(R"((^|\n)Date:\s+([^\n]+))");
                std::smatch match;
                std::string date_string = "unknown_date";

                if (std::regex_search(formatted_email, match, date_regex)) {
                    date_string = match[2];
                    date_string = std::regex_replace(date_string, std::regex("[\\s,:]"), "_");
                 }


            std::string sanitized_msg_id = std::to_string(count);
            std::string full_file_name = config.out_dir + sanitized_msg_id + "_" + login + ".txt";

                // Save email to file
                std::ofstream output(full_file_name);
                if (!output.is_open()) {
                    output.close();
                    error("Cannot open file: " + full_file_name, 0);
                }
                output << formatted_email;
                output.close();

                ++count;
            } catch (const std::exception& e) {

            }
        }
        if(config.h) 
            std::cout << "Downloaded headers of " << count << " messages from mailbox " << config.mailbox << "." << std::endl;
        else
            std::cout << "Downloaded " << count << " message(s) from mailbox " << config.mailbox << "." << std::endl;

        con.logout();
        con.finish();
    } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    return 0;
}

