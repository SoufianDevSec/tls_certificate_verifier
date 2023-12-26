#include <iostream>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main() {
    // Initialize OpenSSL
    SSL_load_error_strings();	
    OpenSSL_add_all_algorithms();
    SSL_library_init();

    // Enter URL
    std::string url;
    std::cout << "Geben Sie die URL ein (z.B. google.com): ";
    std::cin >> url;
    url += ":https";

    // Create a new SSL context
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        std::cerr << "Error creating SSL context." << std::endl;
        return 1;
    }

    // Create a new SSL connection
    BIO *bio = BIO_new_ssl_connect(ctx);
    
    // SSL pointer for the connection
    SSL *ssl;
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    // Set the connection hostname and port
    BIO_set_conn_hostname(bio, url.c_str());

    // Attempt to connect
    // if (BIO_do_connect(bio) <= 0) {
    //     std::cerr << "Error attempting to connect." << std::endl;
    //     BIO_free_all(bio);
    //     SSL_CTX_free(ctx);
    //     return 1;
    // }

    // Attempt to perform a handshake
    if (BIO_do_handshake(bio) <= 0) {
        std::cerr << "Error performing SSL handshake." << std::endl;
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Get the server's certificate
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        std::cout << "Server Certificate:" << std::endl;
        //PEM_write_X509(stdout, cert);
        X509_print_fp(stdout, cert);

        X509_free(cert);
    } else {
        std::cout << "No certificate presented by server." << std::endl;
    }

    // Clean up
    BIO_free_all(bio);
    SSL_CTX_free(ctx);

    return 0;
}
