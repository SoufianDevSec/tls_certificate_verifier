#include "sslmodel.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sstream>

SSLModel::SSLModel() {
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();
}

std::string SSLModel::performSSLConnection(const std::string& url) {
    std::stringstream output;
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        output << "Error creating SSL context.\n";
        return output.str();
    }

    BIO *bio = BIO_new_ssl_connect(ctx);
    SSL *ssl;
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(bio, (url + ":443").c_str());

    if (BIO_do_handshake(bio) <= 0) {
        output << "Error performing SSL handshake.\n";
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return output.str();
    }

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        output << "Server Certificate:\n";
        BIO *buffer = BIO_new(BIO_s_mem());
        X509_print(buffer, cert);
        char *data;
        long len = BIO_get_mem_data(buffer, &data);
        std::string certDetails(data, len);
        output << certDetails;
        BIO_free(buffer);
        X509_free(cert);
    } else {
        output << "No certificate presented by server.\n";
    }

    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return output.str();
}
