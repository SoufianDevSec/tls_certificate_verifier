#ifndef SSLMODEL_H
#define SSLMODEL_H

#include <string>
#include <QObject>
#include <random>
#include <vector>
#include <iostream>
#include <cstdlib> // For std::rand()
#include <netdb.h> // For getaddrinfo
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h> // For close()
#include <cstring>  // For memset
#include <ctime>    // For std::time()
#include <sodium.h>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <QDebug>
#include <QtCore/QDebug>
#include <QtCore/QByteArray>
#include <Validator.h>

class SSLModel : public QObject
{
    Q_OBJECT

public:
    explicit SSLModel(QObject *parent = nullptr);
    std::string performSSLConnection(const std::string &url);

    std::map<uint8_t, std::string> HandshakeTypeMap = {
        {0x02, "Server Hello"}};

    std::map<uint8_t, std::string> contentTypeMap = {
        {0x14, "Change Cipher Spec"},
        {0x15, "Alert"},
        {0x16, "Handshake"},
        {0x17, "Application Data"}};

    std::map<uint16_t ,std::string > cipherMap  = {
            {0x1301, "TLS_AES_128_GCM_SHA256"},
            {0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}
    };

    std::map<uint16_t, std::string> versionMap = {
        {0x0301, "TLS 1.0"},
        {0x0302, "TLS 1.1"},
        {0x0303, "TLS 1.2"},
        {0x0304, "TLS 1.3"}};

private:
    QList<std::shared_ptr<Validator>> validators;
    void setupValidators();
    bool validateInput(const X509 *cert); // Method for input validation
    std::vector<unsigned char> createClientHelloV1_3(const std::string &hostname);
    std::vector<unsigned char> createClientHelloV1_2(const std::string &hostname);
    void parseTLSRecord(const std::vector<uint8_t> &buffer, size_t bytes_received);
signals:
    void connectionSuccessful(const QString &validatorName);
    void connectionFailed(const QString &validatorName, const QString &reason);
};

#endif // SSLMODEL_H