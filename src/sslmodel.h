#ifndef SSLMODEL_H
#define SSLMODEL_H

#include <string>

class SSLModel {
public:
    SSLModel();
    std::string performSSLConnection(const std::string& url);
};

#endif // SSLMODEL_H
