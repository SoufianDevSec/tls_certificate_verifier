#include "SSLmodel.h"
#include <sstream>

SSLModel::SSLModel(QObject *parent) : QObject(parent)
{
    setupValidators();
}

void SSLModel::setupValidators()
{
    // Create a shared pointer for the validator
    auto expirationValidator = std::make_shared<ExpirationValidator>(this, "expirationValidator");
    validators.append(expirationValidator);
}

std::string SSLModel::performSSLConnection(const std::string &url)
{
    std::stringstream output;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(url.c_str(), "443", &hints, &res) != 0)
    {
        output << "DNS resolution failed";
        return output.str();
    }

    // Create socket
    int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0)
    {
        output << "Socket creation failed";
        freeaddrinfo(res);
        return output.str();
    }

    // Connect using the resolved address
    if (::connect(sockfd, res->ai_addr, res->ai_addrlen) < 0)
    {
        output << "Connect failed";
        close(sockfd);
        freeaddrinfo(res);
        return output.str();
    }

    auto clientHelloMessage = createClientHelloV1_3(url);

    // Send the Client Hello
    size_t bytes_sent = send(sockfd, clientHelloMessage.data(), clientHelloMessage.size(), 0);
    if (bytes_sent < 0)
    {
        output << "Send failed";
        close(sockfd);
        freeaddrinfo(res);
        return output.str();
    }

    // Read response from server
    std::vector<unsigned char> buffer(4096); // Adjust buffer size as needed

    size_t bytes_received = recv(sockfd, buffer.data(), buffer.size(), 0);
    if (bytes_received < 0)
    {
        output << "Receive failed";
    }
    else
    {
        // For simplicity, we'll just output the raw bytes received.
        // Parsing the TLS response would require a deeper understanding of the protocol.
        parseTLSRecord(buffer, bytes_received);
        output << "Received " << bytes_received << " bytes in response.\n";
        for (size_t i = 0; i < bytes_received; ++i)
        {
            output << std::hex << static_cast<int>(buffer[i]) << " ";
        }
    }

    // Cleanup
    close(sockfd);
    freeaddrinfo(res);

    return output.str();

    // if (!validateInput(cert)) {
    //     BIO_free(buffer);
    //     X509_free(cert);
    //     BIO_free_all(bio);
    //     SSL_CTX_free(ctx);
    //     return "";
    // }
}

bool SSLModel::validateInput(const X509 *cert)
{
    for (const auto &validator : validators)
    {
        if (!validator->validate(cert))
        {
            emit connectionFailed(validator->getValidatorName(), validator->getReason()); // Relay to MainWindow
            return false;                                                                 // Stop validation process if any validator fails
        }
        else
        {
            emit connectionSuccessful(validator->getValidatorName()); // Relay to MainWindow
        }
    }
    return true;
}

std::vector<unsigned char> SSLModel::createClientHelloV1_3(const std::string &hostname)
{
    std::vector<unsigned char> clientHello;

    // Record Layer Header
    clientHello.push_back(0x16); // Content Type: Handshake (0x16)
    clientHello.push_back(0x03); // TLS Major Version (0x03 for TLS 1.x)
    clientHello.push_back(0x03); // TLS Minor Version (0x03 for TLS 1.2)

    // Record Layer Length placeholder (to be filled later)
    clientHello.push_back(0x00); // Length MSB
    clientHello.push_back(0x00); // Length LSB

    // Handshake Protocol: Client Hello
    clientHello.push_back(0x01); // Handshake Type: Client Hello (0x01)

    // Handshake Length placeholder (to be filled later)
    clientHello.push_back(0x00); // Length
    clientHello.push_back(0x00); // Length
    clientHello.push_back(0x00); // Length

    // Client Version (TLS 1.2)
    clientHello.push_back(0x03); // TLS Major Version
    clientHello.push_back(0x03); // TLS Minor Version

    // Random(32 bytes)
    srand(time(NULL));
    for (int i = 0; i < 32; ++i)
    {
        clientHello.push_back(rand() % 256);
    }

    // Session ID
    clientHello.push_back(0x00); // Session ID Length

    // Cipher Suites
    const std::vector<uint16_t> cipherSuites = {
        0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8,
        0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c,
        0x009d, 0x002f, 0x0035, 0x1301,
        0x1302, 0x1303};

    // Cipher Suites Length
    clientHello.push_back((cipherSuites.size() * 2) >> 8 & 0xFF); // MSB
    clientHello.push_back((cipherSuites.size() * 2) & 0xFF);      // LSB

    for (auto &suite : cipherSuites)
    {
        clientHello.push_back(suite >> 8 & 0xFF); // MSB
        clientHello.push_back(suite & 0xFF);      // LSB
    }

    // Compression Methods
    clientHello.push_back(0x01); // Compression Methods Length
    clientHello.push_back(0x00); // Compression Method (null)

    // Extensions Length placeholder (to be filled later)
    size_t extStart = clientHello.size();
    clientHello.push_back(0x00); // Length MSB placeholder
    clientHello.push_back(0x00); // Length LSB placeholder

    // Server Name Indication (SNI) Extension
    clientHello.push_back(0x00);
    clientHello.push_back(0x00); // Extension Type: Server Name (0x0000)
    size_t sniExtLengthIndex = clientHello.size();
    clientHello.push_back(0x00);
    clientHello.push_back(0x00); // Length placeholder

    size_t sniListLengthIndex = clientHello.size();
    clientHello.push_back(0x00);
    clientHello.push_back(0x00); // Server Name list length placeholder

    clientHello.push_back(0x00); // Server Name Type: host_name (0x00)
    size_t sniNameLengthIndex = clientHello.size();
    clientHello.push_back(0x00);
    clientHello.push_back(0x00); // Server name length placeholder
    for (char c : hostname)
    {
        clientHello.push_back(static_cast<unsigned char>(c));
    }
    size_t sniNameLength = hostname.length();
    clientHello[sniNameLengthIndex] = (sniNameLength >> 8) & 0xFF;
    clientHello[sniNameLengthIndex + 1] = sniNameLength & 0xFF;

    size_t sniListLength = 1 + 2 + sniNameLength; // 1 byte for name type, 2 for name length, name
    clientHello[sniListLengthIndex] = (sniListLength >> 8) & 0xFF;
    clientHello[sniListLengthIndex + 1] = sniListLength & 0xFF;

    size_t sniExtLength = 2 + sniListLength; // 2 for the list length, list
    clientHello[sniExtLengthIndex] = (sniExtLength >> 8) & 0xFF;
    clientHello[sniExtLengthIndex + 1] = sniExtLength & 0xFF;

    // Supported Versions Extension
    clientHello.push_back(0x00);
    clientHello.push_back(0x2b); // Extension Type: supported_versions (0x2b)
    clientHello.push_back(0x00);
    clientHello.push_back(0x05); // Extension Length: 5 bytes (1 for version list size + 4 for versions)
    clientHello.push_back(0x04); // Versions list size: 4 bytes (2 versions)
    clientHello.push_back(0x03);
    clientHello.push_back(0x04); // TLS 1.3 (0x0304)
    clientHello.push_back(0x03);
    clientHello.push_back(0x03); // TLS 1.2 (0x0303)

    // Start of Key Share Extension
    clientHello.push_back(0x00); // Extension Type: key_share (0x33) MSB
    clientHello.push_back(0x33); // Extension Type: key_share (0x33) LSB

    // Placeholder for the Key Share extension length (will be updated later)
    size_t keyShareExtLengthIndex = clientHello.size();
    clientHello.push_back(0x00); // Length MSB placeholder
    clientHello.push_back(0x00); // Length LSB placeholder

    // Placeholder for Client Key Share Length (will be updated later)
    size_t clientKeyShareLengthIndex = clientHello.size();
    clientHello.push_back(0x00); // Length MSB placeholder
    clientHello.push_back(0x00); // Length LSB placeholder

    unsigned char client_publickey[crypto_kx_PUBLICKEYBYTES];
    unsigned char client_secretkey[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(client_publickey, client_secretkey);

    // First Key Share Entry: x25519
    clientHello.push_back(0x00); // Group: x25519 (0x001D) MSB
    clientHello.push_back(0x1D); // Group: x25519 (0x001D) LSB
    clientHello.push_back(0x00); // Key Exchange Length: 32 bytes MSB
    clientHello.push_back(0x20); // Key Exchange Length: 32 bytes LSB

    // x25519 Public Key (32 bytes) - Replace with actual public key
    clientHello.insert(clientHello.end(), client_publickey, client_publickey + crypto_kx_PUBLICKEYBYTES);

    QByteArray keyArray(reinterpret_cast<const char *>(client_publickey), crypto_kx_PUBLICKEYBYTES);
    qDebug().noquote() << keyArray.toHex(':');

    // Second Key Share Entry: secp256r1
    clientHello.push_back(0x00); // Group: secp256r1 (0x0017) MSB
    clientHello.push_back(0x17); // Group: secp256r1 (0x0017) LSB
    clientHello.push_back(0x00); // Key Exchange Length: 65 bytes MSB
    clientHello.push_back(0x41); // Key Exchange Length: 65 bytes LSB

    // secp256r1 Public Key (65 bytes) - Replace with actual public key
    std::vector<unsigned char> secp256r1PublicKey(65, 0x02); // Example public key, replace with actual key
    clientHello.insert(clientHello.end(), secp256r1PublicKey.begin(), secp256r1PublicKey.end());

    // Update Client Key Share Length
    size_t clientKeyShareLength = 4 + crypto_kx_PUBLICKEYBYTES + 4 + secp256r1PublicKey.size();
    clientHello[clientKeyShareLengthIndex] = (clientKeyShareLength >> 8) & 0xFF; // Length MSB
    clientHello[clientKeyShareLengthIndex + 1] = clientKeyShareLength & 0xFF;    // Length LSB

    // Update Key Share Extension Length
    size_t keyShareExtLength = clientHello.size() - keyShareExtLengthIndex - 2;
    clientHello[keyShareExtLengthIndex] = (keyShareExtLength >> 8) & 0xFF; // Length MSB
    clientHello[keyShareExtLengthIndex + 1] = keyShareExtLength & 0xFF;    // Length LSB

    // Start of Signature Algorithms Extension
    clientHello.push_back(0x00); // Extension Type: signature_algorithms (0x0d) MSB
    clientHello.push_back(0x0d); // Extension Type: signature_algorithms (0x0d) LSB

    // Placeholder for the Signature Algorithms extension length (will be updated later)
    size_t sigAlgExtLengthIndex = clientHello.size();
    clientHello.push_back(0x00); // Length MSB placeholder
    clientHello.push_back(0x00); // Length LSB placeholder

    // Placeholder for Signature Hash Algorithms vector (will be filled next)
    std::vector<unsigned char> sigHashAlgos = {
        0x04, 0x03, // ecdsa_secp256r1_sha256
        0x05, 0x03, // ecdsa_secp384r1_sha384
        0x06, 0x03, // ecdsa_secp521r1_sha512
        0x08, 0x04, // rsa_pss_rsae_sha256
        0x08, 0x05, // rsa_pss_rsae_sha384
        0x08, 0x06, // rsa_pss_rsae_sha512
        0x04, 0x01, // rsa_pkcs1_sha256
        0x05, 0x01, // rsa_pkcs1_sha384
        0x06, 0x01, // rsa_pkcs1_sha512
        0x02, 0x01, // rsa_pkcs1_sha1
    };

    // Signature Hash Algorithms length
    size_t sigHashAlgosLength = sigHashAlgos.size();
    clientHello.push_back(sigHashAlgosLength >> 8);   // Signature Hash Algorithms Length MSB
    clientHello.push_back(sigHashAlgosLength & 0xFF); // Signature Hash Algorithms Length LSB

    // Add Signature Hash Algorithms
    clientHello.insert(clientHello.end(), sigHashAlgos.begin(), sigHashAlgos.end());

    // Update Signature Algorithms Extension Length
    size_t sigAlgExtLength = 2 + sigHashAlgosLength;                   // 2 bytes for the length field + the length of the vector
    clientHello[sigAlgExtLengthIndex] = (sigAlgExtLength >> 8) & 0xFF; // Length MSB
    clientHello[sigAlgExtLengthIndex + 1] = sigAlgExtLength & 0xFF;    // Length LSB

    // Supported Groups Extension
    clientHello.push_back(0x00); // Extension Type: supported_groups (0x000A) MSB
    clientHello.push_back(0x0A); // Extension Type: supported_groups (0x000A) LSB

    // Placeholder for the extension length (will be updated later)
    size_t supportedGroupsExtLengthIndex = clientHello.size();
    clientHello.push_back(0x00); // Length MSB
    clientHello.push_back(0x00); // Length LSB

    // Supported Groups List Length
    size_t supportedGroupsListStart = clientHello.size();
    clientHello.push_back(0x00); // Length MSB (to be updated)
    clientHello.push_back(0x00); // Length LSB (to be updated)

    // Supported Groups
    std::vector<uint16_t> supportedGroups = {
        0x001D, // x25519
        0x0017, // secp256r1
        0x0018, // secp384r1
        0x0019, // secp521r1
        0x0100, // ffdhe2048
        0x0101  // ffdhe3072
    };

    for (auto &group : supportedGroups)
    {
        clientHello.push_back(group >> 8);   // Group MSB
        clientHello.push_back(group & 0xFF); // Group LSB
    }

    // Update Supported Groups List Length
    size_t supportedGroupsListLength = supportedGroups.size() * 2;                   // 2 bytes per group
    clientHello[supportedGroupsListStart] = (supportedGroupsListLength >> 8) & 0xFF; // Length MSB
    clientHello[supportedGroupsListStart + 1] = supportedGroupsListLength & 0xFF;    // Length LSB

    // Update Supported Groups Extension Length
    size_t supportedGroupsExtLength = 2 + supportedGroupsListLength;                     // 2 bytes for the list length field
    clientHello[supportedGroupsExtLengthIndex] = (supportedGroupsExtLength >> 8) & 0xFF; // Length MSB
    clientHello[supportedGroupsExtLengthIndex + 1] = supportedGroupsExtLength & 0xFF;    //

    // Record Size Limit Extension
    clientHello.push_back(0x00);
    clientHello.push_back(0x1c); // Extension Type: record_size_limit (0x1c)
    clientHello.push_back(0x00);
    clientHello.push_back(0x02); // Extension Length: 2 bytes
    clientHello.push_back(0x40);
    clientHello.push_back(0x00); // Record Size Limit: 16384 bytes (the default maximum size for TLS)

    // Update Extensions Length
    size_t extLength = clientHello.size() - extStart - 2; // Gesamtlänge der Erweiterungen
    clientHello[extStart] = (extLength >> 8) & 0xFF;      // Extensions Length MSB
    clientHello[extStart + 1] = extLength & 0xFF;         // Extensions Length LSB

    // Update Handshake Length
    size_t handshakeLength = clientHello.size() - 5 - 4; // Gesamtlänge des Handshakes (ohne den Handshake Header)
    clientHello[6] = (handshakeLength >> 16) & 0xFF;     // Handshake Length MSB
    clientHello[7] = (handshakeLength >> 8) & 0xFF;      // Handshake Length
    clientHello[8] = handshakeLength & 0xFF;             // Handshake Length LSB

    // Update Record Layer Length
    size_t recordLayerLength = clientHello.size() - 5; // Gesamtlänge des Record Layers (ohne den Record Layer Header)
    clientHello[3] = (recordLayerLength >> 8) & 0xFF;  // Record Layer Length MSB
    clientHello[4] = recordLayerLength & 0xFF;         // Record Layer Length LSB

    return clientHello;
}

std::vector<unsigned char> SSLModel::createClientHelloV1_2(const std::string &hostname)
{
    std::vector<unsigned char> clientHello;

    // Record Layer Header
    clientHello.insert(clientHello.end(), {0x16, 0x03, 0x03});

    // Record Layer Length placeholder
    size_t recordLayerLengthPos = clientHello.size();
    clientHello.insert(clientHello.end(), {0x00, 0x00});

    // Handshake Type: Client Hello (0x01)
    clientHello.push_back(0x01);

    // Handshake Length placeholder
    size_t handshakeLengthPos = clientHello.size();
    clientHello.insert(clientHello.end(), {0x00, 0x00, 0x00});

    // ClientHello Version (TLS 1.2)
    clientHello.insert(clientHello.end(), {0x03, 0x03});

    // Random (32 bytes)
    srand(time(NULL));
    for (int i = 0; i < 32; ++i)
    {
        clientHello.push_back(rand() % 256);
    }

    // Session ID Length: 0
    clientHello.push_back(0x00);

    // Cipher Suites
    std::vector<unsigned char> cipherSuites = {
        0x00, 0x2F, // TLS_RSA_WITH_AES_128_CBC_SHA
        0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
        0xC0, 0x2F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xCC, 0xA8  // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    };
    size_t cipherSuitesLength = cipherSuites.size();
    clientHello.push_back(cipherSuitesLength >> 8);
    clientHello.push_back(cipherSuitesLength & 0xFF);
    clientHello.insert(clientHello.end(), cipherSuites.begin(), cipherSuites.end());

    // Compression Methods
    clientHello.push_back(0x01); // Compression methods length
    clientHello.push_back(0x00); // Compression method: null

    // Extensions Length placeholder
    size_t extensionsLengthPos = clientHello.size();
    clientHello.insert(clientHello.end(), {0x00, 0x00});

    // Server Name Indication Extension
    std::vector<unsigned char> serverName = {0x00, 0x00};        // Extension type: server_name
    size_t serverNameListLength = hostname.length() + 3;         // Name type (1) + name length (2)
    size_t serverNameExtensionLength = serverNameListLength + 2; // List length (2)
    serverName.push_back(serverNameExtensionLength >> 8);
    serverName.push_back(serverNameExtensionLength & 0xFF);
    serverName.push_back(serverNameListLength >> 8);
    serverName.push_back(serverNameListLength & 0xFF);
    serverName.push_back(0x00); // Name type: host_name
    serverName.push_back(hostname.length() >> 8);
    serverName.push_back(hostname.length() & 0xFF);
    for (char c : hostname)
    {
        serverName.push_back(c);
    }
    clientHello.insert(clientHello.end(), serverName.begin(), serverName.end());

    // Update Extensions Length
    size_t extensionsLength = clientHello.size() - extensionsLengthPos - 2;
    clientHello[extensionsLengthPos] = extensionsLength >> 8;
    clientHello[extensionsLengthPos + 1] = extensionsLength & 0xFF;

    // Update Handshake Length
    size_t handshakeLength = clientHello.size() - handshakeLengthPos - 3;
    clientHello[handshakeLengthPos] = handshakeLength >> 16;
    clientHello[handshakeLengthPos + 1] = (handshakeLength >> 8) & 0xFF;
    clientHello[handshakeLengthPos + 2] = handshakeLength & 0xFF;

    // Update Record Layer Length
    size_t recordLayerLength = clientHello.size() - recordLayerLengthPos - 2;
    clientHello[recordLayerLengthPos] = recordLayerLength >> 8;
    clientHello[recordLayerLengthPos + 1] = recordLayerLength & 0xFF;

    return clientHello;
}


// Function to convert bytes to a hexadecimal string for display
std::string bytesToHexString(const uint8_t* bytes, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << static_cast<unsigned>(bytes[i]);
    }
    return ss.str();
}

void  SSLModel::parseTLSRecord(const std::vector<uint8_t>& buffer, size_t bytes_received) {
    if (bytes_received <= 0) {
        // Handle error or closed connection
        return;
    }

    size_t index = 0;

    if (bytes_received < 5) { // Check if the header is complete
        std::cerr << "Incomplete TLS record header\n";
        return;
    }

    uint8_t contentType = buffer[index++];
    uint16_t version = (buffer[index] << 8) | buffer[index + 1];
    index += 2;
    uint16_t FullLength = (buffer[index] << 8) | buffer[index + 1];
    index += 2;

    // Check if the entire payload has been received based on the length field
    if (bytes_received < index + FullLength) {
        std::cerr << "Incomplete TLS record payload\n";
        return;
    }

    // Proceed to parse the payload based on the content type
    // value = (byte[0] << 8*(n-1)) | (byte[1] << 8*(n-2)) | ... | byte[n-1];

    uint8_t handshakeType = buffer[index++];
    uint32_t lengthServerHello =  (buffer[index] << 16 ) | (buffer[index + 1] << 8) | (buffer[index + 2]);
    index += 3;
    uint16_t newVersion = (buffer[index] << 8) | (buffer[index + 1]);
    index += 2;


    // Now extract the 32-byte random value
    const size_t randomSize = 32; // The length of the random value field

    uint8_t randomBytes[randomSize];
    for (size_t i = 0; i < randomSize; ++i) {
        randomBytes[i] = buffer[index + i];
    }
    std::string randomHexString = bytesToHexString(randomBytes, randomSize);

    index += 32; // Move the index past the random field

    uint8_t sessionIdLength = buffer[index++];

    std::string sessionIdHexString;
    uint16_t  chosenCipherSuite;
    if (sessionIdLength != 0) {
        uint8_t sessionBytes[randomSize];
        for (size_t i = 0; i < randomSize; ++i) {
            sessionBytes[i] = buffer[index + i];
        }

        sessionIdHexString = bytesToHexString(sessionBytes, randomSize);
        index += 32;

        chosenCipherSuite = (buffer[index] << 8) | (buffer[index + 1]);
        index += 2;
    } else{
        chosenCipherSuite = (buffer[index] << 8) | (buffer[index + 1]);
        index += 2;
    }




    std::cout << "Content Type: " << (contentTypeMap.count(contentType) ? contentTypeMap[contentType] : "Unknown") << std::endl;
    std::cout << "Version: " << (versionMap.count(version) ? versionMap[version] : "Unknown Version") << std::endl;
    std::cout << "FullLength: " << FullLength << std::endl;
    std::cout << "Handshake Type: " << (HandshakeTypeMap.count(handshakeType) ? HandshakeTypeMap[handshakeType] : "Unknown") << std::endl;
    std::cout << "lengthServerHello: " << lengthServerHello << std::endl;
    std::cout << "newVersion: " << (versionMap.count(newVersion) ? versionMap[newVersion] : "Unknown Version") << std::endl;
    std::cout << "Random value: " << randomHexString << std::endl;
    std::cout << "Session ID Length: " << static_cast<int>(sessionIdLength) << std::endl;
    std::cout << "Session ID Value: " << sessionIdHexString << std::endl;
    std::cout << "Server Cipher suite: " << (cipherMap.count(chosenCipherSuite) ? cipherMap[chosenCipherSuite] : "unknown") << std::endl;

}


