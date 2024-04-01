#include "Validator.h"
#include <chrono>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>

bool ExpirationValidator::validate(const X509* cert) {
    auto [validFrom, validUntil] = getCertificateValidity(cert);
    std::time_t notBefore = parseASN1Time(validFrom);
    std::time_t notAfter = parseASN1Time(validUntil);
    std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    return now >= notBefore && now <= notAfter;
}

std::pair<std::string, std::string> ExpirationValidator::getCertificateValidity(const X509* cert) {
    const ASN1_TIME* notBefore = X509_get0_notBefore(cert);
    const ASN1_TIME* notAfter = X509_get0_notAfter(cert);
    if (!notBefore || !notAfter) {
        throw std::runtime_error("Invalid certificate dates");
    }
    std::string notBeforeStr = asn1TimeToString(notBefore);
    std::string notAfterStr = asn1TimeToString(notAfter);
    return {notBeforeStr, notAfterStr};
}

std::string ExpirationValidator::asn1TimeToString(const ASN1_TIME* time) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) throw std::runtime_error("Failed to create BIO");
    if (!ASN1_TIME_print(bio, time)) {
        BIO_free(bio);
        throw std::runtime_error("Failed to print ASN1_TIME");
    }
    char* buf;
    long size = BIO_get_mem_data(bio, &buf);
    std::string result(buf, size);
    BIO_free(bio);
    return result;
}

std::time_t ExpirationValidator::parseASN1Time(const std::string& timeStr) {
    std::istringstream ss(timeStr);
    std::tm tm = {};
    ss >> std::get_time(&tm, "%b %d %H:%M:%S %Y GMT");
    if (ss.fail()) {
        throw std::runtime_error("Failed to parse time string");
    }
    return std::mktime(&tm);
}
