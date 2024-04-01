#ifndef VALIDATOR_H
#define VALIDATOR_H

#include <string>
#include <memory>
#include <QObject>
#include <openssl/x509.h>

class Validator : public QObject {

    Q_OBJECT

private:
    QString reason;  // Using QString for better integration with Qt
    
    QString validatorName;  // Using QString for consistency

protected:
    std::shared_ptr<Validator> nextValidator;

public:
    explicit Validator(QObject* parent, const QString& name) : QObject(parent), validatorName(name) {}

    virtual ~Validator() override {}

    // Setter for nextValidator
    virtual void setNext(std::shared_ptr<Validator> validator) {
        nextValidator = validator;
    }

    // Getter for reason
    QString getReason() const {
        return reason;
    }

    // Setter for reason
    void setReason(const QString& r) {
        reason = r;
    }

        // Getter for reason
    QString getValidatorName() const {
        return validatorName;
    }

    // The validate method remains abstract, to be implemented by derived classes
    virtual bool validate(const X509 *cert) = 0;
};



// ExpirationValidator class definition
class ExpirationValidator : public Validator {
public:
    using Validator::Validator; // Inherit constructor if necessary
    bool validate(const X509* cert) override;

private:
    std::pair<std::string, std::string> getCertificateValidity(const X509* cert);
    std::string asn1TimeToString(const ASN1_TIME* time);
    std::time_t parseASN1Time(const std::string& timeStr);
};

#endif // VALIDATOR_H