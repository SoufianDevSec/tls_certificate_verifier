#include "Mainwindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QTextEdit>
#include <QDebug>

MainWindow::MainWindow(QWidget *parent) 
    : QMainWindow(parent), sslModel(new SSLModel()) {
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);

    // Input Layout
    QHBoxLayout *inputLayout = new QHBoxLayout();
    QLabel *urlLabel = new QLabel("URL:", this);
    urlInput = new QLineEdit(this);
    inputLayout->addWidget(urlLabel);
    inputLayout->addWidget(urlInput);
    mainLayout->addLayout(inputLayout);

    // Connect Button
    QPushButton *connectButton = new QPushButton("Connect", this);
    connect(sslModel, &SSLModel::connectionSuccessful, this, &MainWindow::onConnectionSuccessful);
    connect(sslModel, &SSLModel::connectionFailed, this, &MainWindow::onConnectionFailed);
    connect(connectButton, &QPushButton::clicked, this, &MainWindow::onConnectButtonClicked);
    mainLayout->addWidget(connectButton);

    // Output Areas Layout
    QHBoxLayout *outputLayout = new QHBoxLayout();

    // General Output Area
    outputArea = new QTextEdit(this);
    outputArea->setReadOnly(true);
    outputLayout->addWidget(outputArea);

    // SSL Certificate Output Area
    sslOutputArea = new QTextEdit(this);
    sslOutputArea->setReadOnly(true);
    outputLayout->addWidget(sslOutputArea);

    mainLayout->addLayout(outputLayout);

    this->resize(800, 600);
}

MainWindow::~MainWindow() {
    delete sslModel;
}

#include <QDebug>

void MainWindow::onConnectButtonClicked() {
    qDebug() << "Connect button clicked";
    sslOutputArea->clear();
    outputArea->clear();

    QString url = urlInput->text().trimmed(); // Trim the text to remove any leading/trailing whitespace

    if (url.isEmpty()) {
        qDebug() << "URL is empty. Please enter a valid URL.";
        outputArea->append("URL is empty. Please enter a valid URL.");
        return; // Exit the slot if the URL is empty
    }

    std::string certificate = sslModel->performSSLConnection(url.toStdString());
    displaySSLCertificateInfo(certificate);
}


void MainWindow::onConnectionSuccessful(const QString& message) {
    outputArea->append(message); // Update the general output area with the success message
}

void MainWindow::onConnectionFailed(const QString& validatorName, const QString& reason) {
    outputArea->append("Connection failed: " + validatorName + " - " + reason);
}

void MainWindow::displaySSLCertificateInfo(const std::string& certificateInfo) {
    QString certificate = QString::fromStdString(certificateInfo);
    sslOutputArea->append(certificate);
}
