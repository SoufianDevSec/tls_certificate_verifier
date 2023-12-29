#include "Mainwindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QTextEdit>

MainWindow::MainWindow(QWidget *parent) 
    : QMainWindow(parent), sslModel(new SSLModel()) {
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    QVBoxLayout *layout = new QVBoxLayout(centralWidget);

    QHBoxLayout *inputLayout = new QHBoxLayout();
    QLabel *label = new QLabel("URL:", this);
    urlInput = new QLineEdit(this);
    inputLayout->addWidget(label);
    inputLayout->addWidget(urlInput);
    layout->addLayout(inputLayout);

    QPushButton *connectButton = new QPushButton("Connect", this);
    connect(connectButton, &QPushButton::clicked, this, &MainWindow::onConnectButtonClicked);
    layout->addWidget(connectButton);

    outputArea = new QTextEdit(this);
    outputArea->setReadOnly(true);
    layout->addWidget(outputArea);

    this->resize(600, 400);

}

MainWindow::~MainWindow() {
    delete sslModel;
}

void MainWindow::onConnectButtonClicked() {
    std::string url = urlInput->text().toStdString();
    std::string result = sslModel->performSSLConnection(url);
    outputArea->append(QString::fromStdString(result));
}
