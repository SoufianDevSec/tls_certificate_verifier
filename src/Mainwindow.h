#ifndef MAINWINDOW_H
#define MAINWINDOW_H


#include <QMainWindow>
#include <QLineEdit>
#include <QTextEdit>
#include <sodium.h>
#include "SSLmodel.h"


class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void displaySSLCertificateInfo(const std::string& certificateInfo);

private slots:
    void onConnectButtonClicked();

private:
    QLineEdit *urlInput;
    QTextEdit *outputArea;
    QTextEdit *sslOutputArea; // Declaration of sslOutputArea
    SSLModel *sslModel;

private slots:
    void onConnectionSuccessful(const QString& message);
    void onConnectionFailed(const QString& validatorName, const QString& reason);
};

#endif // MAINWINDOW_H
