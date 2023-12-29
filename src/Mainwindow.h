#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QLineEdit>
#include <QTextEdit>
#include "sslmodel.h"

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onConnectButtonClicked();

private:
    QLineEdit *urlInput;
    QTextEdit *outputArea;
    SSLModel *sslModel;
};

#endif // MAINWINDOW_H
