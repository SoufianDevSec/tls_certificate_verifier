#include "Mainwindow.h"
#include <QApplication>

int main(int argc, char *argv[]) {

    if (sodium_init() < 0) {
        /* panic! the library couldn't be initialized; it is not safe to use */
    } 
    
    QApplication app(argc, argv);
    MainWindow mainWindow;
    mainWindow.show();
    return app.exec();
}
